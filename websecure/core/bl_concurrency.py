from __future__ import annotations
from websecure.core.http import hardened_session
import asyncio
import hashlib
import logging
import random
import ssl
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple
from urllib.parse import urljoin
from importlib.util import find_spec

import requests

# =======================
# Opsiyonel async bağımlılık (istisnasız)
# =======================

_AIOHTTP = bool(find_spec("aiohttp"))
if _AIOHTTP:
    import aiohttp  # type: ignore[import-untyped]  # aiohttp has no bundled stubs


# =======================
# Raporlama kancası (opsiyonel)
# =======================

def _load_add_result() -> Callable[..., None]:
    if find_spec("websecure.core.reporting"):
        from websecure.core.reporting import add_result
        return add_result
    # Görünür fallback: log’a yaz, susturma yok
    def _fallback(*a, **k):
        if a:
            logging.debug(f"[reporting-fallback] {a[0]} :: {a[1:] if len(a)>1 else ''} {k if k else ''}")
    return _fallback

add_result = _load_add_result()

# =======================
# Yardımcılar
# =======================

def parse_retry_after(headers: Dict[str, Any]) -> Optional[int]:
    """
    Retry-After değeri saniye olarak döner; yoksa None.
    RFC7231 formatlarını destekler (sayı ya da HTTP-date).
    """
    if not isinstance(headers, dict):
        return None
    raw = headers.get("Retry-After") or headers.get("retry-after")
    if raw is None:
        return None
    s = str(raw).strip()
    if not s:
        return None
    if s.isdigit():
        val = int(s)
        return val if val >= 0 else 0

    # HTTP-date (email.utils.parsedate_to_datetime)
    from email.utils import parsedate_to_datetime  # stdlib; genelde None döner, istisna atmaz
    dt = parsedate_to_datetime(s)
    if dt is None:
        return None
    import datetime as _dt
    now = _dt.datetime.now(_dt.timezone.utc)
    delta = (dt - now).total_seconds()
    return int(delta) if delta > 0 else 0


_IDEMPOTENT = {"GET", "HEAD", "OPTIONS"}
_BODY_SAMPLE = 400


def _now() -> float:
    return time.monotonic()


def _body_fingerprint(text: str) -> str:
    t = (text or "")[:2048]
    return hashlib.sha256(t.encode("utf-8", errors="ignore")).hexdigest()[:16]


def _emit(cb: Optional[Callable[[str, Dict[str, Any]], None]], evt: str, data: Dict[str, Any]) -> None:
    if cb is None:
        return
    ret = cb(evt, data)
    import inspect
    if inspect.isawaitable(ret):
        loop = asyncio.get_event_loop_policy().get_event_loop()
        if loop.is_running():
            loop.create_task(ret)  # mevcut döngüde planla
        else:
            asyncio.run(ret)       # ayrı döngüde tamamla


# =======================
# Rate gates (sync / async)
# =======================

class RateGate:
    """Global rate ve inflight sınırlayıcı (thread)."""

    def __init__(self, rate_ms: int = 0, max_inflight: Optional[int] = None):
        self.rate_ms = max(0, int(rate_ms))
        self.period = self.rate_ms / 1000.0 if self.rate_ms > 0 else 0.0
        self._last = 0.0
        self._lock = threading.Lock()
        upper = max_inflight if (max_inflight and max_inflight > 0) else 10 ** 9
        self._sem = threading.Semaphore(upper)
        self._acq = 0
        self._acq_lock = threading.Lock()

    def acquire(self) -> None:
        self._sem.acquire()
        with self._acq_lock:
            self._acq += 1

    def release(self) -> None:
        with self._acq_lock:
            if self._acq > 0:
                self._acq -= 1
                self._sem.release()

    def throttle(self) -> None:
        if self.period <= 0:
            return
        with self._lock:
            now = _now()
            delta = now - self._last
            if delta < self.period:
                time.sleep(self.period - delta)
                self._last = _now()
            else:
                self._last = now


class AsyncRateGate:
    """Global rate ve inflight sınırlayıcı (asyncio, non-blocking)."""

    def __init__(self, rate_ms: int = 0, max_inflight: Optional[int] = None):
        self.rate_ms = max(0, int(rate_ms))
        self.period = self.rate_ms / 1000.0 if self.rate_ms > 0 else 0.0
        self._last = 0.0
        self._lock = asyncio.Lock()
        upper = max_inflight if (max_inflight and max_inflight > 0) else 10 ** 9
        self._sem = asyncio.Semaphore(upper)
        self._acq = 0
        self._acq_lock = asyncio.Lock()

    async def acquire(self) -> None:
        await self._sem.acquire()
        async with self._acq_lock:
            self._acq += 1

    def release(self) -> None:
        def _release():
            # asyncio.Semaphore.release istisna atmaz; dahili sayaç güvenliği için koruma
            return
        # Sayaç tutarlılığı
        async def _dec():
            async with self._acq_lock:
                if self._acq > 0:
                    self._acq -= 1
                    self._sem.release()
        # Koşan döngüde planla
        loop = asyncio.get_event_loop_policy().get_event_loop()
        if loop.is_running():
            loop.create_task(_dec())
        else:
            asyncio.run(_dec())

    async def throttle(self) -> None:
        if self.period <= 0:
            return
        async with self._lock:
            now = _now()
            delta = now - self._last
            if delta < self.period:
                await asyncio.sleep(self.period - delta)
                self._last = _now()
            else:
                self._last = now


# =======================
# Backoff & retry policy
# =======================

@dataclass
class RetryPolicy:
    retry_max: int = 1
    retry_for: Tuple[int, ...] = (429, 500, 502, 503, 504)
    backoff_factor: float = 0.5  # saniye
    jitter_ms: int = 5
    respect_retry_after: bool = True

    def compute_sleep(self, attempt: int, resp: Optional[requests.Response] = None) -> float:
        if self.respect_retry_after and resp is not None and getattr(resp, "status_code", None) == 429:
            ra = parse_retry_after(getattr(resp, "headers", {}) or {})
            if isinstance(ra, (int, float)) and ra > 0:
                return float(ra) + random.uniform(0, self.jitter_ms / 1000.0)
        base = self.backoff_factor * (2 ** max(0, attempt - 1))
        return base + random.uniform(0, self.jitter_ms / 1000.0)


# =======================
# Request Executors
# =======================

class RequestExecutor:
    def __init__(self, session: requests.Session, timeout: int, verify_tls: bool, policy: RetryPolicy,
                 event_cb: Optional[Callable[[str, Dict[str, Any]], None]] = None):
        self.sess = session
        self.timeout = int(timeout)
        self.verify_tls = bool(verify_tls)
        self.policy = policy
        self.cb = event_cb

    def send(self, method: str, url: str, *, headers=None, data=None, jsn=None) -> Tuple[int, str, Optional[requests.Response]]:
        verify_flag = getattr(self.sess, "verify", True) if self.verify_tls else False
        r = self.sess.request(method, url, headers=headers, data=data, json=jsn,
                              timeout=self.timeout, allow_redirects=True, verify=verify_flag)
        return getattr(r, "status_code", -1), (getattr(r, "text", "") or ""), r

    def run_with_retries(self, method: str, url: str, *, headers=None, data=None, jsn=None) -> Tuple[int, str]:
        attempt = 0
        status = -1
        text = ""
        resp: Optional[requests.Response] = None
        while True:
            attempt += 1
            status, text, resp = self.send(method, url, headers=headers, data=data, jsn=jsn)
            if status not in self.policy.retry_for or attempt > self.policy.retry_max:
                return status, text
            _emit(self.cb, "bl.retry", {"attempt": attempt, "status": status})
            time.sleep(self.policy.compute_sleep(attempt, resp))


class AsyncRequestExecutor:
    def __init__(self, client: "aiohttp.ClientSession", timeout: int, policy: RetryPolicy,
                 event_cb: Optional[Callable[[str, Dict[str, Any]], None]] = None):
        self.client = client
        self.timeout = int(timeout)
        self.policy = policy
        self.cb = event_cb

    async def send(self, method: str, url: str, *, headers=None, data=None, jsn=None) -> Tuple[int, str, Optional["aiohttp.ClientResponse"]]:
        to = aiohttp.ClientTimeout(total=self.timeout)  # type: ignore
        async with self.client.request(method, url, headers=headers, data=data, json=jsn, timeout=to, allow_redirects=True) as r:  # type: ignore
            txt = await r.text()
            return getattr(r, "status", -1), txt, r  # type: ignore

    async def run_with_retries(self, method: str, url: str, *, headers=None, data=None, jsn=None) -> Tuple[int, str]:
        attempt = 0
        status = -1
        text = ""
        resp = None
        while True:
            attempt += 1
            status, text, resp = await self.send(method, url, headers=headers, data=data, jsn=jsn)
            if status not in self.policy.retry_for or attempt > self.policy.retry_max:
                return status, text
            _emit(self.cb, "bl.retry", {"attempt": attempt, "status": status})
            await asyncio.sleep(self.policy.compute_sleep(attempt, None))


# =======================
# Engines
# =======================

@dataclass
class RaceSpec:
    name: str
    method: str
    url: str
    headers: Dict[str, str]
    data: Any
    jsn: Any
    conc: int
    repeat: int
    timeout: int
    verify_tls: bool
    jitter_ms: int
    barrier_timeout: float
    sync_gate: bool
    policy: RetryPolicy
    rate_ms: int
    max_inflight: Optional[int]
    debug: bool


class RaceEngine:
    def run(self, spec: RaceSpec, *, session: Optional[requests.Session] = None,
            base_ssl_ctx: Optional[ssl.SSLContext] = None,
            event_cb: Optional[Callable[[str, Dict[str, Any]], None]] = None) -> Tuple[List[Tuple[int, int, str]], List[str], List[str]]:
        raise NotImplementedError


class ThreadEngine(RaceEngine):
    def run(self, spec: RaceSpec, *, session: Optional[requests.Session] = None,
            base_ssl_ctx: Optional[ssl.SSLContext] = None,
            event_cb: Optional[Callable[[str, Dict[str, Any]], None]] = None) -> Tuple[List[Tuple[int, int, str]], List[str], List[str]]:

        sess = session if session is not None else hardened_session({})
        execu = RequestExecutor(sess, spec.timeout, spec.verify_tls, spec.policy, event_cb=event_cb)
        sigs: List[Tuple[int, int, str]] = []
        bodies: List[str] = []
        errors: List[str] = []

        # Sync-gate: Barrier yerine Event + sayaç (exceptionsız)
        gate_event: Optional[threading.Event] = threading.Event() if spec.sync_gate else None
        gate_count = 0
        gate_lock = threading.Lock()

        def _gate_wait():
            nonlocal gate_count
            if gate_event is None:
                return
            with gate_lock:
                gate_count += 1
                if gate_count >= spec.conc:
                    gate_event.set()
            gate_event.wait(timeout=spec.barrier_timeout)

        rg = RateGate(rate_ms=spec.rate_ms, max_inflight=spec.max_inflight)

        def worker(wid: int, iter_count: int):
            _gate_wait()
            for _ in range(iter_count):
                rg.acquire()
                if spec.jitter_ms > 0:
                    time.sleep(random.uniform(0, spec.jitter_ms / 1000.0))
                rg.throttle()
                st, txt = execu.run_with_retries(spec.method, spec.url, headers=spec.headers, data=spec.data, jsn=spec.jsn)
                fp = _body_fingerprint(txt)
                sigs.append((st, len(txt or ""), fp))
                if spec.debug:
                    bodies.append((txt or "")[:_BODY_SAMPLE])
                rg.release()

        threads: List[threading.Thread] = []
        for i in range(spec.conc):
            t = threading.Thread(target=worker, args=(i, spec.repeat))
            threads.append(t)

        random.shuffle(threads)
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        return sigs, bodies, errors


class AsyncioEngine(RaceEngine):
    def run(self, spec: RaceSpec, *, session: Optional[requests.Session] = None,
            base_ssl_ctx: Optional[ssl.SSLContext] = None,
            event_cb: Optional[Callable[[str, Dict[str, Any]], None]] = None) -> Tuple[List[Tuple[int, int, str]], List[str], List[str]]:
        if not _AIOHTTP:
            raise RuntimeError("aiohttp not available for asyncio engine")

        async def _main() -> Tuple[List[Tuple[int, int, str]], List[str], List[str]]:
            # SSL context
            if spec.verify_tls:
                ssl_ctx = ssl.create_default_context()
            else:
                ssl_ctx = ssl.create_default_context()
                ssl_ctx.check_hostname = False
                ssl_ctx.verify_mode = ssl.CERT_NONE

            connector = aiohttp.TCPConnector(ssl=ssl_ctx, limit=max(spec.conc * 2, 20))  # type: ignore
            sigs: List[Tuple[int, int, str]] = []
            bodies: List[str] = []
            errors: List[str] = []

            async with aiohttp.ClientSession(connector=connector) as client:  # type: ignore
                rg = AsyncRateGate(rate_ms=spec.rate_ms, max_inflight=spec.max_inflight)
                execu = AsyncRequestExecutor(client, spec.timeout, spec.policy, event_cb=event_cb)

                async def one_task() -> Tuple[int, int, str, str]:
                    await rg.acquire()
                    if spec.jitter_ms > 0:
                        await asyncio.sleep(random.uniform(0, spec.jitter_ms / 1000.0))
                    await rg.throttle()
                    st, txt = await execu.run_with_retries(spec.method, spec.url, headers=spec.headers, data=spec.data, jsn=spec.jsn)
                    ln = len(txt or "")
                    fp = _body_fingerprint(txt or "")
                    sample = txt[:_BODY_SAMPLE] if spec.debug else ""
                    rg.release()
                    return (st, ln, fp, sample)

                tasks: List["asyncio.Task[Any]"] = []
                for _ in range(spec.conc * spec.repeat):
                    tasks.append(asyncio.create_task(one_task()))

                await asyncio.sleep(0.01)  # mikro senkron kapı
                results = await asyncio.gather(*tasks, return_exceptions=False)
                for st, ln, fp, sample in results:
                    sigs.append((st, ln, fp))
                    if spec.debug and sample:
                        bodies.append(sample)

            return sigs, bodies, errors

        loop = asyncio.get_event_loop_policy().get_event_loop()
        if loop.is_running():
            # Ayrı thread’de yeni loop ile çalıştır
            result_box: Dict[str, Any] = {}

            def _worker():
                loop2 = asyncio.new_event_loop()
                asyncio.set_event_loop(loop2)
                result_box["val"] = loop2.run_until_complete(_main())
                loop2.close()

            t = threading.Thread(target=_worker, daemon=True)
            t.start()
            t.join()
            return result_box.get("val", ([], [], []))
        else:
            return asyncio.run(_main())


# =======================
# Assertions
# =======================

def _evaluate_assertions(
        sigs: List[Tuple[int, int, str]],
        bodies: List[str],
        assertions: Dict[str, Any],
        debug: bool,
) -> Tuple[bool, Dict[str, Any]]:
    uniq_status_len = {(st, ln) for (st, ln, _) in sigs}
    uniq_fp = {fp for (_, _, fp) in sigs}

    anomaly = len(uniq_status_len) > 1 or (assertions.get('different_signatures') and len(uniq_fp) > 1)
    min_ok = assertions.get('success_at_least')
    max_ok = assertions.get('success_at_most')
    ok_count = sum(1 for (st, _, __) in sigs if 200 <= st < 300)
    if isinstance(min_ok, int) and ok_count < min_ok:
        anomaly = True
    if isinstance(max_ok, int) and ok_count > max_ok:
        anomaly = True

    st_in = assertions.get("status_contains")
    if st_in and not any(st in st_in for (st, _, __) in sigs):
        anomaly = True

    if debug:
        body_has = assertions.get("body_contains")
        if body_has:
            body_ok = any(any(x in b for x in (body_has or [])) for b in bodies)
            if not body_ok:
                anomaly = True

    details = {
        "unique_status_len": len(uniq_status_len),
        "unique_bodies_fingerprint": len(uniq_fp),
        "ok_count": ok_count,
    }
    return anomaly, details


# =======================
# Public API
# =======================

def run_race_conditions(session: requests.Session, base_url: str, cfg: Dict[str, Any], results: Dict[str, Any], *,
                        debug: bool = False,
                        event_cb: Optional[Callable[[str, Dict[str, Any]], None]] = None) -> Dict[str, Any]:
    """
    config.business_logic.races: list of tests
      - name, engine("auto"|"asyncio"|"thread"), target {method,url,headers,body/json}, concurrency, repeat, timeout
      - sync_gate(bool, default True), barrier_timeout(float s), jitter_ms(int)
      - retry {max:int, for:[codes], backoff_factor:float, jitter_ms:int, respect_retry_after:bool}
      - rate {ms:int, max_inflight:int}
      - assertions (opsiyonel): { status_contains:[200], body_contains:["ok"], different_signatures:true,
                                  success_at_least:int, success_at_most:int }
    """
    bl = (cfg.get("business_logic") or {})
    races = bl.get("races") or []
    if not races:
        add_result("meta", {"stage": "race", "status": "skipped:no-races"})
        return {"ran": 0, "findings": 0}

    findings: List[Dict[str, Any]] = []
    seed = int((cfg.get('business_logic') or {}).get('seed', 1337) or 1337)
    random.seed(seed)

    total_tests = 0

    for test in races:
        total_tests += 1
        name = str(test.get("name") or "race")
        tgt = test.get("target") or {}
        method = str(tgt.get("method", "GET")).upper()
        url = tgt.get("url") or "/"
        base_url2 = base_url if base_url.endswith("/") else base_url + "/"
        url = url if isinstance(url, str) and url.startswith("http") else urljoin(base_url2, str(url).lstrip("/"))
        headers = tgt.get("headers") or {}
        data = tgt.get("body")
        jsn = tgt.get("json")
        conc = max(2, int(test.get("concurrency", 12)))
        repeat = max(1, int(test.get("repeat", 2)))
        timeout = int(test.get("timeout", 10))
        verify = bool(bl.get("verify_tls", True))
        jitter_ms = int(test.get("jitter_ms", 5))
        barrier_timeout = float(test.get("barrier_timeout", 2.0))
        sync_gate = bool(test.get("sync_gate", True))
        engine_req = str(test.get("engine", "auto")).lower()
        assertions = test.get("assertions") or {}

        retry_cfg = test.get("retry") or {}
        policy = RetryPolicy(
            retry_max=int(retry_cfg.get("max", 1)),
            retry_for=tuple(int(x) for x in (retry_cfg.get("for") or (429, 500, 502, 503, 504))),
            backoff_factor=float(retry_cfg.get("backoff_factor", 0.5)),
            jitter_ms=int(retry_cfg.get("jitter_ms", jitter_ms)),
            respect_retry_after=bool(retry_cfg.get("respect_retry_after", True)),
        )

        rate_cfg = test.get("rate") or {}
        rate_ms = int(rate_cfg.get("ms", 0))
        max_inflight = int(rate_cfg.get("max_inflight", conc)) if rate_cfg.get("max_inflight") is not None else conc

        if method not in _IDEMPOTENT and debug:
            add_result("meta", {"source": "bizlogic_race", "name": name, "note": f"Non-idempotent method under race: {method}"})

        spec = RaceSpec(
            name=name, method=method, url=url, headers=headers, data=data, jsn=jsn,
            conc=conc, repeat=repeat, timeout=timeout, verify_tls=verify, jitter_ms=jitter_ms,
            barrier_timeout=barrier_timeout, sync_gate=sync_gate, policy=policy,
            rate_ms=rate_ms, max_inflight=max_inflight, debug=debug
        )

        # Engine seçimi (exceptionsız)
        used_engine = "thread"
        if engine_req == "asyncio" and _AIOHTTP:
            eng: RaceEngine = AsyncioEngine()
            used_engine = "asyncio"
        elif engine_req == "auto" and _AIOHTTP:
            eng = AsyncioEngine()
            used_engine = "asyncio"
        else:
            eng = ThreadEngine()
            used_engine = "thread"

        _emit(event_cb, "bl.start", {"name": name, "engine": used_engine, "url": url})
        sigs, bodies, errors = eng.run(spec, session=session, event_cb=event_cb)

        anomaly, details = _evaluate_assertions(sigs, bodies, assertions, debug)

        item = {
            "name": name, "url": url, "method": method,
            "concurrency": conc, "repeat": repeat, "engine": used_engine,
            **details,
            "anomaly": anomaly,
            "errors": errors[:5]
        }
        if debug:
            uniq_status_len = {(st, ln) for (st, ln, _) in sigs}
            uniq_fp = {fp for (_, _, fp) in sigs}
            item["_debug_sigs"] = list(uniq_status_len)
            item["_debug_fps"] = list(uniq_fp)[:5]
            item["_debug_samples"] = [b for b in bodies if b][: min(3, len(bodies))]

        if anomaly:
            findings.append(item)
            add_result('bizlogic_findings', {
                'url': url,
                'type': 'RACE_CONDITION',
                'severity': 'Yüksek' if method not in _IDEMPOTENT else 'Orta',
                'reason': 'Race anomali: status/boyut/parmak izi farklılıkları',
                'method': method
            })
        add_result("vulnerability", {**item, "source": "bizlogic_race", "type": "Race Condition"})
        _emit(event_cb, "bl.done", {"name": name, "engine": used_engine, "anomaly": anomaly})

    add_result("meta", {"stage": "race", "tests": total_tests, "anomaly_count": len(findings)})
    results.setdefault("bizlogic_summary", {})
    results["bizlogic_summary"]["race_anomalies"] = len(findings)
    results["bizlogic_summary"]["tests"] = total_tests

    return {"ran": total_tests, "findings": len(findings)}
