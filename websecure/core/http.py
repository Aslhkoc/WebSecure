from __future__ import annotations
import logging
import os
import time
import random
import contextvars
import threading
import socket
from typing import Dict, Optional

_logger = logging.getLogger(__name__)



try:
    import requests
except ImportError:  # fallback friendly
    requests = None

try:
    from websecure.core.waf_bypass import WAFBypassAdapter
except ImportError:
    WAFBypassAdapter = None

try:
    from websecure.core.exceptions import wrap_requests_error as _wrap_requests_error
except ImportError:
    _wrap_requests_error = None  # type: ignore[assignment]



def _emit_egress_degraded(feature: str, reason: str, details: dict | None = None) -> None:
    rec = {'feature': str(feature), 'reason': str(reason)}
    if isinstance(details, dict):
        rec.update({k: v for k, v in details.items() if isinstance(k, str)})
    if callable(globals().get('add_result')):
        add_result('egress_degraded', rec)




def set_phase(name: str):
    HTTP_METRICS["phase"] = name

def is_open(host: str, port: int, timeout: float = 0.4) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False

# END:### WEBSECURE FLOW FIX PACK



ACTIVE_PHASE = contextvars.ContextVar("ACTIVE_PHASE", default="discovery")

# ---- Last HTTP exchange capture (per-finding request/response evidence) -------
# Every request through _smart_request records a compact snapshot here, scoped to
# the current thread / async context. scanners/base.report_finding() then attaches
# it to a finding so the report can show, for each vuln: the exact payload, WHERE
# it was injected, and the response that came back ("şu payload şu kısma uygulandı
# şu cevap geldi"). Snapshot is intentionally small (2 KB body snippet).
_LAST_EXCHANGE = contextvars.ContextVar("_LAST_EXCHANGE", default=None)


def get_last_exchange():
    """Most recent HTTP exchange snapshot for the current context (or None)."""
    return _LAST_EXCHANGE.get()


def _record_exchange(method, url, kwargs, resp, elapsed_ms) -> None:
    """Store a compact snapshot of the just-completed request/response. Never raises."""
    try:
        _hdrs = {}
        _rh = getattr(resp, "headers", {}) or {}
        for _h in ("Content-Type", "Server", "Content-Length", "Location",
                   "Set-Cookie", "WWW-Authenticate", "X-Powered-By"):
            try:
                _v = _rh.get(_h)
            except Exception:
                _v = None
            if _v:
                _hdrs[_h] = str(_v)[:300]
        try:
            _body = resp.text or ""
        except Exception:
            _body = ""
        _params = kwargs.get("params")
        _data = kwargs.get("data")
        _LAST_EXCHANGE.set({
            "method": str(method).upper(),
            "url": url,
            "status": int(getattr(resp, "status_code", 0) or 0),
            "elapsed_ms": int(elapsed_ms),
            "req_params": dict(_params) if isinstance(_params, dict) else {},
            "req_data": _data if isinstance(_data, (dict, str)) else None,
            "resp_headers": _hdrs,
            "resp_snippet": _body[:2048],
        })
        # Feed the WAF-bypass ML scorer: if this request carried a creative bypass
        # payload, learn whether it got through (200) or was blocked (403/406/429…)
        # so later requests prioritise the evasions that work on THIS target's WAF.
        try:
            _txt = url
            _p = kwargs.get("params")
            _d = kwargs.get("data")
            if _p:
                _txt += " " + str(_p)
            if _d:
                _txt += " " + str(_d)
            from websecure.core.waf_bypass import (
                classify_bypass_strategy as _cbs,
                get_global_scorer as _ggs,
                WAF_BLOCK_STATUS as _WBS,
            )
            _strat = _cbs(_txt)
            if _strat:
                _st = int(getattr(resp, "status_code", 0) or 0)
                _ggs().record_attempt(
                    _strat, blocked=(_st in _WBS),
                    status_code=_st, response_time_ms=float(elapsed_ms),
                )
        except Exception:
            pass
    except Exception:
        pass

# ---- Abandoned-phase cooperative cancellation ----------------------------
# A phase that exceeds its watchdog timeout is logged as "skipped", but Python
# cannot force-kill its daemon thread — so the thread KEEPS issuing throttled
# HTTP requests in the background, stealing the rest of the scan's wall-clock
# budget and interleaving its output into later phases (observed on the neuneon
# run: 'discovery' kept crawling after being skipped). When the watchdog gives
# up on a phase it calls mark_phase_abandoned(); every subsequent request made
# from that phase's thread then short-circuits *before* sleeping or hitting the
# network, so the orphaned thread drains fast instead of running for hours.
_ABANDONED_PHASES: set = set()
_ABANDONED_LOCK = threading.Lock()


class PhaseAbandoned(Exception):
    """Raised to abort requests issued by a phase that the watchdog has skipped."""


def mark_phase_abandoned(name: str) -> None:
    with _ABANDONED_LOCK:
        _ABANDONED_PHASES.add(name)


def clear_phase_abandoned(name: str) -> None:
    with _ABANDONED_LOCK:
        _ABANDONED_PHASES.discard(name)


def is_phase_abandoned(name: Optional[str] = None) -> bool:
    nm = name if name is not None else ACTIVE_PHASE.get()
    with _ABANDONED_LOCK:
        return nm in _ABANDONED_PHASES


# ---------------------------------------------------------------------------
# Global "max power" / timeout-free runtime flags
# ---------------------------------------------------------------------------
# Set once at scan startup from config (settings.no_timeout) and from the
# interactive Tor setup. Two orthogonal switches:
#
#   • no_timeout  — disable the per-phase watchdog skip, the global scan
#                   deadline, and every external-tool subprocess timeout, so
#                   NOTHING is skipped just because it ran long. Ctrl+C remains
#                   the single cooperative stop signal.
#   • tor_active  — SOCKS/Tor egress is in use. The onion circuit adds seconds
#                   of latency, so a 4-5s read timeout (passed by individual
#                   probes) guarantees a flood of ReadTimeoutError → the circuit
#                   breaker trips → whole phases abort early. When Tor is active
#                   we raise every per-request timeout to a sane floor.
#
# Modules that live in separate import graphs (integrations/*, circuit_breaker)
# read the mirror env vars instead of importing this module (avoids cycles).
_NO_TIMEOUT: bool = False
_TOR_ACTIVE: bool = False
# (connect, read) seconds enforced as a MINIMUM when Tor is active.
_TOR_TIMEOUT_FLOOR: tuple[float, float] = (20.0, 45.0)
# (connect, read) seconds imposed as a DEFAULT when a caller omits ``timeout``
# entirely (timeout=None) on a DIRECT (non-Tor) connection. requests' ``read``
# timeout is an *inactivity* timeout (max seconds between bytes from the server),
# so a generous value like 60s NEVER cuts a slow-but-progressing response while
# still guaranteeing a stalled/half-open socket can't hang the request — and thus
# the phase — forever. This is the single most important "always hangs somewhere"
# guard: any scanner that does session.get(url) WITHOUT timeout= used to block
# indefinitely off Tor (the previous _floor_request_timeout no-op'd off Tor and
# build_session's stashed .request_timeout was never read). no_timeout disables
# orchestration deadlines (phase watchdog / global deadline / tool subprocess
# waits) — NOT per-request finiteness; a single HTTP request always stays bounded.
_DEFAULT_REQUEST_TIMEOUT: tuple[float, float] = (15.0, 60.0)


def set_power_flags(no_timeout: Optional[bool] = None,
                    tor_active: Optional[bool] = None,
                    tor_floor: Optional[tuple] = None,
                    request_timeout: Optional[tuple] = None) -> None:
    """Update the process-global power flags. Mirrors to env for cross-module use."""
    global _NO_TIMEOUT, _TOR_ACTIVE, _TOR_TIMEOUT_FLOOR, _DEFAULT_REQUEST_TIMEOUT
    if no_timeout is not None:
        _NO_TIMEOUT = bool(no_timeout)
        os.environ["WEBSECURE_NO_TIMEOUT"] = "1" if _NO_TIMEOUT else "0"
    if tor_active is not None:
        _TOR_ACTIVE = bool(tor_active)
        os.environ["WEBSECURE_TOR_ACTIVE"] = "1" if _TOR_ACTIVE else "0"
    if tor_floor is not None and isinstance(tor_floor, (tuple, list)) and len(tor_floor) == 2:
        try:
            _TOR_TIMEOUT_FLOOR = (float(tor_floor[0]), float(tor_floor[1]))
        except (TypeError, ValueError):
            pass
    if request_timeout is not None and isinstance(request_timeout, (tuple, list)) and len(request_timeout) == 2:
        try:
            _DEFAULT_REQUEST_TIMEOUT = (float(request_timeout[0]), float(request_timeout[1]))
        except (TypeError, ValueError):
            pass


def no_timeout_enabled() -> bool:
    """True when the scan is running in timeout-free 'max power' mode."""
    return _NO_TIMEOUT or os.environ.get("WEBSECURE_NO_TIMEOUT") == "1"


def tor_active() -> bool:
    """True when SOCKS/Tor egress is active for this scan."""
    return _TOR_ACTIVE or os.environ.get("WEBSECURE_TOR_ACTIVE") == "1"


def _floor_request_timeout(timeout):
    """
    Resolve a per-request timeout, GUARANTEEING a finite value. Two jobs:

      1. Tor active  — raise any too-small (connect, read) up to the Tor floor so
         the high-latency onion circuit doesn't flood ReadTimeoutError → trip the
         circuit breaker → abort whole phases. (No-op for already-generous values.)
      2. Tor inactive — if the caller omitted ``timeout`` (None), impose a sane,
         generous default so a stalled/half-open DIRECT connection can never hang
         the request — and therefore the phase — forever. Explicit caller timeouts
         are respected unchanged (tight, fast probes keep their value).

    Accepts the same shapes ``requests``/``httpx`` accept: ``None``, a scalar, or
    a ``(connect, read)`` pair — and returns the same shape, so it is a drop-in for
    the ``timeout`` kwarg and SAFE to call unconditionally on every request.
    """
    if not _TOR_ACTIVE:
        # Direct connection: the only unbounded danger is timeout=None (block
        # forever). Any explicit value is the caller's intentional choice — keep it.
        if timeout is None:
            return _DEFAULT_REQUEST_TIMEOUT
        return timeout
    cmin, rmin = _TOR_TIMEOUT_FLOOR
    if timeout is None:
        # No explicit timeout: impose the floor so a stuck onion circuit cannot
        # hang forever, but stay generous.
        return (cmin, rmin)
    if isinstance(timeout, (tuple, list)) and len(timeout) == 2:
        c, r = timeout
        try:
            c = max(float(c), cmin) if c else cmin
            r = max(float(r), rmin) if r else rmin
            return (c, r)
        except (TypeError, ValueError):
            return (cmin, rmin)
    try:
        return max(float(timeout), rmin)
    except (TypeError, ValueError):
        return (cmin, rmin)


# ---------------------------------------------------------------------------
# Tor egress drop/recovery — user-visible warning (throttled, thread-safe)
# ---------------------------------------------------------------------------
# When Tor is the required egress and it drops mid-scan, requests fail closed
# (no real-IP leak) and the scan keeps going via the circuit breaker. But the
# user needs to KNOW it happened — otherwise the scan silently slows/loses
# coverage. These helpers print ONE clear warning on the down-transition (and a
# recovery notice when Tor returns), de-duplicated across the many request
# threads via a lock + cooldown so a flood of blocked probes can't spam the UI.
_TOR_DROP_STATE: Dict[str, Any] = {"down": False, "last_warn": 0.0}
_TOR_DROP_LOCK = threading.Lock()


def _note_tor_egress_down(reason: str = "") -> None:
    """Announce (once / throttled) that the Tor egress is unreachable."""
    now = time.monotonic()
    with _TOR_DROP_LOCK:
        first = not _TOR_DROP_STATE["down"]
        _TOR_DROP_STATE["down"] = True
        if not first and (now - _TOR_DROP_STATE["last_warn"]) < 30.0:
            return  # already warned recently — don't spam
        _TOR_DROP_STATE["last_warn"] = now
    msg = ("[!] UYARI: Tor baglantisi koptu/erisilemiyor — istekler engellendi "
           "(gercek IP sizmasi onlendi). Tor'un donmesi bekleniyor; tarama devam ediyor.")
    if reason:
        _logger.warning("[egress] Tor drop: %s", reason)
    _logger.warning(msg)
    try:
        print("\033[33m" + msg + "\033[0m", flush=True)
    except Exception:
        pass


def _note_tor_egress_up() -> None:
    """Announce recovery once, only if a drop was previously reported."""
    with _TOR_DROP_LOCK:
        if not _TOR_DROP_STATE["down"]:
            return
        _TOR_DROP_STATE["down"] = False
    msg = "[+] Tor baglantisi geri geldi — tarama normal suruyor."
    _logger.info(msg)
    try:
        print("\033[32m" + msg + "\033[0m", flush=True)
    except Exception:
        pass


def _looks_like_proxy_error(exc: BaseException) -> bool:
    """True if an exception indicates a SOCKS/Tor proxy failure (not a target error)."""
    try:
        import requests as _rq
        if isinstance(exc, _rq.exceptions.ProxyError):
            return True
    except Exception:
        pass
    txt = f"{type(exc).__name__} {exc}".lower()
    return any(k in txt for k in ("proxy", "socks", "sock_connect", "tor"))


_IDENTITY_POOLS = {
    "user_agents": [],
    "accept_language": [],
    "accept": []
}

_HTTP_POLICY = {
    "phase_profiles": {},
    "rate_limit": {
        "min_rps": 1,
        "backoff_multiplier": 0.5,
        "recover_step": 1,
        "canary_interval_seconds": 15,
        "respect_retry_after": True
    },
    "idempotent_first": {
        "enabled": True,
        "early_phases": ["discovery", "mapping"],
        "allow_post_threshold": 0.2,
        # True yapılırsa eski katı davranışa döner: saldırı fazlarında da POST
        # yalnızca _post_ratio_ok=True ise geçer (varsayılan: kapalı — POST izinli).
        "strict_non_idempotent": False
    }
}

# ---- Circuit Breaker (replaces _HttpPaceManager stub) ----
try:
    from websecure.core.circuit_breaker import (
        cb_check as _cb_check,
        cb_record as _cb_record,
        cb_record_error as _cb_record_error,
        cb_reset as _cb_reset,
        CircuitBreakerTripped as _CircuitBreakerTripped,
    )
    _CB_AVAILABLE = True
except ImportError:
    _CB_AVAILABLE = False
    def _cb_check(): pass
    def _cb_record(s): pass
    def _cb_record_error(): pass
    def _cb_reset(): pass
    class _CircuitBreakerTripped(Exception): pass
# ---- /Circuit Breaker ----

_CURRENT_RPS = contextvars.ContextVar("CURRENT_RPS", default=2)
_LAST_IDENTITY = contextvars.ContextVar("LAST_IDENTITY", default=None)
_LAST_CANARY_TS = 0.0
_LAST_CANARY_TS_LOCK = threading.Lock()

# ---------------------------------------------------------------------------
# GLOBAL ADAPTIVE CONCURRENCY (Madde 4 — Adım A)
# ---------------------------------------------------------------------------
# A single AIMD controller + dynamic admission gate caps the TOTAL number of
# in-flight network sends across ALL phases/threads. It GROWS the cap when the
# target answers fast & healthy and HALVES it on 429/503/high-latency/errors →
# "sağlıklı + güçlü" without a fixed thread storm. Defaults are CAUTIOUS/STEALTH
# (low ceiling, fast back-off) per the chosen policy.
#
# Safety: the gate is fully cancel-aware and BOUNDED — acquire() re-checks every
# 0.5s and never waits past an absolute cap (it over-admits rather than hang),
# consistent with the no_timeout "self-bound every wait" rule. The slot is held
# ONLY around the actual network send (retry back-off sleeps stay outside it), so
# a backing-off request never occupies a concurrency slot.
_ADAPTIVE_CFG: Dict[str, Any] = {
    "enabled":    True,
    "initial":    4,
    "min":        1,
    "max":        12,
    "low_ms":     300,
    "high_ms":    1500,
    "error_rate": 0.20,
    "max_wait_s": 120.0,
}
_ADAPTIVE_GATE = None
_ADAPTIVE_GATE_LOCK = threading.Lock()


class _AdaptiveAdmissionGate:
    """Dynamic admission gate sized by ``AdaptiveConcurrencyCtrl.current``.

    ``acquire()`` blocks while in-flight ≥ current, re-checking every 0.5s so it
    tracks AIMD growth, honours phase abandonment, and obeys an absolute safety
    cap. It can NEVER block forever: on cap expiry it admits anyway (degrade, not
    deadlock). ``record()`` feeds each outcome to the controller and wakes waiters
    when the cap grows.
    """

    def __init__(self, ctrl, max_wait_s: float = 120.0):
        self.ctrl = ctrl
        self._cond = threading.Condition()
        self._in_flight = 0
        self._max_wait_s = max(5.0, float(max_wait_s))

    def acquire(self, phase=None) -> None:
        deadline = time.monotonic() + self._max_wait_s
        with self._cond:
            while self._in_flight >= max(1, int(self.ctrl.current)):
                if phase is not None and is_phase_abandoned(phase):
                    raise PhaseAbandoned(f"admission aborted (phase abandoned): {phase}")
                if time.monotonic() >= deadline:
                    break  # safety: never hang — over-admit rather than deadlock
                self._cond.wait(timeout=0.5)
            self._in_flight += 1

    def release(self) -> None:
        with self._cond:
            self._in_flight = max(0, self._in_flight - 1)
            self._cond.notify()

    def record(self, response_ms: float, is_error: bool, status: int) -> None:
        try:
            self.ctrl.record(float(response_ms), bool(is_error), int(status or 0))
        except Exception:
            pass
        # AIMD may have grown current → wake any waiters so they re-check.
        with self._cond:
            self._cond.notify_all()

    def snapshot(self) -> Dict[str, Any]:
        try:
            snap = dict(self.ctrl.snapshot())
        except Exception:
            snap = {}
        snap["in_flight"] = self._in_flight
        return snap


def _configure_adaptive(cfg: dict) -> None:
    """Read ``concurrency.adaptive.*`` from config and reset the global gate."""
    global _ADAPTIVE_GATE
    try:
        ac = ((cfg or {}).get("concurrency") or {}).get("adaptive") or {}
    except Exception:
        ac = {}
    if isinstance(ac, dict):
        for key in ("enabled", "initial", "min", "max", "low_ms", "high_ms",
                    "error_rate", "max_wait_s"):
            if key in ac:
                _ADAPTIVE_CFG[key] = ac[key]
    with _ADAPTIVE_GATE_LOCK:
        _ADAPTIVE_GATE = None  # rebuilt lazily with the new knobs


def _get_adaptive_gate():
    """Lazily build the singleton admission gate; None when disabled/unavailable."""
    global _ADAPTIVE_GATE
    if not _ADAPTIVE_CFG.get("enabled", True):
        return None
    if _ADAPTIVE_GATE is not None:
        return _ADAPTIVE_GATE
    with _ADAPTIVE_GATE_LOCK:
        if _ADAPTIVE_GATE is None:
            try:
                from websecure.core.concurrency import AdaptiveConcurrencyCtrl
                ctrl = AdaptiveConcurrencyCtrl(
                    initial=int(_ADAPTIVE_CFG["initial"]),
                    min_c=int(_ADAPTIVE_CFG["min"]),
                    max_c=int(_ADAPTIVE_CFG["max"]),
                    low_ms=int(_ADAPTIVE_CFG["low_ms"]),
                    high_ms=int(_ADAPTIVE_CFG["high_ms"]),
                )
                try:
                    ctrl.ERROR_RATE = float(_ADAPTIVE_CFG["error_rate"])
                except Exception:
                    pass
                _ADAPTIVE_GATE = _AdaptiveAdmissionGate(
                    ctrl, _ADAPTIVE_CFG.get("max_wait_s", 120.0)
                )
            except Exception as _exc:
                _logger.debug(f"[HTTP] adaptive gate unavailable: {_exc!r}")
                _ADAPTIVE_GATE = None
    return _ADAPTIVE_GATE

def set_active_phase(name: str) -> None:
    # A fresh start for this phase id clears any stale "abandoned" flag from a
    # previous run so it is not pre-emptively cancelled.
    clear_phase_abandoned(name)
    ACTIVE_PHASE.set(name)
    prof = _HTTP_POLICY["phase_profiles"].get(name, {})
    rps = int(prof.get("initial_rps", _CURRENT_RPS.get()))
    _CURRENT_RPS.set(max(1, rps))

def install_http_phase_policies(cfg: dict) -> None:
    http_cfg = cfg.get("http", {}) if isinstance(cfg, dict) else {}
    pools = http_cfg.get("identity_pools", {})
    _IDENTITY_POOLS["user_agents"] = list(pools.get("user_agents", []))
    _IDENTITY_POOLS["accept_language"] = list(pools.get("accept_language", []))
    _IDENTITY_POOLS["accept"] = list(pools.get("accept", []))
    _HTTP_POLICY["phase_profiles"] = dict(http_cfg.get("phase_profiles", {}))
    rl = http_cfg.get("rate_limit", {})
    for k in _HTTP_POLICY["rate_limit"].keys():
        if k in rl:
            _HTTP_POLICY["rate_limit"][k] = rl[k]
    idem = http_cfg.get("idempotent_first", {})
    for k in _HTTP_POLICY["idempotent_first"].keys():
        if k in idem:
            _HTTP_POLICY["idempotent_first"][k] = idem[k]

    # Max-power / timeout-free mode (settings.no_timeout, default ON): disables the
    # per-phase watchdog skip, the global scan deadline and every external-tool
    # subprocess timeout so no work is skipped for running long. Tor activeness is
    # normally wired by the interactive setup_tor() (which runs AFTER this call),
    # but if Tor is already pinned in config we honor it here too.
    _settings = cfg.get("settings", {}) if isinstance(cfg, dict) else {}
    _floor = _settings.get("tor_timeout_floor")
    _tor_pinned = bool(cfg.get("_tor_proxy")) or bool(
        ((cfg.get("privacy") or {}).get("tor") or {}).get("enabled")
    )
    # Default per-request (connect, read) for callers that omit timeout= on a
    # direct connection. Derived from http config but floored generously so it is
    # always finite AND never cuts a slow-but-progressing response (read is an
    # inactivity timeout). connect ≤ 15s; read ≥ 45s (≥ 2× configured).
    _ts = http_cfg.get("timeout_seconds")
    _connect = http_cfg.get("connect_timeout")
    _read = http_cfg.get("read_timeout")
    try:
        _ts_f = float(_ts) if _ts else 20.0
    except (TypeError, ValueError):
        _ts_f = 20.0
    try:
        _c = float(_connect) if _connect else min(_ts_f, 15.0)
    except (TypeError, ValueError):
        _c = min(_ts_f, 15.0)
    try:
        _r = float(_read) if _read else max(_ts_f * 2.0, 45.0)
    except (TypeError, ValueError):
        _r = max(_ts_f * 2.0, 45.0)
    set_power_flags(
        no_timeout=bool(_settings.get("no_timeout", True)),
        tor_active=True if _tor_pinned else None,
        tor_floor=tuple(_floor) if isinstance(_floor, (list, tuple)) and len(_floor) == 2 else None,
        request_timeout=(_c, _r),
    )

    # Global adaptive concurrency knobs (Madde 4 — Adım A). Cautious/stealth
    # defaults; overridable via config.concurrency.adaptive.*.
    _configure_adaptive(cfg)

# Gerçekçi tarayıcı kimliği fallback'i — config http.identity_pools BOŞ olduğunda
# kullanılır. Eskiden çıplak "Mozilla/5.0" + Accept "*/*" gönderiliyordu; bu
# kombinasyon hiçbir gerçek tarayıcıda görülmez ve TEK BAŞINA bir bot imzasıdır
# (Cloudflare/Akamai gibi WAF'lar anında işaretler). Ayrıca WAFBypassAdapter UA'yı
# yalnızca yoksa/"python-requests" ise döndürdüğünden, "Mozilla/5.0" sessizce
# kalıp gerçek rotasyonu da etkisiz bırakıyordu. Artık fallback'te de gerçek,
# rotasyonlu tarayıcı kimlikleri kullanılır.
_FALLBACK_UA_POOL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
]
# Gerçek tarayıcıların gönderdiği tam Accept başlığı (Chrome/Firefox tarzı).
_FALLBACK_ACCEPT = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8"
_FALLBACK_ACCEPT_LANG = "en-US,en;q=0.9"

def _client_hints_for_ua(ua: str) -> Dict[str, str]:
    """UA string'ine TUTARLI sec-ch-ua client-hint başlıkları üretir.

    Modern Chromium tarayıcıları (Chrome/Edge) bu başlıkları gönderir; Firefox/
    Safari göndermez (boş döner). UA "Chrome/124" derken client-hints'in farklı
    bir sürüm/platform söylemesi WAF'lar için bot sinyalidir — bu yüzden ikisini
    aynı UA'dan türetip tutarlı tutuyoruz.
    """
    import re as _re
    hints: Dict[str, str] = {}
    if "Windows" in ua:
        platform = '"Windows"'
    elif "Macintosh" in ua or "Mac OS X" in ua:
        platform = '"macOS"'
    elif "Android" in ua:
        platform = '"Android"'
    elif "iPhone" in ua or "iPad" in ua:
        platform = '"iOS"'
    elif "Linux" in ua:
        platform = '"Linux"'
    else:
        platform = '"Unknown"'
    mobile = "?1" if any(s in ua for s in ("Mobile", "Android", "iPhone")) else "?0"

    if "Edg/" in ua:
        me = _re.search(r"Edg/(\d+)", ua)
        v = me.group(1) if me else "124"
        hints["sec-ch-ua"] = f'"Chromium";v="{v}", "Microsoft Edge";v="{v}", "Not.A/Brand";v="99"'
        hints["sec-ch-ua-mobile"] = mobile
        hints["sec-ch-ua-platform"] = platform
    else:
        mc = _re.search(r"Chrome/(\d+)", ua)
        if mc and "Firefox" not in ua and "OPR/" not in ua:
            v = mc.group(1)
            hints["sec-ch-ua"] = f'"Chromium";v="{v}", "Google Chrome";v="{v}", "Not.A/Brand";v="99"'
            hints["sec-ch-ua-mobile"] = mobile
            hints["sec-ch-ua-platform"] = platform
    return hints

def _choose_identity_for_phase(phase: str) -> Dict[str, str]:
    ua_pool = _IDENTITY_POOLS["user_agents"] or _FALLBACK_UA_POOL
    al_pool = _IDENTITY_POOLS["accept_language"] or [_FALLBACK_ACCEPT_LANG]
    ac_pool = _IDENTITY_POOLS["accept"] or [_FALLBACK_ACCEPT]
    ua = random.choice(ua_pool)
    al = random.choice(al_pool)
    ac = random.choice(ac_pool)
    ident = {"User-Agent": ua, "Accept-Language": al, "Accept": ac}
    # UA ile tutarlı client-hints (Chromium ise) — tutarlı tarayıcı parmak izi
    ident.update(_client_hints_for_ua(ua))
    prev = _LAST_IDENTITY.get()
    if prev != ident:
        _logger.debug(f"[HTTP] identity switch -> UA='{ua[:42]}...' AL='{al}'")
        _LAST_IDENTITY.set(ident)
    return ident

def _respect_idempotent_first(phase: str, method: str, post_ratio_ok: bool) -> bool:
    pol = _HTTP_POLICY["idempotent_first"]
    if not pol["enabled"]:
        return True
    if phase in pol["early_phases"]:
        return method.upper() in ("GET", "HEAD", "OPTIONS")
    # Erken keşif (discovery/mapping) dışındaki fazlar saldırı/test fazlarıdır
    # (xxe, ssrf, sqli, cmdi, ssti, nosqli, graphql, auth, mass_assignment ...).
    # Bu fazlarda POST/PUT/DELETE/PATCH saldırının ÖZÜDÜR.
    # Eski mantık `bool(post_ratio_ok)` döndürüyordu; ancak hiçbir çağıran
    # `_post_ratio_ok=True` geçmediği için bu DAİMA False'tu → tüm non-idempotent
    # istekler "Non-idempotent method blocked by policy" ile sessizce bloklanıyor,
    # XXE çöküyor ve diğer scanner'ların POST kapsamı kayboluyordu.
    # (Kimliksiz/stealth idempotent-only kısıtı zaten ayrı mekanizmada —
    #  HttpClient._kimliksiz_idempotent / suppress_non_idempotent_at_start — uygulanır.)
    # Çağıran açıkça izin vermek isterse _post_ratio_ok=True ek bir kapı olarak kalır.
    if method.upper() in ("POST", "PUT", "DELETE", "PATCH"):
        return True if not pol.get("strict_non_idempotent", False) else bool(post_ratio_ok)
    return True


def _sleep_for_rps():
    rps = max(1, int(_CURRENT_RPS.get()))
    base = 1.0 / float(rps)
    # ±30% jitter: trafik deseni insan gibi görünsün
    jitter = base * random.uniform(-0.30, 0.30)
    time.sleep(max(0.0, base + jitter))

def _parse_retry_after(headers: Dict[str, str]) -> Optional[float]:
    ra = headers.get("Retry-After")
    if ra is None:
        return None
    ra = ra.strip()
    if ra.isdigit():
        return float(int(ra))
    return 5.0

def _observe_rate_headers(headers: Dict[str, str]) -> Optional[int]:
    xrem = headers.get("X-RateLimit-Remaining")
    if xrem is None:
        return None
    try:
        return int(xrem)
    except ValueError:
        return None

# Hard cap on any block/Retry-After/panic cooldown sleep. A hostile or
# misconfigured server can send Retry-After: 3600 (or larger); honoring it
# literally froze a request — and the whole phase thread — for an hour. Beyond
# this cap the circuit breaker + identity rotation handle persistent blocking, so
# there is no value in sleeping longer.
_MAX_BLOCK_SLEEP: float = 60.0


def _bounded_sleep(seconds: float, *, cap: float = _MAX_BLOCK_SLEEP) -> None:
    """Sleep up to ``cap`` seconds in ≤1s steps, bailing early if the active phase
    was abandoned by the watchdog. Keeps a blocked worker responsive instead of
    parking it on a flat multi-minute sleep that fights the phase watchdog/Ctrl+C."""
    total = max(0.0, min(float(seconds or 0.0), float(cap)))
    slept = 0.0
    while slept < total:
        try:
            if is_phase_abandoned(ACTIVE_PHASE.get()):
                return
        except Exception:
            pass
        step = min(1.0, total - slept)
        time.sleep(step)
        slept += step


def _respect_retry_after(headers: Dict[str, str]) -> None:
    """Honor Retry-After header on 429 responses. Circuit breaker handles threshold logic."""
    ra = _parse_retry_after(headers) if _HTTP_POLICY["rate_limit"]["respect_retry_after"] else None
    wait_time = ra if (ra is not None and ra > 0) else 5.0
    _logger.debug(f"[HTTP] Retry-After -> sleeping {min(wait_time, _MAX_BLOCK_SLEEP):.1f}s (cap {_MAX_BLOCK_SLEEP:.0f}s)")
    _bounded_sleep(wait_time)

def _try_rotate_identity(session_obj) -> bool:
    """
    Attempts to rotate Tor identity and updates the session proxies.
    Returns True if rotation signal sent successfully.
    """
    try:
        from websecure.core.waf_bypass import rotate_tor_identity, get_tor_proxy
        if rotate_tor_identity():
            # Refresh proxy usage in session just in case
            proxy = get_tor_proxy()
            if proxy:
                session_obj.proxies.update(proxy)
            return True
    except ImportError:
        # Fallback if module missing
        pass
    except Exception as exc:
        _logger.debug(f"[Autopilot] Rotation failed: {exc!r}")
    return False

def _maybe_recover_from_backoff() -> None:
    global _LAST_CANARY_TS
    now = time.time()
    canary_gap = float(_HTTP_POLICY["rate_limit"]["canary_interval_seconds"])
    with _LAST_CANARY_TS_LOCK:
        if now - _LAST_CANARY_TS < canary_gap:
            return
        _LAST_CANARY_TS = now
    rps = int(_CURRENT_RPS.get())
    prof = _HTTP_POLICY["phase_profiles"].get(ACTIVE_PHASE.get(), {})
    max_rps = int(prof.get("max_rps", rps))
    step = int(_HTTP_POLICY["rate_limit"]["recover_step"])
    if rps < max_rps:
        _CURRENT_RPS.set(min(max_rps, rps + max(1, step)))
        _logger.debug(f"[HTTP] canary -> RPS {rps}->{_CURRENT_RPS.get()} (phase={ACTIVE_PHASE.get()})")

def _smart_request(self, method, url, **kwargs):
    phase = ACTIVE_PHASE.get()

    # Cooperative cancellation: if this phase was abandoned by the watchdog
    # (exceeded its timeout), abort immediately — before sleeping or touching
    # the network — so the orphaned daemon thread stops consuming scan time.
    if is_phase_abandoned(phase):
        raise PhaseAbandoned(f"phase '{phase}' was skipped by the watchdog")

    # Identity setup
    hdrs = dict(kwargs.get("headers", {}) or {})
    for k, v in _choose_identity_for_phase(phase).items():
        if k not in hdrs:
            hdrs[k] = v

    # Idempotent-first policy
    method_u      = str(method).upper()
    post_ratio_ok = kwargs.pop("_post_ratio_ok", False)
    if not _respect_idempotent_first(phase, method_u, post_ratio_ok):
        raise RuntimeError(
            f"Non-idempotent method blocked by policy in phase '{phase}': {method_u}"
        )

    kwargs["headers"] = hdrs

    # --- Circuit breaker pre-check ---
    # Raises CircuitBreakerTripped immediately if circuit is OPEN
    _cb_check()

    # Global adaptive concurrency gate (Madde 4 — Adım A). Resolved once per
    # logical request; the slot is acquired/released around each network send.
    _gate = _get_adaptive_gate()

    # --- IMMORTAL LOOP: Auto-Heal & Retry ---
    max_retries = 3
    attempt     = 0
    resp        = None

    while attempt <= max_retries:
        attempt += 1
        _sleep_for_rps()

        try:
            # Live monitor: log each outgoing request
            try:
                from websecure.core.reporting import get_live_monitor
                import urllib.parse as _up
                _kw_params  = kwargs.get("params") or {}
                _kw_data    = kwargs.get("data") or {}
                _kw_json    = kwargs.get("json") or {}
                _payload_hint = ""
                _param_hint   = ""
                if _kw_params:
                    _param_hint   = list(_kw_params.keys())[0] if isinstance(_kw_params, dict) else ""
                if _kw_data:
                    _payload_hint = str(_kw_data)[:60]
                elif _kw_json:
                    _payload_hint = str(_kw_json)[:60]
                # Also extract from URL query string
                if not _param_hint:
                    _qs = _up.parse_qs(_up.urlparse(url).query)
                    if _qs:
                        _param_hint = list(_qs.keys())[0]
                get_live_monitor().log_request(
                    str(method).upper(), url,
                    phase=phase,
                    payload=_payload_hint,
                    param=_param_hint,
                )
            except (ImportError, AttributeError) as exc:
                _logger.debug(f"[HTTP] Live monitor log_request failed: {exc!r}")

            _req_t0 = time.monotonic()
            # Resolve the per-request timeout UNCONDITIONALLY → always finite:
            #  • off Tor: a missing timeout (None) gets a generous default so a
            #    stalled direct connection can't hang this request/phase forever;
            #  • on Tor: too-tight values are raised to the floor (a 4-5s read over
            #    an onion circuit is a guaranteed ReadTimeoutError → CB trip → abort).
            kwargs["timeout"] = _floor_request_timeout(kwargs.get("timeout"))
            # Hold a concurrency slot ONLY around the actual send (true in-flight
            # window). acquire() is cancel-aware + bounded; finally guarantees the
            # slot is freed even on error so the gate can never leak/deadlock.
            if _gate is not None:
                _gate.acquire(phase)
            try:
                resp = super(type(self), self).request(method, url, **kwargs)
            finally:
                if _gate is not None:
                    _gate.release()
            # Any response means egress is working → clear a prior Tor-drop notice.
            if _TOR_DROP_STATE["down"]:
                _note_tor_egress_up()
            status = resp.status_code
            # Capture this exchange so a finding reported right after can show the
            # exact response that came back (per-finding exploit evidence).
            _record_exchange(method, url, kwargs, resp, (time.monotonic() - _req_t0) * 1000)

            # Metrics wiring FIX: scanner'ların (Tor dahil) kullandığı bu hardened
            # session wrapper, isteği canlı monitöre (log_request) yazıyordu ama
            # HTTP_METRICS'e HİÇ işlemiyordu. Sonuç: 1897 gerçek istekte bile rapordaki
            # "Saldırı Trafiği & Verimlilik" panosu Toplam İstek/2xx/403/429 = 0
            # gösteriyordu (metrics.json counters tamamen sıfır). Yanıtı burada
            # metriklere işle — canlı sayaçla aynı granülerlik (deneme başına). Kullanılan
            # anahtarlar (total/ok_2xx/ban_403/throttle_429/err_4xx/err_5xx) response-hook
            # record_status'un anahtarlarından (2xx/403/429) AYRI; çift sayım olmaz.
            try:
                _rt_ms = int((time.monotonic() - _req_t0) * 1000)
                _st = int(status or 0)
                note_http_response(_st, _rt_ms)
                note_status_location(url, _st)
                record_timing_ms(_rt_ms, _st)
                # Feed the outcome to the AIMD controller (drives the global cap).
                if _gate is not None:
                    _gate.record(_rt_ms, (_st >= 500 or _st in (429, 503)), _st)
            except Exception as _mx:
                _logger.debug(f"[HTTP] metrics record failed: {_mx!r}")

            # Feed status into circuit breaker
            _cb_record(status)

            if status in (403, 429):
                _logger.debug(f"[Autopilot] Block detected ({status}) on attempt {attempt}/{max_retries + 1}…")
                # Live monitor: ban detected
                try:
                    from websecure.core.reporting import get_live_monitor
                    get_live_monitor().log_ban_detected(status, url)
                except (ImportError, AttributeError) as exc:
                    _logger.debug(f"[HTTP] Live monitor log_ban_detected failed: {exc!r}")

                if attempt <= max_retries:
                    rotated = _try_rotate_identity(self)
                    if rotated:
                        _logger.debug("[Autopilot] Identity rotated. Retrying…")
                        _cb_reset()  # new identity -> clean slate for circuit breaker
                        kwargs["headers"].update(_choose_identity_for_phase(phase))
                        continue
                    else:
                        # Honor Retry-After; circuit breaker tracks the 429 streak
                        _respect_retry_after(dict(resp.headers))
                        continue

                return resp

            # --- CAPTCHA detection on 200/OK responses ---
            _captcha_mw = _get_captcha_middleware()
            if _captcha_mw is not None:
                solved = _captcha_mw.handle(self, resp, url, kwargs, method)
                if solved is not None:
                    return solved

            # Canary recovery (RPS ramp-up on success)
            if _observe_rate_headers(dict(resp.headers)) is not None:
                _maybe_recover_from_backoff()

            return resp

        except (requests.exceptions.ConnectionError,
                requests.exceptions.Timeout,
                requests.exceptions.RequestException) as e:
            _cb_record_error()
            # Network error → strong back-off signal for the AIMD controller.
            if _gate is not None:
                _gate.record(5000.0, True, 0)
            err_msg    = str(e).lower()
            is_timeout = "timeout" in err_msg or "timed out" in err_msg
            # Tor egress (session.proxies = socks5h) çöktüğünde requests ProxyError/
            # SOCKS hatası verir → kullanıcıya net "Tor koptu" uyarısı (throttled).
            if tor_active() and _looks_like_proxy_error(e):
                _note_tor_egress_down(f"{type(e).__name__}: {e}")
            _logger.debug(f"[Autopilot] Connection error ({e.__class__.__name__}). Retry {attempt}/{max_retries}…")

            if is_timeout and attempt < max_retries:
                _try_rotate_identity(self)

            if attempt <= max_retries:
                time.sleep(1.0)
                continue

            _logger.debug(f"[Autopilot] Failed to connect to {url} after {max_retries} retries.")
            if _wrap_requests_error is not None:
                raise _wrap_requests_error(e, url=url) from e
            raise e

    return resp  # safe fallback (loop should always return or raise above)

import json
import subprocess as _subp
import uuid
from dataclasses import dataclass
from typing import Any, Mapping, Sequence
from urllib.parse import urlparse as _urlparse
from websecure.core.utils import (
    allowed_http_methods,
    build_raw_http_request,
    build_response_head,
    current_identity,
    get_logging_prefs,
)
try:
    import httpx
except ImportError:
    httpx = None
import importlib.util as _impspec
import requests
from requests.adapters import HTTPAdapter
from urllib3.util import Retry as Urllib3Retry
_HTTPX_AVAILABLE = _impspec.find_spec("httpx") is not None

# Lazy reporting imports — avoids circular deps (reporting imports http lazily inside a function)
try:
    from websecure.core.reporting import add_result, counters_inc, counters_add_bytes
except ImportError:
    def add_result(bucket, item): pass       # type: ignore[misc]
    def counters_inc(name, delta=1): pass    # type: ignore[misc]
    def counters_add_bytes(n): pass          # type: ignore[misc]


class SmartSession(requests.Session):
    """
    requests.Session subclass that routes every request through _smart_request.
    This wires the circuit breaker, identity rotation, live monitor, and rate
    limiting into every HTTP call made by the framework.
    """

    def request(self, method, url, **kwargs):  # type: ignore[override]
        return _smart_request(self, method, url, **kwargs)


# ---------------------------------------------------------------------------
# CAPTCHA middleware (lazy — only active when config sets a solver provider)
# ---------------------------------------------------------------------------
_CAPTCHA_MIDDLEWARE = None  # set by install_captcha_config()

def install_captcha_config(cfg_dict: dict) -> None:
    """
    Push CAPTCHA config from the main config blob into the HTTP layer.
    Call once at scan startup alongside install_http_phase_policies().
    """
    global _CAPTCHA_MIDDLEWARE
    try:
        from websecure.core.analysis import CaptchaBypassMiddleware, read_captcha_config
        cap_cfg = read_captcha_config(cfg_dict)
        if cap_cfg.provider != "none":
            _CAPTCHA_MIDDLEWARE = CaptchaBypassMiddleware(cap_cfg)
    except (ImportError, AttributeError) as exc:
        _logger.debug(f"[HTTP] install_captcha_config failed: {exc!r}")

def _get_captcha_middleware():
    return _CAPTCHA_MIDDLEWARE


# ---------------------------------------------------------------------------
# Access block classifier — replaces the dead websecure.core.detect import
# ---------------------------------------------------------------------------

def classify_access_block(status: int, headers, body: str) -> str:
    """
    Classify a blocked HTTP response into a machine-readable category.

    Returns one of:
      rate_limit     — 429 or Retry-After present
      waf_challenge  — WAF JS/CAPTCHA challenge page (Cloudflare, Akamai …)
      captcha_block  — CAPTCHA challenge (reCAPTCHA / hCaptcha in body)
      auth_required  — plain 401/403 without WAF/CAPTCHA signals
      unknown        — everything else
    """
    get_hdr = headers.get if callable(getattr(headers, "get", None)) else (lambda k, d=None: d)
    server   = (get_hdr("server", "") or "").lower()
    via      = (get_hdr("via", "") or "").lower()
    retry_a  = get_hdr("retry-after", None)
    text     = (body or "").lower()

    if status == 429 or retry_a is not None:
        return "rate_limit"

    if any(s in server + via for s in ("cloudflare", "akamai", "imperva", "incapsula")):
        return "waf_challenge"
    if any(s in text for s in ("attention required", "checking your browser", "cf-browser-verification")):
        return "waf_challenge"

    if status in (401, 403):
        if any(s in text for s in ("captcha", "recaptcha", "hcaptcha", "turnstile")):
            return "captcha_block"
        return "auth_required"

    return "unknown"


# ---------------------------------------------------------------------------
# HPM (HTTP Pace Manager) — lazy-import from phases to avoid circular deps
# ---------------------------------------------------------------------------
def hpm_current_policy() -> dict:
    try:
        from websecure.core.phases import hpm_current_policy as _hpm_pol
        return _hpm_pol()
    except (ImportError, AttributeError) as exc:
        _logger.debug(f"[HTTP] hpm_current_policy import failed: {exc!r}")
        return {"rps": 0.0}

def hpm_record_status(status_code: int) -> None:
    try:
        from websecure.core.phases import hpm_record_status as _hpm_rec
        _hpm_rec(int(status_code))
    except (ImportError, AttributeError) as exc:
        _logger.debug(f"[HTTP] hpm_record_status import failed: {exc!r}")


# ---------------------------------------------------------------------------
# Yardımcılar
# ---------------------------------------------------------------------------

IDEMPOTENT_DEFAULT: frozenset[str] = frozenset({"HEAD", "GET", "OPTIONS"})

_TRACE_CTX: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "websec_trace_id", default=None
)

HTTP_METRICS: dict = {
    "phase": None,
    "requests": 0,
    "errors": 0,
    "2xx": 0,
    "403": 0,
    "429": 0,
    "total": 0,
    "ok_2xx": 0,
    "err_4xx": 0,
    "err_5xx": 0,
    "ban_403": 0,
    "throttle_429": 0,
    "avg_rt_ms": 0.0,
    "crawler_endpoints": 0,
}


# ---------- Per-location status sampler ("nereden 200/3xx/403/429 aldık") ----------
# Bounded: en fazla _HTTP_LOC_CAP farklı (path) tutulur; her path için status-sınıfı
# sayaçları toplanır. results.json'u şişirmeden konum-bazlı trafik dağılımı sağlar.
_HTTP_LOC_CAP = 400
HTTP_STATUS_LOCATIONS: dict[str, dict[str, int]] = {}
_loc_lock = threading.Lock()

def _status_class(code: int) -> str:
    c = int(code or 0)
    if 200 <= c < 300:
        return "2xx"
    if 300 <= c < 400:
        return "3xx"
    if c == 401:
        return "401"
    if c == 403:
        return "403"
    if c == 429:
        return "429"
    if 400 <= c < 500:
        return "4xx"
    if c >= 500:
        return "5xx"
    return "other"

def note_status_location(url: str, code: int) -> None:
    """Kaydı path bazında (query'siz) topla; sınırlı sayıda path tutar."""
    try:
        path = (url or "").split("?", 1)[0]
        if not path:
            return
        cls = _status_class(code)
        with _loc_lock:
            slot = HTTP_STATUS_LOCATIONS.get(path)
            if slot is None:
                if len(HTTP_STATUS_LOCATIONS) >= _HTTP_LOC_CAP:
                    return  # cap aşıldı — yeni path ekleme, mevcutları güncellemeye devam
                slot = {}
                HTTP_STATUS_LOCATIONS[path] = slot
            slot[cls] = int(slot.get(cls, 0)) + 1
            slot["last"] = int(code or 0)
    except Exception:
        pass


# ---------- Structural Metrics (phase + latency histogram + 403/429 trend) ----------
HTTP_LAT_BUCKETS = ((0,50),(50,100),(100,250),(250,500),(500,1000),(1000,None))
HTTP_LATENCY_HIST: dict[str, int] = {f"{lo}-{hi if hi is not None else '+'}": 0 for (lo,hi) in HTTP_LAT_BUCKETS}
_PHASE_STATS: dict[str, dict] = {}

def _percentile_from_hist(hist: dict[str,int], p: float) -> int:
    total = sum(int(v) for v in hist.values())
    if total <= 0:
        return 0
    target = total * p
    acc = 0
    def _parse(label: str) -> tuple[int,int|None]:
        if label.endswith('+'):
            lo = int(label.split('-',1)[0])
            return lo, None
        lo, hi = label.split('-')
        return int(lo), int(hi)
    ordered = sorted(hist.items(), key=lambda kv: _parse(kv[0])[0])
    for lab, cnt in ordered:
        acc += int(cnt)
        if acc >= target:
            lo, hi = _parse(lab)
            if hi is None:
                return lo
            return int((lo + hi) // 2)
    return 0

def _bucket_label(ms: int) -> str:
    val = int(ms)
    for lo, hi in HTTP_LAT_BUCKETS:
        if hi is None and val >= lo:
            return f"{lo}-+"
        if hi is not None and lo <= val < hi:
            return f"{lo}-{hi}"
    return "unknown"

def phase_begin(name: str) -> None:
    nm = str(name)
    set_active_phase(nm)
    HTTP_METRICS["2xx"] = int(HTTP_METRICS.get("2xx", 0))
    HTTP_METRICS["403"] = int(HTTP_METRICS.get("403", 0))
    HTTP_METRICS["429"] = int(HTTP_METRICS.get("429", 0))
    _PHASE_STATS[nm] = {
        "start_ts": time.time(),
        "req": 0,
        "bytes": 0,
        "403_timestamps": [],
        "429_timestamps": [],
        "lat_hist": {k:0 for k in HTTP_LATENCY_HIST.keys()},
    }

def _trend_per_minute(stamps: list[float]) -> float:
    if not stamps:
        return 0.0
    first = stamps[0]
    last = stamps[-1]
    span = max(1.0, last - first)
    per_s = len(stamps) / span
    return per_s * 60.0

def phase_end(name: str, *, write_result: bool = True) -> dict:
    nm = str(name)
    st = _PHASE_STATS.get(nm) or {"start_ts": time.time(), "req": 0, "bytes": 0, "403_timestamps": [], "429_timestamps": [], "lat_hist": {k:0 for k in HTTP_LATENCY_HIST.keys()}}
    dur = max(0.001, time.time() - st["start_ts"])
    rps = st["req"] / dur
    forb_pm = _trend_per_minute(st["403_timestamps"])
    rl_pm = _trend_per_minute(st["429_timestamps"])
    summary = {
        "phase": nm,
        "duration_s": round(dur, 3),
        "requests": int(st["req"]),
        "forbidden_ratio": round((len(st.get("403_timestamps", [])) / st["req"]) if st["req"] else 0.0, 4),
        "rps": round(rps, 2),
        "bytes": int(st["bytes"]),
        "latency_histogram": dict(st["lat_hist"]),
        "p50_ms": int(_percentile_from_hist(st["lat_hist"], 0.5)),
        "p90_ms": int(_percentile_from_hist(st["lat_hist"], 0.9)),
        "trend_403_per_min": round(forb_pm, 2),
        "trend_429_per_min": round(rl_pm, 2),
        "counters": {"2xx": int(HTTP_METRICS.get("2xx",0)), "403": int(HTTP_METRICS.get("403",0)), "429": int(HTTP_METRICS.get("429",0))},
    }
    if write_result and callable(globals().get("add_result")):
        add_result("phase_metrics", summary)
    # do not reset globals here; phase_begin will reset per-phase state on next phase
    return summary

def record_timing_ms(ms: int, status: int, *, content_bytes: int = 0) -> None:
    label = _bucket_label(int(ms))
    HTTP_LATENCY_HIST[label] = int(HTTP_LATENCY_HIST.get(label, 0)) + 1
    phase = ACTIVE_PHASE.get()
    st = _PHASE_STATS.get(phase)
    if st is None:
        _PHASE_STATS[phase] = {
            "start_ts": time.time(),
            "req": 0,
            "bytes": 0,
            "403_timestamps": [],
            "429_timestamps": [],
            "lat_hist": {k:0 for k in HTTP_LATENCY_HIST.keys()},
        }
        st = _PHASE_STATS[phase]
    st["req"] = int(st["req"]) + 1
    st["bytes"] = int(st["bytes"]) + int(content_bytes or 0)
    st["lat_hist"][label] = int(st["lat_hist"].get(label, 0)) + 1
    if int(status) == 403:
        st["403_timestamps"].append(time.time())
    if int(status) == 429:
        st["429_timestamps"].append(time.time())

def get_http_metrics() -> dict:
    total = int(HTTP_METRICS.get("total", 0))
    forb = int(HTTP_METRICS.get("403", 0))
    metrics = {
        k: (len(v) if isinstance(v, list) else int(v) if v is not None else 0)
        for k, v in HTTP_METRICS.items()
    }
    metrics["403_ratio"] = (forb / total) if total else 0.0
    with _loc_lock:
        status_locations = {k: dict(v) for k, v in HTTP_STATUS_LOCATIONS.items()}
    return {
        "counters": metrics,
        "latency_histogram": dict(HTTP_LATENCY_HIST),
        "phases": {k: dict(v) for k,v in _PHASE_STATS.items()},
        "status_locations": status_locations,
    }

def set_trace_id(trace_id: str | None) -> None:
    _TRACE_CTX.set(trace_id)


def get_trace_id() -> str | None:
    return _TRACE_CTX.get()


def _now_iso() -> str:
    import datetime as _dt
    return _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat() + "Z"


def _should_sample(p: float) -> bool:
    pr = max(0.0, min(1.0, float(p)))
    return random.random() < pr


def _normalize_endpoint_for_metrics(url: str, include_query: bool = False) -> str:
    if include_query:
        return url or ""
    return (url or "").split("?", 1)[0]


def _redact_headers_for_log(h: dict) -> dict:
    if not h:
        return {}
    sens = {
        "authorization",
        "cookie",
        "set-cookie",
        "x-api-key",
        "x-xsrf-token",
        "x-csrf-token",
    }
    out = {}
    for k, v in h.items():
        out[k] = "<redacted>" if str(k).lower() in sens else v
    return out


def record_status(code: int) -> None:
    c = int(code)
    if 200 <= c < 300:
        HTTP_METRICS["2xx"] = int(HTTP_METRICS.get("2xx", 0)) + 1
    elif c == 403:
        HTTP_METRICS["403"] = int(HTTP_METRICS.get("403", 0)) + 1
        ph = ACTIVE_PHASE.get()
        st = _PHASE_STATS.get(ph)
        if st is not None:
            st.setdefault("403_timestamps", []).append(time.time())
    elif c == 429:
        HTTP_METRICS["429"] = int(HTTP_METRICS.get("429", 0)) + 1
        ph = ACTIVE_PHASE.get()
        st = _PHASE_STATS.get(ph)
        if st is not None:
            st.setdefault("429_timestamps", []).append(time.time())


def _hook_record_status(resp: Any):
    code = getattr(resp, "status_code", None)
    if isinstance(code, int):
        record_status(code)
    return resp


def _to_http_version_from_requests(resp: requests.Response) -> str:
    ver = getattr(getattr(resp, "raw", None), "version", None)
    if ver == 10:
        return "HTTP/1.0"
    if ver == 11:
        return "HTTP/1.1"
    if ver == 20:
        return "HTTP/2"
    return "HTTP/1.x"


def _to_http_version_from_httpx(resp: "httpx.Response") -> str:  # type: ignore
    v = getattr(resp, "http_version", None)
    if isinstance(v, str) and v.upper().startswith("HTTP/"):
        return v.upper()
    return "HTTP/2" if getattr(resp, "is_http2", False) else "HTTP/1.1"


def _collect_rate_limit(resp: Any, url: str) -> None:
    # UnifiedResponse ya da requests/httpx response olabilir
    headers = dict(getattr(resp, "headers", {}) or {})
    status = int(getattr(resp, "status_code", 0) or 0)
    if not headers:
        return
    lower = {str(k).lower(): str(v) for k, v in headers.items()}
    ra = lower.get("retry-after")
    xl = lower.get("x-ratelimit-limit") or lower.get("ratelimit-limit")
    xr = lower.get("x-ratelimit-remaining") or lower.get("ratelimit-remaining")
    xw = lower.get("x-ratelimit-window") or lower.get("ratelimit-window")
    xrst = lower.get("x-ratelimit-reset") or lower.get("ratelimit-reset")
    if not (ra or xl or xr or xw or xrst):
        return
    add_result(
        "rate_limit_obs",
        {
            "url": url,
            "status": status,
            "retry_after": ra,
            "limit": xl,
            "remaining": xr,
            "window": xw,
            "reset": xrst,
            "http_version": getattr(resp, "http_version", "HTTP/1.x"),
        },
    )


def _alpn_prefs(cfg: Mapping[str, Any] | None) -> tuple[bool, bool]:
    c = dict(cfg or {})
    ab = c.get("anti_blocking") or {}
    tls = (ab.get("tls") or {})
    alpn = [str(x).lower() for x in (tls.get("alpn") or [])]
    if not alpn:
        # fallbacks
        t2 = (c.get("tls") or {})
        alpn = [str(x).lower() for x in (t2.get("alpn") or [])]
    if not alpn:
        net = c.get("network") or {}
        alpn = [str(x).lower() for x in (net.get("alpn") or [])]
    use_h2 = ("h2" in alpn) or ("http/2" in alpn)
    use_h1 = ("http/1.1" in alpn) or (not use_h2)
    return use_h2, use_h1


def _impersonation_headers(profile: str) -> dict:
    p = str(profile or "chrome_122").lower()
    if p.startswith("chrome"):
        return {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/122.0.0.0 Safari/537.36"
            ),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Sec-Ch-Ua": '"Chromium";v="122", "Not(A:Brand";v="24"',
            "Sec-Ch-Ua-Mobile": "?0",
            "Sec-Ch-Ua-Platform": '"Windows"',
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-User": "?1",
            "Sec-Fetch-Dest": "document",
            "Upgrade-Insecure-Requests": "1",
        }
    if p.startswith("firefox"):
        return {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Upgrade-Insecure-Requests": "1",
        }
    import random as _r
    _fallback_uas = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    ]
    return {"User-Agent": _r.choice(_fallback_uas)}


def _build_header_pool(cfg: Mapping[str, Any] | None) -> dict:
    ab = (dict(cfg or {}).get("anti_blocking") or {})
    ident = ab.get("identity") or {}
    hp_conf = ident.get("header_pool") or {}
    out: dict[str, list[str]] = {}
    al = hp_conf.get("accept_language")
    ua = hp_conf.get("ua_family")
    if isinstance(al, list) and al:
        out["accept_language"] = [str(x) for x in al]
    if isinstance(ua, list) and ua:
        out["ua"] = [str(x) for x in ua]
    return out


def _pick_header_variant(pool: Mapping[str, Sequence[str]], tick: int) -> dict:
    out: dict[str, str] = {}
    al = pool.get("accept_language")
    if isinstance(al, Sequence) and al:
        out["Accept-Language"] = str(al[tick % len(al)])
    ua = pool.get("ua")
    if isinstance(ua, Sequence) and ua:
        fam = str(ua[tick % len(ua)])
        out.update(_impersonation_headers(fam))
    return out


def _is_float(s: Any) -> bool:
    if s is None:
        return False
    text = str(s).strip()
    if not text:
        return False
    # basit float doğrulama (scientific notasyonu kapsamıyor)
    if text.count(".") <= 1 and all(ch.isdigit() or ch == "." for ch in text):
        return True
    return False


def _to_float(s: Any, default: Optional[float] = None) -> Optional[float]:
    return float(str(s)) if _is_float(s) else default


# ---------------------------------------------------------------------------
# Birleştirilmiş yanıt
# ---------------------------------------------------------------------------

class UnifiedResponse:
    def __init__(self, raw: Any, driver: str):
        self._raw = raw
        self.driver = driver  # "requests" | "httpx"

        if driver == "requests":
            r = raw
            self.status_code = int(getattr(r, "status_code", 0) or 0)
            self.headers = dict(getattr(r, "headers", {}) or {})
            self.text = getattr(r, "text", "") or ""
            self.content = getattr(r, "content", b"") or b""
            self.url = getattr(r, "url", "") or ""
            self.elapsed = getattr(r, "elapsed", None)
            self.ok = bool(getattr(r, "ok", self.status_code < 400))
            self.reason = getattr(r, "reason", "")
            self.http_version = _to_http_version_from_requests(r)
            self.raw = r
        else:
            hr = raw
            self.status_code = int(getattr(hr, "status_code", 0) or 0)
            self.headers = dict(getattr(hr, "headers", {}) or {})
            self.text = str(getattr(hr, "text", "") or "")
            self.content = bytes(getattr(hr, "content", b"") or b"")
            self.url = str(getattr(hr, "url", "") or "")
            self.elapsed = getattr(hr, "elapsed", None)
            self.ok = bool(getattr(hr, "is_success", self.status_code < 400))
            self.reason = getattr(hr, "reason_phrase", "")
            self.http_version = _to_http_version_from_httpx(hr)
            self.raw = None

    def json(self) -> Any:
        raw_json = getattr(self._raw, "json", None)
        if callable(raw_json):
            return raw_json()
        return json.loads(self.text or "{}")


# ---------------------------------------------------------------------------
# Retry Politikası
# ---------------------------------------------------------------------------

@dataclass
class RetryPolicy:
    total: int = 2
    base_backoff: float = 0.4
    max_backoff: float = 10.0
    status_forcelist: tuple[int, ...] = (429, 500, 502, 503, 504)
    allowed_methods: frozenset[str] = IDEMPOTENT_DEFAULT
    jitter: bool = True
    respect_retry_after_header: bool = True

    def compute_sleep(self, attempt: int) -> float:
        raw = min(self.max_backoff, self.base_backoff * (2 ** (attempt - 1)))
        return random.uniform(0, raw) if self.jitter else raw


# ---------------------------------------------------------------------------
# Proxy Havuzu
# ---------------------------------------------------------------------------

class ProxyPool:
    def __init__(self, cfg: Mapping[str, Any] | None):
        c = dict(cfg or {})
        pool_list: list[str] = []
        ab = c.get("anti_blocking") or {}
        ident = ab.get("identity") or {}
        v = ident.get("proxies")
        if isinstance(v, list):
            pool_list += [str(x) for x in v if isinstance(x, (str, bytes)) and str(x).strip()]
        priv = (c.get("privacy") or {}).get("egress") or {}
        e = priv.get("entries")
        if isinstance(e, list):
            pool_list += [str(x) for x in e if isinstance(x, (str, bytes)) and str(x).strip()]
        net = c.get("network") or {}
        p = net.get("proxies") or {}
        if isinstance(p, dict):
            pool = p.get("pool") or []
            if isinstance(pool, list):
                pool_list += [str(x) for x in pool if isinstance(x, (str, bytes)) and str(x).strip()]
            self.rotate = str(p.get("rotate", "per_target"))
        else:
            self.rotate = "per_target"
        seen = set()
        self.pool = [x for x in pool_list if not (x in seen or seen.add(x))]
        self.enabled = bool(self.pool)
        self._idx = 0


    def next(self, key: str = "") -> Optional[str]:
        if not self.enabled or not self.pool:
            return None
        if self.rotate == "none":
            return self.pool[0]
        if self.rotate == "per_target" and key:
            base = sum(ord(ch) for ch in key) % len(self.pool)
            return self.pool[base]
        self._idx = (self._idx + 1) % len(self.pool)
        return self.pool[self._idx]


# ---------------------------------------------------------------------------
# Requests Sürücüsü
# ---------------------------------------------------------------------------

class _RequestsDriver:
    def __init__(self, http_cfg: Mapping[str, Any], verify: bool, timeout_pair: tuple[float, float]):
        self.verify = verify
        self.timeout_pair = timeout_pair

        pool_conns = int(http_cfg.get("pool_connections", 100))
        pool_max = int(http_cfg.get("pool_maxsize", 100))
        
        # P4 fix: was hardcoded True — now reads from config; defaults to True
        # to preserve existing "strength" behaviour when not explicitly configured.
        _waf_sub = http_cfg.get("waf") or {}
        use_waf_bypass = bool(_waf_sub.get("enabled", True))
        
        try:
            from websecure.core.waf_bypass import WAFBypassAdapter
        except ImportError:
            WAFBypassAdapter = None
            
        if use_waf_bypass and WAFBypassAdapter:
             adapter = WAFBypassAdapter(max_retries=0, pool_connections=pool_conns, pool_maxsize=pool_max)
        else:
             adapter = HTTPAdapter(max_retries=0, pool_connections=pool_conns, pool_maxsize=pool_max)

        # P4 fix: was passing empty dict {} — losing all http config (tls, user-agent, etc.)
        self.s = hardened_session(http_cfg)
        self.s.mount("http://", adapter)
        self.s.mount("https://", adapter)

        ua = http_cfg.get("user_agent")
        self._default_headers = {}
        if isinstance(ua, str) and ua.strip():
            self._default_headers["User-Agent"] = ua.strip()
        
        # If no strict UA set in config, prepopulate with a random one
        if "User-Agent" not in self._default_headers:
             try:
                 from websecure.core.waf_bypass import get_random_user_agent
                 self._default_headers["User-Agent"] = get_random_user_agent()
             except ImportError:
                 pass

        # pacing/anti-blocking (policy ile beslenecek)
        self._rps: float = 0.0
        self._interval: float = 0.0
        self._extra_delay_ms: int = 0
        self._jitter_ms: int = 0
        self._last_ts: float = 0.0

    def _pace_before(self) -> None:
        if self._interval <= 0:
            return
        now = time.monotonic()
        target = self._last_ts + self._interval
        if target > now:
            gap = target - now
            gap = max(0.0, gap * random.uniform(0.70, 1.30))
            time.sleep(gap)
        self._last_ts = time.monotonic()
        delay = 0.0
        if self._extra_delay_ms > 0:
            delay += self._extra_delay_ms / 1000.0
        if self._jitter_ms > 0:
            delay += random.randint(0, self._jitter_ms) / 1000.0
        if delay > 0:
            time.sleep(delay)

    def _on_429(self, retry_after: Optional[float]) -> None:
        if retry_after is not None:
            ms = int(max(200.0, float(retry_after) * 1000.0))
        else:
            ms = max(200, self._extra_delay_ms * 2)
        self._extra_delay_ms = min(ms, 2500)
        # Attempt Tor Rotation on Block
        try:
            from websecure.core.waf_bypass import rotate_tor_identity as _rotate_tor
            _rotate_tor()
        except Exception as e:
            _logger.debug(f"[http] Tor identity rotation failed: {e}")

    def request_once(self, method: str, url: str, **kw) -> requests.Response:
        # Circuit breaker pre-check — raises if scan is halted
        _cb_check()

        kw.pop("verify", None)
        kw.setdefault("timeout", self.timeout_pair)
        # Always resolve to a finite value: if timeout_pair itself was None this
        # still imposes the off-Tor default; on Tor it raises to the floor.
        kw["timeout"] = _floor_request_timeout(kw.get("timeout"))
        headers = dict(kw.pop("headers", {}) or {})
        for k, v in self._default_headers.items():
            headers.setdefault(k, v)
        kw["headers"] = headers

        # Scanner kimliğini ele veren başlıkları temizle
        for _hdr in ("X-Scanner", "X-WebSecure", "X-Forwarded-By", "Via"):
            headers.pop(_hdr, None)
            headers.pop(_hdr.lower(), None)

        if "proxies" not in kw:
            try:
                from websecure.core.waf_bypass import get_egress_manager as _gem
                em = _gem()
                proxy_url = em.get_next_egress() if em else None
            except (ImportError, AttributeError) as exc:
                _logger.debug(f"[HTTP] Egress manager lookup failed: {exc!r}")
                proxy_url = None
            if proxy_url:
                kw["proxies"] = {"http": proxy_url, "https": proxy_url}
            elif tor_active() and not (getattr(self.s, "proxies", None) or {}):
                # FAIL-CLOSED (gizlilik): Tor zorunlu çıkıştı ama canlı Tor/pool
                # proxy yok (Tor tarama ortasında koptu) VE session kendi proxy'sini
                # de taşımıyor. Bu isteği DOĞRUDAN göndermek gerçek IP'yi sızdırır →
                # reddet. get_next_egress'in sessiz None→direkt geri-düşüşü tek
                # fail-open noktasıydı; burada kapatılır. Circuit breaker hatayı sayar,
                # Tor geri gelince (get_next_egress yine proxy döndürünce) tarama
                # kaldığı yerden toparlar — donma/çökme değil, güvenli bekleme.
                _cb_record_error()
                _note_tor_egress_down("egress manager returned no live proxy")
                raise requests.exceptions.ProxyError(
                    "Tor egress unavailable (dropped) — request blocked to prevent real-IP leak"
                )

        pol = hpm_current_policy()
        self._rps = float(pol.get("rps", self._rps))
        self._interval = 0.0 if self._rps <= 0 else 1.0 / self._rps
        self._pace_before()

        __t0 = time.time()
        resp = self.s.request(method, url, verify=self.verify, **kw)
        # Any response (even 403) means egress works again → clear a prior Tor-drop notice.
        if _TOR_DROP_STATE["down"]:
            _note_tor_egress_up()
        __rt_ms = int((time.time() - __t0) * 1000)
        _collect_rate_limit(resp, url)
        st = int(getattr(resp, "status_code", 0) or 0)
        # Global HTTP metrics (feeds output/metrics.json → Saldırı Trafiği panosu).
        # Bu sürücü varsayılan istek yoludur; eksik kalırsa tüm sayaçlar 0 görünür.
        try:
            __clen = len(getattr(resp, "content", b"") or b"")
        except (TypeError, AttributeError):
            __clen = 0
        record_timing_ms(__rt_ms, st, content_bytes=__clen)
        record_status(st)
        note_status_location(url, st)
        hpm_record_status(st)
        _cb_record(st)  # feed circuit breaker

        if st == 429:
            ra = getattr(resp, "headers", {}).get("Retry-After") or None
            ra_s  = str(ra) if ra is not None else ""
            ra_val = float(ra_s) if ra_s.replace(".", "", 1).isdigit() else None
            self._on_429(ra_val)
            add_result("anti_block_event", {"type": "rate-limit", "url": url, "status": st, "retry_after": ra})
        elif st == 403:
            add_result("anti_block_event", {"type": "forbidden", "url": url, "status": st})

        return resp


# ---------------------------------------------------------------------------
# httpx Sürücüsü (opsiyonel)
# ---------------------------------------------------------------------------

class _HttpxDriver:
    def __init__(self, http_cfg: Mapping[str, Any], verify: bool, timeout_pair: tuple[float, float]):
        if not _HTTPX_AVAILABLE:
            raise RuntimeError("httpx yüklü değil ancak driver=httpx seçildi.")

        pool_max = int(http_cfg.get("pool_maxsize", 10))
        keepalive = int(http_cfg.get("pool_connections", 10))
        limits = httpx.Limits(max_connections=pool_max, max_keepalive_connections=keepalive)  # type: ignore

        connect_t, read_t = timeout_pair
        timeout = httpx.Timeout(connect=connect_t, read=read_t, write=read_t, pool=None)  # type: ignore

        ua = http_cfg.get("user_agent")
        headers = {}
        if isinstance(ua, str) and ua.strip():
            headers["User-Agent"] = ua.strip()

        _http2 = _impspec.find_spec("h2") is not None
        self.c = httpx.Client(http2=_http2, verify=verify, limits=limits, timeout=timeout, headers=headers)  # type: ignore

    def request_once(self, method: str, url: str, **kw) -> "httpx.Response":  # type: ignore
        kw.pop("verify", None)
        __t0 = time.time()
        resp = self.c.request(method, url, **kw)
        __rt_ms = int((time.time() - __t0) * 1000)
        try:
            __clen = len(getattr(resp, 'content', b'') or b'')
        except (TypeError, AttributeError):
            __clen = 0
        st = int(getattr(resp, 'status_code', 0) or 0)
        record_timing_ms(__rt_ms, st, content_bytes=__clen)
        record_status(st)
        note_status_location(url, st)
        _collect_rate_limit(resp, url)
        st = int(getattr(resp, "status_code", 0) or 0)
        if st in (429, 403):
            kind = classify_access_block(st, getattr(resp, "headers", {}), getattr(resp, "text", ""))
            if kind == "rate-limit":
                ra = getattr(resp, "headers", {}).get("Retry-After") or None
                add_result(
                    "anti_block_event",
                    {"type": "rate-limit", "url": url, "status": st, "retry_after": ra},
                )
            elif kind in ("waf", "ban"):
                add_result("anti_block_event", {"type": kind, "url": url, "status": st})
        return resp


# ---------------------------------------------------------------------------
# Merkezi HttpClient
# ---------------------------------------------------------------------------

class HttpClient:
    """
    Merkezi HTTP istemcisi — jitter'lı backoff, opsiyonel HTTP/2, kanıta dayalı kayıt.
    """

    def __init__(self, cfg: Optional[Mapping[str, Any]] = None):
        self.cfg = dict(cfg or {})
        self.mode = str((self.cfg.get("mode") or "authenticated")).lower()

        # Proxy havuzu — must be initialized BEFORE egress degrade detection
        self._proxy_pool = ProxyPool(self.cfg)
        self._consecutive_blocks = 0  # [ACIL DURUM] Ardışık blok sayacı

        # Egress degrade detection
        priv = (self.cfg.get('privacy') or {}) if isinstance(self.cfg, dict) else {}
        egress = (priv.get('egress') or {}) if isinstance(priv, dict) else {}
        mode = str(egress.get('mode') or 'direct').lower()
        # ProxyPool present but empty
        if mode == 'proxy_pool':
            pool = getattr(self._proxy_pool, 'pool', [])
            enabled = bool(getattr(self._proxy_pool, 'enabled', False))
            if (not enabled) or (not pool):
                _emit_egress_degraded('proxy_pool', 'empty_or_disabled', {'phase': ACTIVE_PHASE.get()})
        # Tor requested but SOCKS not reachable
        if mode == 'tor':
            ok = is_open('127.0.0.1', 9050)
            if not ok:
                _emit_egress_degraded('tor', 'socks_port_unreachable', {'port': 9050, 'phase': ACTIVE_PHASE.get()})
        self._egress_degraded_checked = True
        # Anti-blocking pacing
        ab = (self.cfg.get("anti_blocking") or {})
        ab_http = (ab.get("http") or {})
        self._rps = float(ab_http.get("rps") or 0)
        self._interval = 0.0 if self._rps <= 0 else 1.0 / self._rps
        self._extra_delay_ms = int(ab_http.get("max_extra_delay_ms") or 0)
        self._backoff_factor = float(ab_http.get("backoff_factor") or 2.0)
        self._jitter_ms = int(ab_http.get("jitter_ms") or 0)
        self._last_ts: float = 0.0

        # Anti-blocking HTTP client — wires token-bucket RateLimiter + jitter + penalty
        # backoff via AntiBlockingHTTP when anti_blocking.http is configured.
        # build_http_client() constructs AntiBlockingHTTP wrapping a hardened_session;
        # _pace_before() delegates to it when present, falling back to manual pacing.
        self._anti_blocking_http: Optional[AntiBlockingHTTP] = None
        if ab_http:
            try:
                self._anti_blocking_http = build_http_client(self.cfg)
            except Exception as _ab_exc:
                _logger.debug(f"[HTTP] AntiBlockingHTTP init failed, using manual pacing: {_ab_exc!r}")

        http_cfg: Mapping[str, Any] = self.cfg.get("http", {})  # type: ignore

        # TLS doğrulama
        self.verify: bool = not bool(http_cfg.get("insecure_skip_verify", False))

        # Timeout (connect, read)
        timeout = float(http_cfg.get("timeout_seconds", 20.0))
        self._timeout_pair: tuple[float, float] = (timeout, timeout)

        # Retry politikası
        allowed = frozenset(map(str.upper, http_cfg.get("retry_allowed_methods", list(IDEMPOTENT_DEFAULT))))
        self.retry_policy = RetryPolicy(
            total=int(http_cfg.get("retries", 2)),
            base_backoff=float(http_cfg.get("backoff_factor", 0.4)),
            max_backoff=float(http_cfg.get("max_backoff", 10.0)),
            status_forcelist=tuple(http_cfg.get("status_forcelist", (429, 500, 502, 503, 504))),
            allowed_methods=allowed,
            jitter=bool(http_cfg.get("jitter", True)),
        )

        # Sürücü seçimi
        driver = str(http_cfg.get("driver", "requests")).strip().lower()

        # Her zaman curl_cffi tercih et (TLS parmak izi gizleme)
        try:
            from websecure.core.waf_bypass import _CURL_CFFI_AVAILABLE
            if _CURL_CFFI_AVAILABLE and driver not in ("httpx", "curl_cffi"):
                driver = "curl_cffi"
            elif not _CURL_CFFI_AVAILABLE and _HTTPX_AVAILABLE and driver != "httpx":
                driver = "httpx"
        except ImportError:
            if _HTTPX_AVAILABLE and driver != "httpx":
                driver = "httpx"

        if driver == "httpx" and not _HTTPX_AVAILABLE:
            driver = "requests"

        self.driver_name = driver

        if self.driver_name == "curl_cffi":
            try:
                from websecure.core.waf_bypass import CurlCffiDriver, _CURL_CFFI_AVAILABLE
                if _CURL_CFFI_AVAILABLE:
                    _imp = (self.cfg.get("privacy", {}).get("impersonation", {}) or {}) if isinstance(self.cfg, dict) else {}
                    _profile = str(_imp.get("profile", "chrome_124"))
                    _proxy = self._proxy_pool.next() if self._proxy_pool.enabled else None
                    _proxy_url = _proxy.url if _proxy else None
                    self._driver = CurlCffiDriver(
                        profile=_profile,
                        proxy_url=_proxy_url,
                        verify=self.verify,
                        timeout_pair=self._timeout_pair,
                    )
                else:
                    self.driver_name = "requests"
                    self._driver = _RequestsDriver(http_cfg=http_cfg, verify=self.verify, timeout_pair=self._timeout_pair)
            except Exception as exc:
                _logger.debug(f"[HTTP] curl_cffi driver init failed, falling back to requests: {exc!r}")
                self.driver_name = "requests"
                self._driver = _RequestsDriver(http_cfg=http_cfg, verify=self.verify, timeout_pair=self._timeout_pair)
        elif self.driver_name == "httpx":
            self._driver = _HttpxDriver(http_cfg=http_cfg, verify=self.verify, timeout_pair=self._timeout_pair)
        else:
            self._driver = _RequestsDriver(http_cfg=http_cfg, verify=self.verify, timeout_pair=self._timeout_pair)

        # Kimliksiz mod idempotent kısıtı
        kz = self.cfg.get("kimliksiz_mod") or {}
        self._kimliksiz_idempotent = bool(kz.get("idempotent_only", False))

    @staticmethod
    def _build_urllib3_retry(http_cfg: Mapping[str, Any]) -> Urllib3Retry:
        allowed = set(http_cfg.get("retry_allowed_methods", list(IDEMPOTENT_DEFAULT)))
        return Urllib3Retry(
            total=int(http_cfg.get("retries", 2)),
            backoff_factor=float(http_cfg.get("backoff_factor", 0.4)),
            status_forcelist=tuple(http_cfg.get("status_forcelist", (429, 500, 502, 503, 504))),
            allowed_methods=allowed,
        )

    # ----- pacing -----
    def _pace_before(self, method: str = "GET") -> None:
        # Delegate to AntiBlockingHTTP token-bucket rate limiter when configured.
        # This connects build_http_client() → RateLimiter → jitter → penalty into the flow.
        if self._anti_blocking_http is not None:
            self._anti_blocking_http.rl.acquire()
            self._anti_blocking_http._sleep_policy(method)
            return
        # Fallback: simple interval-based pacing when AntiBlockingHTTP is not configured
        if self._interval <= 0:
            return
        now = time.monotonic()
        target = self._last_ts + self._interval
        if target > now:
            gap = target - now
            gap = max(0.0, gap * random.uniform(0.70, 1.30))
            time.sleep(gap)
        self._last_ts = time.monotonic()
        delay = 0.0
        if self._extra_delay_ms > 0:
            delay += self._extra_delay_ms / 1000.0
        if self._jitter_ms > 0:
            delay += random.randint(0, self._jitter_ms) / 1000.0
        if delay > 0:
            time.sleep(delay)

    def _should_retry(self, method: str, status: Optional[int], exc: Optional[BaseException]) -> bool:
        if method.upper() not in self.retry_policy.allowed_methods:
            return False
        if status is not None and status in self.retry_policy.status_forcelist:
            return True
        if exc is not None:
            return True
        return False

    def _do_request_with_retries(self, method: str, url: str, **kw) -> UnifiedResponse:
        attempts = 0

        def _retry_after_seconds(resp: UnifiedResponse) -> Optional[float]:
            ra = (resp.headers or {}).get("Retry-After")
            return _to_float(ra, None)

        while True:
            attempts += 1
            raw = self._driver.request_once(method, url, **kw)
            resp = UnifiedResponse(raw, driver=("httpx" if self.driver_name == "httpx" else "requests"))
            status = resp.status_code

            _collect_rate_limit(resp, url)
            
            # [ACIL DURUM] Smart Block Detection & Panic Mode
            # yumuşak (200 OK) blokları da yakalar (waf_challenge, captcha_block)
            block_type = classify_access_block(status, getattr(resp, "headers", {}), getattr(resp, "text", ""))
            
            if block_type in ("waf_challenge", "captcha_block", "rate_limit") or status == 403:
                self._consecutive_blocks += 1
                if self._consecutive_blocks >= 2:
                    # Hafif blok: Tor/Proxy rotasyonu dene
                    try:
                        from websecure.core.waf_bypass import rotate_tor_identity
                        rotate_tor_identity()
                    except (ImportError, OSError, Exception) as _exc:
                        import logging as _lg
                        _lg.getLogger(__name__).debug(f"[HTTP] Tor rotation attempt failed: {_exc!r}")
                    
                if self._consecutive_blocks >= 5:
                    # [PANIK MODU] 5 kere üst üste bloklandık -> soğuma molası.
                    # Bounded + cancel-aware: eski flat time.sleep(120) WAF'lı hedefte
                    # her worker thread'ini 2 dk dondurup taramayı "takılmış" gösteriyordu
                    # ve faz watchdog'una/Ctrl+C'ye yanıt vermiyordu.
                    _logger.critical(f"[PANIC] 5 defa üst üste bloklandık ({block_type})! soğuma molası (≤{_MAX_BLOCK_SLEEP:.0f}sn)…")
                    _bounded_sleep(_MAX_BLOCK_SLEEP)
                    self._consecutive_blocks = 0 # Sıfırla ve tekrar dene
                
                # Bloklandıysa hemen retry logic'e düşür (status_code manipülasyonu ile)
                # Retry policy 429/403'ü zaten kapsıyor mu? Evet.
                # Ama 200 OK dönen Captcha için status'u 429 gibi davranmaya zorlayabiliriz
                if block_type in ("waf_challenge", "captcha_block"):
                    status = 429 # Retry policy'nin bunu 'retryable' görmesini sağla
            
            elif status < 400:
                # Başarılı istek -> Sayacı sıfırla
                self._consecutive_blocks = 0

            if attempts <= self.retry_policy.total and self._should_retry(method, status, None):
                if self.retry_policy.respect_retry_after_header and status in (429, 503):
                    ra = _retry_after_seconds(resp)
                    if ra is not None:
                        _bounded_sleep(ra)  # cap a hostile Retry-After (e.g. 3600s)
                        continue
                _bounded_sleep(self.retry_policy.compute_sleep(attempts))
                continue

            return resp

    # ----- Dış API -----
    def request(self, method: str, url: str, **kw) -> UnifiedResponse:
        self._pace_before(method)

        # curl_cffi sürücüsü — proxy rotation entegrasyonu
        if self.driver_name == "curl_cffi" and hasattr(self._driver, "update_proxy"):
            try:
                from websecure.core.waf_bypass import get_egress_manager as _gem
                em = _gem()
                if em:
                    new_proxy = em.get_next_egress()
                    self._driver.update_proxy(new_proxy)
            except (ImportError, AttributeError) as exc:
                _logger.debug(f"[HTTP] Proxy rotation for curl_cffi driver failed: {exc!r}")

        # curl-impersonate subprocess modu (curl_cffi yokken fallback)
        imp_cfg = (self.cfg.get("privacy") or {}).get("impersonation") if isinstance(self.cfg, dict) else None
        if isinstance(imp_cfg, dict) and imp_cfg.get("enabled") and str(imp_cfg.get("mode", "")).lower() == "curl" and self.driver_name != "curl_cffi":
            ident = current_identity(self.cfg) if self.cfg else {}
            proxy_url = ident.get("proxy_url") or self._proxy_pool.next(url)
            hdrs = dict(kw.get("headers") or {})
            hdrs.update(_impersonation_headers(str(imp_cfg.get("profile", "chrome_120"))))
            use_h2, use_h1 = _alpn_prefs(self.cfg)
            resp = _request_via_curl(
                method,
                url,
                headers=hdrs,
                data=kw.get("data"),
                json_body=kw.get("json"),
                proxy_url=proxy_url,
                timeout=int(self._timeout_pair[0]),
                profile=str(imp_cfg.get("profile", "chrome_120")),
                alpn_prefs=(use_h2, use_h1),
                tls_min=str((((self.cfg.get("anti_blocking") or {}).get("tls") or {}).get("min_version", "")) or None),
                ciphers=str((((self.cfg.get("anti_blocking") or {}).get("tls") or {}).get("ciphers", "")) or None),
                bin_name=_bin_map_from_cfg(self.cfg, str(imp_cfg.get("profile", "chrome_120"))),
            )
            counters_inc("http_requests", 1)
            counters_add_bytes(len(getattr(resp, "content", b"") or b""))
            return _hook_record_status(resp)

        meth = (method or "").upper()

        # Kimliksiz modda idempotent-dışı çağrıları atla
        unauth = self.mode != "authenticated"
        if unauth and self._kimliksiz_idempotent:
            allowed = set(allowed_http_methods(self.cfg, unauthenticated=True))
            if meth not in allowed:
                # P6 fix: was silently skipping with no log — add debug trace for visibility
                _logger.debug("[HTTP] Skipping non-idempotent %s in unauthenticated mode: %s", meth, url)
                add_result("http_skipped", {"url": url, "method": meth, "reason": "idempotent_only"})

                class _Synthetic:
                    def __init__(self) -> None:
                        self.status_code = 0
                        self.headers = {}
                        self.text = "skipped (idempotent_only)"
                        self.content = b""
                        self.url = url
                        self.elapsed = None
                        self.ok = True
                        self.reason = ""
                        self.http_version = "HTTP/1.1"

                return UnifiedResponse(_Synthetic(), driver=("httpx" if self.driver_name == "httpx" else "requests"))

        # sürücüye ver
        kw.pop("verify", None)
        if self.driver_name == "requests":
            kw.setdefault("timeout", self._timeout_pair)

        start = time.time()
        resp = self._do_request_with_retries(meth, url, **kw)

        # Anti-blocking response adjustment — update penalty/backoff based on response status
        if self._anti_blocking_http is not None:
            _ab_status = int(getattr(resp, "status_code", 0) or 0)
            _ab_headers = dict(getattr(resp, "headers", {}) or {})
            self._anti_blocking_http._adjust_on_response(_ab_status, _ab_headers)

        # Kanıt/ölçüm kaydı
        counters_inc("http_requests", 1)
        counters_add_bytes(len(getattr(resp, "content", b"") or b""))
        _hdrs = dict(kw.get("headers") or {})
        _body = kw["data"] if "data" in kw else (kw["json"] if "json" in kw else None)
        _raw_req = build_raw_http_request(meth, url, _hdrs, _body)
        _status = int(getattr(resp, "status_code", 0) or 0)
        _ver = getattr(resp, "http_version", "HTTP/1.1")
        _reason = getattr(resp, "reason", "")
        _resp_head = build_response_head(_status, dict(getattr(resp, "headers", {}) or {}), _ver, _reason)
        add_result(
            "http_proof",
            {
                "method": meth,
                "url": url,
                "request": _raw_req,
                "response_head": _resp_head,
                "status": _status,
                "rt_ms": int((time.time() - start) * 1000),
            },
        )
        add_result(
            "http_timing",
            {
                "url": url,
                "endpoint": _normalize_endpoint_for_metrics(url),
                "method": meth,
                "status": _status,
                "rt_ms": int((time.time() - start) * 1000),
            },
        )
        return _hook_record_status(resp)

    # Kolaycı
    def head(self, url: str, **kw) -> UnifiedResponse:
        return self.request("HEAD", url, **kw)

    def get_http_version(self, resp: UnifiedResponse) -> str:
        return resp.http_version


# Tekil istemci (singleton)
_http_singleton: Optional[HttpClient] = None
_http_singleton_lock = threading.Lock()


def get_http(cfg: Optional[Mapping[str, Any]] = None) -> HttpClient:
    global _http_singleton
    if _http_singleton is None:
        with _http_singleton_lock:
            if _http_singleton is None:
                _http_singleton = HttpClient(cfg)
    return _http_singleton


# ---------------------------------------------------------------------------
# ffuf/ferox için header arg üretimi
# ---------------------------------------------------------------------------

def build_dirbust_headers(
    session: Optional["requests.Session"] = None, auth_ctx: Optional[Mapping[str, Any]] = None
) -> list[str]:
    headers: dict[str, str] = {}
    cookies: dict[str, str] = {}

    if session is not None:
        for k, v in dict(getattr(session, "headers", {}) or {}).items():
            headers[str(k)] = str(v)
        cjar = getattr(session, "cookies", None)
        if cjar:
            for c in cjar:
                cookies[c.name] = c.value

    if isinstance(auth_ctx, Mapping):
        for k, v in (auth_ctx.get("headers") or {}).items():
            headers[str(k)] = str(v)
        for k, v in (auth_ctx.get("cookies") or {}).items():
            cookies[str(k)] = str(v)

    if cookies:
        cookie_val = "; ".join([f"{k}={v}" for k, v in cookies.items()])
        headers["Cookie"] = cookie_val

    banned = {"content-length", "host", "connection"}
    out: list[str] = []
    for k, v in headers.items():
        if str(k).lower() in banned:
            continue
        out.append(f"-H {json.dumps(f'{k}: {v}')}")
    return out


# ---------------------------------------------------------------------------
# requests oturumu sertleştirme
# ---------------------------------------------------------------------------

# ================= SoftTLS Preflight (no try/except) =================
import os as _os, shutil as _shutil, subprocess as _subprocess, urllib.parse as _uparse

def _softtls__have(cmd: str) -> bool:
    return _shutil.which(cmd) is not None

def _softtls__curl_tls_ok(url: str, timeout_s: int) -> tuple[bool|None, str]:
    # Returns (True,"") if TLS verified, (False,"cert") on certificate error,
    # (False,"other") on other failures, (None,"") if curl not available.
    if not _softtls__have("curl"):
        return (None, "")
    # -I: HEAD, -sS: silent, --max-time: timeout, -o /dev/null: drop body
    cp = _subprocess.run(
        ["curl", "-I", "-sS", "--max-time", str(int(timeout_s)), url, "-o", _os.devnull],
        stdout=_subprocess.PIPE, stderr=_subprocess.PIPE, text=True, check=False
    )
    if cp.returncode == 0:
        return (True, "")
    err = (cp.stderr or "").lower()
    cert_markers = (
        "ssl certificate problem", "self signed certificate",
        "unable to get local issuer certificate", "certificate verify failed",
        "certification path", "host name does not match"
    )
    if any(m in err for m in cert_markers):
        return (False, "cert")
    return (False, "other")

def _softtls__openssl_tls_ok(url: str, timeout_s: int) -> tuple[bool|None, str]:
    if not _softtls__have("openssl"):
        return (None, "")
    p = _uparse.urlparse(url)
    host = p.hostname or ""
    port = p.port or (443 if p.scheme == "https" else 80)
    if not host or port != 443 or p.scheme != "https":
        return (True, "")  # Not an HTTPS TLS check scenario
    # Use s_client to verify chain; -verify_return_error will nonzero on failures
    cp = _subprocess.run(
        ["openssl", "s_client", "-verify_return_error", "-servername", host, "-connect", f"{host}:443"],
        input="", text=True, stdout=_subprocess.PIPE, stderr=_subprocess.PIPE, check=False
    )
    if cp.returncode == 0:
        return (True, "")
    err = (cp.stderr or cp.stdout or "").lower()
    cert_markers = ("self signed certificate", "unable to get local issuer certificate",
                    "certificate verify failed", "verify error", "host name mismatch")
    if any(m in err for m in cert_markers):
        return (False, "cert")
    return (False, "other")

def _softtls__preflight(url: str, timeout_s: int = 6) -> tuple[bool|None, str]:
    # Prefer curl, then openssl; return (True/False/None, reason)
    r, why = _softtls__curl_tls_ok(url, timeout_s)
    if r is not None:
        return r, why
    r2, why2 = _softtls__openssl_tls_ok(url, timeout_s)
    return r2, why2

class SoftTLSSession(requests.Session):
    """
    requests.Session türevi: TLS doğrulama varsayılan açık (self.verify=True).
    Eğer ön-kontrol (preflight) sertifika hatası işaret ederse sadece o istek için
    verify=False'a yumuşatır. try/except yoktur; preflight süreçleri alt süreçlerle yapılır.
    """
    def __init__(self, cfg: Mapping[str, Any] | None = None):
        super().__init__()
        self._soft_cfg = dict(cfg or {})
        # keep .verify as configured by hardened_session
        self._soft_enabled = bool(((self._soft_cfg.get("tls") or {}).get("soft_fail", True)))
        self._soft_timeout = int(((self._soft_cfg.get("http") or {}).get("timeout_seconds", 10)))

        # Allowlisted path prefixes for soft TLS on certificate problems/unavailability
        tls_node = (self._soft_cfg.get("tls") or {}) if isinstance(self._soft_cfg, dict) else {}
        allow = tls_node.get("soft_allowlist") if isinstance(tls_node, dict) else None
        if isinstance(allow, (list, tuple)):
            self._soft_allow = [str(x) for x in allow if isinstance(x, (str, bytes)) and str(x).strip()]
        else:
            # Sensible defaults if not configured
            self._soft_allow = ["/robots.txt", "/sitemap.xml", "/sitemap_index.xml"]


    def request(self, method, url, **kwargs):  # type: ignore[override]
        # respect explicit kw verify default, but allow soft-fail override
        verify_kw = kwargs.pop("verify", getattr(self, "verify", True))
        if self._soft_enabled:
            sch = (url or "").split(":",1)[0].lower() if isinstance(url, str) else ""
            if sch == "https" and bool(verify_kw):
                verdict, why = _softtls__preflight(url, self._soft_timeout)
                if verdict is False and why == "cert":
                    verify_kw = False  # soften only on certificate problems
                elif verdict is None:
                    # Preflight unavailable; allowlisted paths get soft-verify
                    try_path = ""
                    if isinstance(url, str):
                        try_path = _urlparse(url).path or "/"
                    for pref in self._soft_allow:
                        if try_path.startswith(pref):
                            verify_kw = False
                            break
        kwargs["verify"] = verify_kw
        # Guarantee a finite per-request timeout (default off-Tor when omitted,
        # floor on Tor) so a stalled connection can't hang the phase forever.
        kwargs["timeout"] = _floor_request_timeout(kwargs.get("timeout"))
        return super().request(method, url, **kwargs)
# ================= /SoftTLS Preflight =================



def hardened_session(cfg: Optional[Mapping[str, Any]] = None) -> requests.Session:
    """
    Returns a production-ready, hardened requests.Session.
    Integrates WAF Bypass if configured, otherwise standard hardening.
    When tls.soft_fail is True, uses SoftTLSSession to gracefully handle
    certificate errors without completely disabling TLS verification.
    """
    c = dict(cfg or {})

    # 1. Determine base session class: SoftTLS or Smart
    tls_cfg = c.get("tls") if isinstance(c, dict) else {}
    use_soft_tls = bool((tls_cfg or {}).get("soft_fail", False)) if isinstance(tls_cfg, dict) else False

    # 1. WAF Evasion Check
    if WAFBypassAdapter and c.get("waf", {}).get("enabled"):
        # Mount WAFBypassAdapter on a SmartSession (preserves circuit-breaker + identity rotation)
        s = SmartSession()
        adapter = WAFBypassAdapter()
        s.mount("https://", adapter)
        s.mount("http://", adapter)
        # Add basic headers
        s.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
            "Accept": "*/*"
        })
    elif use_soft_tls:
        # SoftTLSSession: runs preflight to detect cert errors, auto-softens verify per request
        s = SoftTLSSession(c)
    else:
        # SmartSession wires _smart_request (circuit breaker, identity rotation, live monitor)
        s = SmartSession()

    # 2. Add Timeouts & Retries (via adapter if not WAF)
    # (Note: WAF adapter wraps requests so it might handle retries differently,
    # but we should ensure base resilience)
    if not (WAFBypassAdapter and c.get("waf", {}).get("enabled")):
        retry = Urllib3Retry(
            total=3,
            backoff_factor=0.5,
            status_forcelist=(429, 500, 502, 503, 504),
            allowed_methods=["GET", "POST", "HEAD", "OPTIONS"]
        )
        # Use larger pool sizes to prevent "Connection pool full" warnings under Tor/concurrent scans
        adapter = HTTPAdapter(max_retries=retry, pool_connections=100, pool_maxsize=100)
        s.mount("https://", adapter)
        s.mount("http://", adapter)

    return s



def instrument_requests_session(session: requests.Session, cfg: Mapping[str, Any] | None = None) -> None:
    if getattr(session, "_websec_instrumented", False):
        return
    lg = get_logging_prefs(cfg or {})
    if not lg.get("structured") or not lg.get("http_json"):
        session._websec_instrumented = True  # type: ignore[attr-defined]
        return

    req_id_header = lg.get("req_id_header") or "X-Request-Id"
    trace_id_header = lg.get("trace_id_header") or "X-Trace-Id"
    sample_rate = float(lg.get("sample_rate") or 1.0)
    include_headers = bool(lg.get("include_headers"))
    include_query = bool(lg.get("include_query", True))

    orig = getattr(session, "request")

    def _emit(event: dict) -> None:
        logging.getLogger("websec.http").info(json.dumps(event, ensure_ascii=False))

    def wrapped(method, url, **kw):
        if not _should_sample(sample_rate):
            return orig(method, url, **kw)
        start = time.time()
        rid = kw.pop("req_id", None) or uuid.uuid4().hex
        tr = kw.pop("trace_id", None) or get_trace_id()
        headers = dict(kw.get("headers") or {})
        headers.setdefault(req_id_header, rid)
        if tr:
            headers.setdefault(trace_id_header, tr)
        kw["headers"] = headers
        ev = {
            "ts": _now_iso(),
            "event": "http.request",
            "req_id": rid,
            "trace_id": tr,
            "method": str(method).upper(),
            "url": url if include_query else url.split("?", 1)[0],
            "driver": "requests",
        }
        if include_headers:
            ev["headers"] = _redact_headers_for_log(headers)
        _emit(ev)

        resp = orig(method, url, **kw)
        dur = int(((time.time() - start) * 1000))
        ev2 = {
            "ts": _now_iso(),
            "event": "http.response",
            "req_id": rid,
            "trace_id": tr,
            "status": int(getattr(resp, "status_code", 0) or 0),
            "elapsed_ms": dur,
            "bytes": int(len(getattr(resp, "content", b"") or b"")),
            "http": getattr(getattr(resp, "raw", None), "version", 11),
        }
        _emit(ev2)

        counters_inc("http_requests", 1)
        counters_add_bytes(len(getattr(resp, "content", b"") or b""))
        add_result(
            "http_timing",
            {
                "url": url,
                "endpoint": _normalize_endpoint_for_metrics(url, include_query),
                "method": str(method).upper(),
                "status": int(getattr(resp, "status_code", 0) or 0),
                "rt_ms": dur,
            },
        )
        return _hook_record_status(resp)

    session.request = wrapped  # type: ignore[assignment]
    session._websec_instrumented = True  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# curl-impersonate köprüsü
# ---------------------------------------------------------------------------



def _resolve_curl_bin(val: str) -> str:
    """curl-impersonate bin_map değerini platform/konum bağımsız çöz.

    - Ayraç içermeyen değerler (ör. 'curl_chrome120') PATH araması için aynen döner.
    - Windows dışında '.exe' uzantılı yol → PATH'teki 'curl'e düşer.
    - './tools/...' gibi göreli yollar yazılabilir köke göre (frozen-safe) çözülür.
    """
    if not val or ("/" not in val and "\\" not in val):
        return val
    import sys
    if not sys.platform.startswith("win") and val.lower().endswith(".exe"):
        return "curl"
    from pathlib import Path as _P
    if not _P(val).is_absolute():
        try:
            from websecure.core.paths import writable_root as _wr
            cleaned = val[2:] if val.startswith("./") else val
            cand = _wr() / cleaned
            if cand.exists():
                return str(cand)
        except Exception:
            pass
    return val


def _bin_map_from_cfg(cfg: Mapping[str, Any] | None, profile: str) -> str:
    c = dict(cfg or {})
    imp = (c.get("privacy") or {}).get("impersonation") or {}
    p = str(profile or "chrome_120").lower()
    mp = imp.get("bin_map") or {}
    if isinstance(mp, dict) and p in mp:
        return _resolve_curl_bin(str(mp[p]))
    # built-in defaults
    default = {
        "chrome_120": "curl_chrome120",
        "chrome_121": "curl_chrome121",
        "chrome_122": "curl_chrome122",
        "chrome_123": "curl_chrome123",
        "chrome_124": "curl_chrome124",
        "firefox_115": "curl_ff115",
        "firefox_120": "curl_ff120",
        "firefox_128": "curl_ff128",
    }
    return default.get(p, default["chrome_120"])
class _FakeResponseForCurl:
    def __init__(self, url: str, status: int, headers: dict, body: bytes, http_version: str, elapsed: float):
        self.url = url
        self.status_code = int(status)
        self.headers = dict(headers or {})
        self.content = body or b""
        self.text = self.content.decode("utf-8", errors="ignore")
        self.elapsed = elapsed
        self.ok = self.status_code < 400
        self.reason = ""
        self.raw = None
        self.http_version = http_version


def _profile_to_curl_bin(profile: str) -> str:
    p = str(profile or "chrome_120").lower()
    mapping = {
        "chrome_120": "curl_chrome120",
        "chrome_124": "curl_chrome124",
        "firefox_120": "curl_ff120",
        "firefox_128": "curl_ff128",
    }
    return mapping.get(p, "curl_chrome120")




def _request_via_curl(
    method: str,
    url: str,
    *,
    headers: dict | None = None,
    data: bytes | None = None,
    json_body: dict | None = None,
    proxy_url: str | None = None,
    timeout: int = 30,
    profile: str = "chrome_120",
    alpn_prefs: tuple[bool, bool] | None = None,
    tls_min: str | None = None,
    ciphers: str | None = None,
    bin_name: str | None = None,
) -> UnifiedResponse:
    bin_name = bin_name or _profile_to_curl_bin(profile)
    cmd = [bin_name, "-i", "-sS", "-X", str(method or "GET").upper(), str(url), "--compressed", "--max-time", str(int(timeout))]

    # ALPN preference
    if alpn_prefs:
        use_h2, use_h1 = alpn_prefs
        if use_h2:
            cmd.append("--http2")
        elif use_h1:
            cmd.append("--http1.1")

    # Proxy
    if proxy_url:
        cmd += ["-x", str(proxy_url)]

    # TLS minimum
    if tls_min:
        lo = str(tls_min).upper().replace(" ", "")
        if lo in ("TLS1.3", "TLS13"):
            cmd.append("--tlsv1.3")
        elif lo in ("TLS1.2", "TLS12"):
            cmd.append("--tlsv1.2")
    if ciphers:
        cmd += ["--ciphers", str(ciphers)]

    # Headers
    for k, v in (headers or {}).items():
        cmd += ["-H", f"{k}: {v}"]

    # Body
    stdin_data = None
    if json_body is not None:
        import json as _json
        body = _json.dumps(json_body, separators=(",", ":")).encode("utf-8")
        cmd += ["-H", "Content-Type: application/json", "--data-binary", "@-"]
        stdin_data = body
    elif data is not None:
        stdin_data = data if isinstance(data, (bytes, bytearray)) else str(data).encode("utf-8")
        cmd += ["--data-binary", "@-"]

    t0 = __import__("time").time()
    cp = _subp.run(cmd, input=stdin_data, capture_output=True, check=False)
    elapsed = __import__("time").time() - t0

    raw = cp.stdout.decode("utf-8", "ignore")
    # Split headers and body — curl -i outputs headers followed by \r\n\r\n or \n\n
    header_txt = ""
    body_txt = raw
    if "\r\n\r\n" in raw:
        header_txt, body_txt = raw.split("\r\n\r\n", 1)
    elif "\n\n" in raw:
        header_txt, body_txt = raw.split("\n\n", 1)



    lines = [ln for ln in header_txt.splitlines() if ln.strip()]
    http_version = "HTTP/1.1"
    status_code = 0
    if lines and lines[0].startswith("HTTP/"):
        parts = lines[0].split()
        if len(parts) >= 2 and parts[1].isdigit():
            status_code = int(parts[1])
        http_version = parts[0]

    hdrs = {}
    for ln in lines[1:]:
        if ":" in ln:
            k, v = ln.split(":", 1)
            hdrs[k.strip()] = v.strip()

    fake = _FakeResponseForCurl(url, status_code, hdrs, body_txt.encode("utf-8", "ignore"), http_version, elapsed)
    unified = UnifiedResponse(fake, driver="requests")
    unified.http_version = fake.http_version  # _to_http_version_from_requests raw.version'u okur, fake'de yok
    return unified

def build_xff_variants(ip: str = "127.0.0.1") -> list[dict[str, str]]:
    return [
        {"X-Forwarded-For": ip},
        {"X-Real-IP": ip},
        {"Forwarded": f"for={ip};proto=http"},
    ]

# ---------------------------------------------------------------------------
# TLS Verify helper for phases (no try/except)
# ---------------------------------------------------------------------------

def verify_for_phase(cfg_or_session, phase: str = "", url: str | None = None) -> bool:
    """
    Faz veya kullanım bağlamına göre TLS doğrulama bayrağını döndür.
    - Varsayılan: doğrulama açık (True).
    - http.insecure_skip_verify True ise kapat (False).
    - URL https ve yol allowlist'e denk geliyorsa 'soft' mod devreye girer:
      preflight (curl/openssl) sertifika hatası işaret ederse False döner.
    """
    # default True
    base_verify = True
    cfg = {}
    if isinstance(cfg_or_session, dict):
        cfg = cfg_or_session
    else:
        # Session olabilir; verify alanını saygıla
        base_verify = bool(getattr(cfg_or_session, "verify", True))
        cfg = getattr(cfg_or_session, "_soft_cfg", {}) if hasattr(cfg_or_session, "_soft_cfg") else {}

    http_cfg = cfg.get("http", {}) if isinstance(cfg, dict) else {}
    if isinstance(http_cfg, dict) and http_cfg.get("insecure_skip_verify") is True:
        return False

    # If URL provided and HTTPS: perform preflight without try/except
    if isinstance(url, str) and url.startswith("https://"):
        # Allowlist path shortcuts for discovery-ish phases
        allowlist = ["/robots.txt", "/sitemap.xml", "/sitemap_index.xml"]
        try_path = url.split("://", 1)[-1]
        try_path = "/" + try_path.split("/", 1)[1] if "/" in try_path else "/"

        # Attempt preflight via soft TLS helpers
        verdict, why = _softtls__preflight(url, int(http_cfg.get("timeout_seconds", 10) or 10))
        if verdict is False and why == "cert":
            return False
        if verdict is None and any(try_path.startswith(p) for p in allowlist):
            return False  # soften when tools absent & on allowlisted probes

    return base_verify


def note_http_response(status: int, rt_ms: int) -> None:
    HTTP_METRICS["total"] += 1
    if 200 <= status < 300:
        HTTP_METRICS["ok_2xx"] += 1
    elif status == 403:
        HTTP_METRICS["ban_403"] += 1
        HTTP_METRICS["err_4xx"] += 1
    elif status == 429:
        HTTP_METRICS["throttle_429"] += 1
        HTTP_METRICS["err_4xx"] += 1
    elif 400 <= status < 500:
        HTTP_METRICS["err_4xx"] += 1
    elif status >= 500:
        HTTP_METRICS["err_5xx"] += 1
    # simple rolling avg
    n = HTTP_METRICS["total"]
    HTTP_METRICS["avg_rt_ms"] = ((HTTP_METRICS["avg_rt_ms"] * (n - 1)) + rt_ms) / n


class RateLimiter:
    """Token-bucket rate limiter.

    DEDUP (Madde 4): bucket algoritması artık TEK kaynakta — `rate_controller.TokenBucket`.
    Bu sınıf onu sarar; kendi (önceden kopyalanmış _add_tokens/acquire) bucket döngüsünü
    TAŞIMAZ. http'ye özgü clamp'ler korundu (rps>=0.1, capacity>=1). TokenBucket ayrıca
    capped-sleep (min(wait,0.5)) ile daha responsive bekleme sunar (aynı efektif rate).
    """
    def __init__(self, rps: float, burst: int = 4):
        from websecure.core.rate_controller import TokenBucket
        self.rps = max(0.1, float(rps))
        self.capacity = max(1, int(burst))
        self._bucket = TokenBucket(rate=self.rps, burst=self.capacity)

    def acquire(self) -> None:
        self._bucket.acquire(block=True)

def jitter_delay(jitter_range_ms: list[int] | tuple[int,int] | int | None) -> float:
    if jitter_range_ms is None:
        return 0.0
    if isinstance(jitter_range_ms, int):
        return random.uniform(0.0, jitter_range_ms/1000.0)
    if isinstance(jitter_range_ms, (list, tuple)) and len(jitter_range_ms) >= 2:
        a, b = float(jitter_range_ms[0])/1000.0, float(jitter_range_ms[1])/1000.0
        if b < a: a, b = b, a
        return random.uniform(a, b)
    return 0.0


class AntiBlockingHTTP:
    def __init__(self, session: requests.Session, policy: Dict[str, Any]):
        self.s = session
        self.policy = policy or {}
        rps = float(self.policy.get("rps", 1.0))
        burst = int(self.policy.get("burst", 4))
        self.rl = RateLimiter(rps, burst)
        self.jitter = self.policy.get("jitter_ms", [0,0])
        self.backoff_factor = float(self.policy.get("backoff_factor", 2.0))
        self.max_extra_delay_ms = int(self.policy.get("max_extra_delay_ms", 0))
        self.respect_retry_after = bool(self.policy.get("respect_retry_after", True))
        self.idempotent_only = bool(self.policy.get("suppress_non_idempotent_at_start", False))
        self._penalty = 0.0  # seconds

    def _sleep_policy(self, method: str) -> None:
        if self.idempotent_only and method.upper() not in ("GET","HEAD","OPTIONS"):
            # non-idempotent bastırma: istek anında hafif bekleme
            time.sleep(0.150)
        jd = jitter_delay(self.jitter)
        if jd > 0:
            time.sleep(jd)
        if self._penalty > 0:
            time.sleep(self._penalty)

    def _adjust_on_response(self, status: int, headers: Dict[str, Any]) -> None:
        if status == 429:
            lower_headers = {k.lower(): v for k, v in headers.items()}
            if self.respect_retry_after and "retry-after" in lower_headers:
                ra = lower_headers["retry-after"]
                if isinstance(ra, str) and ra.isdigit():
                    self._penalty = max(self._penalty, float(int(ra)))
            else:
                self._penalty = max(self._penalty * self.backoff_factor, 1.0)
        elif status == 403:
            self._penalty = max(self._penalty * self.backoff_factor, 2.0)
        elif 200 <= status < 300:
            # Yavaşça toparla
            self._penalty = max(0.0, self._penalty / max(1.5, self.backoff_factor))

    def request(self, method: str, url: str, **kwargs) -> requests.Response:
        self.rl.acquire()
        self._sleep_policy(method)
        # Always finite: default off-Tor when timeout omitted, raise to floor on Tor.
        kwargs["timeout"] = _floor_request_timeout(kwargs.get("timeout"))
        t0 = time.monotonic()
        resp = self.s.request(method=method, url=url, **kwargs)
        rt_ms = int((time.monotonic() - t0)*1000)
        note_http_response(getattr(resp, "status_code", 0), rt_ms)
        self._adjust_on_response(getattr(resp, "status_code", 0), getattr(resp, "headers", {}))
        return resp


def build_http_client(cfg: Dict[str, Any]) -> AntiBlockingHTTP:
    ab_cfg = ((cfg.get("anti_blocking") or {}).get("http") or {})
    # P4 fix: pass full cfg so hardened_session() can read top-level waf/tls/privacy keys.
    sess = hardened_session(cfg)
    return AntiBlockingHTTP(sess, ab_cfg)


# ---------------------------------------------------------------------------
# Gizlilik başlıkları: IP leak ve parmak izi koruma
# ---------------------------------------------------------------------------

_PRIVACY_HEADERS = {
    # Gerçek IP'yi sızdırabilecek başlıkları temizle
    "X-Forwarded-For": None,
    "X-Real-IP": None,
    "X-Client-IP": None,
    "Via": None,
    "Forwarded": None,
    # Tarayıcı parmak izini minimize et
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br",
    "Connection": "keep-alive",
    "DNT": "1",
}


def apply_privacy_headers(session, mode: str = "standard") -> None:
    """
    Session başlıklarını gizlilik için temizle/ayarla.
    mode="paranoid": tüm parmak izi başlıklarını kaldır
    mode="standard": sadece IP leak başlıklarını kaldır
    """
    if not session:
        return
    hdrs = getattr(session, "headers", {})
    for k, v in _PRIVACY_HEADERS.items():
        if v is None:
            hdrs.pop(k, None)
            hdrs.pop(k.lower(), None)
        else:
            hdrs[k] = v
    if mode == "paranoid":
        # Ek başlıkları da temizle
        for k in ["Referer", "Origin", "X-Request-ID"]:
            hdrs.pop(k, None)


def build_session(cfg: dict) -> SmartSession:
    """Build a production-ready SmartSession from config (used by phases and scanners)."""
    s = SmartSession()
    http_cfg = (cfg or {}).get("http", {}) or {}
    connect_timeout = float(http_cfg.get("connect_timeout", 15))
    read_timeout = float(http_cfg.get("read_timeout", 15))
    backoff = float(http_cfg.get("backoff_factor", 0.3))
    max_retries = int(http_cfg.get("max_retries", 1))

    retry = Urllib3Retry(
        total=max_retries,
        connect=max_retries if http_cfg.get("retry_on_connect", True) else 0,
        read=max_retries if http_cfg.get("retry_on_read", True) else 0,
        status=max_retries,
        allowed_methods=frozenset({"GET", "HEAD", "OPTIONS", "POST"}),
        status_forcelist=tuple(http_cfg.get("retry_on_status", [502, 503, 504])),
        backoff_factor=backoff,
        respect_retry_after_header=True,
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry, pool_connections=32, pool_maxsize=64)
    s.mount("http://", adapter)
    s.mount("https://", adapter)
    # stash default timeout tuple on session for uniform use
    s.request_timeout = (connect_timeout, read_timeout)  # type: ignore[attr-defined]
    s.verify = bool(http_cfg.get("tls_verify", True))
    return s
