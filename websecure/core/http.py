from __future__ import annotations
import logging
import time
import random
import contextvars
from typing import Dict, Optional
from urllib.parse import urlsplit, urlunsplit
from requests import session
from urllib3.util.retry import Retry
import threading
import socket
import ssl
from typing import Optional

_logger = logging.getLogger(__name__)



try:
    import requests
except ImportError:  # fallback friendly
    requests = None

try:
    from websecure.core.waf_bypass import WAFBypassAdapter
except ImportError:
    WAFBypassAdapter = None



def _emit_egress_degraded(feature: str, reason: str, details: dict | None = None) -> None:
    rec = {'feature': str(feature), 'reason': str(reason)}
    if isinstance(details, dict):
        rec.update({k: v for k, v in details.items() if isinstance(k, str)})
    if callable(globals().get('add_result')):
        add_result('egress_degraded', rec)


def _setup_doh_resolver() -> None:
    """
    DNS sorgularını Cloudflare DoH (1.1.1.1) veya Google DoH üzerinden yapar.
    socket.getaddrinfo monkey-patch ile tüm requests/urllib3 DNS sorgularını yakalar.
    """
    import socket as _socket
    import urllib.request as _ur
    import json as _json

    _DOH_URLS = [
        "https://1.1.1.1/dns-query",
        "https://8.8.8.8/dns-query",
    ]
    _doh_cache: dict = {}

    _orig_getaddrinfo = _socket.getaddrinfo

    def _doh_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
        # IP adresleri için bypass
        try:
            _socket.inet_pton(_socket.AF_INET, host)
            return _orig_getaddrinfo(host, port, family, type, proto, flags)
        except OSError:
            pass
        try:
            _socket.inet_pton(_socket.AF_INET6, host)
            return _orig_getaddrinfo(host, port, family, type, proto, flags)
        except OSError:
            pass

        if host in _doh_cache:
            ip = _doh_cache[host]
        else:
            ip = None
            for doh_url in _DOH_URLS:
                try:
                    req = _ur.Request(
                        f"{doh_url}?name={host}&type=A",
                        headers={"Accept": "application/dns-json"},
                    )
                    with _ur.urlopen(req, timeout=5) as resp:
                        data = _json.loads(resp.read())
                    answers = [a["data"] for a in data.get("Answer", []) if a.get("type") == 1]
                    if answers:
                        ip = answers[0]
                        _doh_cache[host] = ip
                        break
                except Exception:
                    continue

        if ip:
            return _orig_getaddrinfo(ip, port, family, type, proto, flags)
        return _orig_getaddrinfo(host, port, family, type, proto, flags)

    if not getattr(_socket.getaddrinfo, "_doh_patched", False):
        _socket.getaddrinfo = _doh_getaddrinfo
        _socket.getaddrinfo._doh_patched = True  # type: ignore
        _logger.info("[DoH] DNS over HTTPS aktif (Cloudflare 1.1.1.1)")


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
        "allow_post_threshold": 0.2
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

def set_active_phase(name: str) -> None:
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

def _choose_identity_for_phase(phase: str) -> Dict[str, str]:
    ua_pool = _IDENTITY_POOLS["user_agents"] or ["Mozilla/5.0"]
    al_pool = _IDENTITY_POOLS["accept_language"] or ["en-US,en;q=0.9"]
    ac_pool = _IDENTITY_POOLS["accept"] or ["*/*"]
    ua = random.choice(ua_pool)
    al = random.choice(al_pool)
    ac = random.choice(ac_pool)
    ident = {"User-Agent": ua, "Accept-Language": al, "Accept": ac}
    prev = _LAST_IDENTITY.get()
    if prev != ident:
        _logger.debug(f"[HTTP] identity switch → UA='{ua[:42]}...' AL='{al}'")
        _LAST_IDENTITY.set(ident)
    return ident

def _respect_idempotent_first(phase: str, method: str, post_ratio_ok: bool) -> bool:
    pol = _HTTP_POLICY["idempotent_first"]
    if not pol["enabled"]:
        return True
    if phase in pol["early_phases"]:
        return method.upper() in ("GET", "HEAD", "OPTIONS")
    if method.upper() in ("POST", "PUT", "DELETE", "PATCH"):
        return bool(post_ratio_ok)
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

def _respect_retry_after(headers: Dict[str, str]) -> None:
    """Honor Retry-After header on 429 responses. Circuit breaker handles threshold logic."""
    ra = _parse_retry_after(headers) if _HTTP_POLICY["rate_limit"]["respect_retry_after"] else None
    wait_time = ra if (ra is not None and ra > 0) else 5.0
    _logger.debug(f"[HTTP] Retry-After → sleeping {wait_time:.1f}s")
    time.sleep(wait_time)

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
    if now - _LAST_CANARY_TS < canary_gap:
        return
    _LAST_CANARY_TS = now
    rps = int(_CURRENT_RPS.get())
    prof = _HTTP_POLICY["phase_profiles"].get(ACTIVE_PHASE.get(), {})
    max_rps = int(prof.get("max_rps", rps))
    step = int(_HTTP_POLICY["rate_limit"]["recover_step"])
    if rps < max_rps:
        _CURRENT_RPS.set(min(max_rps, rps + max(1, step)))
        _logger.debug(f"[HTTP] canary → RPS {rps}→{_CURRENT_RPS.get()} (phase={ACTIVE_PHASE.get()})")

def _smart_request(self, method, url, **kwargs):
    phase = ACTIVE_PHASE.get()

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

    # --- IMMORTAL LOOP: Auto-Heal & Retry ---
    max_retries = 3
    attempt     = 0

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

            resp   = super(type(self), self).request(method, url, **kwargs)
            status = resp.status_code

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
                        _cb_reset()  # new identity → clean slate for circuit breaker
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
            err_msg    = str(e).lower()
            is_timeout = "timeout" in err_msg or "timed out" in err_msg
            _logger.debug(f"[Autopilot] Connection error ({e.__class__.__name__}). Retry {attempt}/{max_retries}…")

            if is_timeout and attempt < max_retries:
                _try_rotate_identity(self)

            if attempt <= max_retries:
                time.sleep(1.0)
                continue

            _logger.debug(f"[Autopilot] Failed to connect to {url} after {max_retries} retries.")
            raise e

    return resp  # safe fallback (loop should always return or raise above)

import contextvars
import json
import random
import subprocess as _subp
import time
import uuid
from dataclasses import dataclass
from typing import Any, Mapping, Optional, Sequence ,Dict
from urllib.parse import urlparse as _urlparse
from websecure.core.utils import (
    allowed_http_methods,
    build_raw_http_request,
    build_response_head,
    current_identity,
    get_logging_prefs,
)
from .utils import normalize_url, resolve_canonical_base
try:
    import httpx
except ImportError:
    httpx = None
import importlib.util as _impspec
import requests
from requests.adapters import HTTPAdapter
from urllib3.util import Retry as Urllib3Retry
_HTTPX_AVAILABLE = _impspec.find_spec("httpx") is not None

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

HTTP_METRICS: dict[str, int] = {"2xx": 0, "403": 0, "429": 0, "total": 0}


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
    return {
        "counters": metrics,
        "latency_histogram": dict(HTTP_LATENCY_HIST),
        "phases": {k: dict(v) for k,v in _PHASE_STATS.items()},
    }

def set_trace_id(trace_id: str | None) -> None:
    _TRACE_CTX.set(trace_id)


def get_trace_id() -> str | None:
    return _TRACE_CTX.get()


def _now_iso() -> str:
    import datetime as _dt
    return _dt.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


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

        pool_conns = int(http_cfg.get("pool_connections", 10))
        pool_max = int(http_cfg.get("pool_maxsize", 10))
        
        # Determine if we should use WAF Bypass Adapter
        # Default to True for now as requested "strength", or check config
        use_waf_bypass = True 
        
        try:
            from websecure.core.waf_bypass import WAFBypassAdapter
        except ImportError:
            WAFBypassAdapter = None
            
        if use_waf_bypass and WAFBypassAdapter:
             adapter = WAFBypassAdapter(max_retries=0, pool_connections=pool_conns, pool_maxsize=pool_max)
        else:
             adapter = HTTPAdapter(max_retries=0, pool_connections=pool_conns, pool_maxsize=pool_max)

        self.s = hardened_session({})
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
             rotate_tor_identity()
        except Exception as e:
             _logger.debug(f"[http] Tor identity rotation failed: {e}")

    def request_once(self, method: str, url: str, **kw) -> requests.Response:
        # Circuit breaker pre-check — raises if scan is halted
        _cb_check()

        kw.pop("verify", None)
        kw.setdefault("timeout", self.timeout_pair)
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

        pol = hpm_current_policy()
        self._rps = float(pol.get("rps", self._rps))
        self._interval = 0.0 if self._rps <= 0 else 1.0 / self._rps
        self._pace_before()

        resp = self.s.request(method, url, verify=self.verify, **kw)
        _collect_rate_limit(resp, url)
        st = int(getattr(resp, "status_code", 0) or 0)
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
        # DoH requested but not implemented → degrade to system resolver
        dns = (egress.get('dns') or {}) if isinstance(egress, dict) else {}
        if str(dns.get('strategy') or '').lower() == 'doh':
            _setup_doh_resolver()
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

        # Proxy havuzu
        self._proxy_pool = ProxyPool(self.cfg)
        self._consecutive_blocks = 0 # [ACIL DURUM] Ardışık blok sayacı

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
                    # [PANIK MODU] 5 kere üst üste bloklandık -> SİSTEM DURUYOR
                    _logger.critical(f"[PANIC] 5 defa üst üste bloklandık ({block_type})! 120sn soğuma molası...")
                    time.sleep(120)
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
                        time.sleep(ra)
                        continue
                time.sleep(self.retry_policy.compute_sleep(attempts))
                continue

            return resp

    # ----- Dış API -----
    def request(self, method: str, url: str, **kw) -> UnifiedResponse:
        self._pace_before()

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


def get_http(cfg: Optional[Mapping[str, Any]] = None) -> HttpClient:
    global _http_singleton
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
import shutil as _shutil, subprocess as _subprocess, urllib.parse as _uparse

def _softtls__have(cmd: str) -> bool:
    return _shutil.which(cmd) is not None

def _softtls__curl_tls_ok(url: str, timeout_s: int) -> tuple[bool|None, str]:
    # Returns (True,"") if TLS verified, (False,"cert") on certificate error,
    # (False,"other") on other failures, (None,"") if curl not available.
    if not _softtls__have("curl"):
        return (None, "")
    # -I: HEAD, -sS: silent, --max-time: timeout, -o /dev/null: drop body
    cp = _subprocess.run(
        ["curl", "-I", "-sS", "--max-time", str(int(timeout_s)), url, "-o", "/dev/null"],
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
        return super().request(method, url, **kwargs)
# ================= /SoftTLS Preflight =================



def hardened_session(cfg: Optional[Mapping[str, Any]] = None) -> requests.Session:
    """
    Returns a production-ready, hardened requests.Session.
    Integrates WAF Bypass if configured, otherwise standard hardening.
    """
    c = dict(cfg or {})
    
    # 1. WAF Evasion Check
    if WAFBypassAdapter and c.get("waf", {}).get("enabled"):
        # Use WAFBypassSession which mounts the adapter
        # Assuming WAFBypassSession is in websecure.core.waf_bypass or we mount manually
        # Since we imported WAFBypassAdapter, let's mount it manually to a clean session
        s = requests.Session()
        adapter = WAFBypassAdapter()
        s.mount("https://", adapter)
        s.mount("http://", adapter)
        # Add basic headers
        s.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
            "Accept": "*/*"
        })
    else:
        # Standard Session
        s = requests.Session()
        
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
        adapter = HTTPAdapter(max_retries=retry)
        s.mount("https://", adapter)
        s.mount("http://", adapter)

    # 3. SoftTLS Wrappers if needed
    # (Checking logic for SoftTLSSession is complex, skipping for simplicity unless requested)
    
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
    import time as _t

    def _emit(event: dict) -> None:
        logging.getLogger("websec.http").info(json.dumps(event, ensure_ascii=False))

    def wrapped(method, url, **kw):
        if not _should_sample(sample_rate):
            return orig(method, url, **kw)
        start = _t.time()
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
        dur = int(((_t.time() - start) * 1000))
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



def _bin_map_from_cfg(cfg: Mapping[str, Any] | None, profile: str) -> str:
    c = dict(cfg or {})
    imp = (c.get("privacy") or {}).get("impersonation") or {}
    p = str(profile or "chrome_120").lower()
    mp = imp.get("bin_map") or {}
    if isinstance(mp, dict) and p in mp:
        return str(mp[p])
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
    # Split headers and body (first header block)
    header_txt = ""
    body_txt = raw
    if "" in raw:


        header_txt, body_txt = raw.split("", 1)


    elif "" in raw:


        header_txt, body_txt = raw.split("", 1)



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
    return fake

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


def _emit_egress_degraded(feature: str, reason: str, details: dict | None = None) -> None:
    rec = {'feature': str(feature), 'reason': str(reason)}
    if isinstance(details, dict):
        rec.update({k: v for k, v in details.items() if isinstance(k, str)})
    if callable(globals().get('add_result')):
        add_result('egress_degraded', rec)

HTTP_METRICS = {
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
    "crawler_endpoints": 0
}
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
    def __init__(self, rps: float, burst: int = 4):
        self.capacity = max(1, int(burst))
        self.tokens = float(self.capacity)
        self.rps = max(0.1, float(rps))
        self.last = time.monotonic()
        self._lock = threading.Lock()

    def _add_tokens(self, now: float) -> None:
        delta = now - self.last
        self.tokens = min(self.capacity, self.tokens + delta * self.rps)
        self.last = now

    def acquire(self) -> None:
        while True:
            with self._lock:
                now = time.monotonic()
                self._add_tokens(now)
                if self.tokens >= 1.0:
                    self.tokens -= 1.0
                    return
                need = (1.0 - self.tokens) / self.rps
            time.sleep(need)

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
            if self.respect_retry_after and "retry-after" in {k.lower(): v for k,v in headers.items()}:
                ra = headers.get("Retry-After")
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
        t0 = time.monotonic()
        resp = self.s.request(method=method, url=url, **kwargs)
        rt_ms = int((time.monotonic() - t0)*1000)
        note_http_response(getattr(resp, "status_code", 0), rt_ms)
        self._adjust_on_response(getattr(resp, "status_code", 0), getattr(resp, "headers", {}))
        return resp
    # Initialize RPS from phase profile if available
    prof = _HTTP_POLICY["phase_profiles"].get(ACTIVE_PHASE.get(), {})
    if prof:
        _CURRENT_RPS.set(int(prof.get("initial_rps", _CURRENT_RPS.get())))

    # Attach smart request wrapper
    import types as _types
    session.request = _types.MethodType(_smart_request, session)
def build_http_client(cfg: Dict[str, Any]) -> AntiBlockingHTTP:
    http_cfg = (cfg.get("http") or {})
    ab_cfg = ((cfg.get("anti_blocking") or {}).get("http") or {})
    sess = hardened_session(http_cfg)
    return AntiBlockingHTTP(sess, ab_cfg)


from requests import Session
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

def build_session(cfg: dict) -> Session:
    s = Session()
    http_cfg = (cfg or {}).get("http", {}) or {}
    connect_timeout = float(http_cfg.get("connect_timeout", 5))
    read_timeout = float(http_cfg.get("read_timeout", 15))
    backoff = float(http_cfg.get("backoff_factor", 0.3))
    max_retries = int(http_cfg.get("max_retries", 1))

    retry = Retry(
        total=max_retries,
        connect=max_retries if http_cfg.get("retry_on_connect", True) else 0,
        read=max_retries if http_cfg.get("retry_on_read", True) else 0,
        status=max_retries,
        allowed_methods=frozenset({"GET","HEAD","OPTIONS","POST"}),
        status_forcelist=tuple(http_cfg.get("retry_on_status", [502,503,504])),
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
