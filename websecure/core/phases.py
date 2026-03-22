from __future__ import annotations
from websecure.core.utils import _ws_import_any, _ws_maybe_import_any
import logging
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple
import importlib
import importlib.util as _iul
import traceback
import inspect
import threading
from urllib.parse import urlparse
from websecure.core.reporting import _phase_rec
import socket, importlib, os
from typing import List, Tuple, Callable
from .http import hardened_session
from .reporting import add_result
import socket, ssl, json, importlib, importlib.util as _iul
import logging as _logging
import time as _t
# Safe imports for optional scanners
_rs = _ma = _jwt = _nq = _ws = _sx = _gqa = _gqr = _fu = None

try:
    from websecure.scanners import request_smuggling as _rs
except ImportError:
    pass

try:
    from websecure.scanners import mass_assignment as _ma
except ImportError:
    pass

try:
    from websecure.scanners import jwt as _jwt
except ImportError:
    pass

try:
    from websecure.scanners import nosqli as _nq
except ImportError:
    pass

try:
    from websecure.scanners import ws_fuzz as _ws
except ImportError:
    pass

try:
    from websecure.scanners import ssrf_xxe as _sx
except ImportError:
    pass


try:
    from websecure.scanners import graphql as _gql
except ImportError:
    pass


try:
    from websecure.scanners import file_upload as _fu
except ImportError:
    pass

try:
    from websecure.crawler import WebCrawler
except ImportError:
    WebCrawler = None
_logger = _logging.getLogger(__name__)
_req_mod = importlib.import_module('requests') if _iul.find_spec('requests') is not None else None
requests = _req_mod  # alias; may be None

_BOUNDARY_EXC = tuple([
    (_req_mod.exceptions.RequestException if (_req_mod and hasattr(_req_mod, "exceptions")) else Exception),
    TimeoutError,
    ssl.SSLError,
    socket.gaierror,
    OSError,
    json.JSONDecodeError,
    ImportError,
    ValueError,
])

def _report_phase_error(_phase: str, _where: str, _err: BaseException) -> None:
    _rmod = None
    if _iul.find_spec('websecure.core.reporting') is not None:
        _rmod = importlib.import_module('websecure.core.reporting')
    elif _iul.find_spec('reporting') is not None:
        _rmod = importlib.import_module('reporting')
    if _rmod is not None and hasattr(_rmod, 'add_result'):
        _rmod.add_result("phase_error", {
            "type": "phase_error",
            "severity": "error",
            "message": str(_err),
            "meta": {
                "phase": _phase,
                "where": _where,
                "exc_type": _err.__class__.__name__,
            },
        })



def _importable(mod: str):
    try:
        import importlib.util as _iul
        return _iul.find_spec(mod) is not None
    except _BOUNDARY_EXC as e:
        _logger.error('phase error [phases]', exc_info=True)
        _report_phase_error('phases', 'phases.py', e)
        return False

def _call_if_exists(modname: str, cand_funcs=("run","scan","main","execute"), *args, **kwargs) -> bool:
    try:
        mod = importlib.import_module(modname)
    except _BOUNDARY_EXC as e:
        _logger.error('phase error [phases]', exc_info=True)
        _report_phase_error('phases', 'phases.py', e)
        return False
    fn = None
    for n in cand_funcs:
        fn = getattr(mod, n, None)
        if callable(fn):
            break
    if not callable(fn):
        return False
    fn(*args, **kwargs) if args or kwargs else fn()
    return True



def phase_discovery(ctx: dict):
    s = hardened_session()
    target = ctx.get("target") or ""
    if not target:
        return
    # trivial probe to ensure session works
    try:
        r = s.get(target, timeout=6, allow_redirects=True)
        add_result("discovery", {"severity":"info","message":f"Discovery touched: {target} ({r.status_code})","url":target})
    except _BOUNDARY_EXC as e:
        _logger.error('phase error [phases]', exc_info=True)
        _report_phase_error('phases', 'phases.py', e)
        add_result("discovery", {"severity":"warning","message":f"Discovery failed: {e}","url":target})
    
    # [WS3] External Discovery Tools
    try:
        # FFUF
        if _get(ctx.get("config",{}), "offensive.ffuf.enabled", True):
             _runner_ffuf(ctx)
        
        # Feroxbuster
        if _get(ctx.get("config",{}), "offensive.feroxbuster.enabled", True):
             _runner_feroxbuster(ctx)
    except Exception as e:
        _logger.warning(f"External discovery tool failed: {e}")

def phase_portscan(ctx: dict):
    # UPDATED: Using Nmap with config
    nmap_cfg = ctx.get("config",{}).get("nmap", {}) or {}
    if not nmap_cfg.get("enabled", True):
        add_result("portscan", {"severity":"note","message":"nmap disabled"})
        return
        
    from websecure.integrations.nmap import NmapWrapper
    host = ctx.get("host")
    if not host:
         u = ctx.get("url") or ctx.get("target") or ""
         if u:
             host = _host_from_url(u)
    if not host:
        return

    nmap = NmapWrapper()
    if not nmap.is_available():
        add_result("portscan", {"severity":"warning","message":"Nmap binary not found."})
        return

    # Config arguments
    ports_cfg = nmap_cfg.get("ports", [])
    ports_arg = "-F"
    if ports_cfg:
        ports_arg = "-p" + ",".join(map(str, ports_cfg))
    
    extra_args = nmap_cfg.get("arguments", [])

    res = nmap.scan(host, ports=ports_arg, extra_args=extra_args)

    for item in res:
        p = item.get("port")
        if p:
            svc = item.get("service", "?")
            product = item.get("product", "")
            version = item.get("version", "")
            add_result("nmap", {
                "severity": "info",
                "message": f"Open port: {p}/{item.get('protocol','tcp')} ({svc} {product} {version})".strip(),
                "host": item.get("ip") or item.get("hostname") or host,
                "port": p,
                "proto": item.get("protocol", "tcp"),
                "service": svc,
                "product": product,
                "version": version,
                "state": "open",
            })

    if not res:
        add_result("portscan", {"severity": "note", "message": "No open ports found (Nmap)."})

def phase_tls(ctx: dict):
    url = ctx.get("url") or ctx.get("target", "")
    try:
        from websecure.scanners.tls import scan_tls
        tls_result = scan_tls(url, session=ctx.get("session"), config=ctx.get("config", {}))
        if tls_result:
            # Store certificate details under "tls" bucket for the dashboard
            add_result("tls", tls_result)
            # Also push any TLS findings (weak protocols/ciphers) to "offensive"
            for finding in tls_result.get("new_findings", []):
                add_result("offensive", finding)
    except ImportError:
        add_result("tls", {"severity": "note", "message": "tls scanner not present; skipped"})
    except Exception as e:
        add_result("tls", {"severity": "warning", "message": f"TLS scan error: {e}"})

def phase_sec_headers(ctx: dict):
    if not _call_if_exists("websecure.scanners.headers", ("run","scan")):
        add_result("security_headers", {"severity":"note","message":"security_headers scanner not present; skipped"})

def phase_offensive(ctx: dict):
    add_result('offensive', {'severity':'note','message':'offensive_gate_applied'})
    cfg = ctx.get("config", {}) if isinstance(ctx, dict) else getattr(ctx, "config", {}) or {}
    if not (cfg.get("offensive", {}) or {}).get("enabled", True):
        add_result("offensive", {"severity":"note","message":"offensive disabled"})
        return
    mods = [
        "websecure.scanners.request_smuggling",
        "websecure.scanners.mass_assignment",
        "websecure.scanners.jwt",
        "websecure.scanners.ws_fuzz",
        "websecure.scanners.graphql",
        "websecure.scanners.rate_limit",
        "websecure.scanners.csrf",
        "websecure.scanners.owasp",
        "websecure.scanners.passive_recon",
        "websecure.scanners.session_hunter",
        "websecure.scanners.sqli",
        "websecure.scanners.xss",
        "websecure.scanners.nosqli",
        "websecure.scanners.ssrf_xxe",
        "websecure.scanners.file_upload",
        "websecure.scanners.auth",
    ]
    hit = 0
    for m in mods:
        if _call_if_exists(m, ("run","scan","main","execute")):
            hit += 1
    if not hit:
        add_result("offensive", {"severity":"note","message":"no offensive modules found"})
    
    # [WS3] External Tools Execution (Sqlmap)
    try:
        if (cfg.get("offensive", {}).get("sqlmap", {}).get("enabled", True)):
            _runner_sqlmap(ctx)
    except Exception as _e:
        _logger.warning(f"[phases] sqlmap runner error: {_e}")


_reporting_mod = None
if _iul.find_spec("websecure.core.reporting") is not None:
    _reporting_mod = importlib.import_module("websecure.core.reporting")
elif _iul.find_spec("reporting") is not None:
    _reporting_mod = importlib.import_module("reporting")

if _reporting_mod is not None:
    add_result = getattr(_reporting_mod, "add_result", lambda *_a, **_k: None)
    redact_sensitive = getattr(_reporting_mod, "redact_sensitive", lambda x: x)
else:
    def add_result(*_a, **_k) -> None:
        _phase_rec(get_results() if callable(globals().get('get_results')) else {}, 'flow', 'skipped', 'return_none')

        return None
    def redact_sensitive(x):
        return x
"""
Koşul bazlı AMA görünür (visible) fazlar:
 - SSRF/XXE
 - HTTP Request Smuggling
 - Mass Assignment
 - NoSQL Injection
 - File Upload abuse
 - JWT manipülasyonları
 - WebSocket fuzz
 - GraphQL saldırı seti

Notlar
------
* Bu dosya build_plan(ctx) içinde fazları, config'e göre `enabled`/`disabled` kararını
  vererek ama her durumda **görünür** şekilde plana ekler.
* Her fazın `runner`'ı aynı imzaya sahiptir: runner(ctx) -> None
  (Hataları kendisi raporlar; plan akışını bozmaz. İstisnalar yutulmaz.)
* `ctx` için beklenen minimal alanlar:
    - ctx.url            (str)  : hedef temel URL
    - ctx.session        (requests.Session) : ortak oturum
    - ctx.config         (dict) : yapılandırma
    - ctx.results        (dict) : (opsiyonel) sonuç kovası
    - ctx.debug          (bool) : (opsiyonel) hata ayıklama
"""
def get_results() -> dict:
    """Return the central results bucket if available, else an empty dict.
    Prefers core.reporting.get_results when present. No try/except.
    """
    mod = _reporting_mod
    if mod is None:
        if _iul.find_spec("websecure.core.reporting") is not None:
            import importlib as _im
            mod = _im.import_module("websecure.core.reporting")
        elif _iul.find_spec("reporting") is not None:
            import importlib as _im
            mod = _im.import_module("reporting")
    fn = getattr(mod, "get_results", None) if mod is not None else None
    if callable(fn):
        val = fn()
        return val if isinstance(val, dict) else {}
    # Fallback: no global results provider
    return {}

# ----------------------------- Yardımcılar (no try/except) -----------------------------


def _opt_import(module: str, attr: Optional[str] = None):
    fulls = []
    if isinstance(module, str) and module:
        if '.' in module:
            fulls.append(module)
        else:
            fulls.extend((f'websecure.core.{module}', module))
    mod = _ws_maybe_import_any(*fulls) if fulls else None
    if not mod:
        return None
    return getattr(mod, attr) if isinstance(attr, str) and attr else mod

def _resolve_module(primary: str, fallbacks: List[str] | None = None):
    """Önce tam paket adı, sonra fallbackler, en sonda düz modül ismi."""
    cands = [primary] + list(fallbacks or []) + [primary.rsplit(".", 1)[-1]]
    for m in cands:
        mod = _opt_import(m)
        if mod:
            return mod
    _phase_rec(get_results() if callable(globals().get('get_results')) else {}, 'flow', 'skipped', 'return_none')

    return None
def _get(cfg: Dict[str, Any], path: str, default: Any = None) -> Any:
    cur: Any = cfg
    for part in path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return default
        cur = cur[part]
    return cur

def _deep_get(d: object, path: str, default=None):
    cur = d
    for part in path.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return default
    return cur

def _filter_kwargs(fn: Callable, kwargs: Dict[str, Any]) -> Dict[str, Any]:
    """fn imzasına göre kwargs filtrele (TypeError yakalamadan uyum)."""
    params = inspect.signature(fn).parameters
    return {k: v for k, v in kwargs.items() if k in params}

def _ensure_results_bucket(ctx: Any) -> Dict[str, Any]:
    bucket = getattr(ctx, "results", None)
    if not isinstance(bucket, dict):
        setattr(ctx, "results", {})
        bucket = ctx.results
    return bucket

def _host_from_url(u: str) -> str:
    try_netloc = urlparse(u or "").netloc
    return (try_netloc.split(":")[0] or "").lower()

# ----------------------------- Kritik hata işaretleme (no try/except) -----------------------------

def set_critical_error(ctx: Any, reason: str) -> None:
    if not hasattr(ctx, "shared") or not isinstance(ctx.shared, dict):
        setattr(ctx, "shared", {})
    ctx.shared["critical_error"] = reason or True
    add_result("errors", {"stage": "critical", "reason": reason})

def clear_critical_error(ctx: Any) -> None:
    if hasattr(ctx, "shared") and isinstance(ctx.shared, dict):
        ctx.shared.pop("critical_error", None)

# ----------------------------- Faz çalıştırma izolasyonu (no try/except) -----------------------------

def _safe(ctx, fn: Callable[[], None], phase_id: str) -> None:
    """
    Her fazı ayrı bir thread'de çalıştırır. İstisnalar main thread'i bozmaz.
    Hatalar threading.excepthook ile toplanıp raporlanır.
    """
    err: Dict[str, str] = {}

    def _hook(args: threading.ExceptHookArgs):
        err["type"] = getattr(args.exc_type, "__name__", "Exception")
        err["error"] = str(args.exc_value)
        err["trace"] = "".join(traceback.format_exception(args.exc_type, args.exc_value, args.exc_traceback))[-2000:]

    old_hook = getattr(threading, "excepthook", None)
    threading.excepthook = _hook  # type: ignore[assignment]

    t = threading.Thread(target=fn, name=f"phase::{phase_id}", daemon=True)
    t.start()
    t.join()

    threading.excepthook = old_hook  # restore

    if err:
        add_result("errors", {
            "type": "phase_error",
            "phase": phase_id,
            "error": f"{err.get('type')}: {err.get('error')}",
            "trace": err.get("trace", "")[-2000:]
        })

# ----------------------------- Faz nesnesi -----------------------------

@dataclass
class Phase:
    id: str
    title: str
    enabled: bool
    reason: Optional[str] = None
    runner: Optional[Callable[[Any], None]] = None
    tags: List[str] = field(default_factory=list)
    visible: bool = True

def _runner_discovery(ctx) -> None:
    # Skip discovery when flow preflight marked blocked
    try:
        from websecure.core.flow_runner import is_blocked
        if is_blocked(ctx):
            add_result('meta', {'stage': 'discovery', 'status': 'skipped:blocked'})
            return
    except Exception:
        pass
    fm = _opt_import("websecure.core.flow_runner") or _opt_import("flow_runner")
    if not fm or not hasattr(fm, "run_discovery_extended") or not callable(getattr(fm, "run_discovery_extended")):
        add_result("meta", {"stage": "discovery", "status": "skipped:no-flow-runner"}); _phase_rec(get_results() if callable(globals().get('get_results')) else {}, 'flow', 'skipped', 'return'); return
    fm.run_discovery_extended(ctx)

def _runner_fuzz_and_param_discovery(ctx) -> None:
    fm = _opt_import("websecure.core.flow_runner") or _opt_import("flow_runner")
    if not fm or not hasattr(fm, "run_fuzz_and_param_discovery") or not callable(getattr(fm, "run_fuzz_and_param_discovery")):
        add_result("meta", {"stage": "fuzz_param_discovery", "status": "skipped:no-flow-runner"}); _phase_rec(get_results() if callable(globals().get('get_results')) else {}, 'flow', 'skipped', 'return'); return
    fm.run_fuzz_and_param_discovery(ctx)

def _runner_oast_verification(ctx) -> None:
    fm = _opt_import("websecure.core.flow_runner") or _opt_import("flow_runner")
    if not fm or not hasattr(fm, "run_oast_verification") or not callable(getattr(fm, "run_oast_verification")):
        add_result("meta", {"stage": "oast", "status": "skipped:no-flow-runner"}); _phase_rec(get_results() if callable(globals().get('get_results')) else {}, 'flow', 'skipped', 'return'); return
    fm.run_oast_verification(ctx)

def _runner_reporting_and_integration(ctx) -> None:
    fm = _opt_import("websecure.core.flow_runner") or _opt_import("flow_runner")
    if not fm or not hasattr(fm, "run_reporting_and_integration") or not callable(getattr(fm, "run_reporting_and_integration")):
        add_result("meta", {"stage": "reporting", "status": "skipped:no-flow-runner"}); _phase_rec(get_results() if callable(globals().get('get_results')) else {}, 'flow', 'skipped', 'return'); return
    fm.run_reporting_and_integration(ctx)

def _runner_authorization_matrix(ctx) -> None:
    fm = _opt_import("websecure.core.flow_runner") or _opt_import("flow_runner")
    if not fm or not hasattr(fm, "run_authorization_matrix") or not callable(getattr(fm, "run_authorization_matrix")):
        add_result("meta", {"stage": "authorization", "status": "skipped:no-flow-runner"}); _phase_rec(get_results() if callable(globals().get('get_results')) else {}, 'flow', 'skipped', 'return'); return
    fm.run_authorization_matrix(ctx)

def _runner_feroxbuster(ctx):
    fn = _opt_import("websecure.core.flow_runner", "run_feroxbuster_scan")
    if callable(fn):
        fn(ctx)
    else:
        add_result("meta", {"stage": "feroxbuster", "status": "skipped:not-found"})
    return _mk_result("feroxbuster", "finished", {})

def _runner_js_analysis(ctx) -> None:
    fm = _opt_import("websecure.core.flow_runner") or _opt_import("flow_runner")
    if not fm or not hasattr(fm, "run_js_analysis") or not callable(getattr(fm, "run_js_analysis")):
        add_result("js_analysis", {"status": "skipped", "reason": "flow_runner missing run_js_analysis"})
        return
    fm.run_js_analysis(ctx)

def _runner_sqlmap(ctx):
    fn = _opt_import("websecure.core.flow_runner", "run_sqlmap_scan")
    if callable(fn):
        fn(ctx)
    else:
        add_result("meta", {"stage": "sqlmap", "status": "skipped:not-found"})
    return _mk_result("sqlmap", "finished", {})



def _runner_business_logic_races(ctx) -> None:
    fm = _opt_import("websecure.core.flow_runner") or _opt_import("flow_runner")
    if not fm or not hasattr(fm, "run_business_logic_races") or not callable(getattr(fm, "run_business_logic_races")):
        add_result("meta", {"stage": "races", "status": "skipped:no-function"}); _phase_rec(get_results() if callable(globals().get('get_results')) else {}, 'flow', 'skipped', 'return')
        return
    fm.run_business_logic_races(ctx)

def _runner_ffuf(ctx) -> None:
    fm = _opt_import("websecure.core.flow_runner") or _opt_import("flow_runner")
    if not fm or not hasattr(fm, "run_ffuf_scan") or not callable(getattr(fm, "run_ffuf_scan")):
         add_result("meta", {"stage": "ffuf", "status": "skipped:no-flow-runner"})
         return
    fm.run_ffuf_scan(ctx)

def _runner_xss(ctx) -> None:
    fm = _opt_import("websecure.core.flow_runner") or _opt_import("flow_runner")
    if not fm or not hasattr(fm, "run_xss_scan") or not callable(getattr(fm, "run_xss_scan")):
         add_result("meta", {"stage": "xss", "status": "skipped:no-flow-runner"})
         return
    fm.run_xss_scan(ctx)
# ----------------------------- Runner sargıları -----------------------------

def _runner_scanners_ssrf_xxe(ctx) -> None:
    """scanners.ssrf_xxe.scan(...) çağrısı için imza-uyumlu sargı."""
    mod = _opt_import("scanners.ssrf_xxe")
    if not mod or not hasattr(mod, "scan") or not callable(getattr(mod, "scan")):
        add_result("offensive", {
            "type": "SSRF/XXE",
            "severity": "Bilgi",
            "reason": "Modül bulunamadı ya da `scan` yok."
        })
        _phase_rec(get_results() if callable(globals().get('get_results')) else {}, 'flow', 'skipped', 'return')

        return
    scan = getattr(mod, "scan")
    cfg = getattr(ctx, "config", {}) or {}
    oast_cfg = cfg.get("oast", {}) or {}

    base_url = (getattr(ctx, "url", None)
                or getattr(ctx, "base_url", None)
                or getattr(ctx, "target", None)
                or "")
    endpoints = getattr(ctx, "endpoints", None) or ([base_url] if base_url else [])

    results_bucket = _ensure_results_bucket(ctx)
    auth_ctx = getattr(ctx, "auth", None) or getattr(ctx, "auth_ctx", None)

    # olası param adlarını birlikte sun ve filtrele
    kw_all = {
        "session": getattr(ctx, "session", None),
        "endpoints": endpoints,
        "oast_cfg": oast_cfg,
        "oast": oast_cfg,
        "results": results_bucket,
        "debug": bool(getattr(ctx, "debug", False)),
        "auth_ctx": auth_ctx,
    }
    scan(**_filter_kwargs(scan, kw_all))

def _runner_scanners_request_smuggling(ctx) -> None:
    """scanners.request_smuggling.SmugglingProber üzerinden düşük etkili prob seti."""
    prober_cls = _opt_import("scanners.request_smuggling", "SmugglingProber")
    if not prober_cls:
        add_result("offensive", {
            "type": "Request Smuggling",
            "severity": "Bilgi",
            "reason": "Modül bulunamadı."
        })
        _phase_rec(get_results() if callable(globals().get('get_results')) else {}, 'flow', 'skipped', 'return')

        return
    base_url = (getattr(ctx, "url", None)
                or getattr(ctx, "base_url", None)
                or getattr(ctx, "target", None)
                or "")
    cfg = getattr(ctx, "config", {}) or {}
    tls_verify = bool((cfg.get("http") or {}).get("tls_verify", (cfg.get("tls") or {}).get("verify", True)))

    # İmza uyumlu kurucu
    init_kw = {
        "base_url": base_url,
        "target": base_url,
        "tls_verify": tls_verify,
        "verify_tls": tls_verify,
        "user_agent": "WebSecure/SmuggleProbe",
        "ua": "WebSecure/SmuggleProbe",
    }
    ctor_params = inspect.signature(prober_cls).parameters
    prober = prober_cls(**{k: v for k, v in init_kw.items() if k in ctor_params})

    # Probeları ayrık thread'lerde çalıştır; hatalar thread excepthook ile toplanır
    probe_names = (
        "probe_te_cl",
        "probe_te_cl_swap",
        "probe_te_duplicate",
        "probe_te_obfuscated_lws",
        "probe_conn_te_token",
        "probe_hbh_custom_token",
    )
    probes: List[Dict[str, Any]] = []
    errors: List[Dict[str, Any]] = []

    def _hook(args: threading.ExceptHookArgs):
        errors.append({
            "name": getattr(args.thread, "name", "probe"),
            "error": f"{getattr(args.exc_type, '__name__', 'Exception')}: {str(args.exc_value)}",
            "trace": "".join(traceback.format_exception(args.exc_type, args.exc_value, args.exc_traceback))[-1000:]
        })

    old_hook = getattr(threading, "excepthook", None)
    threading.excepthook = _hook  # type: ignore[assignment]
    ts: List[threading.Thread] = []

    for meth in probe_names:
        if not hasattr(prober, meth):
            continue
        fn = getattr(prober, meth)
        if not callable(fn):
            continue

        def _runner(call: Callable = fn, label: str = meth):
            res = call()
            probes.append({
                "name": getattr(res, "name", label),
                "status": getattr(res, "status_line", ""),
                "code": getattr(res, "status_code", 0),
                "headers": getattr(res, "headers", {}),
                "anomaly": getattr(res, "anomaly", None),
                "body_sample": (getattr(res, "body_sample", "") or "")[:400],
            })

        t = threading.Thread(target=_runner, name=f"smuggle::{meth}", daemon=True)
        t.start()
        ts.append(t)

    for t in ts:
        t.join()
    threading.excepthook = old_hook  # restore

    # Rapor
    add_result("offensive", {
        "type": "HTTP Request Smuggling (yan etkisiz prob)",
        "severity": "Bilgi",
        "url": base_url,
        "proof": {"probes": probes, "errors": errors}
    })

def _runner_mass_assignment(ctx) -> None:
    mod = _opt_import("scanners.mass_assignment")
    if not mod:
        add_result("offensive", {"type": "Mass Assignment", "severity": "Bilgi", "reason": "Modül bulunamadı."})
        _phase_rec(get_results() if callable(globals().get('get_results')) else {}, 'flow', 'skipped', 'return')

        return
    base_url = getattr(ctx, "url", "")
    sess = getattr(ctx, "session", None)
    timeout = float(_get(getattr(ctx, "config", {}) or {}, "timeouts.mass_assignment", 10.0))
    endpoints = _get(getattr(ctx, "config", {}) or {}, "mass_assignment.endpoints", None)
    params = _get(getattr(ctx, "config", {}) or {}, "mass_assignment.params", None)

    # run imzasını keşfet
    run = getattr(mod, "run", None)
    if callable(run):
        kw = _filter_kwargs(run, dict(base_url=base_url, session=sess, debug=bool(getattr(ctx, "debug", False)),
                                      timeout=timeout, endpoints=endpoints, params=params))
        run(**kw)

def _runner_nosqli(ctx) -> None:
    mod = _opt_import("scanners.nosqli")
    if not mod:
        add_result("offensive", {"type": "NoSQLi", "severity": "Bilgi", "reason": "Modül bulunamadı."})
        _phase_rec(get_results() if callable(globals().get('get_results')) else {}, 'flow', 'skipped', 'return')

        return
    base_url = getattr(ctx, "url", "")
    sess = getattr(ctx, "session", None)
    timeout = float(_get(getattr(ctx, "config", {}) or {}, "timeouts.nosqli", 8.0))
    endpoints = _get(getattr(ctx, "config", {}) or {}, "nosqli.endpoints", None)
    params = _get(getattr(ctx, "config", {}) or {}, "nosqli.params", None)

    run = getattr(mod, "run", None)
    if callable(run):
        kw = _filter_kwargs(run, dict(base_url=base_url, session=sess, debug=bool(getattr(ctx, "debug", False)),
                                      timeout=timeout, endpoints=endpoints, params=params))
        run(**kw)

def _runner_scanners_file_upload(ctx) -> None:
    """
    scanners.file_upload.{run|scan} için sargı.
    - İmza keşfi ile uyum (TypeError yakalamadan)
    """
    mod = _opt_import("scanners.file_upload")
    if not mod:
        add_result("offensive", {
            "type": "File Upload",
            "severity": "Bilgi",
            "reason": "Modül bulunamadı."
        })
        _phase_rec(get_results() if callable(globals().get('get_results')) else {}, 'flow', 'skipped', 'return')

        return
    run = getattr(mod, "run", None) or getattr(mod, "scan", None)
    if not callable(run):
        add_result("offensive", {
            "type": "File Upload",
            "severity": "Bilgi",
            "reason": "`run`/`scan` bulunamadı."
        })
        _phase_rec(get_results() if callable(globals().get('get_results')) else {}, 'flow', 'skipped', 'return')

        return
    base_url = (getattr(ctx, "url", None)
                or getattr(ctx, "base_url", None)
                or getattr(ctx, "target", None)
                or "")
    sess = getattr(ctx, "session", None)
    debug = bool(getattr(ctx, "debug", False))
    cfg = getattr(ctx, "config", {}) or {}

    endpoints_cfg = _deep_get(cfg, "scanners.file_upload.endpoints", None)
    if endpoints_cfg and not isinstance(endpoints_cfg, list):
        endpoints_cfg = [endpoints_cfg]

    disc = (getattr(ctx, "results", {}) or {}).get("discovery", {}) or {}
    endpoints_disc = disc.get("upload") or []

    endpoints = endpoints_cfg or endpoints_disc or ([base_url] if base_url else [])
    results_bucket = _ensure_results_bucket(ctx)

    kw_all = dict(session=sess, endpoints=endpoints, results=results_bucket,
                  base_url=base_url, debug=debug)
    run(**_filter_kwargs(run, kw_all))

    # Olası bulguları rapora yaz
    fb = results_bucket.get("file_upload") if isinstance(results_bucket, dict) else None
    if isinstance(fb, list):
        for item in fb:
            if isinstance(item, dict):
                add_result("file_upload", item)
    add_result("meta", {"stage": "file_upload", "tested": len(endpoints)})

def _runner_jwt(ctx) -> None:
    mod = _opt_import("scanners.jwt")
    if not mod or not hasattr(mod, "JWTScanner"):
        add_result("offensive", {"type": "JWT", "severity": "Bilgi", "reason": "Modül/Sınıf bulunamadı."})
        _phase_rec(get_results() if callable(globals().get('get_results')) else {}, 'flow', 'skipped', 'return')
        return

    base_url = getattr(ctx, "url", "")
    sess = getattr(ctx, "session", None)
    debug = bool(getattr(ctx, "debug", False))

    try:
        scanner = mod.JWTScanner(session=sess, debug=debug)
        vulns = scanner.run(base_url)

        # Merge results
        for bucket, findings in scanner.results.items():
             if bucket.endswith("_summary"): 
                 continue
             if isinstance(findings, list):
                 for item in findings:
                     add_result("jwt", item)
        
        add_result("meta", {"stage": "jwt", "vulns": vulns})
    except Exception as e:
        add_result("errors", {"stage": "jwt", "error": str(e)})

def _runner_scanners_ws_fuzz(ctx) -> None:
    """
    scanners.ws_fuzz.{run|scan} için sargı.
    - İmza keşfi
    - Sonuçları normalize ederek raporla
    """
    mod = _opt_import("scanners.ws_fuzz")
    if not mod:
        add_result("offensive", {
            "type": "WebSocket",
            "severity": "Bilgi",
            "reason": "Modül bulunamadı."
        })
        _phase_rec(get_results() if callable(globals().get('get_results')) else {}, 'flow', 'skipped', 'return')

        return
    run = getattr(mod, "run", None) or getattr(mod, "scan", None)
    if not callable(run):
        add_result("offensive", {
            "type": "WebSocket",
            "severity": "Bilgi",
            "reason": "`run`/`scan` bulunamadı."
        })
        _phase_rec(get_results() if callable(globals().get('get_results')) else {}, 'flow', 'skipped', 'return')

        return
    base_url = (getattr(ctx, "url", None)
                or getattr(ctx, "base_url", None)
                or getattr(ctx, "target", None)
                or "")
    sess = getattr(ctx, "session", None)
    debug = bool(getattr(ctx, "debug", False))
    cfg = getattr(ctx, "config", {}) or {}

    endpoints_cfg = _deep_get(cfg, "ws.endpoints", None)
    if endpoints_cfg and not isinstance(endpoints_cfg, list):
        endpoints_cfg = [endpoints_cfg]

    disc = (getattr(ctx, "results", {}) or {}).get("discovery", {}) or {}
    endpoints_disc = disc.get("ws") or disc.get("websocket") or []
    endpoints = endpoints_cfg or endpoints_disc or ([base_url] if base_url else [])

    results_bucket = _ensure_results_bucket(ctx)

    kw_all = dict(session=sess, endpoints=endpoints, results=results_bucket,
                  base_url=base_url, debug=debug)
    run(**_filter_kwargs(run, kw_all))

    # normalize & rapor
    for key in ("ws_fuzz", "websocket", "ws"):
        val = results_bucket.get(key) if isinstance(results_bucket, dict) else None
        if not val:
            continue
        items: List[Dict[str, Any]] = []
        if isinstance(val, dict):
            items = [val]
        elif isinstance(val, (list, tuple)):
            for x in val:
                if isinstance(x, dict):
                    items.append(x)
                elif isinstance(x, str):
                    items.append({"message": x})
                else:
                    items.append({"value": repr(x)})
        elif isinstance(val, str):
            items = [{"message": val}]
        else:
            items = [{"value": repr(val)}]
        for item in items:
            add_result(key, item)
    add_result("meta", {"stage": "ws_fuzz", "tested": len(endpoints)})

def _runner_graphql(ctx) -> None:
    att_mod = _opt_import("scanners.graphql_attacks")
    rpc_mod = _opt_import("scanners.graphql_rpc")
    
    # [WS3] Fallback to robust scanner if 'attacks' module missing
    if not att_mod:
        mod_base = _opt_import("scanners.graphql")
        if mod_base and hasattr(mod_base, "GraphQLScanner"):
             add_result("offensive", {"type": "GraphQL Attacks", "severity": "Note", "reason": "Attack module missing, running standard GraphQL Scanner"})
             _runner_scanners_graphql(ctx)
             return
        
        add_result("offensive", {"type": "GraphQL", "severity": "Info", "reason": "Modüller bulunamadı."})
        _phase_rec(get_results() if callable(globals().get('get_results')) else {}, 'flow', 'skipped', 'return')
        return

    gql_url = _get(getattr(ctx, "config", {}) or {}, "graphql.url", None)
    if not gql_url:
        base = (getattr(ctx, "url", "") or "").rstrip("/")
        gql_url = base + "/graphql"

    if rpc_mod and hasattr(rpc_mod, "GraphQLClient") and callable(getattr(rpc_mod, "GraphQLClient")):
        client = rpc_mod.GraphQLClient(getattr(ctx, "session", None),
                                       timeout=float(_get(getattr(ctx, "config", {}) or {}, "timeouts.graphql", 20.0)),
                                       verify_tls=True)
    else:
        # Check if att_mod has Client, if not use base
        client_cls = getattr(att_mod, "GraphQLClient", None)
        if not client_cls:
             # Try base scanner's client if available? Or fail gracefully
             return
        client = client_cls(getattr(ctx, "session", None),
                            timeout=float(_get(getattr(ctx, "config", {}) or {}, "timeouts.graphql", 20.0)))

    probes: List[Tuple[str, Callable]] = []
    if hasattr(att_mod, "probe_persisted_query_bypass") and callable(getattr(att_mod, "probe_persisted_query_bypass")):
        probes.append(("PersistedQuery", getattr(att_mod, "probe_persisted_query_bypass")))
    if hasattr(att_mod, "probe_batch_alias_storm") and callable(getattr(att_mod, "probe_batch_alias_storm")):
        probes.append(("AliasStorm", getattr(att_mod, "probe_batch_alias_storm")))
    if hasattr(att_mod, "probe_introspection_bypass") and callable(getattr(att_mod, "probe_introspection_bypass")):
        probes.append(("IntrospectionBypass", getattr(att_mod, "probe_introspection_bypass")))

    errors: List[Dict[str, Any]] = []

    def _hook(args: threading.ExceptHookArgs):
        errors.append({
            "name": getattr(args.thread, "name", "gql-probe"),
            "error": f"{getattr(args.exc_type, '__name__', 'Exception')}: {str(args.exc_value)}",
            "trace": "".join(traceback.format_exception(args.exc_type, args.exc_value, args.exc_traceback))[-1000:]
        })

    old_hook = getattr(threading, "excepthook", None)
    threading.excepthook = _hook  # type: ignore[assignment]

    ts: List[threading.Thread] = []
    findings_acc: List[Dict[str, Any]] = []

    for name, func in probes:
        def _runner(call: Callable = func, label: str = name):
            # İmza-keşfi ile kwargs filtrele
            kw = _filter_kwargs(call, dict(client=client, url=gql_url, endpoint=gql_url,
                                           session=getattr(ctx, "session", None),
                                           debug=bool(getattr(ctx, "debug", False))))
            out = call(**kw)
            for f in list(out or []):
                findings_acc.append({
                    "type": f"GraphQL {label}",
                    "severity": f.get("severity", "Bilgi"),
                    "url": f.get("endpoint", gql_url),
                    "reason": f.get("issue"),
                    "proof": redact_sensitive({
                        "payload": f.get("payload"),
                        "extra": f.get("extra", {}),
                        "body_hint": f.get("body_hint")
                    })
                })

        t = threading.Thread(target=_runner, name=f"graphql::{name}", daemon=True)
        t.start()
        ts.append(t)

    for t in ts:
        t.join()
    threading.excepthook = old_hook  # restore

    for it in findings_acc:
        add_result("offensive", it)
    if errors:
        add_result("errors", {"type": "graphql_probes", "errors": errors})

def _runner_passive_recon(ctx) -> None:
    mod = _opt_import("scanners.passive_recon")
    if not mod:
        add_result("discovery", {"type": "Passive Recon", "severity": "Info", "reason": "Module not found"})
        return

    base_url = getattr(ctx, "url", "") or getattr(ctx, "base_url", "")
    sess = getattr(ctx, "session", None)
    results = _ensure_results_bucket(ctx)

    # 1. Content Discovery (Robots, Sitemap, Common Files)
    if hasattr(mod, "ContentDiscoveryScanner"):
        cds = mod.ContentDiscoveryScanner(sess)
        findings = cds.scan(base_url)
        for f in findings:
            add_result("discovery", f)

    # 2. Passive JS Analysis
    if hasattr(mod, "PassiveJSScanner"):
        pjs = mod.PassiveJSScanner(sess)
        # Get endpoints from discovery results
        endpoints = results.get("endpoints", [])
        # Also include base_url
        if base_url not in endpoints:
            endpoints.append(base_url)
        
        # Filter for likely JS files or pages that might contain JS
        # For simplicity, we scan explicitly .js files found
        js_urls = [u for u in endpoints if u.split('?')[0].endswith(".js")]
        
        if js_urls:
            js_findings = pjs.scan(js_urls)
            for f in js_findings:
                add_result("offensive", f) # JS secrets are offensive/vulnerability findings

def _runner_owasp_nuclei(ctx) -> None:
    mod = _opt_import("scanners.owasp")
    if not mod:
         add_result("offensive", {"type": "OWASP", "severity": "Info", "reason": "Module not found"})
         return
    run_func = getattr(mod, "run_owasp_and_nuclei", None)
    if not callable(run_func):
         add_result("offensive", {"type": "OWASP", "severity": "Info", "reason": "run function not found"})
         return

    url = getattr(ctx, "url", "") or getattr(ctx, "base_url", "")
    session = getattr(ctx, "session", None)
    results = _ensure_results_bucket(ctx)
    cfg = getattr(ctx, "config", {}) or {}
    debug = bool(getattr(ctx, "debug", False))
    auth_ctx = getattr(ctx, "auth_ctx", None)
    
    # Run
    run_func(url, results, session, config=cfg, debug=debug, auth_ctx=auth_ctx)
    add_result("meta", {"stage": "owasp_nuclei", "status": "completed"})



def _runner_rate_limit(ctx) -> None:
    mod = _opt_import("scanners.rate_limit")
    if not mod:
        add_result("offensive", {"type": "Rate Limit", "severity": "Bilgi", "reason": "Modül bulunamadı."})
        return
    
    # Initialize scanner
    base_url = (getattr(ctx, "url", None) or getattr(ctx, "base_url", None) or "")
    sess = getattr(ctx, "session", None)
    
    if hasattr(mod, "RateLimitScanner"):
        scanner = mod.RateLimitScanner(sess, debug=bool(getattr(ctx, "debug", False)))
        scanner.run(base_url)
    elif hasattr(mod, "run"):
        # Functional variant
        mod.run(sess, base_url, getattr(ctx, "results", {}))

def _runner_scanners_graphql(ctx) -> None:
    mod = _opt_import("scanners.graphql")
    if not mod or not hasattr(mod, "GraphQLScanner"):
        return
    base_url = (getattr(ctx, "url", None) or getattr(ctx, "base_url", None) or "")
    sess = getattr(ctx, "session", None)
    scanner = mod.GraphQLScanner(sess, debug=bool(getattr(ctx, "debug", False)))
    # It updates ctx.results internally if it inherits keys
    # But checks return.
    res = scanner.run(base_url)
    _merge_results(ctx, res)

def _runner_scanners_ws_fuzz(ctx) -> None:
    mod = _opt_import("scanners.ws_fuzz")
    if not mod or not hasattr(mod, "run"):
        return
    base_url = (getattr(ctx, "url", None) or getattr(ctx, "base_url", None) or "")
    sess = getattr(ctx, "session", None)
    # run(url, session, debug, auth_ctx) -> List[Dict]
    findings = mod.run(base_url, session=sess, debug=bool(getattr(ctx, "debug", False)), auth_ctx=getattr(ctx, "auth_ctx", None))
    if findings:
        for f in findings:
            add_result("ws_fuzz", f)

def _runner_scanners_tls(ctx) -> None:
    # Use scanners.tls if available
    mod = _opt_import("scanners.tls")
    if not mod or not hasattr(mod, "scan_tls"):
        return
    base_url = (getattr(ctx, "url", None) or getattr(ctx, "base_url", None) or "")
    # scanners.tls.scan_tls(url, results=...)
    mod.scan_tls(base_url, results=getattr(ctx, "results", {}))

# ----------------------------- Plan oluşturucu -----------------------------


# ----------------------------- CSRF Runner (NEW) -----------------------------
def _runner_csrf(ctx) -> None:
    mod = _opt_import("scanners.csrf")
    if not mod:
        add_result("offensive", {"type": "CSRF", "severity": "Info", "reason": "Module not found"})
        return
    
    url = getattr(ctx, "url", "") or getattr(ctx, "base_url", "")
    session = getattr(ctx, "session", None)
    results = _ensure_results_bucket(ctx)
    debug = bool(getattr(ctx, "debug", False))
    
    # Run scan
    if hasattr(mod, "run_scan"):
        # run_scan internally adds findings or info notes
        mod.run_scan(url, session, results, debug=debug)
    elif hasattr(mod, "run"):
         mod.run(url, session=session, results=results, debug=debug)
    else:
        add_result("offensive", {"type": "CSRF", "severity": "Info", "reason": "run_scan/run not found"})


# ----------------------------- Plan Builder End ---------------------------

def _offensive_phases(ctx) -> List[Phase]:
    cfg = getattr(ctx, "config", {}) or {}
    off = cfg.get("offensive", {}) if isinstance(cfg, dict) else {}

    base_enabled = bool(_get(off, "enabled", True))
    # aggressive override: ctx.mode AGGRESSIVE ⇒ always evaluate offensive set
    mode = str(getattr(ctx, "mode", getattr(getattr(ctx, "config", {}), "mode", "")).upper())
    if mode in ("AGGRESSIVE","DEEP"):
        base_enabled = True
    # [Smart Tactics] "Avcı" Modu ve Derinlemesine Analiz
    detected_techs = getattr(ctx, "technologies", []) or []
    
    def _flag(key: str, default: bool = False, tech_trigger: str = None) -> bool:
        """
        Phase etkinleştirme mantığı:
        1. Config'de AÇIK ise -> True
        2. Config'de KAPALI ise -> False (Kullanıcı explicit olarak kapattıysa saygı duy)
        3. Config'de BELİRSİZ ise:
           a. İlgili teknoloji tespit edildiyse -> TRUE (Smart Activation)
           b. Profil Aggressive/Deep ise -> TRUE
           c. Varsayılan (default) -> ...
        """
        
        # 1. Config Check (Explicit)
        user_val = _get(off, f"{key}.enabled")
        if user_val is False:
             return False # Kullanıcı ısrarla kapatmış
        if user_val is True:
             return True # Kullanıcı ısrarla açmış
             
        # 2. Smart Tech Trigger
        if tech_trigger and tech_trigger in detected_techs:
             print(f"[Smart Tactics] '{key}' modülü, '{tech_trigger}' algoritması tespit edildiği için OTOMATİK etkinleştirildi.")
             return True
             
        # 3. Profile/Default Fallback
        return base_enabled and default

    phases: List[Phase] = [
        Phase(id="discovery", title="Keşif", enabled=True, runner=lambda c: _safe(c, lambda: _runner_discovery(c), "discovery"), tags=["crawl","map"]),
        Phase(id="passive_recon", title="Pasif Keşif", enabled=True, runner=lambda c: _safe(c, lambda: _runner_passive_recon(c), "passive_recon"), tags=["passive"]),
        Phase(id="js_analysis", title="JS Dosya & Endpoint Analizi", enabled=True, runner=lambda c: _safe(c, lambda: _runner_js_analysis(c), "js_analysis"), tags=["js","recon","secrets"]),
        Phase(id="ffuf", title="FFUF Content & File Fuzzing", enabled=True, runner=lambda c: _safe(c, lambda: _runner_ffuf(c), "ffuf"), tags=["fuzz","content","files"]),
        Phase(id="feroxbuster", title="Feroxbuster Recursive Discovery", enabled=True, runner=lambda c: _safe(c, lambda: _runner_feroxbuster(c), "feroxbuster"), tags=["fuzz","content"]),
        Phase(id="port_scan", title="Port Taraması", enabled=True, runner=lambda c: _safe(c, lambda: run_portscan(c), "portscan"), tags=["infra","port"]),
        Phase(id="xss", title="XSS Scan (Nuclei/Dalfox)", enabled=_flag("xss", default=True), runner=lambda c: _safe(c, lambda: _runner_xss(c), "xss"), tags=["xss","active"]),
        Phase(id="csrf", title="CSRF Scanner", enabled=_flag("csrf", default=True), runner=lambda c: _safe(c, lambda: _runner_csrf(c), "csrf"), tags=["csrf","active"]),
        Phase(
            id="scanners.ssrf_xxe",
            title="SSRF/XXE",
            enabled=_flag("scanners.ssrf_xxe", default=True), # Deep profilde varsayılan açık olsun
            runner=lambda c: _safe(c, lambda: _runner_scanners_ssrf_xxe(c), "scanners.ssrf_xxe"),
            tags=["active", "oast"],
        ),
        Phase(
            id="scanners.request_smuggling",
            title="HTTP Request Smuggling",
            enabled=_flag("scanners.request_smuggling", default=True),
            runner=lambda c: _safe(c, lambda: _runner_scanners_request_smuggling(c), "scanners.request_smuggling"),
            tags=["active", "http"],
        ),
        Phase(
            id="mass_assignment",
            title="Mass Assignment",
            enabled=_flag("mass_assignment", default=True, tech_trigger="rest_api"),
            runner=lambda c: _safe(c, lambda: _runner_mass_assignment(c), "mass_assignment"),
            tags=["api", "json"],
        ),
        Phase(
            id="nosqli",
            title="NoSQL Injection",
            enabled=_flag("nosqli", default=True, tech_trigger="rest_api"), # API varsa NoSQL riski yüksek
            runner=lambda c: _safe(c, lambda: _runner_nosqli(c), "nosqli"),
            tags=["api", "query"],
        ),
        Phase(
            id="scanners.file_upload",
            title="File Upload Abuse",
            enabled=_flag("scanners.file_upload", default=True),
            runner=lambda c: _safe(c, lambda: _runner_scanners_file_upload(c), "scanners.file_upload"),
            tags=["active", "upload"],
        ),
        Phase(
            id="scanners.graphql",
            title="GraphQL Scanner",
            enabled=_flag("scanners.graphql", default=True, tech_trigger="graphql"),
            runner=lambda c: _safe(c, lambda: _runner_scanners_graphql(c), "scanners.graphql"),
            tags=["active", "graphql"],
        ),
        Phase(
            id="scanners.ws_fuzz",
            title="WebSocket Fuzzer",
            enabled=_flag("scanners.ws_fuzz", default=True, tech_trigger="websocket"),
            runner=lambda c: _safe(c, lambda: _runner_scanners_ws_fuzz(c), "scanners.ws_fuzz"),
            tags=["active", "websocket"],
        ),
        Phase(
            id="scanners.tls",
            title="TLS/SSL Analysis",
            enabled=_flag("scanners.tls", default=True),
            runner=lambda c: _safe(c, lambda: _runner_scanners_tls(c), "scanners.tls"),
            tags=["ssl", "config"],
        ),
        Phase(
            id="sqlmap",
            title="SQLMap Scan",
            enabled=_flag("sqlmap", default=True),
            runner=lambda c: _safe(c, lambda: _runner_sqlmap(c), "sqlmap"),
            tags=["sqli", "active"],
        ),
        Phase(
            id="jwt",
            title="JWT Manipülasyonları",
            enabled=_flag("jwt", default=True, tech_trigger="rest_api"),
            runner=lambda c: _safe(c, lambda: _runner_jwt(c), "jwt"),
            tags=["auth", "token"],
        ),
        Phase(id="races", title="Race/Concurrency", enabled=_flag("races", default=True), runner=lambda c: _safe(c, lambda: _runner_business_logic_races(c), "races"), tags=["race","concurrency"]),
        Phase(
            id="scanners.graphql_attacks",
            title="GraphQL Saldırı Seti",
            enabled=_flag("graphql_attacks", default=True, tech_trigger="graphql"),
            runner=lambda c: _safe(c, lambda: _runner_graphql(c), "scanners.graphql_attacks"),
            tags=["graphql", "api"],
        ),
        Phase(
            id="scanners.rate_limit",
            title="Rate Limit & Throttling",
            enabled=_flag("rate_limit", default=True),
            runner=lambda c: _safe(c, lambda: _runner_rate_limit(c), "scanners.rate_limit"),
            tags=["infra", "dos"],
        ),
        Phase(
            id="owasp_and_nuclei",
            title="OWASP & Nuclei",
            enabled=_flag("owasp_nuclei", default=True),
            runner=lambda c: _safe(c, lambda: _runner_owasp_nuclei(c), "owasp_and_nuclei"),
            tags=["active", "signatures"],
        ),
        Phase(id="verify_and_score", title="Doğrulama & Skorlama", enabled=True, runner=lambda c: _safe(c, lambda: _runner_verify_and_score(c), "verify_and_score"), tags=["verify","score"]),
        Phase(id="reporting", title="Raporlama", enabled=True, runner=lambda c: _safe(c, lambda: _runner_reporting_and_integration(c), "reporting"), tags=["report"])
    ]

    # Görünürlüklerini koru; devre dışı olanlar için reason ekle
    for ph in phases:
        if not ph.enabled and not ph.reason:
            ph.reason = "config.offensive.{}.enabled = false".format(
                ph.id if ph.id != "scanners.graphql_attacks" else "graphql_attacks"
            )
    return phases

def build_plan(ctx) -> List[Dict[str, Any]]:
    """
    Tüm planı döndürür. Mevcut (varsa) `ctx.base_plan` üzerinden genişletme yapar.
    Eğer ctx.base_plan yoksa yalnızca `offensive` fazları döndürür.
    Dönen yapı sade dict'lere dönüştürülür; runner callables korunur.
    """
    base: List[Phase] = []
    existing = getattr(ctx, "base_plan", None)
    if isinstance(existing, list):
    # Plan: discovery → headers → tls → offensive → finalize
        for item in existing:
            if isinstance(item, Phase):
                base.append(item)
            elif isinstance(item, dict):
                base.append(Phase(
                    id=item.get("id") or item.get("name") or "phase",
                    title=item.get("title") or item.get("name") or item.get("id") or "Phase",
                    enabled=bool(item.get("enabled", True)),
                    reason=item.get("reason"),
                    runner=item.get("runner"),
                    tags=list(item.get("tags", [])),
                    visible=bool(item.get("visible", True))
                ))

    out: List[Dict[str, Any]] = []
    for ph in base + _offensive_phases(ctx):
        out.append({
            "id": ph.id,
            "title": ph.title,
            "enabled": ph.enabled,
            "reason": ph.reason,
            "visible": ph.visible,
            "tags": ph.tags,
            "runner": ph.runner,
        })
        # Akış düzeltmesi: raporlama fazı plan dışı tutulur; final rapor flush_reporting ile yapılır.
    out = [p for p in out if str(p.get('id') or '').lower() not in ('report','reporting') and 'report' not in (p.get('tags') or [])]
    return out

def plan_visible(plan: Dict) -> Dict:
    out = {"visible": []}
    for name, entry in (plan or {}).items():
        if isinstance(entry, dict) and entry.get("enabled"):
            out["visible"].append({
                "id": entry.get("id") or name,
                "title": entry.get("title") or name,
                "enabled": True
            })
    return out

def _runner_verify_and_score(ctx) -> None:
    fm = _opt_import("websecure.core.flow_runner") or _opt_import("flow_runner")
    if not fm:
        add_result("meta", {"stage": "verify_and_score", "status": "skipped:no-flow-runner"})
        _phase_rec(get_results() if callable(globals().get('get_results')) else {}, 'flow', 'skipped', 'return')

        return
    fn = getattr(fm, "run_verify_and_score", None)
    if not callable(fn):
        add_result("meta", {"stage": "verify_and_score", "status": "skipped:no-function"})
        _phase_rec(get_results() if callable(globals().get('get_results')) else {}, 'flow', 'skipped', 'return')

        return
    fn(ctx)

def _mk_result(name, status, metrics=None, errors=None):
    return {
        "name": name,
        "status": status,
        "started_at": None,
        "ended_at": None,
        "metrics": metrics or {},
        "errors": errors or [],
    }


def run_discovery(ctx):

    url = getattr(ctx, "base_url", None) or getattr(ctx, "url", None)

    if not isinstance(getattr(ctx, "results", None), dict):
        setattr(ctx, "results", {})
    results = ctx.results  # type: ignore[attr-defined]

    if url:
        from websecure.crawler import WebCrawler
        try:
            _wc = WebCrawler(getattr(ctx, "session", None), url, debug=bool(getattr(ctx, "debug", False)))
            _res = _wc.start()
            if isinstance(_res, dict):
                results.update(_res)
        except Exception as e:
            add_result("errors", {"stage": "discovery_fallback", "error": str(e)})

    # --- Smart Tactics Analysis ---
    if isinstance(results, dict):
        techs = set()
        endpoints = results.get("endpoints", []) or []
        
        # GraphQL Detection
        if any("graphql" in u or "gql" in u for u in endpoints):
            techs.add("graphql")
        
        # API Detection (REST/JSON)
        if any("/api/" in u for u in endpoints) or any(u.endswith(".json") for u in endpoints):
            techs.add("rest_api")
        
        # CMS / Framework
        if any("wp-content" in u or "wp-json" in u for u in endpoints):
            techs.add("wordpress")
            
        # Store in context for build_plan
        ctx.technologies = list(techs)
        if techs:
             add_result("meta", {"stage": "smart_analysis", "detected_technologies": list(techs)})
             print(f"[Smart Tactics] Algılanan Teknolojiler: {', '.join(techs)}")

    eps = len((results.get("endpoints") or [])) if isinstance(results, dict) else 0
    add_result("phase_event", {"phase": "discovery", "checked": eps})
    return _mk_result("discovery", "ok", {"endpoints": eps})


def run_portscan(ctx):
    """Port taraması: Nmap entegrasyonu (Native scanner silindi)."""
    from websecure.integrations.nmap import NmapWrapper
    
    url = getattr(ctx, "base_url", None) or getattr(ctx, "url", None)
    results = getattr(ctx, "results", None) or {}
    debug = bool(getattr(ctx, "debug", False))
    
    if not url:
        return _mk_result("portscan", "failed", {"error": "no_url"})
        
    try:
        # Host adını ayıkla
        if "://" in url:
            from urllib.parse import urlparse
            host = urlparse(url).hostname or url
        else:
            host = url.split(":")[0]

        nmap = NmapWrapper()
        if not nmap.is_available():
            add_result("errors", {"stage": "portscan", "error": "Nmap binary not found. Please install Nmap."})
            return _mk_result("portscan", "failed", {"error": "nmap_missing"})

        # Hızlı tarama
        scan_res = nmap.scan(host, ports="-F")
        
        # Sonuçları işle
        port_records = []
        open_ports = []
        for item in scan_res:
             p = item.get("port")
             if p:
                 open_ports.append(p)
                 port_records.append({
                     "host": item.get("ip") or host,
                     "port": p,
                     "proto": item.get("protocol", "tcp"),
                     "state": "open",
                     "service": item.get("service", "unknown"),
                     "product": item.get("product", ""),
                     "version": item.get("version", "")
                 })
                 
        # Merkezi sonuçlara ekle (reporting uyumluluğu için)
        results["port_scan"] = port_records 
        results["nmap"] = port_records      
        results["open_ports"] = open_ports
        
        return _mk_result("portscan", "ok", {"scanned": "Nmap Fast", "open": len(open_ports)})
    except Exception as e:
        return _mk_result("portscan", "failed", {"error": str(e)})


def run_tls(ctx):
    """TLS taraması: scan_tls_quick(url|[url])"""
    from websecure.scanners.tls import scan_tls_quick as _scan_tls_quick
    url = getattr(ctx, "base_url", None) or getattr(ctx, "url", None)
    if not url:
        return _mk_result("tls", "skipped:no-url")
    _scan_tls_quick(url)
    return _mk_result("tls", "ok")


def run_security_headers(ctx):
    """Güvenlik başlıkları: scan(session, endpoints, results, debug=False, config=None)"""
    from websecure.scanners.headers import scan as _scan_headers
    session = getattr(ctx, "session", None)
    url = getattr(ctx, "base_url", None) or getattr(ctx, "url", None)
    if not url:
        return _mk_result("security_headers", "skipped:no-url")
    results = getattr(ctx, "results", None) or {}
    endpoints = [url]
    _scan_headers(session, endpoints, results, debug=False, config=getattr(ctx, "config", None))
    return _mk_result("security_headers", "ok")


def run_offensive(ctx):
    """Offensive umbrella: discovery çıktısını tüm modüllere geçir.
    Boşsa bile modüller 'checked_none' kanıtı üretmeli.
    """
    results = getattr(ctx, "results", {}) or {}
    endpoints = list(dict.fromkeys((results.get("endpoints") or [])))
    ep_kw = {"endpoints": endpoints} if endpoints else {"endpoints": []}

    metrics = {}

    if endpoints:
        add_result("offensive", {"type": "discovery_feed", "count": len(endpoints)})
    else:
        add_result("offensive", {"type": "discovery_feed", "count": 0, "note": "checked_none"})

    # Consolidated Offensive Phase
    from websecure.scanners.jwt import JWTScanner
    from websecure.scanners.graphql import GraphQLScanner
    from websecure.scanners.ssrf_xxe import SSRFScanner
    
    url = getattr(ctx, "base_url", None) or getattr(ctx, "url", None)
    if not url:
        return _mk_result("offensive", "skipped:no-url")

    # Run JWT
    jwt_s = JWTScanner(ctx.session, getattr(ctx, "results", None))
    jwt_s.run(url) 
    metrics["jwt"] = 1

    # Run GraphQL
    gql_s = GraphQLScanner(ctx.session, getattr(ctx, "results", None))
    gql_s.run(url)
    metrics["graphql"] = 1

    # Run SSRF
    # SSRFScanner expects endpoints in init and run() takes no args
    ssrf_s = SSRFScanner(ctx.session, [url])
    # Manually inject results dict because SSRFScanner creates its own if not passed (and it doesn't take it in init)
    if getattr(ctx, "results", None) is not None:
        ssrf_s.results = ctx.results
    ssrf_s.run()
    metrics["ssrf"] = 1

    return _mk_result("offensive", "ok", metrics)
def run_finalize(ctx):
    # Final aggregation/report generation, if any
    return _mk_result("finalize", "ok")


def run_port_scan_basic(ctx, *, event_cb=None):
    # Native scanner removed
    pass


def run_security_headers_basic(ctx, *, event_cb=None):
    from websecure.scanners.headers import scan as _scan_headers
    from websecure.core.reporting import add_result
    sess = getattr(ctx, "session", None)
    base_url = getattr(ctx, "base_url", None)
    results = getattr(ctx, "results", {})
    _scan_headers(sess, base_url, results, debug=bool(getattr(ctx, "debug", False)))
    add_result("headers_checked", {"base_url": base_url})
    return results.get("headers", {})


def run_tls_basic(ctx, *, event_cb=None):
    from websecure.scanners.tls import scan_tls as _scan_tls
    from websecure.core.reporting import add_result

    base_url = getattr(ctx, "base_url", None) or ""
    results = getattr(ctx, "results", {}) or {}
    session = getattr(ctx, "session", None)
    config = getattr(ctx, "config", {}) or {}

    _scan_tls(
        base_url,
        results=results,
        session=session,
        config=config,
        debug=bool(getattr(ctx, "debug", False)),
    )
    add_result("tls_checked", {"base_url": base_url})
    return results.get("tls", {})

def run_plan_if_needed(ctx: dict):
    """
    Executes the unified scan plan if not already executed.
    Orchestrates discovery, portscan, tls, offensive phases based on config.
    """
    # Simple guard: if we have significant results, maybe we already ran? 
    # But for now, we just enforce running the plan constructed by build_plan.
    
    plan = build_plan(ctx)
    if not plan:
        add_result("meta", {"stage": "plan", "status": "empty_plan"})
        return

    _logger.info(f"[Phases] Executing plan with {len(plan)} steps.")
    
    results = _ensure_results_bucket(ctx)
    # Mark start
    results.setdefault("meta", {})["scan_start"] = _t.time()

    for item in plan:
        pid = item.get("id")
        runner = item.get("runner")
        enabled = item.get("enabled", False)
        
        if enabled and callable(runner):
            if item.get("visible", True):
                print(f"[•] Faz: {item.get('title', pid)}")
            
            # Run safely
            start_t = _t.time()
            try:
                runner(ctx)
            except Exception as e:
                _logger.error(f"Phase {pid} failed: {e}", exc_info=True)
                add_result("errors", {"phase": pid, "error": str(e)})
            finally:
                dur = _t.time() - start_t
                _d = ctx.get("debug") if isinstance(ctx, dict) else getattr(ctx, "debug", False)
                if _d:
                    print(f"    -> {pid} finished in {dur:.2f}s")
        else:
            _d = ctx.get("debug") if isinstance(ctx, dict) else getattr(ctx, "debug", False)
            if _d:
                _logger.debug(f"Skipping phase {pid} (enabled={enabled})")

    results["meta"]["scan_end"] = _t.time()
