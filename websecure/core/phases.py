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
from websecure.scanners import request_smuggling as _rs
from websecure.scanners import mass_assignment as _ma
from websecure.scanners import jwt as _jwt
from websecure.scanners import nosqli as _nq
from websecure.scanners import ws_fuzz as _ws
from websecure.scanners import ssrf_xxe as _sx
from websecure.scanners import graphql_attacks as _gqa
from websecure.scanners import graphql_rpc as _gqr
from websecure.scanners import file_upload as _fu
from websecure.crawler import WebCrawler
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
    elif _iul.find_spec('core.reporting') is not None:
        _rmod = importlib.import_module('core.reporting')
    if _rmod is not None and hasattr(_rmod, 'add_result'):
        _rmod.add_result(
            type="phase_error",
            severity="error",
            message=str(_err),
            meta={
                "phase": _phase,
                "where": _where,
                "exc_type": _err.__class__.__name__,
            },
        )



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

def phase_portscan(ctx: dict):
    if not (ctx.get("config",{}).get("portscan",{}).get("enabled", True)):
        add_result("portscan", {"severity":"note","message":"portscan disabled"})
        return
    from websecure.core.utils.ports import tcp_connect_scan
    host = ctx.get("host") or ""
    ports = ctx.get("config",{}).get("portscan",{}).get("ports") or [80,443,8080,8443]
    results = tcp_connect_scan(host, ports)
    for p, is_open in results.items():
        if is_open:
            add_result("open_port", {"severity":"info","message":f"Open port: {p}","port":p})
    if not any(results.values()):
        add_result("portscan", {"severity":"note","message":"No open ports from list."})

def phase_tls(ctx: dict):
    # Optional: if scanners.tls exists, call it; otherwise noop
    if not _call_if_exists("websecure.scanners.tls", ("run","scan")):
        add_result("tls", {"severity":"note","message":"tls scanner not present; skipped"})

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
        "websecure.scanners.graphql_attacks",
        "websecure.scanners.graphql_rpc",
    ]
    hit = 0
    for m in mods:
        if _call_if_exists(m, ("run","scan","main","execute")):
            hit += 1
    if not hit:
        add_result("offensive", {"severity":"note","message":"no offensive modules found"})


_reporting_mod = None
if _iul.find_spec("core.reporting") is not None:
    _reporting_mod = importlib.import_module("core.reporting")
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
        if _iul.find_spec("core.reporting") is not None:
            import importlib as _im
            mod = _im.import_module("core.reporting")
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
            fulls.extend((f'websecure.core.{module}', f'core.{module}', module))
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
    fm = _opt_import("core.flow_runner") or _opt_import("flow_runner")
    if not fm or not hasattr(fm, "run_discovery_extended") or not callable(getattr(fm, "run_discovery_extended")):
        add_result("meta", {"stage": "discovery", "status": "skipped:no-flow-runner"}); _phase_rec(get_results() if callable(globals().get('get_results')) else {}, 'flow', 'skipped', 'return'); return
    fm.run_discovery_extended(ctx)

def _runner_fuzz_and_param_discovery(ctx) -> None:
    fm = _opt_import("core.flow_runner") or _opt_import("flow_runner")
    if not fm or not hasattr(fm, "run_fuzz_and_param_discovery") or not callable(getattr(fm, "run_fuzz_and_param_discovery")):
        add_result("meta", {"stage": "fuzz_param_discovery", "status": "skipped:no-flow-runner"}); _phase_rec(get_results() if callable(globals().get('get_results')) else {}, 'flow', 'skipped', 'return'); return
    fm.run_fuzz_and_param_discovery(ctx)

def _runner_oast_verification(ctx) -> None:
    fm = _opt_import("core.flow_runner") or _opt_import("flow_runner")
    if not fm or not hasattr(fm, "run_oast_verification") or not callable(getattr(fm, "run_oast_verification")):
        add_result("meta", {"stage": "oast", "status": "skipped:no-flow-runner"}); _phase_rec(get_results() if callable(globals().get('get_results')) else {}, 'flow', 'skipped', 'return'); return
    fm.run_oast_verification(ctx)

def _runner_reporting_and_integration(ctx) -> None:
    fm = _opt_import("core.flow_runner") or _opt_import("flow_runner")
    if not fm or not hasattr(fm, "run_reporting_and_integration") or not callable(getattr(fm, "run_reporting_and_integration")):
        add_result("meta", {"stage": "reporting", "status": "skipped:no-flow-runner"}); _phase_rec(get_results() if callable(globals().get('get_results')) else {}, 'flow', 'skipped', 'return'); return
    fm.run_reporting_and_integration(ctx)

def _runner_authorization_matrix(ctx) -> None:
    fm = _opt_import("core.flow_runner") or _opt_import("flow_runner")
    if not fm or not hasattr(fm, "run_authorization_matrix") or not callable(getattr(fm, "run_authorization_matrix")):
        add_result("meta", {"stage": "authorization", "status": "skipped:no-flow-runner"}); _phase_rec(get_results() if callable(globals().get('get_results')) else {}, 'flow', 'skipped', 'return'); return
    fm.run_authorization_matrix(ctx)



def _runner_business_logic_races(ctx) -> None:
    fm = _opt_import("core.flow_runner") or _opt_import("flow_runner")
    if not fm or not hasattr(fm, "run_business_logic_races") or not callable(getattr(fm, "run_business_logic_races")):
        add_result("meta", {"stage": "races", "status": "skipped:no-function"}); _phase_rec(get_results() if callable(globals().get('get_results')) else {}, 'flow', 'skipped', 'return')
        return
    fm.run_business_logic_races(ctx)
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
    if not mod:
        add_result("offensive", {"type": "JWT", "severity": "Bilgi", "reason": "Modül bulunamadı."})
        _phase_rec(get_results() if callable(globals().get('get_results')) else {}, 'flow', 'skipped', 'return')

        return
    base_url = getattr(ctx, "url", "")
    sess = getattr(ctx, "session", None)
    timeout = float(_get(getattr(ctx, "config", {}) or {}, "timeouts.jwt", 8.0))
    endpoints = (_get(getattr(ctx, "config", {}) or {}, "jwt.endpoints", None)
                 or _get(getattr(ctx, "config", {}) or {}, "discovery.jwt", None)
                 or ["/api/me", "/me"])
    secrets = (_get(getattr(ctx, "config", {}) or {}, "jwt.weak_secrets", None)
               or _get(getattr(ctx, "config", {}) or {}, "offensive.jwt_attacks.wordlist", None))

    if hasattr(mod, "probe_alg_none") and callable(getattr(mod, "probe_alg_none")):
        for r in mod.probe_alg_none(sess, base_url, endpoints, timeout):
            add_result("offensive", {
                "type": "JWT alg=none",
                "severity": getattr(r, "severity", "Bilgi"),
                "url": getattr(r, "url", base_url),
                "reason": getattr(r, "detail", None),
                "proof": redact_sensitive(getattr(r, "proof", {}))
            })

    if hasattr(mod, "probe_hs256_wordlist") and callable(getattr(mod, "probe_hs256_wordlist")):
        wl = secrets or getattr(mod, "DEFAULT_WEAK_SECRETS", [])
        for r in mod.probe_hs256_wordlist(sess, base_url, endpoints, wl, timeout, stop_on_first=True):
            add_result("offensive", {
                "type": "JWT HS256 zayıf sırrı",
                "severity": getattr(r, "severity", "Bilgi"),
                "url": getattr(r, "url", base_url),
                "reason": getattr(r, "detail", None),
                "proof": redact_sensitive(getattr(r, "proof", {}))
            })

    if hasattr(mod, "probe_rs_to_hs_confusion") and callable(getattr(mod, "probe_rs_to_hs_confusion")):
        jwks_extra = _get(getattr(ctx, "config", {}) or {}, "jwt.jwks_paths", [])
        for r in mod.probe_rs_to_hs_confusion(sess, base_url, endpoints, timeout, jwks_extra, stop_on_first=True):
            add_result("offensive", {
                "type": "JWT RS→HS alg confusion",
                "severity": getattr(r, "severity", "Bilgi"),
                "url": getattr(r, "url", base_url),
                "reason": getattr(r, "detail", None),
                "proof": redact_sensitive(getattr(r, "proof", {}))
            })

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
    if not att_mod:
        add_result("offensive", {"type": "GraphQL", "severity": "Bilgi", "reason": "Modüller bulunamadı."})
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
        client = getattr(att_mod, "GraphQLClient")(getattr(ctx, "session", None),
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

# ----------------------------- Plan oluşturucu -----------------------------

def _offensive_phases(ctx) -> List[Phase]:
    cfg = getattr(ctx, "config", {}) or {}
    off = cfg.get("offensive", {}) if isinstance(cfg, dict) else {}

    base_enabled = bool(_get(off, "enabled", True))
    # aggressive override: ctx.mode AGGRESSIVE ⇒ always evaluate offensive set
    mode = str(getattr(ctx, "mode", getattr(getattr(ctx, "config", {}), "mode", "")).upper())
    if mode in ("AGGRESSIVE","DEEP"):
        base_enabled = True
    def _flag(key: str, default: bool = False) -> bool:
        # Fazlar yalnızca offensive.enabled=true ise değerlendirilir
        return base_enabled and bool(_get(off, f"{key}.enabled", default))

    phases: List[Phase] = [
        Phase(id="discovery", title="Keşif", enabled=True, runner=lambda c: _safe(c, lambda: _runner_discovery(c), "discovery"), tags=["crawl","map"]),
        Phase(id="fuzz_param_discovery", title="Parametre Keşfi & Fuzz", enabled=True, runner=lambda c: _safe(c, lambda: _runner_fuzz_and_param_discovery(c), "fuzz_param_discovery"), tags=["fuzz","inputs"]),
        Phase(
            id="scanners.ssrf_xxe",
            title="SSRF/XXE",
            enabled=_flag("scanners.ssrf_xxe"),
            runner=lambda c: _safe(c, lambda: _runner_scanners_ssrf_xxe(c), "scanners.ssrf_xxe"),
            tags=["active", "oast"],
        ),
        Phase(
            id="scanners.request_smuggling",
            title="HTTP Request Smuggling",
            enabled=_flag("scanners.request_smuggling", True),
            runner=lambda c: _safe(c, lambda: _runner_scanners_request_smuggling(c), "scanners.request_smuggling"),
            tags=["active", "http"],
        ),
        Phase(
            id="mass_assignment",
            title="Mass Assignment",
            enabled=_flag("mass_assignment", True),
            runner=lambda c: _safe(c, lambda: _runner_mass_assignment(c), "mass_assignment"),
            tags=["api", "json"],
        ),
        Phase(
            id="nosqli",
            title="NoSQL Injection",
            enabled=_flag("nosqli"),
            runner=lambda c: _safe(c, lambda: _runner_nosqli(c), "nosqli"),
            tags=["api", "query"],
        ),
        Phase(
            id="scanners.file_upload",
            title="File Upload Abuse",
            enabled=_flag("scanners.file_upload"),
            runner=lambda c: _safe(c, lambda: _runner_scanners_file_upload(c), "scanners.file_upload"),
            tags=["upload", "ct"],
        ),
        Phase(
            id="jwt",
            title="JWT Manipülasyonları",
            enabled=_flag("jwt", True),
            runner=lambda c: _safe(c, lambda: _runner_jwt(c), "jwt"),
            tags=["auth", "token"],
        ),
        Phase(
            id="scanners.ws_fuzz",
            title="WebSocket Fuzz",
            enabled=_flag("scanners.ws_fuzz", True),
            runner=lambda c: _safe(c, lambda: _runner_scanners_ws_fuzz(c), "scanners.ws_fuzz"),
            tags=["ws", "realtime"],
        ),
        Phase(id="races", title="Race/Concurrency", enabled=_flag("races", True), runner=lambda c: _safe(c, lambda: _runner_business_logic_races(c), "races"), tags=["race","concurrency"]),
        Phase(
            id="scanners.graphql_attacks",
            title="GraphQL Saldırı Seti",
            enabled=_flag("graphql_attacks", True),
            runner=lambda c: _safe(c, lambda: _runner_graphql(c), "scanners.graphql_attacks"),
            tags=["graphql", "api"],
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
    fm = _opt_import("core.flow_runner") or _opt_import("flow_runner")
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

    eps = len((results.get("endpoints") or [])) if isinstance(results, dict) else 0
    add_result("phase_event", {"phase": "discovery", "checked": eps})
    return _mk_result("discovery", "ok", {"endpoints": eps})


def run_portscan(ctx):
    """Port taraması: Native scanner geri getirildi."""
    from websecure.core.utils.ports import scan_ports
    
    url = getattr(ctx, "base_url", None) or getattr(ctx, "url", None)
    results = getattr(ctx, "results", None) or {}
    cfg = getattr(ctx, "config", {}) or {}
    debug = bool(getattr(ctx, "debug", False))
    
    if not url:
        return _mk_result("portscan", "failed", {"error": "no_url"})
        
    try:
        # Use simple TCP connect scan
        open_ports = scan_ports(url, results, detailed=False, debug=debug)
        return _mk_result("portscan", "ok", {"scanned": "common", "open": len(open_ports)})
    except Exception as e:
        return _mk_result("portscan", "failed", {"error": str(e)})


def run_tls(ctx):
    """TLS taraması: scan_tls_quick(url|[url])"""
    from websecure.scanners.tls import scan_tls_quick as _scan_tls_quick
    url = getattr(ctx, "base_url", None)
    _scan_tls_quick(url)
    return _mk_result("tls", "ok")


def run_security_headers(ctx):
    """Güvenlik başlıkları: scan(session, endpoints, results, debug=False, config=None)"""
    from websecure.scanners.headers import scan as _scan_headers
    session = getattr(ctx, "session", None)
    url = getattr(ctx, "base_url", None)
    results = getattr(ctx, "results", None) or {}
    endpoints = [url] if url else []
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
    # Note: We now assume scanners are more autonomous or we use valid logic
    from websecure.scanners.jwt import JWTScanner
    from websecure.scanners.graphql import GraphQLScanner
    from websecure.scanners.ssrf_xxe import SSRFScanner
    # Other legacy scanners (_ma, _nq etc.) left as is if they exist, or removed if deleted.
    # Assuming _ws_fuzz etc are still there.
    
    # Run JWT
    jwt_s = JWTScanner(ctx.session, ctx.base_url)
    jwt_s.run(ctx.base_url) 
    metrics["jwt"] = 1

    # Run GraphQL
    # Try discovery on base_url
    gql_s = GraphQLScanner(ctx.session)
    gql_s.run(ctx.base_url)
    metrics["graphql"] = 1

    # Run SSRF
    ssrf_s = SSRFScanner(ctx.session)
    ssrf_s.run(ctx.base_url)
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
