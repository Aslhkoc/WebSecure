from __future__ import annotations
import asyncio
import importlib
import importlib.util as _iul
import json
import logging
import shutil
import socket
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import urlparse
from websecure.core.http import (
    set_active_phase,
    install_http_phase_policies,
    phase_begin,
    phase_end,
    get_http_metrics,
)
import websecure.core.reporting as _rep
import importlib
import importlib.util as _iul
import inspect
from websecure.core.reporting import add_result
from websecure.core.fuzzer import verify_oast_findings, verify_findings_and_score
from websecure.core.reporting import add_result, get_results, flush, _phase_rec
from websecure.fuzzing.verifier import verify_findings  # kept for downstream use
import time, importlib
from typing import Callable, List, Tuple, Dict, Any
from .http import set_phase
from .reporting import add_result
import importlib, importlib.util as _ws_imp_util
import socket, ssl, json, importlib, importlib.util as _iul  # noqa: E401
import logging as _logging  # noqa: E401
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
# --- end auto-injected header ---


def _ws_import_any(*names: str):
    """
    Belirtilen modül adlarını sırayla dener ve ilkini import eder.
    Sadece bu yardımcı içinde find_spec kullanılır (1.2 gereği).
    Çalışma sırasında modül çevirmez; deterministik ve tek-yön.
    """
    for n in names:
        if not isinstance(n, str) or not n.strip():
            continue
        try:
            if _ws_imp_util.find_spec(n) is not None:
                return importlib.import_module(n)
        except _BOUNDARY_EXC as e:
            _logger.error('phase error [flow]', exc_info=True)
            _report_phase_error('flow', 'flow_runner.py', e)
            continue
    return None

def _ws_import_attr(names, attr: str, default=None):
    m = _ws_import_any(*names) if isinstance(names, (list, tuple)) else _ws_import_any(names)
    if m is None:
        return default
    return getattr(m, attr, default)

def _ws_spec(name: str):
    try:
        return _ws_imp_util.find_spec(name)
    except _BOUNDARY_EXC as e:
        _logger.error('phase error [flow]', exc_info=True)
        _report_phase_error('flow', 'flow_runner.py', e)
        return None

def _ws_has(*names: str) -> bool:
    return _ws_import_any(*names) is not None
# === /Deterministik import yardımcıları ===


# === Pre-flight probe & WAF/403 guard ===
def _ensure_shared(ctx):
    if not hasattr(ctx, 'shared') or not isinstance(getattr(ctx, 'shared', None), dict):
        try:
            setattr(ctx, 'shared', {})
        except Exception:
            return {}
    return ctx.shared

def is_blocked(ctx) -> bool:
    sh = getattr(ctx, 'shared', {}) or {}
    return bool(sh.get('blocked_403') or sh.get('blocked_rl') or sh.get('degraded_mode'))

def preflight_probe(ctx) -> None:
    cfg = getattr(ctx, 'config', {}) or {}
    url = getattr(ctx, 'url', None) or cfg.get('base_url') or cfg.get('target') or ''
    if not url:
        return
    sess = getattr(ctx, 'session', None)
    if sess is None:
        try:
            from websecure.core.http import hardened_session
            sess = hardened_session(cfg)
            ctx.session = sess
        except Exception:
            return
    try:
        r = sess.get(url, timeout=10, allow_redirects=True)
        code = getattr(r, 'status_code', 0)
        if code in (403, 429):
            sh = _ensure_shared(ctx)
            if code == 403:
                sh['blocked_403'] = True
                add_result('anti_block_event', {'type':'preflight','status':code,'note':'Forbidden at entry'})
            else:
                sh['blocked_rl'] = True
                add_result('anti_block_event', {'type':'preflight','status':code,'note':'Rate limit at entry'})
            # degrade profile & slow down
            try:
                _degrade_scan_mode(ctx)
                _apply_http_rps(ctx, 0.5)
            except Exception:
                pass
    except _BOUNDARY_EXC as e:
        _logger.error('preflight probe failed', exc_info=True)
        _report_phase_error('flow', 'preflight_probe', e)


log = logging.getLogger(__name__)

Phase = Tuple[str, Callable[[dict], None]]

def _import_optional(modname: str):
    try:
        return importlib.import_module(modname)
    except _BOUNDARY_EXC as e:
        _logger.error('phase error [flow]', exc_info=True)
        _report_phase_error('flow', 'flow_runner.py', e)
        return None

def _results_count() -> int:
    try:
        from websecure.core.reporting import get_results
        res = get_results()
        return sum(len(v) for v in res.values()) if isinstance(res, dict) else 0
    except Exception:
        return 0


def _normalize_phases(phases_obj):
    """Accept many shapes and return a clean list[(name, fn)].
    Supports:
    - list[dict] with keys ('id' or 'name') and 'runner'
    - dict[name] -> fn
    - list/iterable of (name, fn) or (name, fn, *rest)
    - list of single callables -> (callable.__name__ or 'phase', callable)
    - generators
    """
    out = []
    if phases_obj is None:
        return out

    # dict: name -> fn or name -> {runner: fn}
    if isinstance(phases_obj, dict):
        for k, v in phases_obj.items():
            if callable(v):
                out.append((str(k), v))
            elif isinstance(v, dict) and callable(v.get('runner')):
                out.append((str(v.get('id') or k), v['runner']))
        return out

    # list/iterable
    try:
        iterator = iter(phases_obj)
    except TypeError:
        return out

    for item in iterator:
        # direct callable
        if callable(item):
            out.append((getattr(item, '__name__', 'phase'), item))
            continue
        # dict item with runner
        if isinstance(item, dict):
            name = str(item.get('id') or item.get('name') or 'phase')
            fn = item.get('runner')
            if callable(fn):
                out.append((name, fn))
            continue
        # tuple/list item
        if isinstance(item, (tuple, list)):
            if len(item) >= 2 and isinstance(item[0], str) and callable(item[1]):
                out.append((item[0], item[1]))
                continue
            if len(item) == 1 and callable(item[0]):
                out.append((getattr(item[0], '__name__', 'phase'), item[0]))
                continue
        # else: skip silently
    return out


def run(ctx: dict, phases: List[Phase]) -> dict:
    # robust: ctx can be a mapping-like or an object (e.g., ScanContext)
    def _ctx_list(_ctx, key: str):
        if isinstance(_ctx, dict):
            return _ctx.setdefault(key, [])
        val = getattr(_ctx, key, None)
        if val is None:
            val = []
            try:
                setattr(_ctx, key, val)
            except _BOUNDARY_EXC as e:
                _logger.error('phase error [flow]', exc_info=True)
                _report_phase_error('flow', 'flow_runner.py', e)
                # last resort: ignore
                val = []
        return val

    def _ctx_dict(_ctx, key: str):
        if isinstance(_ctx, dict):
            return _ctx.setdefault(key, {})
        val = getattr(_ctx, key, None)
        if not isinstance(val, dict):
            val = {}
            try:
                setattr(_ctx, key, val)
            except _BOUNDARY_EXC as e:
                _logger.error('phase error [flow]', exc_info=True)
                _report_phase_error('flow', 'flow_runner.py', e)
                val = {}
        return val

    # Normalize phases into [(name, fn)] shape
    phases = _normalize_phases(phases)


    phases_list = _ctx_list(ctx, "phases")
    _ = _ctx_dict(ctx, "metrics")

    for name, fn in phases:
        t0 = time.time()
        set_phase(name)
        phase_rec = {"name": name, "status": "start", "t_start": t0}
        phases_list.append(phase_rec)
        try:
            fn(ctx)
            phase_rec["status"] = "done"
        except _BOUNDARY_EXC as e:
            _logger.error('phase error [flow]', exc_info=True)
            _report_phase_error('flow', 'flow_runner.py', e)
            phase_rec["status"] = "error"
            phase_rec["error"] = str(e)
            # log to reporting bucket in a backward-compatible way
            try:
                add_result('errors', {"stage": "phase", "phase": name, "severity": "warning", "message": f"{name}: {e}", "exception": e.__class__.__name__})
            except _BOUNDARY_EXC as e:
                _logger.error('phase error [flow]', exc_info=True)
                _report_phase_error('flow', 'flow_runner.py', e)
                raise

        finally:
            phase_rec["t_end"] = time.time()
            phase_rec["elapsed"] = phase_rec["t_end"] - t0
        # Attach metrics snapshot
        try:
            from websecure.core.http import get_http_metrics
            ms = get_http_metrics()
            if isinstance(ctx, dict):
                ctx['metrics'] = ms
            add_result('metrics_snapshot', ms)
        except Exception:
            pass

    return ctx

# END:### WEBSECURE FLOW FIX PACK





# ================================================================
# Seed / Checkpoint helpers (no try/except; callers handle failures)
# ================================================================
def _apply_seed(cfg: Dict[str, Any]) -> None:
    """Apply deterministic seed when provided in config.settings.seed or config.seed."""
    import random

    settings = cfg.get('settings') or {}
    seed = settings.get('seed', cfg.get('seed'))
    if seed is None:
        return
    random.seed(int(seed))


def _checkpoint_path(cfg: Dict[str, Any]) -> Path:
    base = cfg.get('work_dir') or cfg.get('output_dir') or 'output'
    return Path(base) / 'flow_checkpoint.json'


def _load_checkpoint(cfg: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    p = _checkpoint_path(cfg)
    if not p.exists():
        return None
    data = json.loads(p.read_text(encoding='utf-8'))
    if not isinstance(data, dict):
        return None
    return data


def _save_checkpoint(cfg: Dict[str, Any], data: Dict[str, Any]) -> None:
    p = _checkpoint_path(cfg)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding='utf-8')


class AntiBlockController:
    def __init__(self, *, rl_threshold: int = 3, ban_threshold: int = 2, min_rps: float = 1.0):
        self.rate_hits = 0
        self.ban_hits = 0
        self.forbidden_hits = 0
        self.min_rps = float(min_rps)
        self.rl_threshold = int(rl_threshold)
        self.ban_threshold = int(ban_threshold)

    def note(self, kind: str) -> None:
        k = (kind or '').lower()
        if k == 'rate-limit':
            self.rate_hits += 1
        elif k in ('ban', 'waf'):
            self.ban_hits += 1
        elif k in ('403', 'forbidden'):
            self.forbidden_hits += 1

    def advise(self, current_rps: float) -> dict:
        if self.ban_hits >= self.ban_threshold:
            return {'action': 'rotate_identity', 'new_rps': max(self.min_rps, current_rps * 0.5)}
        if self.rate_hits >= self.rl_threshold:
            return {'action': 'slowdown', 'new_rps': max(self.min_rps, current_rps * 0.7)}
        if self.forbidden_hits >= self.rl_threshold:
            return {'action': 'degrade_mode', 'new_rps': max(self.min_rps, current_rps * 0.8)}
        return {'action': 'none', 'new_rps': current_rps}


def _apply_http_rps(ctx, new_rps: float) -> None:
    cli = getattr(ctx, 'http', None)
    if cli is None:
        _phase_rec(get_results() if callable(globals().get('get_results')) else {}, 'flow', 'skipped', 'return')
        return
    if hasattr(cli, '_rps'):
        cli._rps = float(new_rps)
        cli._interval = 0.0 if cli._rps <= 0 else 1.0 / cli._rps


def _degrade_scan_mode(ctx) -> None:
    if hasattr(ctx, 'mode'):
        ctx.mode = 'STEALTH'


# ========== Param fuzzing arabirimi (opsiyonel) ==========

_param_mod = None
if _ws_spec('websecure.core.fuzzer') is not None:
    _param_mod = importlib.import_module('websecure.core.fuzzer')
elif _ws_spec('core.fuzzer') is not None:
    _param_mod = importlib.import_module('core.fuzzer')

discover_params_from_crawl = getattr(_param_mod, 'discover_params_from_crawl', None) if _param_mod else None
fuzz_endpoint = getattr(_param_mod, 'fuzz_endpoint', None) if _param_mod else None
guess_additional_params = getattr(_param_mod, 'guess_additional_params', None) if _param_mod else None

# Faz planı
_phases_mod = None
if _ws_spec('websecure.core.phases') is not None:
    _phases_mod = importlib.import_module('websecure.core.phases')
elif _ws_spec('phases') is not None:
    _phases_mod = importlib.import_module('phases')
build_plan = getattr(_phases_mod, 'build_plan', None) if _phases_mod else None


# ========== Güvenli dinamik import yardımcıları ==========
def _opt_import(mod: str, name: Optional[str]):
    """
    Deterministik tek-yön import: önce websecure.<mod>, sonra kök ad.
    find_spec kullanımı sadece _ws_import_any içinde.
    """
    # Tam ad doğrudan denensin
    m = _ws_import_any(mod)
    if m is None:
        # "websecure.<mod>" → "<mod>" → "<basename>" sırası
        base = mod.rsplit('.', 1)[-1] if isinstance(mod, str) else mod
        m = _ws_import_any(f'websecure.{mod}', mod, base)
    if m is None:
        _phase_rec(get_results() if callable(globals().get('get_results')) else {}, 'flow', 'skipped', 'return_none')
        return None
    return getattr(m, name, None) if name else m


def run_fuzz_and_param_discovery(ctx, *, event_cb: Optional[Callable[[str, Dict[str, Any]], None]] = None) -> None:
    if discover_params_from_crawl is None:
        add_result('meta', {'stage': 'fuzz_param_discovery', 'status': 'skipped:no-module'})
        _phase_rec(get_results() if callable(globals().get('get_results')) else {}, 'flow', 'skipped', 'return')
        return
    emit = (lambda e, d: None) if event_cb is None else lambda e, d: (event_cb(e, d))
    emit('phase.start', {'name': 'fuzz_param_discovery'})

    crawled = (getattr(ctx, 'results', {}) or {}).get('crawled_pages') or []
    targets = (getattr(ctx, 'results', {}) or {}).get('targets') or []
    cfg = (getattr(ctx, 'config', {}) or {}).get('fuzz') or {}

    discovered = discover_params_from_crawl(crawled)
    discovered = guess_additional_params(discovered, extra_words=cfg.get('extra_words') or []) if callable(guess_additional_params) else discovered

    limits = {
        'per_param': cfg.get('per_param', 25),
        'max_total': cfg.get('max_total', 2500),
        'rate_ms': cfg.get('rate_ms', 0),
        'rps': cfg.get('rps', 0),
        'time_budget_sec': cfg.get('time_budget_sec', 0),
        'stop_on_high': cfg.get('stop_on_high', False),
    }

    all_findings: List[Dict[str, Any]] = []
    for t in targets:
        if not callable(fuzz_endpoint):
            continue
        findings = fuzz_endpoint(
            getattr(ctx, 'session', None),
            {'url': t.get('url'), 'body': t.get('body'), 'json': t.get('json')},
            method=t.get('method', 'GET'),
            base_headers=cfg.get('base_headers') or {},
            base_cookies=cfg.get('base_cookies') or {},
            discovered=discovered,
            limits=limits,
            report_cb=lambda f: add_result('fuzz', f),
            debug=cfg.get('debug', False),
        )
        all_findings.extend(findings or [])

    add_result('meta', {
        'stage': 'fuzz_param_discovery',
        'tested_endpoints': len(targets),
        'candidate_params': {k: len(v) for k, v in discovered.items()},
        'total_findings': len(all_findings),
    })
    emit('phase.end', {'name': 'fuzz_param_discovery', 'tested': len(targets), 'findings': len(all_findings)})


# ================================================================
# FAZ 6b: Blind param fuzz
# ================================================================
def run_blind_param_fuzz_extended(ctx, *, event_cb: Optional[Callable[[str, Dict[str, Any]], None]] = None) -> None:
    blind_param_fuzz = _opt_import('core.fuzzer', 'blind_param_fuzz')
    if not callable(blind_param_fuzz):
        add_result('meta', {'stage': 'blind_param_fuzz', 'status': 'skipped:no-module'})
        _phase_rec(get_results() if callable(globals().get('get_results')) else {}, 'flow', 'skipped', 'return')
        return
    emit = (lambda e, d: None) if event_cb is None else lambda e, d: (event_cb(e, d))
    emit('phase.start', {'name': 'blind_param_fuzz'})

    import requests as _rq
    r0 = getattr(ctx, 'session', _rq.Session()).get(getattr(ctx, 'url', ''), timeout=20)
    baseline = {'len': len(r0.text or ''), 'time_samples': [r0.elapsed.total_seconds() * 1000], 'body': r0.text}

    cfg = getattr(ctx, 'config', {}) or {}
    fz = cfg.get('fuzzing', {}) or {}
    wl_path = fz.get('wordlist')
    wl = []
    if isinstance(wl_path, str) and wl_path:
        p = Path(wl_path)
        if p.exists() and p.is_file():
            wl = p.read_text(encoding='utf-8', errors='ignore').splitlines()

    discovered = (getattr(ctx, 'results', {}) or {}).get('discovery', {}) or {}
    endpoints = discovered.get('all') or []
    bucket: List[Dict[str, Any]] = []

    for ep in endpoints[:60]:
        blind_param_fuzz(getattr(ctx, 'session', None), ep, 'GET', r0.text, wl, baseline, bucket,
                         max_params=int(fz.get('max_params_per_endpoint', 25)), debug=bool(cfg.get('debug')))

    for item in bucket:
        add_result('blind_param_fuzz', item)

    add_result('meta', {'stage': 'blind_param_fuzz', 'tested': len(endpoints[:60]), 'findings': len(bucket)})
    emit('phase.end', {'name': 'blind_param_fuzz', 'tested': len(endpoints[:60]), 'findings': len(bucket)})


# ================================================================
# FAZ 7: OAST Doğrulama
# ================================================================
def run_oast_verification(ctx, *, event_cb: Optional[Callable[[str, Dict[str, Any]], None]] = None) -> None:
    if not callable(verify_oast_findings):
        add_result('meta', {'stage': 'oast', 'status': 'skipped:no-module'})
        _phase_rec(get_results() if callable(globals().get('get_results')) else {}, 'flow', 'skipped', 'return')
        return
    candidates = (getattr(ctx, 'results', {}) or {}).get('oast_candidates', [])
    verified = verify_oast_findings(candidates, getattr(ctx, 'session', None), timeout=10)
    (getattr(ctx, 'results', {}) or {})['oast_verified'] = verified
    add_result('meta', {'stage': 'oast', 'verified': len(verified or [])})


# ================================================================
# FAZ 8: Genel Doğrulama & Skorlama
# ================================================================
def run_verify_and_score(ctx, *, event_cb: Optional[Callable[[str, Dict[str, Any]], None]] = None) -> None:
    # Birleşik doğrulama: injection varsa onu, yoksa local verifier'ı kullanır (try/except YOK).
    results_dict = get_results()
    scored = None
    if 'verify_findings_and_score' in globals() and callable(verify_findings_and_score):
        scored = verify_findings_and_score(results_dict, getattr(ctx, 'session', None))
    else:
        _ver = importlib.import_module('verifier') if _ws_spec('verifier') is not None else None
        if _ver is not None and hasattr(_ver, 'verify_and_score'):
            buckets = []
            keys = ('fuzz', 'authorization', 'ssrf', 'file_upload', 'races', 'oast_verified', 'insecure_headers', 'tls',
                    'graphql', 'public_surface')
            for k in keys:
                v = results_dict.get(k)
                if isinstance(v, list):
                    buckets.extend(v)
            scored = _ver.verify_and_score(buckets, None)
    (getattr(ctx, 'results', {}) or {})['score'] = scored or []
    add_result('meta', {'stage': 'verify_and_score', 'total_final': len(scored or [])})


def run_reporting_and_integration(ctx, *, event_cb: Optional[Callable[[str, Dict[str, Any]], None]] = None) -> None:
    add_result('summary', {
        'target': getattr(ctx, 'url', None),
        'scheme': getattr(ctx, 'scheme', None),
        'detailed': bool(getattr(ctx, 'detailed', False)),
        'meta': (getattr(ctx, 'results', {}) or {}).get('meta', {}),
    })


# ================================================================
# Faz planı çalıştırıcı
# ================================================================
def run_plan_if_needed(ctx, *, event_cb: Optional[Callable[[str, Dict[str, Any]], None]] = None) -> None:
    if not callable(build_plan):
        _phase_rec(get_results() if callable(globals().get('get_results')) else {}, 'flow', 'skipped', 'return')
        return
    cfg = getattr(ctx, 'config', {}) or {}
    _apply_seed(cfg)
    plan = build_plan(ctx)

    vis = []
    for item in plan:
        vis.append({'id': item.get('id'), 'title': item.get('title'), 'enabled': bool(item.get('enabled')),
                    'reason': item.get('reason'), 'tags': item.get('tags', [])})
    add_result('phase_plan', {'visible': vis})

    ck = _load_checkpoint(cfg) or {"completed": []}
    completed = set(ck.get("completed") or [])

    for item in plan:
        pid = str(item.get('id'))
        if pid in completed:
            add_result('phase', {'name': pid, 'status': 'skipped:checkpoint'})
            continue
        if item.get('enabled') and callable(item.get('runner')):
            set_active_phase(pid)
            phase_begin(pid)
            t0 = time.time()
            item['runner'](ctx)
            dt = time.time() - t0
            summary = phase_end(pid)
            logging.info(f"[phase:{pid}] rps={summary.get('rps')} 2xx={summary.get('counters',{}).get('2xx',0)} 403={summary.get('counters',{}).get('403',0)} 429={summary.get('counters',{}).get('429',0)}")
            if isinstance(getattr(ctx, 'results', None), dict):
                (ctx.results.setdefault('phase_timings', {}))[pid] = round(dt, 2)
            completed.add(pid)
            ck = {"completed": sorted(list(completed)), "last_phase": pid, "phase_metrics": summary, "http_metrics": get_http_metrics()}
            _save_checkpoint(cfg, ck)



# ================================================================
# FAZ 1: Extended Discovery (Crawler Integration)
# ================================================================
def run_discovery_extended(ctx, *, event_cb: Optional[Callable[[str, Dict[str, Any]], None]] = None) -> None:
    from websecure.crawler import WebCrawler, CrawlerConfig
    
    emit = (lambda e, d: None) if event_cb is None else lambda e, d: (event_cb(e, d))
    emit('phase.start', {'name': 'discovery'})

    cfg = getattr(ctx, 'config', {}) or {}
    url = getattr(ctx, 'url', None) or cfg.get('base_url') or cfg.get('target')
    
    if not url:
        return

    session = getattr(ctx, 'session', None)
    if not session:
        from websecure.core.http import hardened_session
        session = hardened_session(cfg)
        if isinstance(ctx, dict):
            ctx['session'] = session
        else:
            setattr(ctx, 'session', session)

    # Configure Crawler
    c_conf = cfg.get('crawler') or {}
    crawler_cfg = CrawlerConfig()
    
    # Map essential config
    if c_conf.get('max_depth') is not None: crawler_cfg.max_depth = int(c_conf['max_depth'])
    if c_conf.get('max_pages') is not None: crawler_cfg.max_pages = int(c_conf['max_pages'])
    if c_conf.get('ignore_robots') is not None: crawler_cfg.ignore_robots = bool(c_conf['ignore_robots'])
    
    crawler = WebCrawler(session, url, config=crawler_cfg, debug=bool(getattr(ctx, 'debug', False)))
    res = crawler.start()
    
    # Context Update
    if isinstance(ctx, dict):
        if 'results' not in ctx or not isinstance(ctx['results'], dict):
            ctx['results'] = {}
        ctx['results'].update(res)
    else:
         if not hasattr(ctx, 'results') or not isinstance(ctx.results, dict):
            setattr(ctx, 'results', {})
         ctx.results.update(res)

    add_result('discovery', {'endpoints': len(res.get('endpoints') or []), 'map': res.get('crawl_map')})
    emit('phase.end', {'name': 'discovery', 'endpoints': len(res.get('endpoints') or [])})


def run_authorization_matrix(ctx, *, event_cb: Optional[Callable[[str, Dict[str, Any]], None]] = None) -> None:
    """Çoklu rol/oturum havuzu ile Authorization taraması; IDOR denemeleri dahil."""
    # Import authorization primitives
    _auth_mod = _opt_import('scanners.authorization', None)
    if _auth_mod is None:
        add_result('meta', {'stage': 'authorization', 'status': 'skipped:no-module'})
        _phase_rec(get_results() if callable(globals().get('get_results')) else {}, 'flow', 'skipped', 'return')
        return
    RoleProfile = getattr(_auth_mod, 'RoleProfile')
    RoleContext = getattr(_auth_mod, 'RoleContext')
    auth_run = getattr(_auth_mod, 'run')

    cfg = getattr(ctx, 'config', {}) or {}
    base_url = getattr(ctx, 'url', None) or cfg.get('base_url') or cfg.get('target') or ''
    discovered = (getattr(ctx, 'results', {}) or {}).get('discovery', {}) or {}
    endpoints = discovered.get('all') or []

    # Build role sessions: anonymous + header-based + optional authenticated user
    sessions: Dict[str, Any] = {}
    base_sess = getattr(ctx, 'session', None)
    if base_sess is None:
        from websecure.core.http import hardened_session
        base_sess = hardened_session(cfg)

    # anonymous
    sessions['anonymous'] = getattr(base_sess, 'copy', lambda : base_sess)()

    # Header role candidates
    role_names = ['user','viewer','staff','editor','manager','admin']
    for rn in role_names:
        s = getattr(base_sess, 'copy', lambda : base_sess)()
        if hasattr(s, 'headers'):
            s.headers['X-Role'] = rn
        sessions[rn] = s

    # Authenticated 'user' session if creds provided
    auth = cfg.get('auth') or {}
    creds = (auth.get('creds') or {})
    login_url = auth.get('login_url') or ''
    if login_url and creds.get('username') and creds.get('password'):
        _asc_mod = _opt_import('scanners.authenticated_scan', None)
        if _asc_mod is not None and hasattr(_asc_mod, 'AuthenticatedSession'):
            AS = getattr(_asc_mod, 'AuthenticatedSession')
            au = AS(base_sess, cfg)
            au.login()  # raises on failure; no silent try/except
            sessions['user'] = au.session

    # Build RoleContext
    profiles = [RoleProfile(name=k, headers=dict(getattr(v, 'headers', {})), cookies=dict(getattr(v, 'cookies', {}))) for k, v in sessions.items()]
    rc = RoleContext(base_session=base_sess, roles=profiles, base_url=base_url)

    results: Dict[str, Any] = {}
    auth_run(endpoints, rc, results, debug=bool(getattr(ctx, 'debug', False)))

    for item in (results.get('authorization') or []):
        add_result('authorization', item)
    # Optional summary
    if results.get('authorization_summary'):
        add_result('authorization_summary', results['authorization_summary'])

    add_result('meta', {'stage': 'authorization', 'tested': len(endpoints)})


def run_file_upload_scans(ctx, *, event_cb: Optional[Callable[[str, Dict[str, Any]], None]] = None) -> None:
    scan = _opt_import('scanners.file_upload', 'scan')
    if not callable(scan):
        add_result('meta', {'stage': 'file_upload', 'status': 'skipped:no-module'})
        _phase_rec(get_results() if callable(globals().get('get_results')) else {}, 'flow', 'skipped', 'return')
        return
    discovered = (getattr(ctx, 'results', {}) or {}).get('discovery', {}) or {}
    upload_eps = discovered.get('upload') or []
    results: Dict[str, Any] = {}
    if upload_eps:
        scan(getattr(ctx, 'session', None), upload_eps, results, debug=bool(getattr(ctx, 'debug', False)))
        for item in results.get('file_upload', []) or []:
            add_result('file_upload', item)
    add_result('meta', {'stage': 'file_upload', 'tested': len(upload_eps)})


def run_ssrf_xxe_scan(ctx, *, event_cb: Optional[Callable[[str, Dict[str, Any]], None]] = None) -> None:
    scan = _opt_import('scanners.ssrf_xxe', 'scan')
    if not callable(scan):
        add_result('meta', {'stage': 'ssrf_xxe', 'status': 'skipped:no-module'})
        _phase_rec(get_results() if callable(globals().get('get_results')) else {}, 'flow', 'skipped', 'return')
        return

    discovered = (getattr(ctx, 'results', {}) or {}).get('discovery', {}) or {}
    endpoints = discovered.get('all') or []
    cfg = getattr(ctx, 'config', {}) or {}
    ssrfc = dict(cfg.get('ssrf_xxe') or {})
    oastc = dict(cfg.get('oast') or {})
    # Merge toggles into oast_cfg expected by scanner
    oast_cfg = {
        'enabled': bool(oastc.get('enabled', True)),
        'provider': oastc.get('provider', 'generic'),
        'dns_domain': oastc.get('dns_domain') or oastc.get('root_domain') or '',
        'token_prefix': oastc.get('token_prefix', 'ws'),
        'timeout': int(oastc.get('timeout', 120)),
        'enable_local_schemes': bool(ssrfc.get('enable_local_schemes', True)),
        'enable_dict_scheme': bool(ssrfc.get('enable_dict_scheme', False)),
        'enable_tftp_scheme': bool(ssrfc.get('enable_tftp_scheme', True)),
        'enable_metadata_probes': bool(ssrfc.get('enable_metadata_probes', True)),
        'base_headers': dict(ssrfc.get('base_headers') or {}),
        'base_cookies': dict(ssrfc.get('base_cookies') or {}),
        'timing_threshold': float((cfg.get('fuzz') or {}).get('rate_limit', {}).get('timing_threshold_ms', 300))/1000.0 if isinstance((cfg.get('fuzz') or {}).get('rate_limit', {}).get('timing_threshold_ms', None), (int, float)) else 2.0
    }
    tuning = {
        'concurrency': int((cfg.get('settings') or {}).get('concurrency', 6) or 6),
        'retries': int((cfg.get('http') or {}).get('retries', 0) or 0),
        'methods': ('GET','POST'),
        'user_agent': str(cfg.get('user_agent') or (cfg.get('http') or {}).get('user_agent') or 'WebSecure/SSRF-XXE'),
        'respect_redirects': True
    }

    results: Dict[str, Any] = {}
    scan(getattr(ctx, 'session', None), endpoints, oast_cfg, results, debug=bool(getattr(ctx, 'debug', False)),
         auth_ctx=None, tuning=tuning)

    for item in (results.get('ssrf_xxe') or []):
        add_result('ssrf_xxe', item)

    # IMDS evidence & summary to report
    for ev in (results.get('ssrf_xxe_imds') or []):
        add_result('ssrf_xxe_imds', ev)
    summ = results.get('ssrf_xxe_summary') or {}
    if summ:
        add_result('ssrf_xxe_summary', summ)

    add_result('meta', {'stage': 'ssrf_xxe', 'tested': len(endpoints)})


def run_graphql_rpc_scan(ctx, *, event_cb: Optional[Callable[[str, Dict[str, Any]], None]] = None) -> None:
    scan = _opt_import('scanners.graphql_rpc', 'scan')
    if not callable(scan):
        add_result('meta', {'stage': 'graphql_rpc', 'status': 'skipped:no-module'})
        _phase_rec(get_results() if callable(globals().get('get_results')) else {}, 'flow', 'skipped', 'return')
        return
    discovered = (getattr(ctx, 'results', {}) or {}).get('discovery', {}) or {}
    gql = discovered.get('graphql') or []
    results: Dict[str, Any] = {}
    if gql:
        scan(getattr(ctx, 'session', None), gql, results, debug=bool(getattr(ctx, 'debug', False)))
        for item in results.get('graphql_rpc', []) or []:
            add_result('graphql_rpc', item)

    # Introspection kapalıysa fallback denemeleri işlendiğini ayrıca not düş
    summ = results.get('graphql_rpc_summary') or {}
    if isinstance(summ, dict) and not bool(summ.get('introspection_anonymous', False)):
        add_result('graphql_rpc', {
            'endpoint': (gql[0] if isinstance(gql, list) and gql else ''),
            'issue': 'Introspection kapalı — fallback testleri uygulandı',
            'severity': 'Bilgi',
        })
    add_result('meta', {'stage': 'graphql_rpc', 'tested': len(gql)})


def run_business_logic_races(ctx, *, event_cb: Optional[Callable[[str, Dict[str, Any]], None]] = None) -> None:
    if is_blocked(ctx):
        add_result('meta', {'stage': 'races', 'status': 'skipped:blocked'})
        _phase_rec(get_results() if callable(globals().get('get_results')) else {}, 'flow', 'skipped', 'blocked')
        return
    """Konfigürasyondaki business_logic.races senaryolarını eşzamanlı gönderimler ile uygular."""
    cfg = getattr(ctx, 'config', {}) or {}
    bl = (cfg.get('business_logic') or {})
    races = list(bl.get('races') or [])
    if not races:
        add_result('meta', {'stage': 'races', 'status': 'skipped:none'})
        _phase_rec(get_results() if callable(globals().get('get_results')) else {}, 'flow', 'skipped', 'return')
        return

    from urllib.parse import urljoin
    import threading

    metrics: List[Dict[str, Any]] = []
    session = getattr(ctx, 'session', None)
    # Increase requests pool to avoid pool-full warnings
    try:
        from requests.adapters import HTTPAdapter
        if hasattr(session, 'mount'):
            session.mount('https://', HTTPAdapter(pool_maxsize=64))
            session.mount('http://', HTTPAdapter(pool_maxsize=64))
    except Exception:
        pass
    base_url = getattr(ctx, 'url', None) or cfg.get('base_url') or cfg.get('target') or ''

    def _fire(method: str, url: str, body: str | bytes | None, headers: Dict[str, str] | None):
        u = url if (url.startswith('http://') or url.startswith('https://')) else urljoin(base_url, url)
        data = body if body is not None else None
        hdr = dict(headers or {})
        t0 = time.time()
        if session is not None and hasattr(session, 'request'):
            resp = session.request(method.upper(), u, data=data, headers=hdr)
            rt = int((time.time() - t0) * 1000)
            add_result('races', {'url': u, 'status': getattr(resp, 'status_code', 0), 'rt_ms': rt})
            metrics.append({'rt_ms': rt, 'status': getattr(resp, 'status_code', 0)})
            return
        import requests as _rq
        resp = _rq.request(method.upper(), u, data=data, headers=hdr)
        rt = int((time.time() - t0) * 1000)
        add_result('races', {'url': u, 'status': getattr(resp, 'status_code', 0), 'rt_ms': rt})
        metrics.append({'rt_ms': rt, 'status': getattr(resp, 'status_code', 0)})

    for rc in races:
        tgt = rc.get('target') or {}
        method = str(tgt.get('method') or 'GET')
        url = str(tgt.get('url') or '/')
        body = tgt.get('body')
        headers = tgt.get('headers') or {}
        conc = int(rc.get('concurrency') or 4)
        repeat = int(rc.get('repeat') or 1)
        threads = []
        for _ in range(repeat):
            for i in range(conc):
                th = threading.Thread(target=_fire, kwargs={'method': method, 'url': url, 'body': body, 'headers': headers}, daemon=True)
                threads.append(th)
                th.start()
        for th in threads:
            th.join()

    total = len(metrics)
    if total > 0:
        ok = sum(1 for m in metrics if 200 <= int(m.get('status',0)) < 400)
        lat = [int(m.get('rt_ms',0)) for m in metrics]
        add_result('races_summary', {'runs': total, 'ok': ok, 'min_ms': min(lat), 'max_ms': max(lat), 'avg_ms': int(sum(lat)/max(1,len(lat)))})
    add_result('meta', {'stage': 'races', 'status': 'ok', 'count': len(races)})



# ================================================================
# Legacy wrapper functions for basic phases (portscan, discovery, headers, TLS)
# These provide deterministic, no-try/except adapters to underlying modules.
# ================================================================
def run_port_scan_basic(ctx, *, event_cb: Optional[Callable[[str, Dict[str, Any]], None]] = None) -> None:
    emit = (lambda e, d: None) if event_cb is None else (lambda e, d: event_cb(e, d))
    emit('phase.start', {'name': 'portscan.basic'})
    # ps_mod removed (legacy port scanner)
    pass
    quick_scan = getattr(ps_mod, 'quick_scan', None) if ps_mod else None
    if not callable(quick_scan):
        add_result('meta', {'stage': 'portscan', 'status': 'skipped:no-module'})
        return
    url = getattr(ctx, 'url', None) or getattr(ctx, 'base_url', None) or getattr(ctx, 'target', None)
    host = urlparse(url).hostname if isinstance(url, str) else None
    if not host:
        add_result('meta', {'stage': 'portscan', 'status': 'skipped:no-host'})
        return
    results = quick_scan(host)
    # normalize & record
    items = []
    for r in (results or []):
        item = {'port': int(getattr(r, 'port', 0)), 'open': bool(getattr(r, 'open', False)),
                'service': getattr(r, 'service', None)}
        items.append(item)
    add_result('portscan', {'host': host, 'results': items})
    emit('phase.end', {'name': 'portscan.basic'})

def run_discovery_extended(ctx, *, event_cb: Optional[Callable[[str, Dict[str, Any]], None]] = None) -> dict:
    if is_blocked(ctx):
        add_result('meta', {'stage': 'discovery', 'status': 'skipped:blocked'})
        _phase_rec(get_results() if callable(globals().get('get_results')) else {}, 'flow', 'skipped', 'blocked')
        return {}
    emit = (lambda e, d: None) if event_cb is None else (lambda e, d: event_cb(e, d))
    emit('phase.start', {'name': 'discovery.extended'})
    craw = _opt_import('crawler.crawler', None)
    crawl_website = getattr(craw, 'crawl_website', None) if craw else None
    if not callable(crawl_website):
        add_result('meta', {'stage': 'discovery', 'status': 'skipped:no-module'})
        return {}
    url = getattr(ctx, 'url', None) or getattr(ctx, 'base_url', None) or getattr(ctx, 'target', None)
    if not isinstance(url, str) or not url.strip():
        add_result('meta', {'stage': 'discovery', 'status': 'skipped:no-url'})
        return {}
    results = {}
    crawl_website(url, results, debug=bool(getattr(ctx, 'debug', False)))
    # merge back onto ctx.results if present
    if isinstance(getattr(ctx, 'results', None), dict):
        ctx.results.update(results)
    emit('phase.end', {'name': 'discovery.extended'})
    return results

def run_security_headers_basic(ctx, *, event_cb: Optional[Callable[[str, Dict[str, Any]], None]] = None) -> None:
    emit = (lambda e, d: None) if event_cb is None else (lambda e, d: event_cb(e, d))
    emit('phase.start', {'name': 'headers.basic'})
    mod = _opt_import('scanners.headers', None)
    scan = getattr(mod, 'scan', None) if mod else None
    if not callable(scan):
        add_result('meta', {'stage': 'headers', 'status': 'skipped:no-module'})
        return
    sess = getattr(ctx, 'session', None)
    url = getattr(ctx, 'url', None) or getattr(ctx, 'base_url', None)
    cfg = getattr(ctx, 'config', {}) or {}
    results = getattr(ctx, 'results', {}) or {}
    scan(sess, url, cfg, results, auth_ctx=getattr(ctx, 'auth', None))
    emit('phase.end', {'name': 'headers.basic'})

def run_tls_basic(ctx, *, event_cb: Optional[Callable[[str, Dict[str, Any]], None]] = None) -> None:
    emit = (lambda e, d: None) if event_cb is None else (lambda e, d: event_cb(e, d))
    emit('phase.start', {'name': 'tls.basic'})
    mod = _opt_import('scanners.tls', None) or _opt_import('scanners.tls', None)
    scan_tls = getattr(mod, 'scan_tls', None) if mod else None
    if not callable(scan_tls):
        add_result('meta', {'stage': 'tls', 'status': 'skipped:no-module'})
        return
    url = getattr(ctx, 'url', None) or getattr(ctx, 'base_url', None)
    cfg = getattr(ctx, 'config', {}) or {}
    results = getattr(ctx, 'results', {}) or {}
    scan_tls(url, cfg, results)
    emit('phase.end', {'name': 'tls.basic'})

def run_rate_limit_profiles(ctx, *, event_cb: Optional[Callable[[str, Dict[str, Any]], None]] = None) -> None:
    cfg = getattr(ctx, 'config', {}) or {}
    if not (cfg.get('scanners', {}) or {}).get('rate_limit'):
        add_result('meta', {'stage': 'rate_limit', 'status': 'skipped:disabled'})
        _phase_rec(get_results() if callable(globals().get('get_results')) else {}, 'flow', 'skipped', 'return')
        return
    discovered = (getattr(ctx, 'results', {}) or {}).get('discovery', {}) or {}
    endpoints = discovered.get('all') or []
    tested = 0
    for ep in endpoints[:10]:
        tested += 1

        def _burst(n: int, sleep_s=0.05):
            import requests as _rq
            codes, t0 = [], time.time()
            for _ in range(n):
                r = getattr(ctx, 'session', _rq.Session()).get(ep, allow_redirects=False)
                codes.append(r.status_code)
                time.sleep(sleep_s)
            return {'codes': codes, 'ms': (time.time() - t0) * 1000}

        n, last_ok, max_n = 2, 2, 64
        while n <= max_n:
            res = _burst(n)
            if any(c in (429, 403) for c in res['codes']):
                break
            add_result('anti_block_event', {'type': 'capacity-probe', 'codes': res['codes'], 'burst': n})
            ctrl = getattr(ctx, '_ab_ctrl', None)
            if ctrl is None:
                ctrl = AntiBlockController()
                ctx._ab_ctrl = ctrl
            if any(c == 429 for c in res['codes']):
                ctrl.note('rate-limit')
            if any(c == 403 for c in res['codes']):
                ctrl.note('forbidden')
            rps = getattr(getattr(ctx, 'http', None), '_rps', 0.0)
            adv = ctrl.advise(float(rps))
            if adv.get('action') in ('slowdown', 'rotate_identity', 'degrade_mode'):
                _apply_http_rps(ctx, float(adv.get('new_rps', rps)))
                if adv.get('action') == 'degrade_mode':
                    _degrade_scan_mode(ctx)
                add_result('anti_block_event', {'type': 'capacity-probe-adjust', 'action': adv.get('action'),
                                                'new_rps': adv.get('new_rps')})
            last_ok = n
            n *= 2
        lo, hi = last_ok, min(n, max_n)
        while lo < hi:
            mid = (lo + hi) // 2
            res = _burst(mid)
            if any(c in (429, 403) for c in res['codes']):
                hi = mid
            else:
                lo = mid + 1
        add_result('rate_limit', {'endpoint': ep, 'limit': lo, 'note': 'approx per burst before throttle'})

    add_result('meta', {'stage': 'rate_limit', 'tested': tested})


# ================================================================
# Hepsini koşturan tek giriş noktası
# ================================================================
def run_all_extended(ctx, *, event_cb: Optional[Callable[[str, Dict[str, Any]], None]] = None) -> None:

    _get = globals().get
    def _call(name: str):
        fn = _get(name)
        return fn(ctx, event_cb=event_cb) if callable(fn) else None

    # Basit port taraması → discovery → headers → TLS
        # Phase: portscan
    set_active_phase('portscan'); phase_begin('portscan')
    __before = _results_count()
    _call('run_port_scan_basic')
    __after = _results_count()
    if __after <= __before:
        add_result('none_found', {'phase':'portscan','scope':'run_port_scan_basic','proof':'checked but none found'})

    _summary = phase_end('portscan'); add_result('phase', {'name':'portscan','status':'ok','metrics':_summary})

    # Phase: discovery
    set_active_phase('discovery'); phase_begin('discovery')
    disc = _call('run_discovery_extended') or {}
    _summary = phase_end('discovery'); add_result('phase', {'name':'discovery','status':'ok','metrics':_summary})

    # Phase: headers
    set_active_phase('headers'); phase_begin('headers')
    __before = _results_count()
    _call('run_security_headers_basic')
    __after = _results_count()
    if __after <= __before:
        add_result('none_found', {'phase':'headers','scope':'run_security_headers_basic','proof':'checked but none found'})

    _summary = phase_end('headers'); add_result('phase', {'name':'headers','status':'ok','metrics':_summary})

    # Phase: tls
    set_active_phase('tls'); phase_begin('tls')
    __before = _results_count()
    _call('run_tls_basic')
    __after = _results_count()
    if __after <= __before:
        add_result('none_found', {'phase':'tls','scope':'run_tls_basic','proof':'checked but none found'})

    _summary = phase_end('tls'); add_result('phase', {'name':'tls','status':'ok','metrics':_summary})

    fz_cfg = (getattr(ctx, 'config', {}) or {}).get('fuzzing', {})
    if fz_cfg and fz_cfg.get('blind_param_fuzz'):
        _call('run_blind_param_fuzz_extended')

    cfg_sc = (getattr(ctx, 'config', {}) or {}).get('scanners', {}) or {}
    if cfg_sc.get('authorization'):
        _call('run_authorization_matrix')
    if disc.get('upload') and cfg_sc.get('file_upload'):
        _call('run_file_upload_scans')
    if cfg_sc.get('ssrf_xxe'):
        _call('run_ssrf_xxe_scan')
    if disc.get('graphql') and cfg_sc.get('graphql_rpc'):
        _call('run_graphql_rpc_scan')
    if cfg_sc.get('rate_limit'):
        _call('run_rate_limit_profiles')




if hasattr(_rep, 'perform_reporting'):
    def flush_reporting(ctx):
        cfg = getattr(ctx, 'config', {}) or {}
        results = getattr(ctx, 'results', {}) or {}
        _rep.finalize(getattr(ctx, 'session', None), cfg, results, ctx)
else:
    def flush_reporting(ctx):
        _phase_rec(get_results() if callable(globals().get('get_results')) else {}, 'flow', 'skipped', 'return_none')
        return None
# </INTEGRATION:{tag}>


def _crit(ctx) -> bool:
    shared = getattr(ctx, 'shared', None)
    if isinstance(shared, dict):
        return bool(shared.get('critical_error'))
    return False


    from websecure.core.reporting import finalize
    finalize(ctx)
def adjust_scan_mode(results: dict, cfg: object) -> str:
    buckets = results if isinstance(results, dict) else {}
    auth = buckets.get('auth_coverage_delta') or {}
    byc = auth.get('by_class') or {}
    total_429 = int(byc.get('RateLimit', 0) or 0)
    total_forb = int(byc.get('Auth', 0) or 0)
    mode = 'AGGRESSIVE'
    if total_429 >= 5 or total_forb >= 10:
        mode = 'STEALTH'
    elif total_429 == 0 and total_forb == 0:
        mode = 'DEEP'
    add_result('meta', {'stage': 'profile_adjust', 'mode': mode, 'signals': {'429': total_429, '403': total_forb}})
    return mode


def _dyn_profile_update(stats: dict, current: str) -> str:
    p = (current or 'NORMAL').upper()
    four = int(stats.get('403', 0)) + int(stats.get('429', 0))
    ok = int(stats.get('2xx', 0))
    if four >= 5:
        if p == 'AGGRESSIVE':
            return 'NORMAL'
        if p == 'NORMAL':
            return 'STEALTH'
    if ok >= 20 and four == 0:
        if p == 'STEALTH':
            return 'NORMAL'
        if p == 'NORMAL':
            return 'AGGRESSIVE'
    return p


def _maybe_adjust_profile(current: str):
    # Keep compatibility with both websecure.core.http and plain core.http/http module names
    if _ws_spec('websecure.core.http') is None and _ws_spec('core.http') is None and _ws_spec('http') is None:
        return current
    try_mod = 'websecure.core.http' if _ws_spec('websecure.core.http') is not None else ('core.http' if _ws_spec('core.http') is not None else 'http')
    _hm = importlib.import_module(try_mod)
    if not hasattr(_hm, 'get_http_metrics'):
        return current
    stats = _hm.get_http_metrics()
    return _dyn_profile_update(stats, current)


# === SSRF/XXE Fazı (Adım 2) ===
def run_phase_ssrf_xxe(session, cfg, results):
    """
    SSRF & XXE taraması.
    ssrf_xxe.scan(session, endpoints, oast_cfg, results, debug=?, auth_ctx=?, tuning=?)
    Not: try/except kullanılmaz; hatalar yükselir.
    """
    # Raporlama: add_result kısa adı
    from websecure.core.reporting import add_result as _add_result

    # Modül çözümleme (try/except yok; deterministik)
    import importlib as _im, importlib.util as _iul2
    if _ws_spec('scanners.ssrf_xxe') is not None:
        ssrf_mod = _im.import_module('scanners.ssrf_xxe')
    elif _ws_spec('ssrf_xxe') is not None:
        ssrf_mod = _im.import_module('ssrf_xxe')
    else:
        raise ModuleNotFoundError("SSRF/XXE modülü bulunamadı: 'scanners.ssrf_xxe' veya 'ssrf_xxe'")

    scan_fn = getattr(ssrf_mod, "scan")  # yoksa AttributeError yükselir (istenen davranış)

    # Endpoints: config.ssrf_xxe.scan_endpoints veya base_url
    ssrf_cfg = cfg.get("ssrf_xxe") or {}
    endpoints = list(ssrf_cfg.get("scan_endpoints") or [])
    if not endpoints:
        base = cfg.get("base_url") or cfg.get("target") or ""
        if base:
            endpoints = [str(base).rstrip("/") + "/"]

    # OAST ve auth context
    oast_cfg = cfg.get("oast") or {}
    auth_ctx = cfg.get("auth") or {}

    # Çalıştır
    scan_fn(
        session,
        endpoints,
        oast_cfg,
        results,
        debug=bool(ssrf_cfg.get("debug", False)),
        auth_ctx=auth_ctx,
        tuning=ssrf_cfg.get("tuning"),
    )

    # Faz görünürlüğü (rapor planına düş)
    _add_result("phase_plan", {
        "visible": [{"title": "SSRF/XXE", "id": "ssrf_xxe", "enabled": True}]
    })


def run_business_logic_flows(ctx, *, event_cb: Optional[Callable[[str, Dict[str, Any]], None]] = None) -> None:
    """config.business_logic.flows DSL'ini uygular.
    Adımlar sıralı çalışır; {{var}} yer tutucuları config.auth.creds ve ctx değişkenlerinden doldurulur.
    Her adım için latency ve temel doğrulamalar (status/contains) rapora eklenir.
    """
    cfg = getattr(ctx, 'config', {}) or {}
    bl = (cfg.get('business_logic') or {})
    flows = list(bl.get('flows') or [])
    if not flows:
        add_result('meta', {'stage': 'biz_logic', 'status': 'skipped:none'})
        _phase_rec(get_results() if callable(globals().get('get_results')) else {}, 'flow', 'skipped', 'return')
        return

    from urllib.parse import urljoin
    session = getattr(ctx, 'session', None)
    base_url = getattr(ctx, 'url', None) or cfg.get('base_url') or cfg.get('target') or ''

    def _subst(s: str) -> str:
        # primitive template: {{username}}, {{password}} comes from cfg.auth.creds
        auth = cfg.get('auth') or {}
        creds = (auth.get('creds') or {})
        m = s
        for k, v in creds.items():
            m = m.replace('{{'+k+'}}', str(v))
        return m

    flow_metrics: List[Dict[str, Any]] = []
    for fl in flows:
        name = str(fl.get('name') or 'flow')
        base_headers = dict(fl.get('base_headers') or {})
        steps = list(fl.get('steps') or [])
        step_results: List[Dict[str, Any]] = []
        t_flow0 = time.time()
        for idx, st in enumerate(steps):
            method = str(st.get('method') or 'GET').upper()
            url = st.get('url') or '/'
            body = st.get('body')
            headers = {**base_headers, **(st.get('headers') or {})}
            u = url if (str(url).startswith('http://') or str(url).startswith('https://')) else urljoin(base_url, str(url))
            data = None
            if isinstance(body, str):
                data = _subst(body)
            elif body is not None:
                data = body
            t0 = time.time()
            if hasattr(session, 'request'):
                resp = session.request(method, u, data=data, headers=headers, allow_redirects=True)
            else:
                import requests as _rq
                resp = _rq.request(method, u, data=data, headers=headers, allow_redirects=True)
            dt = (time.time() - t0)
            code = int(getattr(resp, 'status_code', 0) or 0)
            text = getattr(resp, 'text', '') or ''
            expect = list(st.get('expect') or [])
            ok = True
            for ex in expect:
                if 'status' in ex and code != int(ex['status']):
                    ok = False
                if 'contains' in ex and str(ex['contains']) not in text:
                    ok = False
            rec = {'flow': name, 'step': idx+1, 'method': method, 'url': u, 'status': code, 'ok': ok, 'rt_ms': int(dt*1000)}
            step_results.append(rec)
            add_result('biz_logic', rec)
        flow_metrics.append({'name': name, 'steps': len(steps), 'duration_ms': int((time.time()-t_flow0)*1000),
                             'ok_steps': sum(1 for r in step_results if r['ok'])})

    add_result('biz_logic_summary', {
        'flows': len(flows),
        'total_steps': sum(m['steps'] for m in flow_metrics),
        'ok_steps': sum(m['ok_steps'] for m in flow_metrics),
        'dur_ms_total': sum(m['duration_ms'] for m in flow_metrics)
    })

def run_request_smuggling(ctx, *, event_cb=None) -> None:



    # Modülü deterministik çöz
    _mod_name = None
    for _name in ("websecure.scanners.request_smuggling",
                  "scanners.request_smuggling",
                  "request_smuggling"):
        if _ws_spec(_name) is not None:
            _mod_name = _name
            break
    if not _mod_name:
        raise ModuleNotFoundError(
            "Request Smuggling modülü bulunamadı: "
            "'websecure.scanners.request_smuggling' / 'scanners.request_smuggling' / 'request_smuggling'"
        )

    _mod = importlib.import_module(_mod_name)

    # Fonksiyon adayı seçimi (scan yoksa diğer varyantlar)
    _scan = None
    for _fn in ("scan", "run", "run_scan", "execute", "main"):
        _cand = getattr(_mod, _fn, None)
        if callable(_cand):
            _scan = _cand
            break
    if _scan is None:
        raise AttributeError(f"{_mod_name} içinde beklenen tarama fonksiyonu yok (denenen: scan/run/run_scan/execute/main)")

    # Girdiler
    _discovered = (getattr(ctx, "results", {}) or {}).get("discovery", {}) or {}
    _endpoints = _discovered.get("all") or []
    _session = getattr(ctx, "session", None)
    _debug = bool(getattr(ctx, "debug", False))

    # İmza-uyumlu çağrı için argüman filtresi
    _sig = inspect.signature(_scan)
    _kwargs = {}

    # session
    if "session" in _sig.parameters: _kwargs["session"] = _session
    elif "sess" in _sig.parameters:  _kwargs["sess"] = _session
    elif "http" in _sig.parameters:  _kwargs["http"] = _session
    elif "client" in _sig.parameters:_kwargs["client"] = _session

    # endpoints
    if "endpoints" in _sig.parameters: _kwargs["endpoints"] = _endpoints
    elif "targets" in _sig.parameters:  _kwargs["targets"] = _endpoints
    elif "urls" in _sig.parameters:     _kwargs["urls"] = _endpoints

    # results çıktısını toplayacağımız kap
    _results = {}
    if "results" in _sig.parameters:   _kwargs["results"] = _results
    elif "out" in _sig.parameters:     _kwargs["out"] = _results
    elif "findings" in _sig.parameters:_kwargs["findings"] = _results

    # opsiyoneller
    if "debug" in _sig.parameters:     _kwargs["debug"] = _debug
    if "auth_ctx" in _sig.parameters:  _kwargs["auth_ctx"] = getattr(ctx, "auth", None)
    if "tuning" in _sig.parameters:    _kwargs["tuning"] = getattr(ctx, "tuning", {})

    # Çalıştır
    _scan(**_kwargs)

    # Sonuçları rapora dök
    _items = (
        _results.get("request_smuggling")
        or _results.get("findings")
        or _results.get("items")
        or []
    )
    for it in _items:
        add_result("request_smuggling", it)

    add_result("meta", {
        "stage": "request_smuggling",
        "status": "done",
        "count": len(_items)
    })

    if event_cb:
        event_cb({"stage": "request_smuggling", "count": len(_items)})

    return




def run_mass_assignment(ctx, *, event_cb=None) -> None:

    _mod_name = None
    for _name in ("websecure.scanners.mass_assignment",
                  "scanners.mass_assignment",
                  "mass_assignment"):
        if _ws_spec(_name) is not None:
            _mod_name = _name
            break
    if not _mod_name:
        raise ModuleNotFoundError(
            "Mass Assignment modülü bulunamadı: "
            "'websecure.scanners.mass_assignment' / 'scanners.mass_assignment' / 'mass_assignment'"
        )

    _mod = importlib.import_module(_mod_name)

    # Fonksiyon adayı (scan yoksa diğer yaygın isimler)
    _scan = None
    for _fn in ("scan", "run", "run_scan", "execute", "main"):
        _cand = getattr(_mod, _fn, None)
        if callable(_cand):
            _scan = _cand
            break
    if _scan is None:
        raise AttributeError(f"{_mod_name} içinde beklenen tarama fonksiyonu yok (denenen: scan/run/run_scan/execute/main)")

    # Girdiler
    _discovered = (getattr(ctx, "results", {}) or {}).get("discovery", {}) or {}
    _endpoints = _discovered.get("all") or []
    _session = getattr(ctx, "session", None)
    _debug = bool(getattr(ctx, "debug", False))

    # İmza-uyumlu çağrı (sadece beklenen parametreleri ver)
    _sig = inspect.signature(_scan)
    _kwargs = {}

    # session
    if "session" in _sig.parameters: _kwargs["session"] = _session
    elif "sess" in _sig.parameters:  _kwargs["sess"] = _session
    elif "http" in _sig.parameters:  _kwargs["http"] = _session
    elif "client" in _sig.parameters:_kwargs["client"] = _session

    # endpoints
    if "endpoints" in _sig.parameters: _kwargs["endpoints"] = _endpoints
    elif "targets" in _sig.parameters:  _kwargs["targets"] = _endpoints
    elif "urls" in _sig.parameters:     _kwargs["urls"] = _endpoints

    # sonuç kabı
    _results = {}
    if "results" in _sig.parameters:    _kwargs["results"] = _results
    elif "out" in _sig.parameters:      _kwargs["out"] = _results
    elif "findings" in _sig.parameters: _kwargs["findings"] = _results

    # opsiyoneller
    if "debug" in _sig.parameters:     _kwargs["debug"] = _debug
    if "auth_ctx" in _sig.parameters:  _kwargs["auth_ctx"] = getattr(ctx, "auth", None)
    if "tuning" in _sig.parameters:    _kwargs["tuning"] = getattr(ctx, "tuning", {})

    # Çalıştır
    _scan(**_kwargs)

    # Sonuçları raporla
    _items = (
        _results.get("mass_assignment")
        or _results.get("findings")
        or _results.get("items")
        or []
    )
    for it in _items:
        add_result("mass_assignment", it)

    add_result("meta", {
        "stage": "mass_assignment",
        "status": "done",
        "count": len(_items)
    })

    if event_cb:
        event_cb({"stage": "mass_assignment", "count": len(_items)})

    return



def run_jwt(ctx, *, event_cb=None) -> None:
    from websecure.scanners.jwt import scan as _scan
    discovered = (getattr(ctx, 'results', {}) or {}).get('discovery', {}) or {}
    endpoints = discovered.get('all') or []
    results = {}
    _scan(getattr(ctx, 'session', None), endpoints, results, debug=bool(getattr(ctx, 'debug', False)))
    for it in results.get('jwt', []) or []:
        add_result('jwt', it)
    add_result('meta', {'stage': 'jwt', 'status': 'done', 'count': len(results.get('jwt', []) or [])})
    return


def run_ws_fuzz(ctx, *, event_cb=None) -> None:
    from websecure.scanners.ws_fuzz import scan as _scan
    discovered = (getattr(ctx, 'results', {}) or {}).get('discovery', {}) or {}
    endpoints = discovered.get('all') or []
    results = {}
    _scan(getattr(ctx, 'session', None), endpoints, results, debug=bool(getattr(ctx, 'debug', False)))
    for it in results.get('ws_fuzz', []) or []:
        add_result('ws_fuzz', it)
    add_result('meta', {'stage': 'ws_fuzz', 'status': 'done', 'count': len(results.get('ws_fuzz', []) or [])})
    return


def run_graphql_attacks(ctx, *, event_cb=None) -> None:
    from websecure.scanners.graphql_attacks import scan as _scan
    discovered = (getattr(ctx, 'results', {}) or {}).get('discovery', {}) or {}
    endpoints = discovered.get('all') or []
    results = {}
    _scan(getattr(ctx, 'session', None), endpoints, results, debug=bool(getattr(ctx, 'debug', False)))
    for it in results.get('graphql_attacks', []) or []:
        add_result('graphql_attacks', it)
    add_result('meta', {'stage': 'graphql_attacks', 'status': 'done', 'count': len(results.get('graphql_attacks', []) or [])})
    return

def run_plan_if_needed(ctx):
    """Deterministic phase plan runner.
    Order: Discovery → Portscan → TLS → Security Headers → Offensive → Finalize.
    Each phase must return a PhaseResult-like object with fields:
      - name (str), status ("ok" | "failed" | "skipped"), started_at, ended_at
      - metrics (dict), errors (list[str])
    No exceptions should be raised from here; phases are invoked directly and
    expected to honor the contract.
    """
    # Local import ladder without try/except: rely on package path guard.
    from websecure.core import reporting as _reporting
    from websecure.core import phases as _phases

    results = []

    # Resolve phase callables from phases module (must exist)
    phase_fns = [
        ("discovery", getattr(_phases, "run_discovery", None)),
        ("portscan", getattr(_phases, "run_portscan", None)),
        ("tls", getattr(_phases, "run_tls", None)),
        ("security_headers", getattr(_phases, "run_security_headers", None)),
        ("offensive", getattr(_phases, "run_offensive", None)),
        ("finalize", getattr(_phases, "run_finalize", None)),
    ]

    for name, fn in phase_fns:
        if fn is None:
            # If a phase function is missing, synthesize a failed PhaseResult without raising.
            res = dict(name=name, status="failed", started_at=None, ended_at=None,
                       metrics={}, errors=[f"missing phase function: {name}"])
            results.append(res)
            _reporting.add_result(ctx, {"type": "phase_error", "phase": name, "message": "missing function"})
            continue
        res = fn(ctx)
        results.append(res)
        # If failed, record an event but continue deterministically.
        if getattr(res, "status", res.get("status", "ok")) != "ok":
            _reporting.add_result(ctx, {"type": "phase_error", "phase": name, "message": "phase failed"})

    # High-level summary hook
    if hasattr(_reporting, "phase_summary"):
        _reporting.phase_summary(ctx, results)

    return results


def flush(ctx=None):
    """Finalize reporting & teardown using reporting.finalize(ctx)."""
    cfg = getattr(ctx, 'config', {}) or {}
    results = getattr(ctx, 'results', {}) or {}
    _rep.finalize(getattr(ctx, 'session', None), cfg, results, ctx)



def run_offensive_scanners(ctx, *, event_cb=None):
    cfg = getattr(ctx, "config", {}) or {}
    sc = (cfg.get("scanners") or {})
    sess = getattr(ctx, "session", None)
    base_url = getattr(ctx, "base_url", None)
    results = getattr(ctx, "results", {})

    # Param fuzzing (covers XSS/SQLi-style vectors via wordlists through ws_fuzz)
    if sc.get("xss", True) or sc.get("sqli", True):
        from websecure.scanners.ws_fuzz import run as _ws_run
        _ws_run(sess, base_url, cfg, results)

    if sc.get("jwt"):
        from websecure.scanners.jwt import scan as _scan_jwt
        _scan_jwt(sess, [base_url], results, debug=bool(getattr(ctx,"debug", False)))

    if sc.get("nosqli"):
        from websecure.scanners.nosqli import scan as _scan_nosqli
        _scan_nosqli(sess, [base_url], results, debug=bool(getattr(ctx,"debug", False)))

    if sc.get("graphql"):
        from websecure.scanners.graphql_rpc import scan as _scan_graphql
        _scan_graphql(sess, [], results, base_url=base_url, debug=bool(getattr(ctx,"debug", False)))

    if sc.get("mass_assignment"):
        from websecure.scanners.mass_assignment import scan as _scan_mass
        _scan_mass(sess, [base_url], results, debug=bool(getattr(ctx,"debug", False)))

    if sc.get("ssrf_xxe"):
        from websecure.scanners.ssrf_xxe import scan as _scan_ssrf
        _scan_ssrf(sess, [base_url], results, debug=bool(getattr(ctx,"debug", False)))

    if sc.get("request_smuggling"):
        from websecure.scanners.request_smuggling import scan as _scan_rs
        _scan_rs(sess, [base_url], results, debug=bool(getattr(ctx,"debug", False)))

def run_forms_probe_phase(ctx, *, event_cb=None):
    from websecure.scanners.forms_probe import run as _run_forms
    from websecure.core.reporting import add_result
    tries = _run_forms(ctx, limit_per_host=30, debug=bool(getattr(ctx,'debug', False)))
    add_result("phase", {"name":"forms_probe", "attempts": tries})
    return tries
