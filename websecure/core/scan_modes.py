from __future__ import annotations
from websecure.core.utils import _ws_import_any, _ws_maybe_import_any
from importlib import import_module
from websecure.core.http import hardened_session
import re
import logging
from importlib.util import find_spec
import asyncio
import importlib
from dataclasses import dataclass
from pathlib import Path
import sys
import importlib.util as _ilu
from websecure.core.http import hardened_session as _hardened_session
import inspect as __ins
from importlib.util import find_spec as _find_spec
from importlib import import_module as _import_module
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

__all__ = ['run_mode','run','run_many','build_plan','hpm_current_policy']

def _importable(mod: str) -> bool:
    return _find_spec(mod) is not None

def _import_mod(*candidates: str):
    for name in candidates:
        if _importable(name):
            return _import_module(name)
    raise ModuleNotFoundError(f"Modül bulunamadı: {candidates!r}")

def run(*args, **kwargs):
    fr = _import_mod('websecure.core.flow_runner', 'core.flow_runner')
    if hasattr(fr, 'run') and callable(fr.run):
        return fr.run(*args, **kwargs)
    raise AttributeError("flow_runner.run bulunamadı")

def run_many(*args, **kwargs):
    fr = _import_mod('websecure.core.flow_runner', 'core.flow_runner')
    if hasattr(fr, 'run_many') and callable(fr.run_many):
        return fr.run_many(*args, **kwargs)
    # Geriye uyumlu köprü: run_many yoksa run ile çoklu çalıştır
    targets = args[0] if args else None
    rest = args[1:] if len(args) > 1 else ()
    if isinstance(targets, (list, tuple)) and hasattr(fr, 'run') and callable(fr.run):
        return [fr.run(t, *rest, **kwargs) for t in targets]
    if hasattr(fr, 'run') and callable(fr.run):
        return fr.run(*args, **kwargs)
    raise AttributeError("flow_runner.run_many ve run bulunamadı")

def build_plan(*args, **kwargs):
    ph = _import_mod('websecure.core.phases', 'core.phases')
    if hasattr(ph, 'build_plan') and callable(ph.build_plan):
        return ph.build_plan(*args, **kwargs)
    raise AttributeError("phases.build_plan bulunamadı")

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


def __ensure_triple_plan(plan):
    out = []
    for item in list(plan or []):
        if isinstance(item, (list, tuple)):
            if len(item) == 3:
                out.append(tuple(item))
            elif len(item) == 2:
                name, fn = item
                est = 90 if str(name).lower() not in ("discovery","portscan","tls","security_headers") else {"discovery":60,"portscan":60,"tls":45,"security_headers":45}.get(str(name).lower(),90)
                out.append((name, est, fn))
        else:
            # pass through (unknown)
            out.append(item)
    return out

def __run_plan_adapt(run_plan_fn, plan, ctx, cfg):
    try:
        params = list(__ins.signature(run_plan_fn).parameters.keys())
    except _BOUNDARY_EXC as e:
        _logger.error('phase error [scan_modes]', exc_info=True)
        _report_phase_error('scan_modes', 'scan_modes.py', e)
        params = ["plan", "ctx"]
    if len(params) >= 3:
        return run_plan_fn(plan, ctx, cfg)
    return run_plan_fn(plan, ctx)

# --- Safe signature-aware call helper (prevents TypeError for unexpected kwargs) ---
import inspect as _ins

def _safe_call_runner(_fn, session=None, base_url=None, config=None, logger=None, context=None):
    """
    Signature-aware caller:
      - If _fn(ctx, phases) is expected, synthesize ctx and phases.
      - Else call with filtered kwargs: (session, base_url|url|base, config|cfg, logger)
    """
    import inspect as _ins_local
    try:
        params = list(_ins_local.signature(_fn).parameters.keys())
    except _BOUNDARY_EXC as e:
        _logger.error('phase error [scan_modes]', exc_info=True)
        _report_phase_error('scan_modes', 'scan_modes.py', e)
        params = []

    # If runner expects (ctx, phases): build minimal ctx + phases
    if (len(params) >= 2 and params[0] == "ctx" and params[1] == "phases") or {"ctx","phases"}.issubset(params):
        # Build a minimal ScanContext if not provided
        if context is None:
            try:
                from websecure.core.scan_modes import ScanContext as _SC  # self-module import
            except _BOUNDARY_EXC as e:
                _logger.error('phase error [scan_modes]', exc_info=True)
                _report_phase_error('scan_modes', 'scan_modes.py', e)
                # Fallback tiny context
                class _SC:  # type: ignore
                    def __init__(self, url, session, config, logger):
                        self.url, self.session, self.config, self.logger = url, session, (config or {}), logger
                        self.results = {}
                        self.detailed = False
                        self.save_report = False
                        self.debug = False
            context = _SC(url=base_url, session=session, config=(config or {}), logger=logger)

        try:
            from websecure.core.phases import build_plan as _build_plan
        except _BOUNDARY_EXC as e:
            _logger.error('phase error [scan_modes]', exc_info=True)
            _report_phase_error('scan_modes', 'scan_modes.py', e)
            # ultimate fallback: empty plan
            def _build_plan(_ctx): return []  # type: ignore

        phases = getattr(context, "phases", None) or _build_plan(context)
        # normalize phases if they are dicts from build_plan
        if phases and isinstance(phases, (list, tuple)) and phases and isinstance(phases[0], dict):
            phases = [(str(p.get('id') or p.get('name') or 'phase'), p.get('runner')) for p in phases if callable(p.get('runner'))]
        return _fn(context, phases)

    # Otherwise: filter kwargs to expected names
    try:
        params = _ins_local.signature(_fn).parameters
    except _BOUNDARY_EXC as e:
        _logger.error('phase error [scan_modes]', exc_info=True)
        _report_phase_error('scan_modes', 'scan_modes.py', e)
        params = {}

    kwargs = {}
    if "context" in params:
        kwargs["context"] = context
    elif "ctx" in params:
        kwargs["ctx"] = context
    
    # Pass raw results if requested (and context not used or redundant)
    if "results" in params:
        if context and context.results:
            kwargs["results"] = context.results
        else:
            kwargs["results"] = {}

    if "session" in params:
        kwargs["session"] = session
    if "base_url" in params:
        kwargs["base_url"] = base_url
    elif "url" in params:
        kwargs["url"] = base_url
    elif "base" in params:
        kwargs["base"] = base_url
    if "config" in params:
        kwargs["config"] = config
    elif "cfg" in params:
        kwargs["cfg"] = config
    if "logger" in params:
        kwargs["logger"] = logger
    return _fn(**kwargs) if kwargs else _fn()
def _safe_construct_and_run(_cls, session, base_url, config, logger=None):
    """
    Constructs class with only supported kwargs, then calls run_all/run appropriately,
    again filtering kwargs if the methods accept parameters.
    """
    # Construct
    try:
        cparams = _ins.signature(_cls).parameters
    except _BOUNDARY_EXC as e:
        _logger.error('phase error [scan_modes]', exc_info=True)
        _report_phase_error('scan_modes', 'scan_modes.py', e)
        cparams = {}
    ckwargs = {}
    # Check for context/results in constructor
    # Note: Usually scanners take session/results in __init__
    if "results" in cparams:
         # Need to retrieve results from somewhere. 
         # In _safe_construct_and_run signature we don't have 'context' explicitly passed often, 
         # but let's check if we can get it. 
         # Actually this function doesn't receive context, only session/base_url/config.
         # We'll skip results here unless we change signature. 
         # Wait, looking at usage, this is called by phases.py usually.
         # For now, standard scanners take 'results' in __init__.
         # We will pass empty dict if not available, OR if we had context we'd pass it.
         pass 

    if "session" in cparams:
        ckwargs["session"] = session
    if "base_url" in cparams:
        ckwargs["base_url"] = base_url
    elif "url" in cparams:
        ckwargs["url"] = base_url
    if "config" in cparams:
        ckwargs["config"] = config
    elif "cfg" in cparams:
        ckwargs["cfg"] = config
    if "logger" in cparams:
        ckwargs["logger"] = logger
    inst = _cls(**ckwargs) if ckwargs else _cls()

    # Prefer run_all, fallback to run
    runner = getattr(inst, "run_all", None) or getattr(inst, "run", None)
    if not callable(runner):
        # if the instance itself is callable, try that
        if callable(inst):
            return _safe_call_runner(inst, session, base_url, config, logger)
        return None

    try:
        rparams = _ins.signature(runner).parameters
    except _BOUNDARY_EXC as e:
        _logger.error('phase error [scan_modes]', exc_info=True)
        _report_phase_error('scan_modes', 'scan_modes.py', e)
        rparams = {}
    rkwargs = {}
    if "context" in rparams:
         # We don't have context here easily in _safe_construct_and_run unless passed.
         # But wait, this function is usually called from run_plan which might not have full context object 
         # if it was called with simple args. 
         # However, if we look at _safe_call_runner, it builds context.
         pass

    if "results" in rparams:
         # Similar issue.
         pass

    if "session" in rparams:
        rkwargs["session"] = session
    if "base_url" in rparams:
        rkwargs["base_url"] = base_url
    elif "url" in rparams:
        rkwargs["url"] = base_url
    if "config" in rparams:
        rkwargs["config"] = config
    elif "cfg" in rparams:
        rkwargs["cfg"] = config
    if "logger" in rparams:
        rkwargs["logger"] = logger
    return runner(**rkwargs) if rkwargs else runner()


# --- Qualified import helpers (no try/except, no lazy hacks) ---
_PKG_ROOT = (__package__.split('.')[0] if __package__ else 'websecure')  # expected 'websecure'

def _qualify(name: str) -> str:
    # Map 'core.xxx' to 'websecure.core.xxx' inside the package
    if name.startswith(f"{_PKG_ROOT}."):
        return name
    if name.startswith("core."):
        return f"{_PKG_ROOT}.{name}"
    return name

def _opt_import(mod: str):
    full = _qualify(mod)
    return _ws_maybe_import_any(full, mod)
from typing import Any, Dict, Optional

_PROJECT_ROOT = Path(__file__).resolve().parents[1]  # .../<root>
_SITEPK_SUBSTR = ("site-packages", "dist-packages")


def _spec_origin(spec) -> str:
    return "" if spec is None or getattr(spec, "origin", None) in (None, "built-in") else str(
        Path(spec.origin).resolve())


def _is_sitepkg_path(p: str) -> bool:
    up = p.replace('\\', '/').lower()
    return any(s in up for s in _SITEPK_SUBSTR)


def _is_local_path(p: str) -> bool:
    return bool(p) and str(Path(p)).startswith(str(_PROJECT_ROOT))



def _resolve_module(primary: str, fallbacks: list[str] | None = None):
    """
    Önce tam paket adını (ör. 'scanners.jwt'), sonra fallback'leri, en sonda düz modül ismini dener.
    Import sırasında modül içi hatalar yükselir (susturma yok).
    """
    cands: list[str] = [primary]
    if fallbacks:
        cands.extend([m for m in fallbacks if m])

    base = primary.rsplit(".", 1)[-1] if primary else ""
    if base and base not in cands:
        cands.append(base)

    for m in cands:
        mod = _opt_import(m)
        if mod is not None:
            return mod
    return None


_reporting = _opt_import("websecure.core.reporting")
_requests = _opt_import("requests")


class ScanMode:
    NORMAL = "normal"
    DETAILED = "detailed"
    AUTHENTICATED = "authenticated"
    DEEP = "deep"  # eklendi
    # Aliases
    STEALTH = NORMAL
    AGGRESSIVE = DEEP


@dataclass
class ScanContext:
    url: str = ""
    scheme: str = ""
    config: Dict[str, Any] | None = None
    driver: Any = None
    session: Any = None
    results: Dict[str, Any] | None = None
    detailed: bool = False
    save_report: bool = False
    debug: bool = False
    logger: Any = None

    def __post_init__(self):
        if self.config is None:
            self.config = {}
        if self.results is None:
            self.results = {}

    @property
    def endpoints(self):
        return self.results.get("endpoints", [])



# ------------------------- Raporlama köprüleri -------------------------
def _report(bucket: str, item: Dict[str, Any]) -> None:
    if _reporting and hasattr(_reporting, "add_result"):
        _reporting.add_result(bucket, item)


def _flush_report() -> None:
    if _reporting and hasattr(_reporting, "flush"):
        _reporting.flush()


def _ensure_session(sess: Any):
    if sess is not None:
        return sess
    if _requests is None:
        raise RuntimeError("requests modülü bulunamadı; oturum gerekli.")
    return _hardened_session({})


def _resolve_reporter():
    """
    Yerel raporlama modülünü güvenli biçimde çözer.
    Öncelik: build.lib.core.reporting → core.reporting → kökte reporting.py.
    site-packages/dist-packages altındaki 'reporting' paketleri BİLİNÇLİ OLARAK ATLANIR.
    Dönüş: çağrılabilir bir fonksiyon ya da None.
    """
    # 1) build.lib.core.reporting
    spec_bl = _ilu.find_spec("build.lib.core.reporting")
    if spec_bl is not None:
        origin = _spec_origin(spec_bl)
        if origin and _is_local_path(origin):
            mod = importlib.import_module("build.lib.core.reporting")
            fn = getattr(mod, "perform_reporting_and_integration", None)
            if callable(fn):
                return fn

    # 2) core.reporting
    spec_core = _ilu.find_spec("websecure.core.reporting")
    if spec_core is not None:
        origin = _spec_origin(spec_core)
        if origin and _is_local_path(origin):
            mod = importlib.import_module("websecure.core.reporting")
            fn = getattr(mod, "perform_reporting_and_integration", None)
            if callable(fn):
                return fn

    # 3) düz 'reporting' sadece yerelse
    spec_plain = _ilu.find_spec("reporting")
    if spec_plain is not None:
        origin = _spec_origin(spec_plain)
        if origin and _is_local_path(origin) and not _is_sitepkg_path(origin):
            mod = importlib.import_module("reporting")
            fn = getattr(mod, "perform_reporting_and_integration", None)
            if callable(fn):
                return fn

    # 4) Dosya yolundan yükleme (kök/reporting.py)
    local_path = _PROJECT_ROOT / "reporting.py"
    if local_path.exists():
        spec = _ilu.spec_from_file_location("websec_reporting_local", str(local_path))
        if spec and spec.loader:
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)  # type: ignore
            fn = getattr(module, "perform_reporting_and_integration", None)
            if callable(fn):
                return fn

    return None


def _maybe_perform_reporting(ctx: 'ScanContext'):
    rep_fn = _resolve_reporter()
    if not callable(rep_fn):
        return

    cfg = ctx.config or {}
    rep_cfg = (cfg.get("reporting") or {})
    enabled = bool(rep_cfg) or bool(getattr(ctx, "save_report", False))
    if not enabled:
        return

    # Hata saklama yok: raporlama fonksiyonu patlarsa görünür şekilde yükselir
    rep_fn(ctx.session, cfg, ctx.results)


# ---------------------- Authenticated akışı arayıcı ----------------------
def _resolve_auth_runner():
    """
    authenticated_scan veya varyantlarını bulur; None dönebilir.

    """
    # Birincil adaylar
    for m in ("core.authenticated_scan", "authenticated_scan"):
        mod = _opt_import(m)
        if not mod:
            continue

        fn = getattr(mod, "run", None)
        if callable(fn):
            return lambda session, base_url, config, logger: _safe_call_runner(fn, session, base_url, config, logger)

        cls = getattr(mod, "AuthenticatedScanner", None)
        if cls is not None:
            def _call(session, base_url, config, logger):
                scanner = cls(session=session, base_url=base_url, config=config, logger=logger)
                run_all = getattr(scanner, "run_all", None)
                return run_all() if callable(run_all) else scanner.run()

            return _call

    # Geriye dönük (zorunlu değil)
    for m in ("core.flow_runner", "flow_runner"):
        mod = _opt_import(m)
        if not mod:
            continue
        for cand in ("run_authenticated", "run", "main"):
            fn = getattr(mod, cand, None)
            if callable(fn):
                return lambda session, base_url, config, logger: _safe_call_runner(fn, session, base_url, config, logger)
    return None


# ----------------------------- Offensive profil haritası -----------------------------
def offensive_enabled_map(config: dict[str, 'Any']) -> dict[str, bool]:
    off = config.get('offensive') or {}
    mode = str((config.get('mode') or '')).upper()
    def _e(k: str, default: bool) -> bool:
        v = off.get(k)
        if isinstance(v, dict) and 'enabled' in v:
            return bool(v.get('enabled'))
        return True if mode in ('AGGRESSIVE','DEEP') else default
    return {
        'request_smuggling': _e('request_smuggling', False),
        'mass_assignment': _e('mass_assignment', False),
        'jwt_attacks': _e('jwt_attacks', False),
        'nosql_injection': _e('nosql_injection', False),
        'websocket_fuzz': _e('websocket_fuzz', False),
    }



# ----------------------------- Ana giriş -----------------------------
import asyncio
import logging


# [AUTO-CLEANUP] removed duplicate def '_resolve_auth_runner' defined at lines 393-421


# ----------------------------- Offensive profil haritası -----------------------------
# [AUTO-CLEANUP] removed duplicate def 'offensive_enabled_map' defined at lines 425-439


# ----------------------------- Ana giriş -----------------------------

def incremental_targets(all_links: list[str], previous: list[str] | None = None) -> list[str]:
    prev = set(previous or [])
    return [u for u in (all_links or []) if u not in prev]


from dataclasses import dataclass
from typing import Dict, Any, List, Set
import time

from websecure.core.reporting import add_result


@dataclass(frozen=True)
class HProfilePolicy:
    name: str
    rps: float
    concurrency: int
    allow_categories: Set[str]
    idempotent_only: bool
    oast: bool
    heavy_modules: bool
    robots_respect: bool
    politeness_ms: int
    # Geçiş eşikleri
    obs_seconds: int
    min_req: int
    up_when_block_rate_below: float  # 0.01 => %1
    down_when_block_rate_above: float  # 0.05 => %5


class HProfileManager:

    def __init__(self, profiles: Dict[str, Any] | None = None, active: str = "normal"):
        # Policy set + active profile
        self._policies: Dict[str, HProfilePolicy] = self._load_policies(profiles or {})
        act = str(active or "normal").strip().lower()
        self._active: str = act if act in self._policies else "normal"
        # Runtime stats for adaptive switching
        self._timeline: List[Dict[str, Any]] = []
        self._req_count: int = 0
        self._blocked_count: int = 0
        import time as _t
        self._window_start: float = _t.monotonic()
        # ... (sınıfın diğer kısımları aynen)

    @staticmethod
    def _as_bool(x: Any, default: bool) -> bool:
        if isinstance(x, bool):
            return x
        if isinstance(x, str):
            lx = x.strip().lower()
            if lx in ('1', 'true', 'yes', 'on'):
                return True
            if lx in ('0', 'false', 'no', 'off'):
                return False
        return default

    @staticmethod
    def _as_set(xs: Any) -> Set[str]:
        if isinstance(xs, (list, tuple, set)):
            return {str(x).strip().lower() for x in xs if str(x).strip()}
        return set()

    @staticmethod
    def _num(x, default: float) -> float:
        # Safe numeric converter without try/except
        if isinstance(x, (int, float)):
            return float(x)
        if isinstance(x, str):
            s = x.strip()
            # Accept simple ints/floats and scientific notation
            if re.fullmatch(r'[+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?', s):
                return float(s)
        return float(default)

    def _load_policies(self, cfg: Dict[str, Any]) -> Dict[str, HProfilePolicy]:
        pols: Dict[str, HProfilePolicy] = {}

        def build(name: str, node: Dict[str, Any]) -> HProfilePolicy:
            rps = self._num(node.get('rps'), 5.0 if name == 'stealth' else (20.0 if name == 'normal' else 50.0))
            conc = int(node.get('concurrency') or (10 if name == 'stealth' else (25 if name == 'normal' else 60)))
            allow_cats = self._as_set(node.get('allow_categories') or (['xss', 'sqli'] if name == 'stealth' else (
                ['xss', 'sqli', 'ssrf', 'xxe', 'rce', 'nosqli', 'ssti', 'open_redirect'] if name == 'aggressive' else [
                    'xss', 'sqli', 'ssrf', 'ssti', 'open_redirect'])))
            idem = self._as_bool(node.get('idempotent_only'), name == 'stealth')
            oast = self._as_bool(node.get('oast', node.get('oast_enabled', False)), name == 'aggressive')
            heavy = self._as_bool(node.get('heavy_modules'), name == 'aggressive')
            robots = self._as_bool(node.get('robots_respect'), name != 'aggressive')
            polite = int(node.get('politeness_ms') or (800 if name == 'stealth' else (300 if name == 'normal' else 0)))
            obs = int(node.get('obs_seconds') or 60)
            min_req = int(node.get('min_req') or 40)
            up_below = self._num(node.get('up_when_block_rate_below'), 0.01 if name == 'stealth' else 0.005)
            down_above = self._num(node.get('down_when_block_rate_above'), 0.05 if name == 'aggressive' else 0.03)
            return HProfilePolicy(name, rps, conc, allow_cats, idem, oast, heavy, robots, polite, obs, min_req,
                                  up_below, down_above)

        # Varsayılan üçlü
        base = {
            'stealth': cfg.get('stealth') or {},
            'normal': cfg.get('normal') or {},
            'aggressive': cfg.get('aggressive') or (cfg.get('deep') or {}),
        }
        for k, node in base.items():
            pols[k] = build(k, node if isinstance(node, dict) else {})
        return pols

    # Timeline
    def _emit_event(self, etype: str, data: Dict[str, Any]) -> None:
        evt = {'t': time.time(), 'type': etype, **data}
        self._timeline.append(evt)
        add_result('profile_event', evt)

    def policy(self) -> HProfilePolicy:
        return self._policies[self._active]

    def name(self) -> str:
        return self._active

    # HTTP sinyalleri
    def record_status(self, status_code: int) -> None:
        self._req_count += 1
        if status_code in (429, 403):
            self._blocked_count += 1
        self._maybe_rotate()

    def _reset_window(self) -> None:
        self._req_count = 0
        self._blocked_count = 0
        self._window_start = time.monotonic()

    def _maybe_rotate(self) -> None:
        now = time.monotonic()
        elapsed = now - self._window_start
        pol = self.policy()
        if elapsed < float(pol.obs_seconds):
            return
        if self._req_count < pol.min_req:
            self._reset_window()
            return
        rate = 0.0 if self._req_count <= 0 else (self._blocked_count / float(self._req_count))

        # Geçiş kuralları:
        # AGGRESSIVE → NORMAL: blok oranı üst eşiğin üzerinde
        # NORMAL → STEALTH: blok oranı üst eşiğin üzerinde
        # STEALTH → NORMAL: blok oranı alt eşiğin altında
        # NORMAL → AGGRESSIVE: blok oranı çok düşük
        cur = self._active
        nxt = cur
        if cur == 'aggressive' and rate >= pol.down_when_block_rate_above:
            nxt = 'normal'
        elif cur == 'normal' and rate >= pol.down_when_block_rate_above:
            nxt = 'stealth'
        elif cur == 'stealth' and rate <= pol.up_when_block_rate_below:
            nxt = 'normal'
        elif cur == 'normal' and rate <= pol.up_when_block_rate_below:
            nxt = 'aggressive'

        if nxt != cur:
            old_pol = self.policy()
            self._active = nxt
            new_pol = self.policy()
            self._emit_event('profile_switch', {
                'from': cur,
                'to': nxt,
                'window_seconds': pol.obs_seconds,
                'req': self._req_count,
                'blocked': self._blocked_count,
                'block_rate': rate,
                'old_rps': old_pol.rps,
                'new_rps': new_pol.rps,
                'old_conc': old_pol.concurrency,
                'new_conc': new_pol.concurrency,
            })

        self._reset_window()


# ---- Global Tekil ----
_HPM: HProfileManager | None = None


# [AUTO-CLEANUP] removed duplicate def 'hpm_init_from_config' defined at lines 625-632


def hpm_bootstrap_from_file(path: str) -> None:
    import json, os
    with open(path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    hpm_init_from_config(data)


def hpm() -> HProfileManager:
    if _HPM is None:
        # Varsayılan boş yapı; kullanıcı init etmemişse minimum profille ayağa kalkar
        hpm_init_from_config({'settings': {'profiles': {}, 'scan_profile': 'normal'}})
    return _HPM  # type: ignore


# Kısa yardımcılar
# [AUTO-CLEANUP] removed duplicate def 'hpm_record_status' defined at lines 650-651


# [AUTO-CLEANUP] removed duplicate def 'hpm_current_policy' defined at lines 654-666


# ==== HPM Tekil Yönetici (imza-tabanlı başlatma; try/except yok) ====
import inspect as _inspect
from typing import Dict as _Dict, Any as _Any

_HPM: "HProfileManager | None" = globals().get("_HPM", None)


def _set_attr_if_present(obj, name: str, value) -> None:
    if hasattr(obj, name):
        setattr(obj, name, value)


def hpm_init_from_config(cfg: _Dict[str, _Any] | None) -> None:
    global _HPM
    settings = (cfg or {}).get("settings") or {}
    profiles = settings.get("profiles") or {}
    initial = str(settings.get("scan_profile") or "normal")

    sig = _inspect.signature(HProfileManager)
    params = [p for p in sig.parameters.values() if p.name != "self"]
    names = [p.name for p in params]

    if len(params) >= 2 or ({"profiles", "active"} <= set(names)):
        _HPM = HProfileManager(profiles, initial)  # type: ignore[arg-type]
        return

    if len(params) == 1 or ("profiles" in names and "active" not in names):
        _HPM = HProfileManager(profiles)  # type: ignore[arg-type]
        if hasattr(_HPM, "set_active") and callable(getattr(_HPM, "set_active")):
            _HPM.set_active(initial)  # type: ignore[attr-defined]
        else:
            _set_attr_if_present(_HPM, "active", initial)
            _set_attr_if_present(_HPM, "_active", initial)
        return

    _HPM = HProfileManager()  # type: ignore[call-arg]
    if hasattr(_HPM, "load_profiles") and callable(getattr(_HPM, "load_profiles")):
        _HPM.load_profiles(profiles)  # type: ignore[attr-defined]
    else:
        _set_attr_if_present(_HPM, "_policies", profiles)
        _set_attr_if_present(_HPM, "policies", profiles)
    if hasattr(_HPM, "set_active") and callable(getattr(_HPM, "set_active")):
        _HPM.set_active(initial)  # type: ignore[attr-defined]
    else:
        _set_attr_if_present(_HPM, "_active", initial)
        _set_attr_if_present(_HPM, "active", initial)


# [AUTO-CLEANUP] removed duplicate def 'hpm' defined at lines 717-721


def hpm_record_status(status_code: int) -> None:
    mgr = hpm()
    if hasattr(mgr, "record_status") and callable(getattr(mgr, "record_status")):
        mgr.record_status(int(status_code))  # type: ignore[attr-defined]


def hpm_current_policy() -> _Dict[str, _Any]:
    mgr = hpm()
    pol = None
    if hasattr(mgr, "policy") and callable(getattr(mgr, "policy")):
        pol = mgr.policy()  # type: ignore[attr-defined]

    def _get(obj, name: str, default):
        if obj is None:
            return default
        if isinstance(obj, dict):
            return obj.get(name, default)
        return getattr(obj, name, default)

    allow = _get(pol, "allow_categories", []) or []
    if not isinstance(allow, list):
        allow = list(allow)

    return {
        "name": _get(pol, "name", "normal"),
        "rps": _get(pol, "rps", 10.0),
        "concurrency": _get(pol, "concurrency", 10),
        "allow_categories": sorted(set(allow)),
        "idempotent_only": bool(_get(pol, "idempotent_only", True)),
        "oast": bool(_get(pol, "oast", False)),
        "heavy_modules": bool(_get(pol, "heavy_modules", False)),
        "robots_respect": bool(_get(pol, "robots_respect", True)),
        "politeness_ms": int(_get(pol, "politeness_ms", 300)),
    }

def run_mode(context: 'ScanContext', mode: str) -> 'Optional[Dict[str, Any]]':
    """
    NORMAL/DETAILED/DEEP: core.phases.build_plan + core.runner.run_plan (signature-aware).
    AUTHENTICATED: dış köprü + raporlama.
    """
    mode = (mode or "").strip().lower()
    if mode == "stealth":
        mode = ScanMode.NORMAL
    elif mode == "aggressive":
        mode = ScanMode.DEEP

    # Ensure session and target
    context.session = _ensure_session(getattr(context, "session", None))
    cfg = context.config or {}
    base_url = (getattr(context, "url", None) or cfg.get("base_url") or cfg.get("target") or "")
    if not base_url:
        _report("errors", {"stage": "run_mode", "error": "Target/base_url eksik"})
        _flush_report()
        _maybe_perform_reporting(context)
        return context.results

    # Non-authenticated modes
    if mode in (ScanMode.NORMAL, ScanMode.DETAILED, ScanMode.DEEP):
        context.detailed = (mode != ScanMode.NORMAL)

        # Resolve phases & runner
        pkg = (__package__ or "").strip()
        phases_mod = (_opt_import(f"{pkg}.phases") if pkg else None) or _opt_import("websecure.core.phases") or _opt_import("phases")
        runner_mod = (_opt_import(f"{pkg}.runner") if pkg else None) or _opt_import("websecure.core.runner") or _opt_import("runner")

        build_plan = getattr(phases_mod, "build_plan", None) if phases_mod else None
        run_plan_fn = getattr(runner_mod, "run_plan", None) if runner_mod else None

        if not callable(build_plan) or not callable(run_plan_fn):
            _report("errors", {"stage": "run_mode", "error": "Flow runner çözümlemesi başarısız (build_plan/run_plan yok)"})
            _flush_report()
            _maybe_perform_reporting(context)
            return context.results

        plan = build_plan(context)
        plan = __ensure_triple_plan(plan)

        loop = asyncio.get_event_loop_policy().get_event_loop()
        if loop.is_running():
            asyncio.create_task(__run_plan_adapt(run_plan_fn, plan, context, cfg))
        else:
            asyncio.run(__run_plan_adapt(run_plan_fn, plan, context, cfg))

        _flush_report()
        _maybe_perform_reporting(context)
        return context.results

    # Authenticated mode
    if mode == ScanMode.AUTHENTICATED:
        auth_runner = _resolve_auth_runner()
        if not callable(auth_runner):
            _report("errors", {"stage": "run_mode", "error": "Authenticated runner bulunamadı"})
            _flush_report()
            _maybe_perform_reporting(context)
            return context.results
        logger = logging.getLogger(__name__)
        auth_runner(context.session, base_url, cfg, logger=logger)
        _flush_report()
        _maybe_perform_reporting(context)
        return context.results

    _report("errors", {"stage": "run_mode", "error": f"desteklenmeyen mod: {mode}"})
    _flush_report()
    _maybe_perform_reporting(context)
    return context.results
