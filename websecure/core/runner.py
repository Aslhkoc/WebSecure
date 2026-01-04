from __future__ import annotations
from websecure.core.flow_runner import adjust_scan_mode
from websecure.core.reporting import get_bucket_results
import asyncio
from dataclasses import dataclass
from typing import List, Tuple, Awaitable, Callable, Optional, Dict, Any
import sys
import time
import asyncio
from .scan_modes import ScanContext
from websecure.core.reporting import log_info, log_warn, add_result, flush as _report_flush
from websecure.core.flow_runner import flush
from importlib.util import find_spec
from types import SimpleNamespace
from types import SimpleNamespace
import importlib

from typing import TYPE_CHECKING, Callable
if TYPE_CHECKING:
    from websecure.core.runner import run_plan as run_plan
# --------------------------- Dinamik import yardımcıları ---------------------------
def _missing_guard(symbol: str, where: str):
    def _raise(*_args, **_kwargs):
        raise RuntimeError(f"{symbol} kullanılabilir değil: {where} modülü/öğesi bulunamadı.")
    return _raise

def _import_first_available(module_names: list[str]):
    """İlk mevcut modül adını döndürür; hiçbiri yoksa None."""
    for name in module_names:
        if name and find_spec(name) is not None:
            return importlib.import_module(name)
    return None

_pkg = (__package__ or "").strip()

# --------------------------- flow_runner fonksiyonları ---------------------------
# Varsayılan: çağrılırsa NET hata versin (susturma yok)
_run_all = _missing_guard("run_all_extended", "flow_runner")
_run_plan_if_needed = _missing_guard("run_plan_if_needed", "flow_runner")
_flush_reporting = _missing_guard("flush_reporting", "flow_runner")

_flow_mod_candidates = []
if _pkg:
    _flow_mod_candidates.append(f"{_pkg}.flow_runner")
_flow_mod_candidates.append("core.flow_runner")

_flow_mod = _import_first_available(_flow_mod_candidates)
if _flow_mod is not None:
    if hasattr(_flow_mod, "run_all_extended"):
        _run_all = getattr(_flow_mod, "run_all_extended")
    if hasattr(_flow_mod, "run_plan_if_needed"):
        _run_plan_if_needed = getattr(_flow_mod, "run_plan_if_needed")
    if hasattr(_flow_mod, "flush_reporting"):
        _flush_reporting = getattr(_flow_mod, "flush_reporting")

# --------------------------- http.hardened_session ---------------------------
# Not: hardened oturum opsiyonel ise None bırakılabilir; zorunlu ise guard kullan.
_hardened_session = None

_http_mod_candidates = []
if _pkg:
    _http_mod_candidates.append(f"{_pkg}.http")
_http_mod_candidates.append("core.http")

_http_mod = _import_first_available(_http_mod_candidates)
if _http_mod is not None and hasattr(_http_mod, "hardened_session"):
    _hardened_session = getattr(_http_mod, "hardened_session")

# --------------------------- İptal/Kritik kontrol ---------------------------
def _is_cancelled(ctx: 'ScanContext') -> bool:
    if ctx is None:
        return False
    if bool(getattr(ctx, "cancelled", False)):
        return True
    shared = getattr(ctx, "shared", None)
    if isinstance(shared, dict) and bool(shared.get("critical_error", False)):
        return True
    return False

# --------------------------- Tipler ---------------------------
PhaseFn = Callable[[ScanContext], Awaitable[None]]
Plan = List[Tuple[str, int, PhaseFn]]  # (ad, tahmini_saniye, faz_fn)

@dataclass
class RunnerConfig:
    interactive: bool = False               # True ise 'ask' seçeneği input() ile sorulur
    on_timeout: str = "extend"              # "extend" | "retry" | "skip" | "ask"
    extend_factor: float = 1.5              # zaman aşımında yeni timeout = eski * faktor
    max_timeout_sec: int = 30 * 60          # tek faz için üst sınır
    max_retries: int = 1                    # zaman aşımı sonrası tekrar sayısı
    progress_cb: Optional[Callable[[str, str, Dict[str, Any]], None]] = None
    confirm_cb: Optional[Callable[[str, int, int, ScanContext], bool]] = None  # (faz_adı, deneme, timeout, ctx) -> extend?

# --------------------------- Yardımcılar ---------------------------
def _cfg_from_ctx(ctx: ScanContext) -> RunnerConfig:
    rcfg = ((getattr(ctx, "config", {}) or {}).get("runner") or {})
    return RunnerConfig(
        interactive=bool(rcfg.get("interactive", False)),
        on_timeout=str(rcfg.get("on_timeout", "extend")).lower(),
        extend_factor=float(rcfg.get("extend_factor", 1.5)),
        max_timeout_sec=int(rcfg.get("max_timeout_sec", 30*60)),
        max_retries=int(rcfg.get("max_retries", 1)),
        progress_cb=rcfg.get("progress_cb"),
        confirm_cb=rcfg.get("confirm_cb"),
    )
def _dynamic_estimate(name: str, base_est: int, ctx: ScanContext) -> int:
    est = int(base_est)
    lname = name.lower()
    if "injection" in lname:
        p = len((ctx.results or {}).get("detected_get_params") or [])
        f = len((ctx.results or {}).get("detected_forms") or [])
        est = base_est + 30 * (p if p > 0 else 1) + 20 * (1 if f > 0 else 0)
    elif "owasp" in lname:
        open_ports = (ctx.results or {}).get("open_ports") or []
        est = base_est + 10 * len(open_ports)
    # 60s–20m aralığına kelepçe
    return max(60, min(est, 20 * 60))

def _should_extend(name: str, attempt: int, timeout_sec: int, cfg: 'RunnerConfig', ctx: 'ScanContext') -> bool:
    # DIP: confirm_cb varsa karar oradan gelir (sorumluluk çağıranda; hata saklanmaz)
    if callable(getattr(cfg, "confirm_cb", None)):
        return bool(cfg.confirm_cb(name, attempt, timeout_sec, ctx))

    decision = getattr(cfg, "on_timeout", None)
    if decision == "ask" and getattr(cfg, "interactive", False):
        # Yalnızca gerçekten etkileşimli uçta sor
        if hasattr(sys, "stdin") and sys.stdin is not None and sys.stdin.isatty():
            ans = (input(f"[?] '{name}' zaman aşımına uğradı. Süreyi uzatalım mı? (E/h): ").strip().lower() or "")
            return not ans.startswith("h")
        # TTY yoksa “ask” mümkün değil → uzatma yok
        return False

    return decision in ("extend", "retry")


async def _run_phase_with_policy(name: str, base_est: int, phase: 'PhaseFn', ctx: 'ScanContext', cfg: 'RunnerConfig') -> None:
    est = _dynamic_estimate(name, base_est, ctx)
    attempts = 0

    # progress: start
    if callable(getattr(cfg, "progress_cb", None)):
        cfg.progress_cb("start", name, {"estimate_sec": est})

    t_phase_start = time.time()

    while True:
        # kritik/iptal kontrolü
        if _is_cancelled(ctx):
            add_result("meta", {"stage": "phase", "name": name, "status": "cancelled"})
            return

        log_info(f"\n[i] Aşama: {name}  (~{max(1, est // 60)} dk)")

        task = asyncio.create_task(phase(ctx))
        done, pending = await asyncio.wait({task}, timeout=est)

        # Zaman aşımı
        if pending:
            for t in pending:
                t.cancel()
            log_warn(f"Aşama '{name}' tahmini sürede bitmedi (timeout={est}s).")

            if attempts >= getattr(cfg, "max_retries", 0) or not _should_extend(name, attempts + 1, est, cfg, ctx):
                # progress: skipped
                if callable(getattr(cfg, "progress_cb", None)):
                    cfg.progress_cb("skipped", name, {"attempts": attempts, "reason": "timeout"})
                add_result("meta", {
                    "stage": "phase",
                    "name": name,
                    "status": "skipped_timeout",
                    "duration_sec": round(time.time() - t_phase_start, 2)
                })
                return

            # yeniden dene: deneme sayısını artır, süreyi yeniden değerlendir
            attempts += 1
            est = _dynamic_estimate(name, base_est, ctx)
            continue

        # Tamamlandı: sonucu değerlendir (hata saklama yok)
        finished = next(iter(done))
        exc = finished.exception()
        if exc is not None:
            # Hata durumunu rapora yaz ve yükselt (susturma yok)
            add_result("meta", {
                "stage": "phase",
                "name": name,
                "status": "error",
                "error": str(exc),
                "duration_sec": round(time.time() - t_phase_start, 2)
            })
            raise exc

        # Başarılı
        if callable(getattr(cfg, "progress_cb", None)):
            cfg.progress_cb("done", name, {"attempts": attempts})

        add_result("meta", {
            "stage": "phase",
            "name": name,
            "status": "done",
            "duration_sec": round(time.time() - t_phase_start, 2)
        })
        return

async def run_plan(plan: 'Plan', ctx: 'ScanContext', cfg: 'Dict'):
    """
    Planı sıralı ve politikaya bağlı timeout yönetimiyle çalıştırır.
    Hata saklama yok: faz içi hatalar 'meta: error' olarak rapora yazılır ve faz biter;
    run_plan try/except kullanmaz, böylece kontrol akışı sade ve deterministiktir.
    """
    # Plan G hook: profil ayarı (rapor metriklerine göre)
    _ = adjust_scan_mode(get_bucket_results(), cfg)

    cfg_local = _cfg_from_ctx(ctx)
    for (name, base_est, phase) in plan:
        if _is_cancelled(ctx):
            add_result("meta", {"stage": "phase", "name": name, "status": "cancelled"})
            _report_flush() # sonuç kovalarını/phase izini kayda geç
            return
        # Fazın kendi içinde timeout/hata durumları rapora işlenir;
        await _run_phase_with_policy(name, base_est, phase, ctx, cfg_local)



# === PATCH: WebSecure Upgrade (auto-applied) @ 2025-09-07T16:53:43.705200 ===

# Politikalar: hata yönetimi + iptal
from typing import Literal, cast
import signal

ErrorPolicy = Literal["continue","skip","stop","ask"]

@dataclass
class _ExtendedRunnerConfig(RunnerConfig):
    on_error: ErrorPolicy = "continue"   # continue | skip | stop | ask
    cancel_on_sigint: bool = True

def _cfg_extend(cfg: RunnerConfig, ctx: ScanContext) -> _ExtendedRunnerConfig:
    rcfg = ((getattr(ctx, "config", {}) or {}).get("runner") or {})
    return _ExtendedRunnerConfig(
        **cfg.__dict__,
        on_error=str(rcfg.get("on_error","continue")).lower(),
        cancel_on_sigint=bool(rcfg.get("cancel_on_sigint", True)),
    )
import sys
import time
import asyncio
import signal
import threading

def _install_cancel_hook(enabled: bool):
    if not enabled:
        return lambda: None

    # Sadece ana thread ve SIGINT mevcutsa kanca kur.
    is_main_thread = threading.current_thread() is threading.main_thread()
    has_sigint = hasattr(signal, "SIGINT") and callable(getattr(signal, "signal", None))
    if not (is_main_thread and has_sigint):
        return lambda: None

    cancelled = {"val": False}

    def _mark(_signum, _frame):
        cancelled["val"] = True  # Yerel bayrak; iptal kontrolünüz ctx tarafında ilerliyor.

    old = signal.getsignal(signal.SIGINT) if hasattr(signal, "getsignal") else None
    signal.signal(signal.SIGINT, _mark)

    def _restore():
        if old is not None and is_main_thread and has_sigint:
            signal.signal(signal.SIGINT, old)

    return _restore


_EXPORTS = ("run", "run_many", "run_plan")
__all__ = [name for name in _EXPORTS if name in globals()]



# Yardımcı: bir fonksiyonun beklenen modülden gelip gelmediğini doğrula
def _is_from_modules(fn, *expected_modules: str) -> bool:
    if fn is None:
        return False
    modname = getattr(fn, "__module__", "") or ""
    # hem "core.flow_runner" gibi tam ad hem de ".flow_runner" soneki desteklenir
    return any(modname == m or modname.endswith(f".{m.split('.')[-1]}") for m in expected_modules)

# --------------------------- Context Kurulumu ---------------------------
def _resolve_url_from_target(target, cfg) -> str | None:
    # target içinden url çıkar
    if isinstance(target, str):
        return target
    if isinstance(target, dict):
        return target.get("url") or target.get("base_url") or target.get("target")
    # nesne benzeri
    url = getattr(target, "url", None) or getattr(target, "base_url", None) or getattr(target, "target", None)
    if url:
        return url
    # cfg içinden yedek
    if isinstance(cfg, dict):
        return cfg.get("base_url") or cfg.get("target")
    return getattr(cfg, "base_url", None) or getattr(cfg, "target", None)

def _build_ctx(target, cfg, session=None, debug=False):
    url = _resolve_url_from_target(target, cfg)
    if not url:
        log_warn("hedef URL çıkarılamadı: target/cfg içinde 'url' ya da 'base_url' yok")
    # mevcut session yoksa ve gerçek hardened_session varsa kur
    sess = session
    if sess is None and callable(_hardened_session) and _is_from_modules(_hardened_session, "core.http", "http"):
        sess = _hardened_session(cfg)
    ctx = SimpleNamespace(url=url, base_url=url, session=sess, config=(cfg or {}), results={}, debug=bool(debug))
    return ctx

# --------------------------- Koşucu Köprüleri ---------------------------
def _flow_runner_available() -> bool:
    # Tekrar import etmeden, fonksiyonun gerçekten flow_runner modülünden gelip gelmediğini kontrol et
    return (
        _is_from_modules(_run_plan_if_needed, "core.flow_runner", "flow_runner")
        or _is_from_modules(_run_all, "core.flow_runner", "flow_runner")
        or _is_from_modules(_flush_reporting, "core.flow_runner", "flow_runner")
    )

def run(target, cfg, *, session=None, debug=False, event_cb=None):
    """Sadece faz planını çalıştırır; mükerrer tarama yok."""
    # Önce bağlamı kur, sonra oturumu garanti altına al
    ctx = _build_ctx(target, cfg, session=session, debug=debug)
    _ensure_session(ctx)

    # Plan çalıştırma (tüm fazlar + rapor)
    if _is_from_modules(_run_plan_if_needed, "core.flow_runner", "flow_runner") and callable(_run_plan_if_needed):
        _run_plan_if_needed(ctx, event_cb=event_cb)
    else:
        log_warn("run_plan_if_needed mevcut değil (flow_runner bulunamadı).")

    # Raporu diske yazdır (susturma yok)
    _flush_reporting(ctx)
    return getattr(ctx, "results", None)



def run_many(targets, cfg, *, session=None, debug=False, event_cb=None, progress_cb=None):
    """Birden çok hedefi sırayla koşturur (seri); hata yutma yok."""
    results = []
    for idx, t in enumerate(list(targets or [])):
        if callable(progress_cb):
            progress_cb("start", {"index": idx, "target": t})
        res = run(t, cfg, session=session, debug=debug, event_cb=event_cb)
        results.append({"target": t, "results": res})
        if callable(progress_cb):
            progress_cb("end", {"index": idx, "target": t})
    return results

def _dyn_profile_update(stats: dict, current: str) -> str:
    p = (current or "NORMAL").upper()
    four = int(stats.get("403",0)) + int(stats.get("429",0))
    ok = int(stats.get("2xx",0))
    if four >= 5:
        if p == "AGGRESSIVE": return "NORMAL"
        if p == "NORMAL": return "STEALTH"
    if ok >= 20 and four == 0:
        if p == "STEALTH": return "NORMAL"
        if p == "NORMAL": return "AGGRESSIVE"
    return p


def _maybe_adjust_profile(current: str) -> str:
    pkg = (__package__ or "").strip()
    candidates = []
    if pkg:
        candidates.append(f"{pkg}.http")   # yerel paket
    candidates.append("core.http")         # proje içi çekirdek
    candidates.append("http")              # düz ad (legacy)

    http_mod = None
    for name in candidates:
        if find_spec(name) is not None:
            http_mod = importlib.import_module(name)
            break

    if http_mod is None or not hasattr(http_mod, "get_http_metrics"):
        log_warn("get_http_metrics yok; profil ayarı değiştirilmedi.")
        return current

    stats = http_mod.get_http_metrics()    # hata varsa yükselir; saklama yok
    return _dyn_profile_update(stats, current)



# -- Compatibility wrapper: accept (plan, ctx) or (plan, ctx, cfg) --
def run_plan_adapt(*args, _run_plan=None, **kwargs):

    import inspect

    # 1) run_plan hedefini çağrı anında çöz
    rp = _run_plan if _run_plan is not None else globals().get("run_plan")
    if rp is None or not callable(rp):
        raise RuntimeError("run_plan not available in current module scope")

    # 2) Argümanları tek noktadan çıkar
    plan = kwargs.get("plan", args[0] if len(args) > 0 else None)
    ctx  = kwargs.get("ctx",  args[1] if len(args) > 1 else None)
    cfg  = kwargs.get("cfg",  args[2] if len(args) > 2 else getattr(ctx, "config", None))

    # 3) İmzaya göre çağır
    params = list(inspect.signature(rp).parameters.values())
    if len(params) >= 3:
        return rp(plan, ctx, cfg)
    elif len(params) == 2:
        return rp(plan, ctx)
    else:
        # Olağandışı durum: beklenmeyen imza
        return rp()

def _ensure_session(ctx):
    from websecure.core.http import build_session
    if getattr(ctx, "session", None) is None:
        cfg = getattr(ctx, "config", {}) or {}
        ctx.session = build_session(cfg)
    return ctx.session
