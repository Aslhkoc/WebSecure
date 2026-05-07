"""
websecure.core.scan_runner
~~~~~~~~~~~~~~~~~~~~~~~~~~~
Scanner orchestration yardımcıları.
`_call_scanner_if_available()` ve `_bind_offensive()` main.py'den taşındı.

FAZ 4.2: main.py'den ayrıştırıldı.
FAZ 16 : checkpoint + ETA entegrasyonu eklendi.

Geriye dönük uyumluluk: main.py bu modülden import edip re-export eder.
"""
from __future__ import annotations

import importlib
import importlib.util
import inspect
import logging
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Checkpoint & ETA — lazy import (isteğe bağlı bağımlılıklar)
# ---------------------------------------------------------------------------

def _import_checkpoint():
    """checkpoint modülünü lazy olarak import eder."""
    try:
        from websecure.core.checkpoint import (
            make_checkpoint,
            CheckpointHook,
            get_manager,
        )
        return make_checkpoint, CheckpointHook, get_manager
    except ImportError as exc:
        logger.debug(f"[scan_runner] checkpoint modülü yüklenemedi: {exc!r}")
        return None, None, None


def _import_eta():
    """ETACalculator'ı lazy olarak import eder."""
    try:
        from websecure.core.concurrency import ETACalculator
        return ETACalculator
    except ImportError as exc:
        logger.debug(f"[scan_runner] ETACalculator yüklenemedi: {exc!r}")
        return None


# ---------------------------------------------------------------------------
# Modül keşif yardımcısı
# ---------------------------------------------------------------------------

def _spec_exists(name: str):
    """Modülün import edilebilir olup olmadığını kontrol eder (None veya ModuleSpec döner)."""
    try:
        return importlib.util.find_spec(name)
    except (ImportError, ModuleNotFoundError, AttributeError, ValueError):
        return None


# ---------------------------------------------------------------------------
# Scanner çağırma
# ---------------------------------------------------------------------------

def _call_scanner_if_available(
    mod_name: str,
    url: str,
    session=None,
    debug: bool = False,
    auth_ctx=None,
) -> Any:
    """
    Bir scanner modülünü dinamik olarak yükler ve `run()` fonksiyonunu çağırır.
    Modül bulunamazsa `None` döner — hata fırlatmaz.

    Parametre keşfi: `inspect.signature` ile `run()` imzasına bakılır;
    sadece desteklenen parametreler iletilir.

    FAZ 4.2: main.py:906'dan taşındı.
    """
    spec = _spec_exists(mod_name)
    mod = None

    if spec is not None:
        try:
            mod = importlib.import_module(mod_name)
        except ImportError as exc:
            logger.warning(f"[scan_runner] {mod_name} import edilemedi: {exc!r}")
            return None
    else:
        # Fallback: "websecure.scanners.xxx" → "scanners.xxx" → "xxx"
        if "." in mod_name:
            fallback = mod_name.split(".", 1)[1]
            fb_spec = _spec_exists(fallback)
            if fb_spec is not None:
                try:
                    mod = importlib.import_module(fallback)
                except ImportError as exc:
                    logger.debug(f"[scan_runner] {fallback} fallback import başarısız: {exc!r}")

    if mod is None:
        logger.debug(f"[scan_runner] Modül bulunamadı, atlanıyor: {mod_name}")
        return None

    run_fn = getattr(mod, "run", None)
    if not callable(run_fn):
        logger.debug(f"[scan_runner] {mod_name}.run() çağrılabilir değil")
        return None

    try:
        sig = inspect.signature(run_fn)
        params = sig.parameters
    except (TypeError, ValueError) as exc:
        logger.warning(f"[scan_runner] {mod_name}.run() imzası alınamadı: {exc!r}")
        return None

    kw: dict = {}
    if "url" in params:
        kw["url"] = url
    if "session" in params:
        kw["session"] = session
    if "debug" in params:
        kw["debug"] = debug
    if "auth_ctx" in params:
        kw["auth_ctx"] = auth_ctx

    try:
        return run_fn(**kw)
    except Exception as exc:
        logger.error(f"[scan_runner] {mod_name}.run() çalışırken hata: {exc!r}", exc_info=True)
        return None


# ---------------------------------------------------------------------------
# Offensive scanner bağlama
# ---------------------------------------------------------------------------

def _bind_offensive(modname: str, fallback_name: str) -> Callable:
    """
    Bir offensive scanner modülünü yükler ve `run` fonksiyonunu döner.
    Modül yoksa veya `run` bulunamazsa, sessiz bir no-op fallback döner.

    FAZ 4.2: main.py:938'den taşındı.
    """
    fn: Optional[Callable] = None

    if _spec_exists(modname) is not None:
        try:
            _m = importlib.import_module(modname)
            _r = getattr(_m, "run", None)
            if callable(_r):
                fn = _r
            else:
                logger.debug(f"[scan_runner] {modname}.run() bulunamadı veya çağrılabilir değil")
        except ImportError as exc:
            logger.debug(f"[scan_runner] {modname} import edilemedi: {exc!r}")

    if fn is None:
        def _fallback(*a, **k):
            return None

        _fallback.__name__ = fallback_name
        return _fallback

    return fn


# ---------------------------------------------------------------------------
# ScanSession — Tarama oturum yöneticisi (checkpoint + ETA birleştirici)
# ---------------------------------------------------------------------------

class ScanSession:
    """
    Tek bir tarama oturumunu temsil eden orkestrasyon sınıfı.

    Sorumluluklar
    -------------
    * Checkpoint oluşturma / yükleme / otomatik kaydetme
    * ETA (Tahmini Bitiş Süresi) hesaplama ve loglama
    * Modül bazlı ilerleme takibi
    * Önceki taramadan devam (resume) desteği

    Kullanım
    --------
    ```python
    session = ScanSession.new("https://example.com", profile="aggressive")
    # veya devam:
    session = ScanSession.resume_from("scan-id-abc123")

    with session:
        for url in urls:
            result = do_scan(url)
            session.on_task_done(task_hash, duration_s=elapsed)
        session.on_module_done("sqli")
    ```
    """

    def __init__(
        self,
        scan_id: str,
        target: str,
        profile: str,
        total_tasks: int = 0,
        checkpoint_enabled: bool = True,
        checkpoint_dir: Optional[Path] = None,
        auto_save_interval_s: float = 60.0,
        log_interval_s: float = 120.0,
    ) -> None:
        self.scan_id = scan_id
        self.target = target
        self.profile = profile

        make_cp, CheckpointHook, _ = _import_checkpoint()
        ETACalc = _import_eta()

        # Checkpoint
        if make_cp is not None and checkpoint_enabled:
            self._checkpoint = make_cp(
                scan_id=scan_id,
                target=target,
                profile=profile,
                checkpoint_dir=checkpoint_dir,
                auto_save_interval_s=auto_save_interval_s,
                enabled=True,
            )
        else:
            try:
                from websecure.core.checkpoint import NoopCheckpoint
                self._checkpoint = NoopCheckpoint(scan_id=scan_id)
            except ImportError:
                self._checkpoint = None  # type: ignore[assignment]

        # ETA
        self._eta = None
        if ETACalc is not None and total_tasks > 0:
            try:
                self._eta = ETACalc(total_tasks=total_tasks)
            except Exception:
                pass

        # Hook
        self._hook = None
        if CheckpointHook is not None and self._checkpoint is not None:
            self._hook = CheckpointHook(
                checkpoint=self._checkpoint,
                eta_calculator=self._eta,
                log_interval_s=log_interval_s,
            )
            self._checkpoint.set_total_tasks(total_tasks)

        # Arka plan tick thread'i
        self._tick_stop = threading.Event()
        self._tick_thread: Optional[threading.Thread] = None

    # ------------------------------------------------------------------
    # Fabrika metotları
    # ------------------------------------------------------------------

    @classmethod
    def new(
        cls,
        target: str,
        profile: str = "default",
        total_tasks: int = 0,
        checkpoint_enabled: bool = True,
        checkpoint_dir: Optional[Path] = None,
    ) -> "ScanSession":
        """Yeni bir tarama oturumu başlatır."""
        scan_id = _generate_scan_id()
        session = cls(
            scan_id=scan_id,
            target=target,
            profile=profile,
            total_tasks=total_tasks,
            checkpoint_enabled=checkpoint_enabled,
            checkpoint_dir=checkpoint_dir,
        )
        logger.info(f"[scan_runner] Yeni oturum başlatıldı: {scan_id}  →  {target}")
        return session

    @classmethod
    def resume_from(
        cls,
        scan_id: str,
        deduplicator: Any = None,
        checkpoint_dir: Optional[Path] = None,
    ) -> Optional["ScanSession"]:
        """
        Mevcut bir taramayı kaldığı yerden devam ettirir.

        Parameters
        ----------
        scan_id      : Devam edilecek tarama ID'si
        deduplicator : ScanDeduplicator (varsa tamamlanan görevler enjekte edilir)
        checkpoint_dir : Checkpoint dizini

        Returns
        -------
        ScanSession veya None (checkpoint bulunamazsa)
        """
        _, _, get_mgr = _import_checkpoint()
        if get_mgr is None:
            logger.warning("[scan_runner] Checkpoint modülü yüklü değil, resume imkânsız.")
            return None

        manager = get_mgr(checkpoint_dir=checkpoint_dir)
        state = manager.resume(scan_id, deduplicator) if deduplicator else None

        cp = manager.get(scan_id)
        if cp is None:
            return None

        s = cp.state
        session = cls(
            scan_id=scan_id,
            target=s.target,
            profile=s.profile,
            total_tasks=s.total_tasks,
            checkpoint_enabled=True,
            checkpoint_dir=checkpoint_dir,
        )
        # Mevcut checkpoint'i kullan
        session._checkpoint = cp  # noqa: SLF001
        if session._hook is not None:
            session._hook._cp = cp  # noqa: SLF001

        logger.info(
            f"[scan_runner] Devam ediliyor: {scan_id}  "
            f"%{s.progress_pct:.1f} daha önce tamamlandı  "
            f"({s.completed_count}/{s.total_tasks} görev)"
        )
        return session

    # ------------------------------------------------------------------
    # Context manager
    # ------------------------------------------------------------------

    def __enter__(self) -> "ScanSession":
        self._start_tick_thread()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self._stop_tick_thread()
        if self._hook:
            self._hook.on_scan_complete()

    # ------------------------------------------------------------------
    # Olay callback'leri
    # ------------------------------------------------------------------

    def on_task_done(self, task_hash: str, duration_s: float = 0.0) -> None:
        """Bir görev tamamlandığında çağır."""
        if self._hook:
            self._hook.on_task_done(task_hash, duration_s)

    def on_module_done(self, module: str) -> None:
        """Bir modül bittiğinde çağır."""
        if self._hook:
            self._hook.on_module_done(module)

    def save_now(self) -> None:
        """Anında checkpoint kaydet."""
        if self._checkpoint:
            self._checkpoint.save(force=True)

    def add_finding(self, key: str, finding: Any) -> None:
        """Bulgu ekle ve checkpoint'e yaz."""
        if self._checkpoint:
            self._checkpoint.add_finding(key, finding)

    def eta_snapshot(self) -> Dict[str, Any]:
        """ETA anlık görüntüsü döner (ETA yoksa boş dict)."""
        if self._eta is None:
            return {}
        try:
            return self._eta.snapshot()
        except Exception:
            return {}

    def progress(self) -> Dict[str, Any]:
        """İlerleme bilgisi döner."""
        if self._checkpoint is None:
            return {}
        s = self._checkpoint.state
        info: Dict[str, Any] = {
            "scan_id":         self.scan_id,
            "target":          self.target,
            "profile":         self.profile,
            "progress_pct":    round(s.progress_pct, 1),
            "completed_count": s.completed_count,
            "total_tasks":     s.total_tasks,
            "elapsed_seconds": round(s.elapsed_seconds, 1),
        }
        info.update(self.eta_snapshot())
        return info

    # ------------------------------------------------------------------
    # Arka plan tick
    # ------------------------------------------------------------------

    def _start_tick_thread(self) -> None:
        if self._hook is None:
            return
        self._tick_stop.clear()
        self._tick_thread = threading.Thread(
            target=self._tick_loop,
            name=f"cp-tick-{self.scan_id[:8]}",
            daemon=True,
        )
        self._tick_thread.start()

    def _stop_tick_thread(self) -> None:
        self._tick_stop.set()
        if self._tick_thread and self._tick_thread.is_alive():
            self._tick_thread.join(timeout=5)

    def _tick_loop(self) -> None:
        while not self._tick_stop.is_set():
            time.sleep(10)
            if self._hook:
                try:
                    self._hook.tick()
                except Exception as exc:
                    logger.debug(f"[scan_runner] tick hatası: {exc!r}")


# ---------------------------------------------------------------------------
# Yardımcı fonksiyonlar
# ---------------------------------------------------------------------------

def _generate_scan_id() -> str:
    """Kısa, benzersiz tarama kimliği üretir."""
    return uuid.uuid4().hex[:12]


def list_checkpoints(checkpoint_dir: Optional[Path] = None) -> List[Dict[str, Any]]:
    """
    Kaydedilmiş tüm checkpoint'leri listeler.

    Returns
    -------
    List[Dict] — scan_id, target, profile, progress_pct, saved_at vb.
    """
    _, _, get_mgr = _import_checkpoint()
    if get_mgr is None:
        return []
    return get_mgr(checkpoint_dir=checkpoint_dir).list_checkpoints()


def cleanup_checkpoints(
    max_age_days: int = 7,
    checkpoint_dir: Optional[Path] = None,
) -> int:
    """Eski checkpoint dosyalarını temizler. Silinen dosya sayısını döner."""
    _, _, get_mgr = _import_checkpoint()
    if get_mgr is None:
        return 0
    return get_mgr(checkpoint_dir=checkpoint_dir).cleanup(max_age_days)


__all__ = [
    # Orijinal yardımcılar
    "_call_scanner_if_available",
    "_bind_offensive",
    # Yeni: oturum yönetimi
    "ScanSession",
    "list_checkpoints",
    "cleanup_checkpoints",
    "_generate_scan_id",
]
