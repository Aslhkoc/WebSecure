"""
websecure.core.checkpoint
~~~~~~~~~~~~~~~~~~~~~~~~~
Tarama durumu kaydetme / devam ettirme (Checkpoint & Resume) sistemi.

Özellikler
----------
* **CheckpointState** — Atomik JSON serileştirme, dataclass tabanlı durum.
* **ScanCheckpoint** — Tek bir tarama için kaydet/yükle işlemleri.
  - Atomik yazma: temp dosya oluştur -> rename (POSIX + Windows).
  - Otomatik kaydetme aralığı (auto_save_interval_s).
* **CheckpointManager** — Çok-tarama yönetimi: liste, temizleme, devam.
  - `resume(scan_id, deduplicator)` -> ScanDeduplicator'a tamamlanan
    görev hash'lerini enjekte eder; tarama kaldığı yerden devam eder.
* **CheckpointHook** — scan_runner ile entegrasyon için callback arayüzü.

SOLID
-----
- SRP: Her sınıf tek sorumlu.
- OCP: `CheckpointSerializer` soyut — gelecekte Protobuf/MessagePack desteği.
- LSP: `NoopCheckpoint` aynı arayüzü implement eder.
- ISP: `Saveable` / `Loadable` ayrı protocol.
- DIP: `CheckpointManager`, soyut `CheckpointSerializer` alır.
"""
from __future__ import annotations

import json
import logging
import os
import shutil
import tempfile
import threading
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, FrozenSet, List, Optional, Set

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Sabitler
# ---------------------------------------------------------------------------

_DEFAULT_CHECKPOINT_DIR = Path.home() / ".websecure" / "checkpoints"
_CHECKPOINT_EXT = ".chk.json"
_TEMP_EXT = ".tmp"
_MAX_CHECKPOINT_AGE_DAYS = 7
_AUTO_SAVE_INTERVAL_S = 60          # varsayılan otomatik kaydetme: 60 sn
_FORMAT_VERSION = "1.0"


# ---------------------------------------------------------------------------
# CheckpointState — Tarama durumu veri modeli
# ---------------------------------------------------------------------------

@dataclass
class CheckpointState:
    """
    Bir taramanın anlık durumunu temsil eden veri sınıfı.

    Alanlar
    -------
    scan_id          : str
        Taramayı benzersiz tanımlayan UUID/kısa kimlik.
    target           : str
        Taranan hedef URL.
    profile          : str
        Kullanılan profil adı (örn. "aggressive", "stealth").
    started_at       : str
        ISO-8601 başlangıç zamanı (UTC).
    saved_at         : str
        Son kaydetme zamanı (UTC), her save() çağrısında güncellenir.
    completed_tasks  : List[str]
        Tamamlanan görev hash'leri listesi (ScanDeduplicator fingerprint'leri).
    completed_modules: List[str]
        Tamamen biten modül isimleri.
    pending_urls     : List[str]
        Henüz taranmamış URL'ler.
    findings         : Dict[str, Any]
        Şimdiye kadar bulunan bulgular (seri hale getirilebilir dict).
    total_tasks      : int
        Toplam görev sayısı (ETA hesabı için).
    completed_count  : int
        Tamamlanan görev sayısı.
    elapsed_seconds  : float
        Toplam geçen süre (saniye).
    format_version   : str
        Checkpoint formatı versiyonu — geriye dönük uyumluluk.
    extra            : Dict[str, Any]
        Genişletilebilir metadata alanı.
    """

    scan_id: str
    target: str
    profile: str
    started_at: str = field(default_factory=lambda: _utc_now())
    saved_at: str = field(default_factory=lambda: _utc_now())

    # Görev takibi
    completed_tasks: List[str] = field(default_factory=list)
    completed_modules: List[str] = field(default_factory=list)
    pending_urls: List[str] = field(default_factory=list)

    # Bulgular
    findings: Dict[str, Any] = field(default_factory=dict)

    # İlerleme
    total_tasks: int = 0
    completed_count: int = 0
    elapsed_seconds: float = 0.0

    # Meta
    format_version: str = _FORMAT_VERSION
    extra: Dict[str, Any] = field(default_factory=dict)

    # ------------------------------------------------------------------ #
    # Progress helpers
    # ------------------------------------------------------------------ #

    @property
    def progress_pct(self) -> float:
        """0-100 arası ilerleme yüzdesi."""
        if self.total_tasks <= 0:
            return 0.0
        return min(100.0, self.completed_count / self.total_tasks * 100.0)

    @property
    def completed_tasks_set(self) -> FrozenSet[str]:
        """Hızlı arama için frozen set."""
        return frozenset(self.completed_tasks)

    # ------------------------------------------------------------------ #
    # Seri hale getirme
    # ------------------------------------------------------------------ #

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["saved_at"] = _utc_now()
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CheckpointState":
        # Bilinmeyen alanları 'extra'ya taşı; forward-compatible
        known = {f.name for f in cls.__dataclass_fields__.values()}  # type: ignore[attr-defined]
        extra = {k: v for k, v in data.items() if k not in known}
        filtered = {k: v for k, v in data.items() if k in known}
        if extra:
            filtered.setdefault("extra", {}).update(extra)
        return cls(**filtered)

    def mark_task_done(self, task_hash: str) -> None:
        """Bir görevi tamamlandı olarak işaretle."""
        if task_hash not in self.completed_tasks_set:
            self.completed_tasks.append(task_hash)
            self.completed_count += 1

    def mark_module_done(self, module: str) -> None:
        if module not in self.completed_modules:
            self.completed_modules.append(module)

    def update_elapsed(self, started_ts: float) -> None:
        self.elapsed_seconds = time.monotonic() - started_ts


# ---------------------------------------------------------------------------
# Serializer — Strateji Deseni
# ---------------------------------------------------------------------------

class CheckpointSerializer(ABC):
    """Checkpoint serileştirme stratejisi (OCP / DIP)."""

    @abstractmethod
    def dumps(self, state: CheckpointState) -> bytes:
        ...

    @abstractmethod
    def loads(self, data: bytes) -> CheckpointState:
        ...


class JsonCheckpointSerializer(CheckpointSerializer):
    """JSON tabanlı serileştirici (varsayılan)."""

    def dumps(self, state: CheckpointState) -> bytes:
        return json.dumps(state.to_dict(), indent=2, ensure_ascii=False).encode("utf-8")

    def loads(self, data: bytes) -> CheckpointState:
        raw = json.loads(data.decode("utf-8"))
        _migrate(raw)
        return CheckpointState.from_dict(raw)


def _migrate(raw: Dict[str, Any]) -> None:
    """Eski format versiyonlarını güncel formata dönüştürür."""
    ver = raw.get("format_version", "0.0")
    if ver == "0.0":
        # v0 -> v1: 'done_hashes' -> 'completed_tasks'
        if "done_hashes" in raw and "completed_tasks" not in raw:
            raw["completed_tasks"] = raw.pop("done_hashes")
        raw["format_version"] = "1.0"


# ---------------------------------------------------------------------------
# ScanCheckpoint — Tek tarama için kaydet/yükle
# ---------------------------------------------------------------------------

class ScanCheckpoint:
    """
    Tek bir taramaya ait checkpoint dosyasını yönetir.

    Kullanım
    --------
    ```python
    cp = ScanCheckpoint(scan_id="abc123", target="https://example.com",
                        profile="stealth")
    cp.save()        # diske yazar
    state = cp.load()  # diskten yükler
    ```
    """

    def __init__(
        self,
        scan_id: str,
        target: str,
        profile: str,
        checkpoint_dir: Optional[Path] = None,
        serializer: Optional[CheckpointSerializer] = None,
        auto_save_interval_s: float = _AUTO_SAVE_INTERVAL_S,
    ) -> None:
        self.scan_id = scan_id
        self._checkpoint_dir = Path(checkpoint_dir or _DEFAULT_CHECKPOINT_DIR)
        self._serializer = serializer or JsonCheckpointSerializer()
        self.auto_save_interval_s = auto_save_interval_s

        self._state = CheckpointState(
            scan_id=scan_id,
            target=target,
            profile=profile,
        )
        self._path: Path = self._checkpoint_dir / f"{scan_id}{_CHECKPOINT_EXT}"
        self._lock = threading.Lock()
        self._last_save: float = 0.0
        self._start_ts: float = time.monotonic()

        self._checkpoint_dir.mkdir(parents=True, exist_ok=True)
        logger.debug(f"[checkpoint] Checkpoint dizini: {self._checkpoint_dir}")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @property
    def state(self) -> CheckpointState:
        return self._state

    @property
    def path(self) -> Path:
        return self._path

    def save(self, force: bool = False) -> bool:
        """
        Durumu diske atomik olarak yazar.

        Parameters
        ----------
        force : bool
            True ise `auto_save_interval_s` kontrolü atlanır.

        Returns
        -------
        bool
            Dosya yazıldıysa True, atlandıysa False.
        """
        now = time.monotonic()
        if not force and (now - self._last_save) < self.auto_save_interval_s:
            return False

        with self._lock:
            self._state.update_elapsed(self._start_ts)
            data = self._serializer.dumps(self._state)
            _atomic_write(self._path, data)
            self._last_save = time.monotonic()

        logger.info(
            f"[checkpoint] Kaydedildi -> {self._path.name}  "
            f"(%{self._state.progress_pct:.1f}  "
            f"{self._state.completed_count}/{self._state.total_tasks} görev)"
        )
        return True

    def load(self) -> Optional[CheckpointState]:
        """
        Diskten checkpoint yükler. Dosya yoksa None döner.
        """
        if not self._path.exists():
            return None
        try:
            data = self._path.read_bytes()
            state = self._serializer.loads(data)
            self._state = state
            logger.info(
                f"[checkpoint] Yüklendi <- {self._path.name}  "
                f"(%{state.progress_pct:.1f}  "
                f"{state.completed_count}/{state.total_tasks} görev)"
            )
            return state
        except Exception as exc:
            logger.error(f"[checkpoint] Yükleme hatası ({self._path}): {exc!r}")
            return None

    def delete(self) -> bool:
        """Checkpoint dosyasını siler."""
        try:
            self._path.unlink(missing_ok=True)
            logger.debug(f"[checkpoint] Silindi: {self._path.name}")
            return True
        except OSError as exc:
            logger.warning(f"[checkpoint] Silinemedi: {exc!r}")
            return False

    # ------------------------------------------------------------------
    # Kısayol mutators (thread-safe)
    # ------------------------------------------------------------------

    def mark_task_done(self, task_hash: str) -> None:
        with self._lock:
            self._state.mark_task_done(task_hash)

    def mark_module_done(self, module: str) -> None:
        with self._lock:
            self._state.mark_module_done(module)

    def set_total_tasks(self, n: int) -> None:
        with self._lock:
            self._state.total_tasks = n

    def add_finding(self, key: str, finding: Any) -> None:
        with self._lock:
            self._state.findings[key] = finding

    def set_pending_urls(self, urls: List[str]) -> None:
        with self._lock:
            self._state.pending_urls = list(urls)

    def maybe_autosave(self) -> bool:
        """Otomatik kaydetme aralığı dolduysa kaydet."""
        return self.save(force=False)


# ---------------------------------------------------------------------------
# NoopCheckpoint — Checkpoint devre dışıyken sessiz fallback
# ---------------------------------------------------------------------------

class NoopCheckpoint:
    """
    Checkpoint sistemi istenilmediğinde kullanılır.
    ScanCheckpoint ile aynı arayüzü sunar — hiçbir şey yazmaz.
    """

    def __init__(self, scan_id: str = "", **_kw) -> None:
        self.scan_id = scan_id
        self._state = CheckpointState(
            scan_id=scan_id, target="", profile=""
        )

    @property
    def state(self) -> CheckpointState:
        return self._state

    @property
    def path(self) -> Path:
        return Path(os.devnull)

    def save(self, force: bool = False) -> bool:
        return False

    def load(self) -> None:
        return None

    def delete(self) -> bool:
        return True

    def mark_task_done(self, task_hash: str) -> None:
        pass

    def mark_module_done(self, module: str) -> None:
        pass

    def set_total_tasks(self, n: int) -> None:
        pass

    def add_finding(self, key: str, finding: Any) -> None:
        pass

    def set_pending_urls(self, urls: List[str]) -> None:
        pass

    def maybe_autosave(self) -> bool:
        return False


# ---------------------------------------------------------------------------
# CheckpointManager — Çok-tarama yönetimi
# ---------------------------------------------------------------------------

class CheckpointManager:
    """
    Tüm checkpoint dosyalarını merkezi olarak yöneten Facade sınıfı.

    Sorumluluklar
    -------------
    * `list_checkpoints()` — Kayıtlı tüm taramaları listele.
    * `get(scan_id)` — Belirli bir taramanın ScanCheckpoint nesnesini döndür.
    * `resume(scan_id, deduplicator)` — Eski tamamlanan görev hash'lerini
      ScanDeduplicator'a enjekte ederek taramayı kaldığı yerden devam ettir.
    * `cleanup(max_age_days)` — Eski checkpoint dosyalarını temizle.
    * `create(scan_id, target, profile)` — Yeni checkpoint oluştur ve kayıt et.
    """

    def __init__(
        self,
        checkpoint_dir: Optional[Path] = None,
        serializer: Optional[CheckpointSerializer] = None,
    ) -> None:
        self._dir = Path(checkpoint_dir or _DEFAULT_CHECKPOINT_DIR)
        self._dir.mkdir(parents=True, exist_ok=True)
        self._serializer = serializer or JsonCheckpointSerializer()
        self._registry: Dict[str, ScanCheckpoint] = {}
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Factory
    # ------------------------------------------------------------------

    def create(
        self,
        scan_id: str,
        target: str,
        profile: str,
        auto_save_interval_s: float = _AUTO_SAVE_INTERVAL_S,
    ) -> ScanCheckpoint:
        """Yeni bir ScanCheckpoint oluştur ve yöneticiye kaydet."""
        cp = ScanCheckpoint(
            scan_id=scan_id,
            target=target,
            profile=profile,
            checkpoint_dir=self._dir,
            serializer=self._serializer,
            auto_save_interval_s=auto_save_interval_s,
        )
        with self._lock:
            self._registry[scan_id] = cp
        return cp

    def get(self, scan_id: str) -> Optional[ScanCheckpoint]:
        """Kayıtlı ScanCheckpoint nesnesini döner (bellekte değilse diskten yükler)."""
        with self._lock:
            if scan_id in self._registry:
                return self._registry[scan_id]

        # Disk araması
        path = self._dir / f"{scan_id}{_CHECKPOINT_EXT}"
        if not path.exists():
            return None

        state = self._load_state(path)
        if state is None:
            return None

        cp = ScanCheckpoint(
            scan_id=state.scan_id,
            target=state.target,
            profile=state.profile,
            checkpoint_dir=self._dir,
            serializer=self._serializer,
        )
        cp._state = state  # noqa: SLF001
        with self._lock:
            self._registry[scan_id] = cp
        return cp

    # ------------------------------------------------------------------
    # Resume
    # ------------------------------------------------------------------

    def resume(
        self,
        scan_id: str,
        deduplicator: Any,  # ScanDeduplicator — circular import önlemi
    ) -> Optional[CheckpointState]:
        """
        Tamamlanmış görev hash'lerini `deduplicator`'a enjekte eder.

        Parametreler
        ------------
        scan_id : str
            Devam edilecek tarama kimliği.
        deduplicator : ScanDeduplicator
            `websecure.core.concurrency.ScanDeduplicator` örneği.

        Döndürür
        --------
        CheckpointState veya None (checkpoint yoksa).
        """
        cp = self.get(scan_id)
        if cp is None:
            logger.warning(f"[checkpoint] Resume başarısız — {scan_id!r} bulunamadı")
            return None

        state = cp.state
        injected = 0
        for task_hash in state.completed_tasks:
            if hasattr(deduplicator, "_seen"):
                # ScanDeduplicator._seen setine doğrudan ekle
                deduplicator._seen.add(task_hash)  # noqa: SLF001
                injected += 1

        logger.info(
            f"[checkpoint] Resume <- {scan_id}  "
            f"{injected} tamamlanan görev enjekte edildi  "
            f"(%{state.progress_pct:.1f} daha önce yapıldı)"
        )
        return state

    # ------------------------------------------------------------------
    # Listeleme ve temizleme
    # ------------------------------------------------------------------

    def list_checkpoints(self) -> List[Dict[str, Any]]:
        """
        Mevcut tüm checkpoint'leri listeler.

        Döndürür
        --------
        List[Dict] — Her dict şunları içerir:
            scan_id, target, profile, started_at, saved_at,
            progress_pct, completed_count, total_tasks, path
        """
        results: List[Dict[str, Any]] = []
        for path in sorted(self._dir.glob(f"*{_CHECKPOINT_EXT}"),
                           key=lambda p: p.stat().st_mtime, reverse=True):
            state = self._load_state(path)
            if state is None:
                continue
            results.append({
                "scan_id":        state.scan_id,
                "target":         state.target,
                "profile":        state.profile,
                "started_at":     state.started_at,
                "saved_at":       state.saved_at,
                "progress_pct":   round(state.progress_pct, 1),
                "completed_count": state.completed_count,
                "total_tasks":    state.total_tasks,
                "elapsed_seconds": round(state.elapsed_seconds, 1),
                "path":           str(path),
            })
        return results

    def cleanup(self, max_age_days: int = _MAX_CHECKPOINT_AGE_DAYS) -> int:
        """
        `max_age_days` gün öncesinden eski checkpoint'leri siler.

        Döndürür
        --------
        int — Silinen dosya sayısı.
        """
        cutoff = time.time() - max_age_days * 86400
        removed = 0
        for path in self._dir.glob(f"*{_CHECKPOINT_EXT}"):
            try:
                if path.stat().st_mtime < cutoff:
                    path.unlink(missing_ok=True)
                    removed += 1
                    logger.debug(f"[checkpoint] Temizlendi: {path.name}")
            except OSError as exc:
                logger.warning(f"[checkpoint] Temizleme hatası ({path}): {exc!r}")
        if removed:
            logger.info(f"[checkpoint] {removed} eski checkpoint temizlendi.")
        return removed

    def delete(self, scan_id: str) -> bool:
        """Belirli bir taramanın checkpoint'ini siler."""
        cp = self.get(scan_id)
        if cp is None:
            return False
        ok = cp.delete()
        with self._lock:
            self._registry.pop(scan_id, None)
        return ok

    # ------------------------------------------------------------------
    # İç yardımcılar
    # ------------------------------------------------------------------

    def _load_state(self, path: Path) -> Optional[CheckpointState]:
        try:
            data = path.read_bytes()
            return self._serializer.loads(data)
        except Exception as exc:
            logger.debug(f"[checkpoint] Okuma hatası ({path.name}): {exc!r}")
            return None


# ---------------------------------------------------------------------------
# CheckpointHook — scan_runner entegrasyonu için callback
# ---------------------------------------------------------------------------

class CheckpointHook:
    """
    scan_runner.py içinde tarama döngüsünden checkpoint çağrılarını
    yöneten yardımcı sınıf.

    Kullanım
    --------
    ```python
    hook = CheckpointHook(checkpoint, eta_calculator)
    # Her görev tamamlandığında:
    hook.on_task_done(task_hash)
    # Periyodik (döngü içinde):
    hook.tick()
    # Modül bitiminde:
    hook.on_module_done("sqli")
    # Tarama bitiminde:
    hook.on_scan_complete()
    ```
    """

    def __init__(
        self,
        checkpoint: ScanCheckpoint | NoopCheckpoint,
        eta_calculator: Any = None,   # ETACalculator (opsiyonel)
        log_interval_s: float = 120.0,
    ) -> None:
        self._cp = checkpoint
        self._eta = eta_calculator
        self._log_interval = log_interval_s
        self._last_log: float = 0.0

    def on_task_done(self, task_hash: str, duration_s: float = 0.0) -> None:
        self._cp.mark_task_done(task_hash)
        if self._eta is not None and duration_s > 0:
            try:
                self._eta.tick(duration_s)
            except Exception:
                pass

    def on_module_done(self, module: str) -> None:
        self._cp.mark_module_done(module)
        self._cp.maybe_autosave()

    def on_scan_complete(self) -> None:
        self._cp.save(force=True)
        logger.info("[checkpoint] Tarama tamamlandı, checkpoint kaydedildi.")

    def tick(self) -> None:
        """Periyodik görevler: otomatik kaydet + ETA log."""
        self._cp.maybe_autosave()
        self._log_eta()

    def _log_eta(self) -> None:
        now = time.monotonic()
        if (now - self._last_log) < self._log_interval:
            return
        self._last_log = now
        state = self._cp.state
        pct = state.progress_pct
        eta_str = "?"
        if self._eta is not None:
            try:
                snap = self._eta.snapshot()
                eta_str = snap.get("eta_human", "?")
            except Exception:
                pass
        logger.info(
            f"[checkpoint] İlerleme: %{pct:.1f}  "
            f"({state.completed_count}/{state.total_tasks} görev)  "
            f"ETA: {eta_str}"
        )


# ---------------------------------------------------------------------------
# Yardımcı fonksiyonlar
# ---------------------------------------------------------------------------

def _utc_now() -> str:
    """ISO-8601 UTC zaman damgası."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _atomic_write(path: Path, data: bytes) -> None:
    """
    Veriyi atomik olarak `path`'a yazar.
    Önce geçici dosyaya yazar, sonra rename ile yerleştirir.
    Windows'ta rename hedef varsa önce siler (POSIX rename-over desteklemez).
    """
    parent = path.parent
    parent.mkdir(parents=True, exist_ok=True)

    fd, tmp_path_str = tempfile.mkstemp(dir=parent, suffix=_TEMP_EXT)
    tmp_path = Path(tmp_path_str)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        # Windows atomik rename
        if os.name == "nt" and path.exists():
            path.unlink(missing_ok=True)
        tmp_path.rename(path)
    except Exception:
        # Başarısız olursa geçici dosyayı temizle
        try:
            tmp_path.unlink(missing_ok=True)
        except OSError:
            pass
        raise


# ---------------------------------------------------------------------------
# Modül fabrikaları (kullanım kolaylığı)
# ---------------------------------------------------------------------------

def make_checkpoint(
    scan_id: str,
    target: str,
    profile: str,
    checkpoint_dir: Optional[Path] = None,
    auto_save_interval_s: float = _AUTO_SAVE_INTERVAL_S,
    enabled: bool = True,
) -> ScanCheckpoint | NoopCheckpoint:
    """
    Checkpoint etkinse ScanCheckpoint, değilse NoopCheckpoint döner.

    Parametreler
    ------------
    scan_id               : Tarama kimliği
    target                : Hedef URL
    profile               : Profil adı
    checkpoint_dir        : Checkpoint dizini (None -> ev dizini)
    auto_save_interval_s  : Otomatik kaydetme aralığı
    enabled               : False -> NoopCheckpoint döner
    """
    if not enabled:
        return NoopCheckpoint(scan_id=scan_id)
    return ScanCheckpoint(
        scan_id=scan_id,
        target=target,
        profile=profile,
        checkpoint_dir=checkpoint_dir,
        auto_save_interval_s=auto_save_interval_s,
    )


# Küresel CheckpointManager — lazy singleton
_manager: Optional[CheckpointManager] = None
_manager_lock = threading.Lock()


def get_manager(checkpoint_dir: Optional[Path] = None) -> CheckpointManager:
    """Küresel CheckpointManager singleton'ını döner."""
    global _manager
    if _manager is None:
        with _manager_lock:
            if _manager is None:
                _manager = CheckpointManager(checkpoint_dir=checkpoint_dir)
    return _manager


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

__all__ = [
    # Veri modeli
    "CheckpointState",
    # Checkpoint nesneleri
    "ScanCheckpoint",
    "NoopCheckpoint",
    # Serileştiriciler
    "CheckpointSerializer",
    "JsonCheckpointSerializer",
    # Yönetim
    "CheckpointManager",
    "CheckpointHook",
    # Fabrikalar
    "make_checkpoint",
    "get_manager",
]
