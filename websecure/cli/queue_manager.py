"""
websecure.cli.queue_manager
~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Çok hedefli tarama kuyruğu yöneticisi.

Özellikler
----------
* JSON kalıcılık: ~/.websecure/queue.json
* FIFO işleme + öncelik desteği (1=düşük … 5=kritik)
* Durum: pending / running / completed / failed / cancelled
* Paralel işleme (worker sayısı yapılandırılabilir)
* Kuyruk durumu: kalan, çalışan, tamamlanan sayıları
* Retry on failure (yapılandırılabilir)

SOLID
-----
- SRP  : Kuyruk yönetimi / tarama çalıştırma ayrı sorumluluklarda.
- OCP  : Yeni öncelik/strateji mevcut kodu değiştirmez.
- DIP  : QueueManager, ScanRunner soyut callback'e bağımlı.
"""
from __future__ import annotations

import json
import logging
import threading
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Sabitler
# ---------------------------------------------------------------------------

_DATA_DIR   = Path.home() / ".websecure"
_QUEUE_PATH = _DATA_DIR / "queue.json"
_MAX_RETRIES = 2


# ---------------------------------------------------------------------------
# Durum sabitleri
# ---------------------------------------------------------------------------

class QueueStatus:
    PENDING   = "pending"
    RUNNING   = "running"
    COMPLETED = "completed"
    FAILED    = "failed"
    CANCELLED = "cancelled"


# ---------------------------------------------------------------------------
# QueueEntry
# ---------------------------------------------------------------------------

@dataclass
class QueueEntry:
    """Tek bir kuyruk girişi."""
    id: str
    target: str
    priority: int = 3                   # 1 (düşük) … 5 (kritik)
    options: Dict[str, Any] = field(default_factory=dict)
    status: str = QueueStatus.PENDING
    added_at: str = field(
        default_factory=lambda: datetime.now().isoformat()
    )
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    finding_count: int = 0
    duration_s: float = 0.0
    error: str = ""
    retries: int = 0
    label: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "QueueEntry":
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})

    @property
    def is_terminal(self) -> bool:
        return self.status in (
            QueueStatus.COMPLETED, QueueStatus.FAILED, QueueStatus.CANCELLED
        )


# ---------------------------------------------------------------------------
# ScanQueue
# ---------------------------------------------------------------------------

class ScanQueue:
    """
    Çok hedefli tarama kuyruğu.

    Kullanım
    --------
    ```python
    def my_runner(target: str, options: dict) -> dict:
        # ... tarama ...
        return {"success": True, "finding_count": 5, "duration_s": 120.0}

    q = ScanQueue(runner=my_runner, max_workers=2)
    q.add("https://example.com", priority=5)
    q.add("https://other.com", priority=3)
    q.run()  # tüm kuyruğu işle (blocking)
    print(q.stats())
    ```
    """

    def __init__(
        self,
        runner: Optional[Callable[[str, Dict[str, Any]], Dict[str, Any]]] = None,
        max_workers: int = 1,
        db_path: Optional[Path] = None,
        max_retries: int = _MAX_RETRIES,
    ) -> None:
        self._runner = runner
        self._max_workers = max_workers
        self._db_path = db_path or _QUEUE_PATH
        self._max_retries = max_retries
        self._entries: Dict[str, QueueEntry] = {}
        self._lock = threading.Lock()
        self._running = False
        self._load()

    # ------------------------------------------------------------------
    # Entry yönetimi
    # ------------------------------------------------------------------

    def add(
        self,
        target: str,
        priority: int = 3,
        options: Optional[Dict[str, Any]] = None,
        label: str = "",
    ) -> QueueEntry:
        """Kuyruğa yeni hedef ekle."""
        entry = QueueEntry(
            id=str(uuid.uuid4())[:8],
            target=target,
            priority=max(1, min(5, priority)),
            options=options or {},
            label=label or target,
        )
        with self._lock:
            self._entries[entry.id] = entry
        self._save()
        logger.info(f"[Queue] Eklendi: {target}  P{priority}  ID={entry.id}")
        return entry

    def cancel(self, entry_id: str) -> bool:
        """Bekleyen girişi iptal et."""
        with self._lock:
            e = self._entries.get(entry_id)
            if e is None or e.status != QueueStatus.PENDING:
                return False
            e.status = QueueStatus.CANCELLED
        self._save()
        return True

    def remove_completed(self) -> int:
        """Tamamlanan/başarısız/iptal girişleri temizle."""
        with self._lock:
            before = len(self._entries)
            self._entries = {
                k: v for k, v in self._entries.items()
                if not v.is_terminal
            }
            removed = before - len(self._entries)
        self._save()
        return removed

    def list_entries(
        self,
        status: Optional[str] = None,
    ) -> List[QueueEntry]:
        """Girişleri listele (öncelik sırasına göre)."""
        with self._lock:
            entries = list(self._entries.values())
        if status:
            entries = [e for e in entries if e.status == status]
        # Önce yüksek öncelik, sonra eklenme zamanı
        entries.sort(key=lambda e: (-e.priority, e.added_at))
        return entries

    def get(self, entry_id: str) -> Optional[QueueEntry]:
        with self._lock:
            return self._entries.get(entry_id)

    def stats(self) -> Dict[str, int]:
        with self._lock:
            entries = list(self._entries.values())
        return {
            "total":     len(entries),
            "pending":   sum(1 for e in entries if e.status == QueueStatus.PENDING),
            "running":   sum(1 for e in entries if e.status == QueueStatus.RUNNING),
            "completed": sum(1 for e in entries if e.status == QueueStatus.COMPLETED),
            "failed":    sum(1 for e in entries if e.status == QueueStatus.FAILED),
            "cancelled": sum(1 for e in entries if e.status == QueueStatus.CANCELLED),
        }

    # ------------------------------------------------------------------
    # Çalıştırma
    # ------------------------------------------------------------------

    def run(self, blocking: bool = True, max_workers: Optional[int] = None) -> None:
        """
        Kuyruktaki tüm bekleyen girişleri işle.

        Parametreler
        ------------
        blocking    : True -> tüm worker'lar bitene kadar bekle (CLI için)
        max_workers : Geçici worker sınırı (None = mevcut ayar korunur)
        """
        if max_workers is not None:
            self._max_workers = max_workers
        self._running = True
        pending = self.list_entries(status=QueueStatus.PENDING)

        if not pending:
            logger.info("[Queue] Kuyrukta bekleyen giriş yok.")
            self._running = False
            return

        logger.info(f"[Queue] {len(pending)} giriş işlenecek — {self._max_workers} worker")

        workers: List[threading.Thread] = []
        sem = threading.Semaphore(self._max_workers)

        for entry in pending:
            if not self._running:
                break
            sem.acquire()
            t = threading.Thread(
                target=self._process_entry,
                args=(entry, sem),
                name=f"QueueWorker-{entry.id}",
                daemon=True,
            )
            t.start()
            workers.append(t)

        if blocking:
            for w in workers:
                w.join()
        self._running = False

    def stop(self) -> None:
        """İşlemeyi durdur (mevcut çalışan tamamlanır)."""
        self._running = False

    def _process_entry(self, entry: QueueEntry, sem: threading.Semaphore) -> None:
        try:
            self._run_entry(entry)
        finally:
            sem.release()

    def _run_entry(self, entry: QueueEntry) -> None:
        # Durumu running yap
        with self._lock:
            entry.status = QueueStatus.RUNNING
            entry.started_at = datetime.now().isoformat()
        self._save()

        start = time.monotonic()
        success = False
        finding_count = 0
        error_msg = ""

        for attempt in range(1, self._max_retries + 2):
            try:
                if self._runner:
                    result = self._runner(entry.target, entry.options)
                    success = result.get("success", True)
                    finding_count = result.get("finding_count", 0)
                    error_msg = result.get("error", "")
                else:
                    logger.warning(f"[Queue] Runner tanımlanmamış: {entry.target}")
                    success = False
                    error_msg = "Runner tanımlanmamış"

                if success:
                    break

            except Exception as exc:
                error_msg = str(exc)
                logger.error(
                    f"[Queue] Tarama hatası deneme {attempt}: {entry.target}  {exc!r}"
                )

            if attempt <= self._max_retries and not success:
                logger.info(f"[Queue] Yeniden deneniyor ({attempt}/{self._max_retries}): {entry.target}")
                entry.retries += 1
                time.sleep(2 ** attempt)

        duration = time.monotonic() - start

        with self._lock:
            entry.status = QueueStatus.COMPLETED if success else QueueStatus.FAILED
            entry.completed_at = datetime.now().isoformat()
            entry.duration_s = round(duration, 2)
            entry.finding_count = finding_count
            entry.error = error_msg

        self._save()
        logger.info(
            f"[Queue] {'[OK]' if success else '[FAIL]'} {entry.target}  "
            f"{duration:.1f}s  {finding_count} bulgu"
        )

    # ------------------------------------------------------------------
    # Kalıcılık
    # ------------------------------------------------------------------

    def _save(self) -> None:
        try:
            self._db_path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self._db_path.with_suffix(".tmp")
            with self._lock:
                data = [e.to_dict() for e in self._entries.values()]
            tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
            tmp.replace(self._db_path)
        except Exception as exc:
            logger.error(f"[Queue] Kaydetme hatası: {exc!r}")

    def _load(self) -> None:
        if not self._db_path.exists():
            return
        try:
            data = json.loads(self._db_path.read_text(encoding="utf-8"))
            for d in data:
                try:
                    e = QueueEntry.from_dict(d)
                    # Başlarken "running" olanları "pending" yap (crash recovery)
                    if e.status == QueueStatus.RUNNING:
                        e.status = QueueStatus.PENDING
                    self._entries[e.id] = e
                except Exception as exc:
                    logger.debug(f"[Queue] Giriş yüklenemedi: {exc!r}")
            logger.info(f"[Queue] {len(self._entries)} giriş yüklendi.")
        except Exception as exc:
            logger.error(f"[Queue] DB yükleme hatası: {exc!r}")


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------

_queue_instance: Optional[ScanQueue] = None


def _make_websecure_runner() -> Callable:
    """
    CLI için gerçek WebSecure tarama runner'ı oluşturur.
    Her hedefi ayrı bir subprocess olarak çalıştırır; bu sayede paralel
    worker'lar sys.argv üzerinden çakışmaz.
    """
    import subprocess
    import sys

    def _runner(target: str, options: dict) -> dict:
        import time as _time
        t0 = _time.monotonic()
        try:
            cmd = [sys.executable, "-m", "websecure", target]
            profile = options.get("profile")
            if profile:
                cmd += ["--profile", profile]
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=int(options.get("timeout", 3600)),
            )
            return {
                "success": proc.returncode == 0,
                "finding_count": 0,
                "duration_s": round(_time.monotonic() - t0, 2),
                "error": proc.stderr.strip() if proc.returncode != 0 else "",
            }
        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "error": "Tarama zaman aşımına uğradı",
                "finding_count": 0,
                "duration_s": round(_time.monotonic() - t0, 2),
            }
        except Exception as _exc:
            logger.error(f"[Queue] Tarama runner hatası: {_exc!r}")
            return {
                "success": False,
                "error": str(_exc),
                "finding_count": 0,
                "duration_s": round(_time.monotonic() - t0, 2),
            }

    return _runner


def get_queue(runner: Optional[Callable] = None) -> ScanQueue:
    """
    Global ScanQueue singleton'ını döndür.
    Singleton runner'sız oluşturulmuşsa ve yeni runner verilmişse günceller.
    """
    global _queue_instance
    if _queue_instance is None:
        _queue_instance = ScanQueue(runner=runner)
    elif runner is not None and _queue_instance._runner is None:
        # Sonradan sağlanan runner'ı singleton'a bağla
        _queue_instance._runner = runner
    return _queue_instance


# ---------------------------------------------------------------------------
# CLI kısayol
# ---------------------------------------------------------------------------

def run_queue_cli(args: list) -> int:
    """
    websecure queue alt komutu için CLI işleyicisi.

    Alt komutlar
    ------------
    add <target> [--priority 1-5] [--label]
    cancel <id>
    list [--status pending|running|completed|failed]
    stats
    clear   — tamamlananları temizle
    run [--workers N]
    """
    import argparse

    parser = argparse.ArgumentParser(prog="websecure queue")
    sub = parser.add_subparsers(dest="subcmd")

    add_p = sub.add_parser("add", help="Kuyruğa hedef ekle")
    add_p.add_argument("target")
    add_p.add_argument("--priority", "-p", type=int, default=3,
                       choices=[1,2,3,4,5],
                       help="Öncelik 1(düşük)…5(kritik)")
    add_p.add_argument("--label", default="")

    can_p = sub.add_parser("cancel", help="Bekleyen girişi iptal et")
    can_p.add_argument("id")

    lst_p = sub.add_parser("list", help="Kuyruğu listele")
    lst_p.add_argument("--status",
                       choices=["pending","running","completed","failed","cancelled"])

    sub.add_parser("stats",  help="Kuyruk istatistikleri")
    sub.add_parser("clear",  help="Tamamlananları temizle")

    run_p = sub.add_parser("run", help="Kuyruğu işle")
    run_p.add_argument("--workers", "-w", type=int, default=1)

    ns = parser.parse_args(args)
    q = get_queue(runner=_make_websecure_runner())

    if ns.subcmd == "add":
        e = q.add(target=ns.target, priority=ns.priority, label=ns.label)
        print(f"[[OK]] Eklendi — ID: {e.id}  Öncelik: P{e.priority}  Hedef: {e.target}")

    elif ns.subcmd == "cancel":
        if q.cancel(ns.id):
            print(f"[[OK]] İptal edildi: {ns.id}")
        else:
            print(f"[!] İptal edilemedi (bulunamadı veya çalışıyor): {ns.id}")
            return 1

    elif ns.subcmd == "list":
        entries = q.list_entries(status=getattr(ns, "status", None))
        if not entries:
            print("  Giriş bulunamadı.")
            return 0
        print(f"\n  {'ID':<8}  {'P':<2}  {'Durum':<12}  {'Hedef':<40}  Eklenme")
        print("  " + "-" * 80)
        for e in entries:
            added = e.added_at[:16]
            target = (e.label or e.target)[:40]
            print(f"  {e.id:<8}  {e.priority:<2}  {e.status:<12}  {target:<40}  {added}")

    elif ns.subcmd == "stats":
        s = q.stats()
        print("\n  Kuyruk İstatistikleri")
        print("  " + "-" * 30)
        for k, v in s.items():
            print(f"  {k:<12}: {v}")

    elif ns.subcmd == "clear":
        removed = q.remove_completed()
        print(f"[[OK]] {removed} tamamlanan giriş temizlendi.")

    elif ns.subcmd == "run":
        stats_before = q.stats()
        pending = stats_before["pending"]
        if pending == 0:
            print("[*] Kuyrukta bekleyen giriş yok.")
            return 0
        print(f"[*] {pending} giriş işleniyor — {ns.workers} worker...")
        q.run(blocking=True, max_workers=ns.workers)
        print("[[OK]] Tamamlandı.")
        for k, v in q.stats().items():
            print(f"  {k:<12}: {v}")

    else:
        parser.print_help()

    return 0


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

__all__ = [
    "QueueEntry",
    "QueueStatus",
    "ScanQueue",
    "get_queue",
    "run_queue_cli",
]
