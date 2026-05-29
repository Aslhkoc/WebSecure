"""
websecure.cli.scheduler
~~~~~~~~~~~~~~~~~~~~~~~~
Cron tabanlı tarama zamanlama sistemi.

Özellikler
----------
* Cron ifadesi desteği: "0 2 * * *" (dakika saat gün ay haftaGünü)
* JSON kalıcılık: ~/.websecure/schedules.json
* Arka plan daemon thread
* Sonraki çalışma zamanı hesaplama (stdlib ile — APScheduler bağımlılığı yok)
* Tarama geçmişi kaydı (son 50 çalışma)
* Etkinleştir/Devre Dışı Bırak / Sil API

SOLID
-----
- SRP  : Zamanlama / çalıştırma ayrı sorumluluklarda.
- OCP  : Yeni trigger tipi eklemek mevcut kodu değiştirmez.
- DIP  : CronScheduler, ScanRunner soyut interface üzerinden çalışır.
"""
from __future__ import annotations

import json
import logging
import threading
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Kalıcılık yolu
# ---------------------------------------------------------------------------

_DATA_DIR      = Path.home() / ".websecure"
_SCHEDULES_PATH = _DATA_DIR / "schedules.json"
_HISTORY_LIMIT  = 50
_TICK_INTERVAL  = 30  # saniye


# ---------------------------------------------------------------------------
# Cron ifadesi ayrıştırıcı (stdlib only)
# ---------------------------------------------------------------------------

class CronParser:
    """
    5 alanlı cron ifadesi ayrıştırıcısı.

    Desteklenen sözdizimi
    --------------------
    * Joker (her değer)
    N Kesin değer
    N,M Virgülle ayrılmış liste
    N-M Aralık
    */N Her N adımda bir
    N/M N'den başlayarak her M adımda bir

    Örnekler
    --------
    "0 2 * * *"    -> Her gece 02:00
    "*/15 * * * *" -> Her 15 dakikada bir
    "0 9 * * 1-5"  -> Hafta içi 09:00
    "0 0 1 * *"    -> Her ayın 1'i gece yarısı
    """

    def __init__(self, expr: str) -> None:
        parts = expr.strip().split()
        if len(parts) != 5:
            raise ValueError(
                f"Geçersiz cron ifadesi: '{expr}' — 5 alan gerekli "
                "(dakika saat gün ay haftaGünü)"
            )
        self._minute, self._hour, self._dom, self._month, self._dow = parts

    def next_run(self, after: Optional[datetime] = None) -> datetime:
        """
        `after` zamanından sonra ilk uygun datetime'ı döndür.
        Varsayılan: şimdiki zaman.
        """
        now = (after or datetime.now()).replace(second=0, microsecond=0)
        current = now + timedelta(minutes=1)

        # Maksimum 1 yıl ileriye bak
        deadline = current + timedelta(days=366)

        while current < deadline:
            if (
                self._matches(current.month,  self._month,  1, 12)
                and self._matches(current.day,    self._dom,    1, 31)
                and self._matches(current.weekday() + 1, self._dow, 0, 7)
                and self._matches(current.hour,   self._hour,   0, 23)
                and self._matches(current.minute, self._minute, 0, 59)
            ):
                return current
            current += timedelta(minutes=1)

        raise RuntimeError(f"Cron '{self}' için sonraki çalışma zamanı bulunamadı.")

    def _matches(self, value: int, field_str: str, lo: int, hi: int) -> bool:
        """Tek bir cron alanı için değer eşleşmesi."""
        if field_str == "*":
            return True

        values: set = set()

        for part in field_str.split(","):
            part = part.strip()
            if "/" in part:
                base, step_str = part.split("/", 1)
                step = int(step_str)
                if base == "*":
                    values.update(range(lo, hi + 1, step))
                elif "-" in base:
                    a, b = base.split("-", 1)
                    values.update(range(int(a), int(b) + 1, step))
                else:
                    values.update(range(int(base), hi + 1, step))
            elif "-" in part:
                a, b = part.split("-", 1)
                values.update(range(int(a), int(b) + 1))
            else:
                values.add(int(part))

        # DOM=7 ve DOW=0 her ikisi de Pazar'ı temsil eder
        if hi == 7:
            if 7 in values:
                values.add(0)
            if 0 in values:
                values.add(7)

        return value in values

    def __str__(self) -> str:
        return f"{self._minute} {self._hour} {self._dom} {self._month} {self._dow}"


# ---------------------------------------------------------------------------
# ScheduleEntry — tek bir zamanlanmış tarama
# ---------------------------------------------------------------------------

@dataclass
class ScheduleEntry:
    """Tek bir zamanlanmış tarama girişi."""
    id: str
    target: str
    cron_expr: str
    label: str = ""
    options: Dict[str, Any] = field(default_factory=dict)
    enabled: bool = True
    created_at: str = field(
        default_factory=lambda: datetime.now().isoformat()
    )
    last_run: Optional[str] = None
    next_run: Optional[str] = None
    run_count: int = 0
    history: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "ScheduleEntry":
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})

    def compute_next_run(self) -> Optional[str]:
        """Sonraki çalışma zamanını hesapla ve kaydet."""
        try:
            parser = CronParser(self.cron_expr)
            nxt = parser.next_run()
            self.next_run = nxt.isoformat()
            return self.next_run
        except Exception as exc:
            logger.error(f"[Scheduler] '{self.cron_expr}' next_run hesaplanamadı: {exc!r}")
            return None

    def is_due(self) -> bool:
        """Bu taramanın çalışması gerekiyor mu?"""
        if not self.enabled or not self.next_run:
            return False
        try:
            nxt = datetime.fromisoformat(self.next_run)
            return datetime.now() >= nxt
        except Exception:
            return False

    def record_run(self, success: bool, duration_s: float, finding_count: int) -> None:
        """Çalışma geçmişine kayıt ekle."""
        entry = {
            "timestamp": datetime.now().isoformat(),
            "success": success,
            "duration_s": round(duration_s, 2),
            "finding_count": finding_count,
        }
        self.history.append(entry)
        if len(self.history) > _HISTORY_LIMIT:
            self.history = self.history[-_HISTORY_LIMIT:]
        self.last_run = entry["timestamp"]
        self.run_count += 1
        self.compute_next_run()


# ---------------------------------------------------------------------------
# CronScheduler — ana zamanlayıcı
# ---------------------------------------------------------------------------

class CronScheduler:
    """
    Cron tabanlı tarama zamanlayıcısı.

    Kullanım
    --------
    ```python
    def my_runner(target: str, options: dict) -> dict:
        # taramayı çalıştır, {success, duration_s, finding_count} döndür
        ...

    scheduler = CronScheduler(runner=my_runner)
    scheduler.add("https://example.com", "0 2 * * *", label="Gece taraması")
    scheduler.start()   # daemon thread başlatır
    # scheduler.stop()  # durdur
    ```
    """

    def __init__(
        self,
        runner: Optional[Callable[[str, Dict[str, Any]], Dict[str, Any]]] = None,
        db_path: Optional[Path] = None,
        tick_interval: int = _TICK_INTERVAL,
    ) -> None:
        self._runner = runner
        self._db_path = db_path or _SCHEDULES_PATH
        self._tick_interval = tick_interval
        self._entries: Dict[str, ScheduleEntry] = {}
        self._lock = threading.Lock()
        self._thread: Optional[threading.Thread] = None
        self._running = False
        self._load()

    # ------------------------------------------------------------------
    # Entry yönetimi
    # ------------------------------------------------------------------

    def add(
        self,
        target: str,
        cron_expr: str,
        label: str = "",
        options: Optional[Dict[str, Any]] = None,
        enabled: bool = True,
    ) -> ScheduleEntry:
        """Yeni zamanlanmış tarama ekle."""
        # Cron ifadesini doğrula
        CronParser(cron_expr)

        entry = ScheduleEntry(
            id=str(uuid.uuid4())[:8],
            target=target,
            cron_expr=cron_expr,
            label=label or target,
            options=options or {},
            enabled=enabled,
        )
        entry.compute_next_run()

        with self._lock:
            self._entries[entry.id] = entry
        self._save()

        logger.info(f"[Scheduler] Eklendi: {entry.label}  cron='{cron_expr}'  "
                    f"next={entry.next_run}")
        return entry

    def remove(self, entry_id: str) -> bool:
        """Girişi sil."""
        with self._lock:
            if entry_id not in self._entries:
                return False
            del self._entries[entry_id]
        self._save()
        return True

    def enable(self, entry_id: str) -> bool:
        with self._lock:
            e = self._entries.get(entry_id)
            if e is None:
                return False
            e.enabled = True
            e.compute_next_run()
        self._save()
        return True

    def disable(self, entry_id: str) -> bool:
        with self._lock:
            e = self._entries.get(entry_id)
            if e is None:
                return False
            e.enabled = False
        self._save()
        return True

    def list_entries(self) -> List[ScheduleEntry]:
        with self._lock:
            return list(self._entries.values())

    def get(self, entry_id: str) -> Optional[ScheduleEntry]:
        with self._lock:
            return self._entries.get(entry_id)

    # ------------------------------------------------------------------
    # Daemon
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Arka plan tick thread'ini başlat."""
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(
            target=self._tick_loop,
            name="CronScheduler",
            daemon=True,
        )
        self._thread.start()
        logger.info(f"[Scheduler] Başlatıldı — {len(self._entries)} zamanlama yüklü.")

    def stop(self) -> None:
        """Zamanlayıcıyı durdur."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
        logger.info("[Scheduler] Durduruldu.")

    def _tick_loop(self) -> None:
        while self._running:
            try:
                self._check_due()
            except Exception as exc:
                logger.error(f"[Scheduler] Tick hatası: {exc!r}", exc_info=True)
            time.sleep(self._tick_interval)

    def _check_due(self) -> None:
        with self._lock:
            due_entries = [e for e in self._entries.values() if e.is_due()]

        for entry in due_entries:
            logger.info(f"[Scheduler] Çalıştırılıyor: {entry.label}  ->  {entry.target}")
            self._run_entry(entry)

    def _run_entry(self, entry: ScheduleEntry) -> None:
        start = time.monotonic()
        success = False
        finding_count = 0

        try:
            if self._runner:
                result = self._runner(entry.target, entry.options)
                success = result.get("success", True)
                finding_count = result.get("finding_count", 0)
            else:
                logger.warning(f"[Scheduler] Runner tanımlanmamış: {entry.target}")
                success = False
        except Exception as exc:
            logger.error(f"[Scheduler] Tarama hatası: {entry.target}  {exc!r}")
            success = False
        finally:
            duration = time.monotonic() - start
            with self._lock:
                entry.record_run(success, duration, finding_count)
            self._save()

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
            logger.error(f"[Scheduler] Kaydetme hatası: {exc!r}")

    def _load(self) -> None:
        if not self._db_path.exists():
            return
        try:
            data = json.loads(self._db_path.read_text(encoding="utf-8"))
            for d in data:
                try:
                    e = ScheduleEntry.from_dict(d)
                    e.compute_next_run()
                    self._entries[e.id] = e
                except Exception as exc:
                    logger.debug(f"[Scheduler] Giriş yüklenemedi: {exc!r}")
            logger.info(f"[Scheduler] {len(self._entries)} zamanlama yüklendi.")
        except Exception as exc:
            logger.error(f"[Scheduler] DB yükleme hatası: {exc!r}")


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------

_scheduler_instance: Optional[CronScheduler] = None


def _make_websecure_runner() -> Callable:
    """
    CLI için gerçek WebSecure tarama runner'ı oluşturur.
    Her hedefi ayrı bir subprocess olarak çalıştırır; bu sayede paralel
    daemon tick'leri sys.argv üzerinden çakışmaz.
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
            logger.error(f"[Scheduler] Tarama runner hatası: {_exc!r}")
            return {
                "success": False,
                "error": str(_exc),
                "finding_count": 0,
                "duration_s": round(_time.monotonic() - t0, 2),
            }

    return _runner


def get_scheduler(
    runner: Optional[Callable] = None,
) -> CronScheduler:
    """
    Global CronScheduler singleton'ını döndür.
    Singleton runner'sız oluşturulmuşsa ve yeni runner verilmişse günceller.
    """
    global _scheduler_instance
    if _scheduler_instance is None:
        _scheduler_instance = CronScheduler(runner=runner)
    elif runner is not None and _scheduler_instance._runner is None:
        # Sonradan sağlanan runner'ı singleton'a bağla
        _scheduler_instance._runner = runner
    return _scheduler_instance


# ---------------------------------------------------------------------------
# CLI kısayol
# ---------------------------------------------------------------------------

def run_scheduler_cli(args: list) -> int:
    """
    websecure schedule alt komutu için CLI işleyicisi.

    Alt komutlar
    ------------
    add <target> <cron> [--label] [--disabled]
    remove <id>
    list
    run  — foreground daemon
    """
    import argparse

    parser = argparse.ArgumentParser(prog="websecure schedule")
    sub = parser.add_subparsers(dest="subcmd")

    add_p = sub.add_parser("add", help="Zamanlama ekle")
    add_p.add_argument("target")
    add_p.add_argument("cron", help='Cron ifadesi (örn: "0 2 * * *")')
    add_p.add_argument("--label", default="")
    add_p.add_argument("--disabled", action="store_true")

    rem_p = sub.add_parser("remove", help="Zamanlama sil")
    rem_p.add_argument("id")

    en_p = sub.add_parser("enable", help="Zamanlamayı etkinleştir")
    en_p.add_argument("id")

    dis_p = sub.add_parser("disable", help="Zamanlamayı devre dışı bırak")
    dis_p.add_argument("id")

    sub.add_parser("list", help="Tüm zamanlamaları listele")
    sub.add_parser("run",  help="Daemon modunda çalıştır (Ctrl+C ile durdur)")

    ns = parser.parse_args(args)
    sched = get_scheduler(runner=_make_websecure_runner())

    if ns.subcmd == "add":
        try:
            e = sched.add(
                target=ns.target,
                cron_expr=ns.cron,
                label=ns.label,
                enabled=not ns.disabled,
            )
            print(f"[[OK]] Zamanlama eklendi — ID: {e.id}  Sonraki: {e.next_run}")
        except ValueError as exc:
            print(f"[!] Hata: {exc}")
            return 1

    elif ns.subcmd == "remove":
        if sched.remove(ns.id):
            print(f"[[OK]] Silindi: {ns.id}")
        else:
            print(f"[!] Bulunamadı: {ns.id}")
            return 1

    elif ns.subcmd == "enable":
        if sched.enable(ns.id):
            print(f"[[OK]] Etkinleştirildi: {ns.id}")
        else:
            print(f"[!] Bulunamadı: {ns.id}")
            return 1

    elif ns.subcmd == "disable":
        if sched.disable(ns.id):
            print(f"[[OK]] Devre dışı: {ns.id}")
        else:
            print(f"[!] Bulunamadı: {ns.id}")
            return 1

    elif ns.subcmd == "list":
        entries = sched.list_entries()
        if not entries:
            print("  Kayıtlı zamanlama yok.")
            return 0
        print(f"\n  {'ID':<8}  {'Durum':<8}  {'Cron':<15}  {'Label':<30}  Sonraki")
        print("  " + "-" * 80)
        for e in entries:
            status = "aktif" if e.enabled else "pasif"
            label = (e.label or e.target)[:30]
            next_r = (e.next_run or "?")[:19]
            print(f"  {e.id:<8}  {status:<8}  {e.cron_expr:<15}  {label:<30}  {next_r}")

    elif ns.subcmd == "run":
        print("[*] Zamanlayıcı daemon başlatıldı — Ctrl+C ile durdur")
        sched.start()
        try:
            while True:
                time.sleep(60)
        except KeyboardInterrupt:
            print("\n[*] Durduruluyor...")
            sched.stop()

    else:
        parser.print_help()

    return 0


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

__all__ = [
    "CronParser",
    "ScheduleEntry",
    "CronScheduler",
    "get_scheduler",
    "run_scheduler_cli",
]
