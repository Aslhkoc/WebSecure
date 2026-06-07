# -*- coding: utf-8 -*-
"""
websecure.core.concurrency
--------------------------
Eşzamanlılık & Dayanıklılık Motoru v1.0

Bileşenler (SOLID / OOP):
  ScanTask                    : Görev veri sınıfı (öncelik + meta)
  PriorityTaskQueue           : Thread-safe öncelikli görev kuyruğu (heapq)
  ScanDeduplicator            : Aynı parametreyi tekrar test etmeyi önler (SHA256 + LRU)
  AdaptiveConcurrencyCtrl     : AIMD — yanıt süresine göre thread sayısını otomatik ayarlar
  ETACalculator               : Gerçek zamanlı ETA hesaplama (rolling average)
  AdaptiveThreadPool          : Adaptive concurrency kullanan ThreadPoolExecutor wrapper
  StreamingURLProcessor       : Büyük URL listelerini RAM taşmadan batch işleme
  DistributedScanCoordinator  : Redis tabanlı çok makineli tarama koordinasyonu
  NoopCoordinator             : Redis yoksa sessiz fallback koordinatör
"""
from __future__ import annotations

import hashlib
import heapq
import logging
import statistics
import threading
import time
from collections import deque
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Callable, Dict, Generator, Iterable, List, Optional, Set, Tuple

_logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Opsiyonel bağımlılıklar
# ---------------------------------------------------------------------------

try:
    import redis as _redis_lib
    _REDIS_AVAILABLE = True
except ImportError:
    _redis_lib = None          # type: ignore[assignment]
    _REDIS_AVAILABLE = False

try:
    import psutil as _psutil
    _PSUTIL_AVAILABLE = True
except ImportError:
    _psutil = None             # type: ignore[assignment]
    _PSUTIL_AVAILABLE = False


# ---------------------------------------------------------------------------
# Öncelik Sabitleri
# ---------------------------------------------------------------------------

class TaskPriority(IntEnum):
    """Görev öncelik seviyeleri — düşük sayı = daha önce çalışır."""
    CRITICAL = 0   # Auth bypass, RCE, SQLi (error-based)
    HIGH     = 1   # XSS stored, SSRF, XXE, LFI
    MEDIUM   = 2   # CSRF, IDOR, open redirect, headers
    LOW      = 3   # Info disclosure, passive checks
    IDLE     = 4   # Arka plan / temizlik görevleri


# Endpoint / modül adına göre otomatik öncelik tablosu
_MODULE_PRIORITY: Dict[str, TaskPriority] = {
    "sqli":          TaskPriority.CRITICAL,
    "cmdi":          TaskPriority.CRITICAL,
    "rce":           TaskPriority.CRITICAL,
    "ssti":          TaskPriority.CRITICAL,
    "auth_scanners": TaskPriority.CRITICAL,
    "jwt":           TaskPriority.CRITICAL,
    "ssrf":          TaskPriority.HIGH,
    "xxe":           TaskPriority.HIGH,
    "xss":           TaskPriority.HIGH,
    "lfi":           TaskPriority.HIGH,
    "file_upload":   TaskPriority.HIGH,
    "idor":          TaskPriority.MEDIUM,
    "csrf":          TaskPriority.MEDIUM,
    "cors":          TaskPriority.MEDIUM,
    "headers":       TaskPriority.MEDIUM,
    "redirect":      TaskPriority.MEDIUM,
    "tls":           TaskPriority.LOW,
    "subdomain":     TaskPriority.LOW,
    "passive_recon": TaskPriority.IDLE,
}


# ---------------------------------------------------------------------------
# ScanTask — Görev Veri Sınıfı
# ---------------------------------------------------------------------------

@dataclass(order=False)
class ScanTask:
    """
    Tek bir tarama görevini temsil eder.
    PriorityTaskQueue içinde önceliğe göre sıralanır.
    """
    priority:    int             # TaskPriority değeri
    created_at:  float           # time.monotonic() — eşit öncelikte FIFO sıralama
    fn:          Callable        # Çalıştırılacak fonksiyon
    args:        Tuple  = field(default_factory=tuple)
    kwargs:      Dict   = field(default_factory=dict)
    task_id:     str    = ""
    module:      str    = ""
    url:         str    = ""
    param:       str    = ""
    description: str    = ""

    def __lt__(self, other: "ScanTask") -> bool:
        if self.priority != other.priority:
            return self.priority < other.priority
        return self.created_at < other.created_at  # FIFO tie-breaking

    @classmethod
    def from_module(
        cls,
        fn: Callable,
        module: str,
        url: str = "",
        param: str = "",
        *,
        args: Tuple = (),
        kwargs: Optional[Dict] = None,
        description: str = "",
    ) -> "ScanTask":
        prio = _MODULE_PRIORITY.get(module, TaskPriority.MEDIUM)
        return cls(
            priority=int(prio),
            created_at=time.monotonic(),
            fn=fn,
            args=args,
            kwargs=dict(kwargs) if kwargs else {},
            task_id=_make_task_id(module, url, param),
            module=module,
            url=url,
            param=param,
            description=description or f"{module}:{url}",
        )

    def run(self) -> Any:
        return self.fn(*self.args, **self.kwargs)


def _make_task_id(module: str, url: str, param: str) -> str:
    key = f"{module}:{url}:{param}"
    return hashlib.sha256(key.encode()).hexdigest()[:16]


# ---------------------------------------------------------------------------
# PriorityTaskQueue — Thread-Safe Öncelikli Kuyruk
# ---------------------------------------------------------------------------

class PriorityTaskQueue:
    """
    Thread-safe min-heap öncelik kuyruğu.

    - Kritik görevler (TaskPriority.CRITICAL=0) önce çalışır.
    - Aynı öncelikte FIFO (created_at ile tie-break).
    - put() / get() / qsize() / empty() API.
    - Opsiyonel boyut sınırı (max_size=0 -> sınırsız).
    """

    def __init__(self, max_size: int = 0) -> None:
        self._heap:     List[ScanTask] = []
        self._lock      = threading.Lock()
        self._not_empty = threading.Condition(self._lock)
        self._max_size  = max_size
        self._total_in  = 0
        self._total_out = 0

    def put(self, task: ScanTask, block: bool = True, timeout: Optional[float] = None) -> bool:
        """Kuyruğa görev ekle. Dolu olduğunda block=True ise bekler, False ise False döner."""
        with self._not_empty:
            if self._max_size > 0:
                deadline = (time.monotonic() + timeout) if timeout else None
                while len(self._heap) >= self._max_size:
                    if not block:
                        return False
                    wait_time = (deadline - time.monotonic()) if deadline else None
                    if wait_time is not None and wait_time <= 0:
                        return False
                    self._not_empty.wait(timeout=wait_time)
            heapq.heappush(self._heap, task)
            self._total_in += 1
            self._not_empty.notify()
        return True

    def get(self, block: bool = True, timeout: Optional[float] = None) -> Optional[ScanTask]:
        """Kuyruğun başından en öncelikli görevi al."""
        with self._not_empty:
            deadline = (time.monotonic() + timeout) if timeout else None
            while not self._heap:
                if not block:
                    return None
                wait_time = (deadline - time.monotonic()) if deadline else None
                if wait_time is not None and wait_time <= 0:
                    return None
                self._not_empty.wait(timeout=wait_time)
            task = heapq.heappop(self._heap)
            self._total_out += 1
            self._not_empty.notify_all()
        return task

    def put_many(self, tasks: Iterable[ScanTask]) -> int:
        """Birden fazla görevi verimli biçimde ekle."""
        count = 0
        with self._not_empty:
            for t in tasks:
                heapq.heappush(self._heap, t)
                self._total_in += 1
                count += 1
            if count:
                self._not_empty.notify_all()
        return count

    def qsize(self) -> int:
        with self._lock:
            return len(self._heap)

    def empty(self) -> bool:
        with self._lock:
            return not self._heap

    def stats(self) -> Dict[str, int]:
        # P12 fix: all fields read inside the lock; the original return was
        # outside the with-block, exposing len/_total_in/_total_out to races.
        with self._lock:
            by_prio: Dict[int, int] = {}
            for t in self._heap:
                by_prio[t.priority] = by_prio.get(t.priority, 0) + 1
            return {
                "queued":      len(self._heap),
                "total_in":    self._total_in,
                "total_out":   self._total_out,
                "by_priority": by_prio,
            }


# ---------------------------------------------------------------------------
# ScanDeduplicator — Tekrar Testi Önleme
# ---------------------------------------------------------------------------

class ScanDeduplicator:
    """
    Aynı (module, url, param, payload_category) kombinasyonunun
    tekrar test edilmesini önler.

    - SHA256 tabanlı fingerprint
    - Thread-safe
    - LRU boyut sınırı (max_entries=0 -> sınırsız)
    - is_new(): True -> daha önce görülmedi, test edilebilir
    """

    def __init__(self, max_entries: int = 500_000) -> None:
        self._seen:      Set[str]             = set()
        self._order:     deque[str]           = deque()
        self._lock       = threading.Lock()
        self._max_entries = max_entries
        self._hits        = 0
        self._misses      = 0

    def fingerprint(
        self,
        module:   str,
        url:      str,
        param:    str = "",
        category: str = "",
    ) -> str:
        key = f"{module}|{url}|{param}|{category}"
        return hashlib.sha256(key.encode()).hexdigest()

    def is_new(
        self,
        module:   str,
        url:      str,
        param:    str = "",
        category: str = "",
    ) -> bool:
        """
        True döner -> bu kombinasyon daha önce görülmedi (test edilebilir).
        False döner -> zaten test edildi (atla).
        """
        fp = self.fingerprint(module, url, param, category)
        with self._lock:
            if fp in self._seen:
                self._hits += 1
                return False
            # LRU eviction
            if self._max_entries > 0 and len(self._seen) >= self._max_entries:
                old = self._order.popleft()
                self._seen.discard(old)
            self._seen.add(fp)
            self._order.append(fp)
            self._misses += 1
        return True

    def mark_seen(self, module: str, url: str, param: str = "", category: str = "") -> None:
        """Kombinasyonu görüldü olarak işaretle (is_new() çağrısı olmadan)."""
        fp = self.fingerprint(module, url, param, category)
        with self._lock:
            if fp not in self._seen:
                if self._max_entries > 0 and len(self._seen) >= self._max_entries:
                    old = self._order.popleft()
                    self._seen.discard(old)
                self._seen.add(fp)
                self._order.append(fp)

    def reset(self) -> None:
        with self._lock:
            self._seen.clear()
            self._order.clear()
            self._hits = self._misses = 0

    def stats(self) -> Dict[str, int]:
        with self._lock:
            return {
                "seen":   len(self._seen),
                "hits":   self._hits,
                "misses": self._misses,
                "dedup_rate": round(
                    self._hits / max(1, self._hits + self._misses) * 100, 1
                ),
            }


# ---------------------------------------------------------------------------
# ETACalculator — Gerçek Zamanlı ETA Hesaplama
# ---------------------------------------------------------------------------

class ETACalculator:
    """
    Rolling average ile gerçek zamanlı tahmini tamamlanma süresi (ETA).

    Algoritma:
      - Son N görevin tamamlanma süresi rolling window'da tutulur.
      - avg_task_time = median(son N görev süresi)
      - ETA = remaining_tasks × avg_task_time
    """

    def __init__(self, window: int = 50, total_tasks: int = 0) -> None:
        self._window      = window
        self._task_times: deque[float] = deque(maxlen=window)
        self._lock        = threading.Lock()
        self._total       = max(0, total_tasks)
        self._completed   = 0
        self._started_at  = time.monotonic()
        self._last_tick   = self._started_at

    def set_total(self, total: int) -> None:
        with self._lock:
            self._total = max(0, total)

    def tick(self, task_duration_s: float) -> None:
        """Bir görev tamamlandığında çağrılır."""
        with self._lock:
            self._task_times.append(max(0.0, task_duration_s))
            self._completed += 1
            self._last_tick  = time.monotonic()

    def tick_batch(self, count: int, total_duration_s: float) -> None:
        """Birden fazla görevi aynı anda tamamla."""
        if count <= 0:
            return
        per_task = total_duration_s / count
        with self._lock:
            for _ in range(count):
                self._task_times.append(max(0.0, per_task))
            self._completed += count
            self._last_tick  = time.monotonic()

    @property
    def avg_task_s(self) -> float:
        with self._lock:
            if not self._task_times:
                return 0.0
            return statistics.median(self._task_times)

    @property
    def eta_seconds(self) -> float:
        with self._lock:
            remaining = max(0, self._total - self._completed)
            if not self._task_times:
                return 0.0
            avg = statistics.median(self._task_times)
            return remaining * avg

    @property
    def progress_pct(self) -> float:
        with self._lock:
            if self._total <= 0:
                return 0.0
            return round(min(100.0, self._completed / self._total * 100), 1)

    @property
    def elapsed_seconds(self) -> float:
        return time.monotonic() - self._started_at

    def snapshot(self) -> Dict[str, Any]:
        # P12 fix: _total and _completed were read outside the lock after
        # eta_seconds/progress_pct released it, leaving a window for concurrent
        # tick() calls to produce an inconsistent snapshot.
        with self._lock:
            total     = self._total
            completed = self._completed
            remaining = max(0, total - completed)
            avg       = statistics.median(self._task_times) if self._task_times else 0.0
            eta       = remaining * avg
            pct       = round(min(100.0, completed / total * 100), 1) if total > 0 else 0.0
        elapsed = time.monotonic() - self._started_at
        return {
            "total":         total,
            "completed":     completed,
            "remaining":     remaining,
            "progress_pct":  pct,
            "avg_task_s":    round(avg, 3),
            "eta_seconds":   round(eta, 1),
            "eta_human":     _fmt_duration(eta),
            "elapsed_s":     round(elapsed, 1),
            "elapsed_human": _fmt_duration(elapsed),
        }


def _fmt_duration(seconds: float) -> str:
    """Saniyeyi okunabilir "Xd Xh Xm Xs" formatına çevirir."""
    s = int(seconds)
    if s <= 0:
        return "0s"
    parts = []
    for unit, div in (("d", 86400), ("h", 3600), ("m", 60), ("s", 1)):
        val, s = divmod(s, div)
        if val:
            parts.append(f"{val}{unit}")
    return " ".join(parts) or "0s"


# ---------------------------------------------------------------------------
# AdaptiveConcurrencyCtrl — AIMD Concurrency Kontrolü
# ---------------------------------------------------------------------------

class AdaptiveConcurrencyCtrl:
    """
    AIMD (Additive Increase, Multiplicative Decrease) tabanlı adaptive concurrency.

    Kurallar:
      - Response time < LOW_MS  -> concurrency += 1  (additive increase)
      - Response time > HIGH_MS -> concurrency = max(min_c, concurrency // 2) (mult. decrease)
      - Error rate > 30%        -> concurrency = max(min_c, concurrency // 2)
      - 429 / 503 aldı          -> concurrency = min_c (acil düşüş)

    Thread-safe: tüm erişimler _lock ile korunur.
    """

    LOW_MS      = 300    # ms — bu altında hız artır
    HIGH_MS     = 2000   # ms — bu üstünde hızı yavaşlat
    ERROR_RATE  = 0.30   # 30% hata -> yavaşla
    WINDOW      = 30     # son N ölçüm

    def __init__(
        self,
        initial:    int = 10,
        min_c:      int = 1,
        max_c:      int = 50,
        low_ms:     int = 300,
        high_ms:    int = 2000,
    ) -> None:
        self._current   = initial
        self._min_c     = min_c
        self._max_c     = max_c
        self.LOW_MS     = low_ms
        self.HIGH_MS    = high_ms
        self._lock      = threading.Lock()
        self._times:    deque[float] = deque(maxlen=self.WINDOW)
        self._errors:   deque[bool]  = deque(maxlen=self.WINDOW)
        self._adj_count = 0   # kaç kez ayarlandı

    def record(self, response_ms: float, is_error: bool = False,
               status: int = 200) -> None:
        """Bir istek sonucunu kaydet ve gerekirse concurrency ayarla."""
        with self._lock:
            self._times.append(response_ms)
            self._errors.append(is_error)
            self._adjust(status)

    def _adjust(self, status: int) -> None:
        """Mevcut ölçümlere göre concurrency'i güncelle. Lock tutuluyken çağrılır."""
        if not self._times:
            return

        # Acil durum: 429 / 503
        if status in (429, 503):
            new = max(self._min_c, self._current // 2)
            if new != self._current:
                _logger.debug(f"[AdaptiveCC] {status} alındı -> concurrency {self._current} -> {new}")
                self._current = new
                self._adj_count += 1
            return

        # Hata oranı kontrolü
        if self._errors:
            err_rate = sum(self._errors) / len(self._errors)
            if err_rate > self.ERROR_RATE:
                new = max(self._min_c, self._current // 2)
                if new != self._current:
                    _logger.debug(f"[AdaptiveCC] Hata oranı {err_rate:.0%} -> {self._current} -> {new}")
                    self._current = new
                    self._adj_count += 1
                return

        # Yanıt süresi kontrolü
        median_ms = statistics.median(self._times)
        if median_ms > self.HIGH_MS:
            new = max(self._min_c, self._current - max(1, self._current // 4))
            if new != self._current:
                _logger.debug(f"[AdaptiveCC] Yavaş ({median_ms:.0f}ms) -> {self._current} -> {new}")
                self._current = new
                self._adj_count += 1
        elif median_ms < self.LOW_MS:
            new = min(self._max_c, self._current + 1)
            if new != self._current:
                _logger.debug(f"[AdaptiveCC] Hızlı ({median_ms:.0f}ms) -> {self._current} -> {new}")
                self._current = new
                self._adj_count += 1

    @property
    def current(self) -> int:
        with self._lock:
            return self._current

    def snapshot(self) -> Dict[str, Any]:
        with self._lock:
            median_ms = statistics.median(self._times) if self._times else 0.0
            err_rate  = sum(self._errors) / len(self._errors) if self._errors else 0.0
            return {
                "concurrency":   self._current,
                "min":           self._min_c,
                "max":           self._max_c,
                "median_ms":     round(median_ms, 1),
                "error_rate":    round(err_rate, 3),
                "adjustments":   self._adj_count,
                "window_size":   len(self._times),
            }


# ---------------------------------------------------------------------------
# AdaptiveThreadPool — Adaptive Concurrency ThreadPoolExecutor Wrapper
# ---------------------------------------------------------------------------

class AdaptiveThreadPool:
    """
    AdaptiveConcurrencyCtrl ile entegre ThreadPoolExecutor wrapper.

    - submit() -> future döner
    - map() -> sonuç generator döner
    - Periyodik olarak worker sayısını ayarlar (auto_resize=True)
    - ETA tracking entegre (ETACalculator)
    - Deduplication entegre (ScanDeduplicator)
    """

    def __init__(
        self,
        initial_workers:  int = 10,
        min_workers:      int = 1,
        max_workers:      int = 50,
        dedup:            Optional[ScanDeduplicator] = None,
        eta:              Optional[ETACalculator]    = None,
        auto_resize:      bool = True,
    ) -> None:
        self._ctrl        = AdaptiveConcurrencyCtrl(
            initial=initial_workers, min_c=min_workers, max_c=max_workers
        )
        self._dedup       = dedup
        self._eta         = eta
        self._auto_resize = auto_resize
        self._executor    = ThreadPoolExecutor(max_workers=initial_workers)
        self._lock        = threading.Lock()
        self._active      = 0
        self._resize_lock = threading.Lock()

    def submit(
        self,
        fn:     Callable,
        *args,
        module:   str = "",
        url:      str = "",
        param:    str = "",
        category: str = "",
        **kwargs,
    ) -> Optional[Future]:
        """
        Dedup kontrolü yaparak görevi pool'a gönderir.
        Daha önce görülmüş kombinasyon -> None döner.
        """
        if self._dedup and not self._dedup.is_new(module, url, param, category):
            return None

        def _wrapped():
            t0 = time.monotonic()
            try:
                result = fn(*args, **kwargs)
                # P7 fix: reuse the same elapsed value for both ctrl and eta
                # instead of calling time.monotonic() twice (second call was
                # slightly later, after ctrl.record() overhead).
                elapsed_ms = (time.monotonic() - t0) * 1000
                self._ctrl.record(elapsed_ms, is_error=False)
                if self._eta:
                    self._eta.tick(elapsed_ms / 1000)
                return result
            except Exception:
                elapsed_ms = (time.monotonic() - t0) * 1000
                self._ctrl.record(elapsed_ms, is_error=True)
                if self._eta:
                    self._eta.tick(elapsed_ms / 1000)
                raise
            finally:
                with self._lock:
                    self._active = max(0, self._active - 1)
                if self._auto_resize:
                    self._maybe_resize()

        with self._lock:
            self._active += 1
        return self._executor.submit(_wrapped)

    def map_tasks(
        self,
        tasks: Iterable[ScanTask],
        stop_on_first: bool = False,
    ) -> List[Any]:
        """PriorityTaskQueue'dan gelen görevleri sırayla işler."""
        futures: Dict[Future, ScanTask] = {}
        results: List[Any] = []

        for task in tasks:
            fut = self.submit(
                task.fn, *task.args,
                module=task.module, url=task.url, param=task.param,
                **task.kwargs,
            )
            if fut:
                futures[fut] = task

        for fut in as_completed(futures):
            try:
                result = fut.result()
                if result is not None:
                    results.append(result)
                    if stop_on_first:
                        for f in futures:
                            f.cancel()
                        break
            except Exception as exc:
                task = futures[fut]
                _logger.debug(f"[AdaptivePool] Görev hatası {task.task_id}: {exc!r}")

        return results

    def _maybe_resize(self) -> None:
        """Executor worker sayısını adaptive controller'a göre ayarla."""
        if not self._resize_lock.acquire(blocking=False):
            return
        try:
            target = self._ctrl.current
            current_max = getattr(self._executor, "_max_workers", target)
            if abs(target - current_max) >= 2:
                # Python TPE dinamik resize desteklemez; yeni executor aç.
                # P7 fix: shutdown(wait=True) deadlocked when called from a task
                # running on `old` — the task's Future is not DONE until _wrapped
                # returns (after this finally block), so wait=True blocks forever.
                # wait=False stops new submissions to the old executor while
                # already-running tasks finish naturally.
                old = self._executor
                self._executor = ThreadPoolExecutor(max_workers=target)
                old.shutdown(wait=False)
                _logger.debug(f"[AdaptivePool] Workers {current_max} -> {target}")
        finally:
            self._resize_lock.release()

    def shutdown(self, wait: bool = True) -> None:
        self._executor.shutdown(wait=wait)

    def snapshot(self) -> Dict[str, Any]:
        return {
            "concurrency":   self._ctrl.snapshot(),
            "active_tasks":  self._active,
            "dedup":         self._dedup.stats() if self._dedup else None,
            "eta":           self._eta.snapshot() if self._eta else None,
        }

    def __enter__(self) -> "AdaptiveThreadPool":
        return self

    def __exit__(self, *_) -> None:
        self.shutdown()


# ---------------------------------------------------------------------------
# StreamingURLProcessor — Büyük URL Listesi RAM-Verimli İşleme
# ---------------------------------------------------------------------------

class StreamingURLProcessor:
    """
    Büyük URL listelerini / dosyalarını RAM taşmadan batch işler.

    - Iterator / generator tabanlı — hepsini RAM'e yükleme
    - Opsiyonel RAM limiti kontrolü (psutil gerekli)
    - Batch size adaptif: RAM kullanımı yüksekse batch küçülür
    - process() -> her batch için callback çağırır
    """

    DEFAULT_BATCH  = 100
    MAX_BATCH      = 1000
    MIN_BATCH      = 10
    RAM_LIMIT_PCT  = 80   # %80 RAM doluysa batch'i yarıya indir

    def __init__(
        self,
        batch_size:    int = 100,
        ram_limit_pct: int = 80,
        dedup:         Optional[ScanDeduplicator] = None,
    ) -> None:
        self._batch_size    = max(self.MIN_BATCH, min(batch_size, self.MAX_BATCH))
        self._ram_limit_pct = ram_limit_pct
        self._dedup         = dedup
        self._total_yielded = 0

    def stream_file(self, filepath: str) -> Generator[str, None, None]:
        """Büyük URL listesi dosyasını satır satır generator olarak okur."""
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    url = line.strip()
                    if url and not url.startswith("#"):
                        yield url
        except FileNotFoundError:
            _logger.warning(f"[StreamingURL] Dosya bulunamadı: {filepath}")
        except Exception as exc:
            _logger.error(f"[StreamingURL] Okuma hatası: {exc!r}")

    def batches(
        self,
        urls: Iterable[str],
        module: str = "",
    ) -> Generator[List[str], None, None]:
        """
        URL generator'ı batch'lere böler.
        Dedup aktifse zaten işlenmiş URL'leri atlar.
        RAM yüksekse batch boyutunu küçültür.
        """
        batch:      List[str] = []
        batch_size  = self._batch_size

        for url in urls:
            # Dedup kontrolü
            if self._dedup and not self._dedup.is_new(module, url):
                continue

            batch.append(url)
            self._total_yielded += 1

            if len(batch) >= batch_size:
                yield batch
                batch = []
                # RAM kontrolü
                batch_size = self._adaptive_batch_size(batch_size)

        if batch:
            yield batch

    def process(
        self,
        urls:     Iterable[str],
        callback: Callable[[List[str]], Any],
        module:   str = "",
    ) -> int:
        """
        Tüm URL'leri batch'ler halinde işler.
        Her batch için callback(batch) çağrılır.
        Toplam işlenen URL sayısını döner.
        """
        processed = 0
        for batch in self.batches(urls, module=module):
            try:
                callback(batch)
                processed += len(batch)
            except Exception as exc:
                _logger.error(f"[StreamingURL] Batch callback hatası: {exc!r}")
        return processed

    def _adaptive_batch_size(self, current: int) -> int:
        """RAM kullanımı yüksekse batch boyutunu küçült."""
        if not _PSUTIL_AVAILABLE:
            return current
        try:
            ram_pct = _psutil.virtual_memory().percent
            if ram_pct > self._ram_limit_pct:
                new = max(self.MIN_BATCH, current // 2)
                if new < current:
                    _logger.debug(
                        f"[StreamingURL] RAM {ram_pct:.0f}% > {self._ram_limit_pct}%"
                        f" -> batch {current} -> {new}"
                    )
                return new
        except Exception as _fix_e:
            _logger.debug(f"[core.concurrency] {type(_fix_e).__name__}: {_fix_e!r}")
        return current

    @property
    def total_yielded(self) -> int:
        return self._total_yielded


# ---------------------------------------------------------------------------
# DistributedScanCoordinator — Redis Tabanlı Dağıtık Koordinasyon
# ---------------------------------------------------------------------------

class _BaseCoordinator:
    """Tüm koordinatörlerin soyut tabanı."""

    def enqueue(self, task_data: Dict[str, Any]) -> bool:
        raise NotImplementedError

    def dequeue(self, timeout: int = 5) -> Optional[Dict[str, Any]]:
        raise NotImplementedError

    def lock_task(self, task_id: str, ttl: int = 60) -> bool:
        raise NotImplementedError

    def unlock_task(self, task_id: str) -> None:
        raise NotImplementedError

    def publish_result(self, scan_id: str, result: Dict[str, Any]) -> None:
        raise NotImplementedError

    def get_results(self, scan_id: str) -> List[Dict[str, Any]]:
        raise NotImplementedError

    def heartbeat(self, worker_id: str, scan_id: str) -> None:
        raise NotImplementedError

    def close(self) -> None:
        pass


class NoopCoordinator(_BaseCoordinator):
    """
    Redis yoksa devreye giren sessiz fallback koordinatör.
    Tek makineli çalışmayı engellemez.
    """

    def __init__(self) -> None:
        _logger.info("[Coordinator] Redis bulunamadı -> Noop koordinatör kullanılıyor.")

    def enqueue(self, task_data: Dict[str, Any]) -> bool:
        return True

    def dequeue(self, timeout: int = 5) -> Optional[Dict[str, Any]]:
        return None

    def lock_task(self, task_id: str, ttl: int = 60) -> bool:
        return True

    def unlock_task(self, task_id: str) -> None:
        pass

    def publish_result(self, scan_id: str, result: Dict[str, Any]) -> None:
        pass

    def get_results(self, scan_id: str) -> List[Dict[str, Any]]:
        return []

    def heartbeat(self, worker_id: str, scan_id: str) -> None:
        pass


class DistributedScanCoordinator(_BaseCoordinator):
    """
    Redis tabanlı çok makineli tarama koordinasyonu.

    Redis veri yapıları:
      {prefix}:queue:{scan_id}   -> LIST  — bekleyen görev JSON'ları
      {prefix}:lock:{task_id}    -> STRING (TTL) — görev kilidi
      {prefix}:results:{scan_id} -> LIST  — tamamlanmış sonuçlar
      {prefix}:workers:{scan_id} -> HASH  — worker heartbeat'leri
      {prefix}:meta:{scan_id}    -> HASH  — tarama meta verileri

    Kullanım:
      coordinator = DistributedScanCoordinator.create(
          host="localhost", port=6379, scan_id="scan_abc123"
      )
      coordinator.enqueue({"url": "...", "module": "sqli"})
      task = coordinator.dequeue(timeout=5)
    """

    KEY_PREFIX = "websecure"

    def __init__(self, client: Any, scan_id: str) -> None:
        self._redis   = client
        self._scan_id = scan_id

    @classmethod
    def create(
        cls,
        scan_id:  str,
        host:     str = "localhost",
        port:     int = 6379,
        db:       int = 0,
        password: Optional[str] = None,
        ssl:      bool = False,
    ) -> "_BaseCoordinator":
        """Factory — Redis bağlantısı başarısız olursa NoopCoordinator döner."""
        if not _REDIS_AVAILABLE:
            _logger.warning("[Coordinator] redis-py yüklü değil. `pip install redis`")
            return NoopCoordinator()
        try:
            client = _redis_lib.Redis(
                host=host, port=port, db=db,
                password=password, ssl=ssl,
                socket_timeout=5, decode_responses=True,
            )
            client.ping()
            _logger.info(f"[Coordinator] Redis bağlantısı kuruldu: {host}:{port}")
            return cls(client, scan_id)
        except Exception as exc:
            _logger.warning(f"[Coordinator] Redis bağlantısı başarısız: {exc!r} -> Noop")
            return NoopCoordinator()

    # -- Kuyruk işlemleri ------------------------------------------------

    def _queue_key(self) -> str:
        return f"{self.KEY_PREFIX}:queue:{self._scan_id}"

    def _lock_key(self, task_id: str) -> str:
        return f"{self.KEY_PREFIX}:lock:{task_id}"

    def _results_key(self) -> str:
        return f"{self.KEY_PREFIX}:results:{self._scan_id}"

    def _workers_key(self) -> str:
        return f"{self.KEY_PREFIX}:workers:{self._scan_id}"

    def _meta_key(self) -> str:
        return f"{self.KEY_PREFIX}:meta:{self._scan_id}"

    def enqueue(self, task_data: Dict[str, Any]) -> bool:
        """Görevi Redis kuyruğuna ekle."""
        import json
        try:
            self._redis.rpush(self._queue_key(), json.dumps(task_data))
            return True
        except Exception as exc:
            _logger.error(f"[Coordinator] Enqueue hatası: {exc!r}")
            return False

    def enqueue_many(self, tasks: List[Dict[str, Any]]) -> int:
        """Birden fazla görevi pipeline ile verimli biçimde ekle."""
        import json
        try:
            pipe = self._redis.pipeline()
            for task in tasks:
                pipe.rpush(self._queue_key(), json.dumps(task))
            pipe.execute()
            return len(tasks)
        except Exception as exc:
            _logger.error(f"[Coordinator] Enqueue_many hatası: {exc!r}")
            return 0

    def dequeue(self, timeout: int = 5) -> Optional[Dict[str, Any]]:
        """Kuyruktan bir görev al (blocking, timeout saniyelik)."""
        import json
        try:
            result = self._redis.blpop(self._queue_key(), timeout=timeout)
            if result:
                _, data = result
                return json.loads(data)
        except Exception as exc:
            _logger.error(f"[Coordinator] Dequeue hatası: {exc!r}")
        return None

    def queue_size(self) -> int:
        try:
            return self._redis.llen(self._queue_key())
        except Exception:
            return 0

    # -- Görev kilitleme ------------------------------------------------

    def lock_task(self, task_id: str, ttl: int = 60) -> bool:
        """
        Görevi kilitle (SET NX EX).
        True -> kilit alındı (bu worker işleyecek).
        False -> başka worker zaten işliyor.
        """
        try:
            return bool(self._redis.set(
                self._lock_key(task_id), "1",
                nx=True, ex=ttl
            ))
        except Exception:
            return True   # Redis hatasında işlemeye izin ver

    def unlock_task(self, task_id: str) -> None:
        try:
            self._redis.delete(self._lock_key(task_id))
        except Exception as _e:
            _logger.debug(f"[Coordinator] Redis unlock_task failed: {_e!r}")

    def extend_lock(self, task_id: str, ttl: int = 60) -> None:
        """Uzun süren görevler için TTL'yi uzat."""
        try:
            self._redis.expire(self._lock_key(task_id), ttl)
        except Exception as _e:
            _logger.debug(f"[Coordinator] Redis extend_lock failed: {_e!r}")

    # -- Sonuç yönetimi -------------------------------------------------

    def publish_result(self, scan_id: str, result: Dict[str, Any]) -> None:
        import json
        try:
            self._redis.rpush(self._results_key(), json.dumps(result))
        except Exception as exc:
            _logger.error(f"[Coordinator] Sonuç yayımlama hatası: {exc!r}")

    def get_results(self, scan_id: str) -> List[Dict[str, Any]]:
        import json
        try:
            items = self._redis.lrange(self._results_key(), 0, -1)
            return [json.loads(i) for i in items]
        except Exception:
            return []

    # -- Worker heartbeat -----------------------------------------------

    def heartbeat(self, worker_id: str, scan_id: str) -> None:
        try:
            self._redis.hset(self._workers_key(), worker_id, str(time.time()))
            self._redis.expire(self._workers_key(), 120)
        except Exception as _fix_e:
            _logger.debug(f"[core.concurrency] {type(_fix_e).__name__}: {_fix_e!r}")

    def active_workers(self) -> Dict[str, float]:
        """Son 2 dakika içinde heartbeat gönderen worker'ları döner."""
        try:
            raw = self._redis.hgetall(self._workers_key())
            now = time.time()
            return {
                wid: float(ts)
                for wid, ts in raw.items()
                if now - float(ts) < 120
            }
        except Exception:
            return {}

    # -- Meta yönetimi --------------------------------------------------

    def set_meta(self, key: str, value: Any) -> None:
        try:
            self._redis.hset(self._meta_key(), key, str(value))
        except Exception as _fix_e:
            _logger.debug(f"[core.concurrency] {type(_fix_e).__name__}: {_fix_e!r}")

    def get_meta(self, key: str) -> Optional[str]:
        try:
            return self._redis.hget(self._meta_key(), key)
        except Exception:
            return None

    def close(self) -> None:
        try:
            self._redis.close()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Module-level yardımcı fonksiyonlar (kolay erişim)
# ---------------------------------------------------------------------------

def make_pool(
    workers:     int = 10,
    max_workers: int = 50,
    dedup:       bool = True,
    eta_total:   int  = 0,
) -> AdaptiveThreadPool:
    """AdaptiveThreadPool factory — kolay kullanım için."""
    deduplicator = ScanDeduplicator() if dedup else None
    calculator   = ETACalculator() if eta_total > 0 else None
    if calculator:
        calculator.set_total(eta_total)
    return AdaptiveThreadPool(
        initial_workers=workers,
        max_workers=max_workers,
        dedup=deduplicator,
        eta=calculator,
    )


def make_coordinator(
    scan_id:  str,
    host:     str = "localhost",
    port:     int = 6379,
    password: Optional[str] = None,
) -> _BaseCoordinator:
    """DistributedScanCoordinator factory — Redis yoksa Noop döner."""
    return DistributedScanCoordinator.create(
        scan_id=scan_id, host=host, port=port, password=password
    )


__all__ = [
    "TaskPriority",
    "ScanTask",
    "PriorityTaskQueue",
    "ScanDeduplicator",
    "ETACalculator",
    "AdaptiveConcurrencyCtrl",
    "AdaptiveThreadPool",
    "StreamingURLProcessor",
    "DistributedScanCoordinator",
    "NoopCoordinator",
    "make_pool",
    "make_coordinator",
]
