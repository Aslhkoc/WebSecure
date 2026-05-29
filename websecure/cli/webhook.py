"""
websecure.cli.webhook
~~~~~~~~~~~~~~~~~~~~~~
Finding ve tarama olaylarını dış sistemlere HTTP webhook olarak iletir.

Özellikler
----------
* on_finding  — her yeni bulgu için tetiklenir
* on_critical — sadece Critical/High bulgular için
* on_complete — tarama tamamlandığında
* on_error    — hata oluştuğunda
* Retry: 3 deneme, üstel geri çekilme (1s -> 2s -> 4s)
* HMAC-SHA256 imzalama (opsiyonel — X-WebSecure-Signature header)
* Asenkron gönderim (arka plan thread)
* Çoklu endpoint desteği

SOLID
-----
- SRP  : Webhook iletimi tek sorumluluk.
- OCP  : Yeni event tipi eklemek mevcut kodu değiştirmez.
- DIP  : WebhookDispatcher soyut WebhookSender üzerinden çalışır.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import queue
import threading
import time
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Sabitler
# ---------------------------------------------------------------------------

_MAX_RETRIES   = 3
_RETRY_BASE_S  = 1.0      # 1s -> 2s -> 4s
_TIMEOUT_S     = 10
_QUEUE_SIZE    = 1000
_WORKER_COUNT  = 2


# ---------------------------------------------------------------------------
# Event modeli
# ---------------------------------------------------------------------------

@dataclass
class WebhookEvent:
    """Webhook gönderilen tek olay."""
    event_type: str           # "finding", "complete", "error", "scan_start"
    scan_id: str
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    target: str = ""
    payload: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event": self.event_type,
            "scan_id": self.scan_id,
            "timestamp": self.timestamp,
            "target": self.target,
            **self.payload,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False)


# ---------------------------------------------------------------------------
# WebhookEndpoint — tek bir hedef URL yapılandırması
# ---------------------------------------------------------------------------

@dataclass
class WebhookEndpoint:
    """Tek webhook hedefi."""
    url: str
    secret: str = ""                   # HMAC imzalama için gizli anahtar
    events: List[str] = field(         # hangi event'leri dinler
        default_factory=lambda: ["finding", "complete", "error"]
    )
    min_severity: str = "Info"         # minimum önem seviyesi filtresi
    headers: Dict[str, str] = field(default_factory=dict)

    # Önem sırası — filtreleme için
    _SEVERITY_ORDER = {
        "Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0
    }

    def listens_to(self, event_type: str) -> bool:
        """Bu endpoint bu event'i dinliyor mu?"""
        return event_type in self.events or "all" in self.events

    def severity_ok(self, severity: str) -> bool:
        """Bulgunun önem seviyesi eşiği geçiyor mu?"""
        sev_val = self._SEVERITY_ORDER.get(severity, 0)
        min_val = self._SEVERITY_ORDER.get(self.min_severity, 0)
        return sev_val >= min_val


# ---------------------------------------------------------------------------
# HTTP gönderici
# ---------------------------------------------------------------------------

class WebhookSender:
    """
    Tek bir WebhookEvent'i belirli bir endpoint'e gönderir.
    Retry + HMAC imzalama içerir.
    """

    def send(
        self,
        event: WebhookEvent,
        endpoint: WebhookEndpoint,
    ) -> bool:
        """
        Olayı gönder.

        Döndürür
        --------
        bool — Başarılı mı?
        """
        body = event.to_json().encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "User-Agent":   "WebSecure/2.0",
            "X-Event-Type": event.event_type,
            "X-Scan-ID":    event.scan_id,
            **endpoint.headers,
        }

        # HMAC imzalama
        if endpoint.secret:
            sig = hmac.new(
                endpoint.secret.encode("utf-8"),
                body,
                hashlib.sha256,
            ).hexdigest()
            headers["X-WebSecure-Signature"] = f"sha256={sig}"

        for attempt in range(1, _MAX_RETRIES + 1):
            try:
                req = urllib.request.Request(
                    endpoint.url,
                    data=body,
                    headers=headers,
                    method="POST",
                )
                with urllib.request.urlopen(req, timeout=_TIMEOUT_S) as resp:
                    if 200 <= resp.status < 300:
                        logger.debug(
                            f"[Webhook] [OK] {event.event_type} -> {endpoint.url}  "
                            f"HTTP {resp.status}"
                        )
                        return True
                    else:
                        logger.warning(
                            f"[Webhook] HTTP {resp.status} deneme {attempt}/{_MAX_RETRIES}"
                        )

            except urllib.error.HTTPError as exc:
                logger.warning(
                    f"[Webhook] HTTP hata {exc.code} deneme {attempt}/{_MAX_RETRIES}: "
                    f"{endpoint.url}"
                )
            except urllib.error.URLError as exc:
                logger.warning(
                    f"[Webhook] Bağlantı hatası deneme {attempt}/{_MAX_RETRIES}: {exc.reason}"
                )
            except Exception as exc:
                logger.warning(
                    f"[Webhook] Beklenmedik hata deneme {attempt}/{_MAX_RETRIES}: {exc!r}"
                )

            if attempt < _MAX_RETRIES:
                delay = _RETRY_BASE_S * (2 ** (attempt - 1))
                time.sleep(delay)

        logger.error(f"[Webhook] Başarısız — tüm denemeler tükendi: {endpoint.url}")
        return False


# ---------------------------------------------------------------------------
# WebhookDispatcher — çok-thread asenkron dağıtıcı
# ---------------------------------------------------------------------------

class WebhookDispatcher:
    """
    Webhook olaylarını arka plan thread'lerinde asenkron olarak gönderir.

    Kullanım
    --------
    ```python
    dispatcher = WebhookDispatcher()
    dispatcher.add_endpoint("https://hooks.slack.com/...", events=["finding"])
    dispatcher.start()

    # Bulgu oluştuğunda:
    dispatcher.dispatch_finding(
        scan_id="abc123", target="https://example.com",
        title="SQLi Found", severity="Critical", url="https://example.com/login"
    )

    dispatcher.stop()
    ```
    """

    def __init__(self) -> None:
        self._endpoints: List[WebhookEndpoint] = []
        self._queue: queue.Queue[Optional[tuple]] = queue.Queue(maxsize=_QUEUE_SIZE)
        self._workers: List[threading.Thread] = []
        self._sender = WebhookSender()
        self._running = False
        self._callbacks: List[Callable[[WebhookEvent, bool], None]] = []

    # ------------------------------------------------------------------
    # Yapılandırma
    # ------------------------------------------------------------------

    def add_endpoint(
        self,
        url: str,
        secret: str = "",
        events: Optional[List[str]] = None,
        min_severity: str = "Info",
        headers: Optional[Dict[str, str]] = None,
    ) -> "WebhookDispatcher":
        """Endpoint ekle (fluent API)."""
        ep = WebhookEndpoint(
            url=url,
            secret=secret,
            events=events or ["finding", "complete", "error"],
            min_severity=min_severity,
            headers=headers or {},
        )
        self._endpoints.append(ep)
        logger.info(f"[Webhook] Endpoint eklendi: {url}")
        return self

    def add_callback(
        self, fn: Callable[[WebhookEvent, bool], None]
    ) -> "WebhookDispatcher":
        """Gönderim sonrası çağrılacak callback ekle."""
        self._callbacks.append(fn)
        return self

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        for i in range(_WORKER_COUNT):
            t = threading.Thread(
                target=self._worker,
                name=f"WebhookWorker-{i}",
                daemon=True,
            )
            t.start()
            self._workers.append(t)
        logger.debug(f"[Webhook] {_WORKER_COUNT} worker başlatıldı.")

    def stop(self, timeout: float = 5.0) -> None:
        """Kuyruktaki olayları bekle ve worker'ları durdur."""
        self._running = False
        for _ in self._workers:
            self._queue.put(None)  # poison pill
        for w in self._workers:
            w.join(timeout=timeout)
        self._workers.clear()

    # ------------------------------------------------------------------
    # Dispatch API
    # ------------------------------------------------------------------

    def dispatch_finding(
        self,
        scan_id: str,
        target: str,
        title: str,
        severity: str,
        url: str,
        tool: str = "websecure",
        description: str = "",
        **extra: Any,
    ) -> None:
        """Yeni bulgu olayını kuyruğa ekle."""
        event = WebhookEvent(
            event_type="finding",
            scan_id=scan_id,
            target=target,
            payload={
                "finding": {
                    "title": title,
                    "severity": severity,
                    "url": url,
                    "tool": tool,
                    "description": description,
                    **extra,
                }
            },
        )
        self._enqueue(event)

    def dispatch_scan_start(self, scan_id: str, target: str, **meta: Any) -> None:
        event = WebhookEvent(
            event_type="scan_start",
            scan_id=scan_id,
            target=target,
            payload={"meta": meta},
        )
        self._enqueue(event)

    def dispatch_scan_complete(
        self,
        scan_id: str,
        target: str,
        duration_s: float,
        finding_count: int = 0,
        severity_summary: Optional[Dict[str, int]] = None,
    ) -> None:
        event = WebhookEvent(
            event_type="complete",
            scan_id=scan_id,
            target=target,
            payload={
                "finding_count": finding_count,
                "duration_s": round(duration_s, 2),
                "severity_summary": severity_summary or {},
            },
        )
        self._enqueue(event)

    def dispatch_error(
        self,
        scan_id: str,
        target: str,
        error: str,
        phase: str = "",
    ) -> None:
        event = WebhookEvent(
            event_type="error",
            scan_id=scan_id,
            target=target,
            payload={"error": error, "phase": phase},
        )
        self._enqueue(event)

    # ------------------------------------------------------------------
    # İç işleyiş
    # ------------------------------------------------------------------

    def _enqueue(self, event: WebhookEvent) -> None:
        if not self._endpoints:
            return
        try:
            self._queue.put_nowait((event, self._endpoints[:]))
        except queue.Full:
            logger.warning("[Webhook] Kuyruk dolu — olay atlandı.")

    def _worker(self) -> None:
        while True:
            item = self._queue.get()
            if item is None:  # poison pill
                self._queue.task_done()
                break
            try:
                event, endpoints = item
                for ep in endpoints:
                    if not ep.listens_to(event.event_type):
                        continue
                    # Finding önem filtresi
                    if event.event_type == "finding":
                        sev = event.payload.get("finding", {}).get("severity", "Info")
                        if not ep.severity_ok(sev):
                            continue
                    try:
                        ok = self._sender.send(event, ep)
                        for cb in self._callbacks:
                            try:
                                cb(event, ok)
                            except Exception as _fix_e:
                                logger.debug(f"[cli.webhook] {type(_fix_e).__name__}: {_fix_e!r}")
                    except Exception as exc:
                        logger.error(f"[Webhook] Worker hatası: {exc!r}", exc_info=True)
            finally:
                self._queue.task_done()


# ---------------------------------------------------------------------------
# Singleton global dispatcher
# ---------------------------------------------------------------------------

_global_dispatcher: Optional[WebhookDispatcher] = None


def get_dispatcher() -> WebhookDispatcher:
    """Global WebhookDispatcher singleton'ını döndür."""
    global _global_dispatcher
    if _global_dispatcher is None:
        _global_dispatcher = WebhookDispatcher()
    return _global_dispatcher


def configure_webhook(
    url: str,
    secret: str = "",
    events: Optional[List[str]] = None,
    min_severity: str = "Info",
) -> WebhookDispatcher:
    """
    Global dispatcher'ı tek bir URL ile yapılandır ve başlat.

    Kısayol fonksiyon — çoğu kullanım senaryosu için yeterli.
    """
    dispatcher = get_dispatcher()
    dispatcher.add_endpoint(url, secret=secret, events=events, min_severity=min_severity)
    dispatcher.start()  # guarded internally — safe to call unconditionally
    return dispatcher


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

__all__ = [
    "WebhookEvent",
    "WebhookEndpoint",
    "WebhookSender",
    "WebhookDispatcher",
    "get_dispatcher",
    "configure_webhook",
]
