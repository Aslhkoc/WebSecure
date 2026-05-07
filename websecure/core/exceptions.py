"""
websecure.core.exceptions
~~~~~~~~~~~~~~~~~~~~~~~~~
Merkezi exception hiyerarşisi. Tüm scanner ve core modülleri bu exception'ları kullanır.
Her exception; url, param, payload ve orijinal hatayı taşır — sessiz failure imkansız.
"""
from __future__ import annotations

from typing import Optional


# ---------------------------------------------------------------------------
# Root
# ---------------------------------------------------------------------------

class WebSecureError(Exception):
    """Tüm WebSecure hatalarının base sınıfı."""

    def __init__(
        self,
        message: str,
        *,
        url: str = "",
        param: str = "",
        payload: str = "",
        original_exc: Optional[BaseException] = None,
    ) -> None:
        self.url = url
        self.param = param
        self.payload = payload
        self.original_exc = original_exc
        super().__init__(message)

    def __str__(self) -> str:
        parts = [super().__str__()]
        if self.url:
            parts.append(f"url={self.url!r}")
        if self.param:
            parts.append(f"param={self.param!r}")
        if self.payload:
            parts.append(f"payload={self.payload!r}")
        if self.original_exc:
            parts.append(f"caused_by={self.original_exc!r}")
        return " | ".join(parts)


# ---------------------------------------------------------------------------
# Scan errors — tarama zamanı hataları
# ---------------------------------------------------------------------------

class ScanError(WebSecureError):
    """Bir tarama adımı başarısız oldu."""


class ProbeError(ScanError):
    """Tek bir HTTP probe isteği başarısız oldu."""


class BaselineError(ScanError):
    """Baseline response alınamadı; tarama devam edemez."""


class PayloadError(ScanError):
    """Payload injection veya mutasyon başarısız oldu."""


# ---------------------------------------------------------------------------
# Network errors — ağ katmanı hataları
# ---------------------------------------------------------------------------

class NetworkError(WebSecureError):
    """Ağ katmanından kaynaklanan hatalar."""


class ConnectionRefusedError(NetworkError):  # noqa: A001 — intentional shadow
    """Hedefe bağlantı kurulamadı (refused veya unreachable)."""


class RequestTimeoutError(NetworkError):
    """İstek zaman aşımına uğradı."""


class SSLHandshakeError(NetworkError):
    """SSL/TLS el sıkışması başarısız oldu."""


# ---------------------------------------------------------------------------
# Parse errors — yanıt ayrıştırma hataları
# ---------------------------------------------------------------------------

class ParseError(WebSecureError):
    """HTTP yanıtı veya HTML/JSON ayrıştırılamadı."""


# ---------------------------------------------------------------------------
# Config errors — yapılandırma hataları
# ---------------------------------------------------------------------------

class ConfigError(WebSecureError):
    """Yapılandırma dosyası veya parametresi geçersiz."""


# ---------------------------------------------------------------------------
# Yardımcı: requests exception'larını WebSecure hiyerarşisine çevir
# ---------------------------------------------------------------------------

def wrap_requests_error(
    exc: BaseException,
    *,
    url: str = "",
    param: str = "",
    payload: str = "",
) -> NetworkError:
    """
    requests / urllib3 exception'ını uygun NetworkError alt sınıfına çevirir.
    Her zaman bir WebSecureError döndürür — çağıran kod sınıfı bilinir.
    """
    import requests as _req

    if isinstance(exc, _req.exceptions.SSLError):
        return SSLHandshakeError(
            str(exc), url=url, param=param, payload=payload, original_exc=exc
        )
    if isinstance(exc, (_req.exceptions.Timeout, _req.exceptions.ConnectTimeout, _req.exceptions.ReadTimeout)):
        return RequestTimeoutError(
            str(exc), url=url, param=param, payload=payload, original_exc=exc
        )
    if isinstance(exc, _req.exceptions.ConnectionError):
        return ConnectionRefusedError(
            str(exc), url=url, param=param, payload=payload, original_exc=exc
        )
    # Genel requests hatası -> NetworkError
    return NetworkError(
        str(exc), url=url, param=param, payload=payload, original_exc=exc
    )


__all__ = [
    "WebSecureError",
    "ScanError",
    "ProbeError",
    "BaselineError",
    "PayloadError",
    "NetworkError",
    "ConnectionRefusedError",
    "RequestTimeoutError",
    "SSLHandshakeError",
    "ParseError",
    "ConfigError",
    "wrap_requests_error",
]
