"""
tls_driver.py — curl_cffi tabanlı TLS parmak izi sahteciliği.

Cloudflare, Akamai, Imperva gibi JA3/JA4 tabanlı WAF'lar Python
requests/httpx kütüphanelerinin standart TLS imzasını tanır ve engeller.
Bu modül curl_cffi kullanarak gerçek tarayıcı TLS握手taklidini sağlar.
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

_logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Opsiyonel import — curl_cffi kurulu değilse sessizce degrade edilir
# ---------------------------------------------------------------------------
try:
    from curl_cffi import requests as _cffi_requests
    from curl_cffi.requests import Session as _CffiSession
    _CURL_CFFI_AVAILABLE = True
    _logger.debug("[TLSDriver] curl_cffi mevcut — tarayıcı TLS taklidi aktif.")
except ImportError:
    _cffi_requests = None  # type: ignore
    _CffiSession = None    # type: ignore
    _CURL_CFFI_AVAILABLE = False
    _logger.debug("[TLSDriver] curl_cffi bulunamadı — subprocess curl fallback kullanılacak.")


# ---------------------------------------------------------------------------
# Profil Haritası  (websecure profil adı → curl_cffi impersonate değeri)
# ---------------------------------------------------------------------------
CFFI_PROFILE_MAP: Dict[str, str] = {
    # Chrome
    "chrome_120":  "chrome120",
    "chrome_122":  "chrome122",
    "chrome_124":  "chrome124",
    "chrome_131":  "chrome131",
    # Firefox
    "firefox_115": "firefox115",
    "firefox_120": "ff120",
    "firefox_133": "firefox133",
    # Safari macOS
    "safari_17":   "safari17_0",
    "safari_18":   "safari18_0",
    # Safari iOS
    "safari_ios":  "safari_ios17_2",
    "safari_ios18":"safari_ios18_1_1",
    # Edge
    "edge_122":    "edge122",
    "edge_131":    "edge131",
}

DEFAULT_PROFILE = "chrome124"


def _resolve_profile(profile: str) -> str:
    """İç profil adını curl_cffi impersonate string'ine çevirir."""
    return CFFI_PROFILE_MAP.get(profile, profile or DEFAULT_PROFILE)


# ---------------------------------------------------------------------------
# Hafif yanıt sarmalayıcısı — requests.Response ile aynı arayüz
# ---------------------------------------------------------------------------
class CffiResponse:
    """curl_cffi yanıtını websecure UnifiedResponse ile uyumlu hale getirir."""

    def __init__(self, raw) -> None:
        self._raw = raw

    @property
    def status_code(self) -> int:
        return getattr(self._raw, "status_code", 0)

    @property
    def headers(self) -> Dict[str, str]:
        h = getattr(self._raw, "headers", {})
        return dict(h) if h else {}

    @property
    def text(self) -> str:
        try:
            return self._raw.text
        except Exception:
            return ""

    @property
    def content(self) -> bytes:
        return getattr(self._raw, "content", b"")

    @property
    def url(self) -> str:
        return str(getattr(self._raw, "url", ""))

    @property
    def ok(self) -> bool:
        return 200 <= self.status_code < 400

    @property
    def reason(self) -> str:
        return getattr(self._raw, "reason", "")

    def json(self, **kwargs):
        return self._raw.json(**kwargs)

    def raise_for_status(self):
        return self._raw.raise_for_status()


# ---------------------------------------------------------------------------
# Ana sürücü sınıfı
# ---------------------------------------------------------------------------
@dataclass
class CurlCffiDriver:
    """
    curl_cffi tabanlı HTTP sürücüsü.

    Gerçek tarayıcı JA3/JA4 TLS parmak izi + HTTP/2 başlık sıralaması
    ile istek gönderir. requests.Session ile birebir uyumlu arayüz sunar.

    Kullanım::

        driver = CurlCffiDriver(profile="chrome_124")
        resp = driver.request_once("GET", "https://hedef.com/")
    """

    profile: str = "chrome_124"
    proxy_url: Optional[str] = None
    verify: bool = True
    timeout_pair: tuple[float, float] = (10.0, 30.0)
    extra_headers: Dict[str, str] = field(default_factory=dict)

    # Dahili oturum — yeniden kullanılır
    _session: Any = field(init=False, default=None, repr=False)

    def __post_init__(self) -> None:
        if not _CURL_CFFI_AVAILABLE:
            raise RuntimeError(
                "curl_cffi kurulu değil. "
                "Kurulum: pip install 'websecure-scanner[bypass]' veya pip install curl-cffi"
            )
        impersonate = _resolve_profile(self.profile)
        proxies = {"https": self.proxy_url, "http": self.proxy_url} if self.proxy_url else None

        self._session = _CffiSession(
            impersonate=impersonate,
            verify=self.verify,
            proxies=proxies,
        )
        if self.extra_headers:
            self._session.headers.update(self.extra_headers)
        _logger.debug(f"[TLSDriver] Oturum oluşturuldu: impersonate={impersonate}, proxy={self.proxy_url}")

    # ------------------------------------------------------------------
    def update_proxy(self, proxy_url: Optional[str]) -> None:
        """Proxy URL'yi çalışma zamanında değiştirir."""
        self.proxy_url = proxy_url
        if self._session is not None:
            proxies = {"https": proxy_url, "http": proxy_url} if proxy_url else {}
            self._session.proxies = proxies

    def update_profile(self, profile: str) -> None:
        """TLS profilini değiştirir — yeni oturum oluşturur."""
        self.profile = profile
        old_headers = dict(self._session.headers) if self._session else {}
        impersonate = _resolve_profile(profile)
        proxies = {"https": self.proxy_url, "http": self.proxy_url} if self.proxy_url else None
        self._session = _CffiSession(
            impersonate=impersonate,
            verify=self.verify,
            proxies=proxies,
        )
        self._session.headers.update(old_headers)
        _logger.debug(f"[TLSDriver] Profil güncellendi: {impersonate}")

    # ------------------------------------------------------------------
    def request_once(self, method: str, url: str, **kw) -> CffiResponse:
        """
        Tek bir HTTP isteği gönderir.

        kw parametreleri requests.Session.request ile aynıdır:
        headers, params, data, json, files, cookies, allow_redirects, timeout
        """
        if self._session is None:
            raise RuntimeError("CurlCffiDriver başlatılmamış.")

        # Zaman aşımı
        kw.setdefault("timeout", int(self.timeout_pair[1]))

        # Doğrulama — curl_cffi verify parametresini kabul eder
        kw.setdefault("verify", self.verify)

        # Başlıkları birleştir
        headers = dict(kw.pop("headers", {}) or {})
        for k, v in self.extra_headers.items():
            headers.setdefault(k, v)
        if headers:
            kw["headers"] = headers

        t0 = time.monotonic()
        try:
            raw = self._session.request(method.upper(), url, **kw)
            elapsed = time.monotonic() - t0
            _logger.debug(
                f"[TLSDriver] {method.upper()} {url} → {raw.status_code} ({elapsed*1000:.0f}ms)"
            )
            return CffiResponse(raw)
        except Exception as exc:
            _logger.warning(f"[TLSDriver] İstek hatası: {exc}")
            raise

    # ------------------------------------------------------------------
    def close(self) -> None:
        if self._session is not None:
            try:
                self._session.close()
            except Exception:
                pass
            self._session = None


# ---------------------------------------------------------------------------
# Yardımcı fabrika fonksiyonu
# ---------------------------------------------------------------------------
def make_cffi_driver(
    profile: str = "chrome_124",
    proxy_url: Optional[str] = None,
    verify: bool = True,
    timeout_connect: float = 10.0,
    timeout_read: float = 30.0,
    headers: Optional[Dict[str, str]] = None,
) -> Optional["CurlCffiDriver"]:
    """
    curl_cffi mevcut değilse None döner; mevcut ise yeni bir CurlCffiDriver örneği döner.
    """
    if not _CURL_CFFI_AVAILABLE:
        return None
    return CurlCffiDriver(
        profile=profile,
        proxy_url=proxy_url,
        verify=verify,
        timeout_pair=(timeout_connect, timeout_read),
        extra_headers=headers or {},
    )
