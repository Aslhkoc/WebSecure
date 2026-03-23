"""
proxy_pool.py — Gelişmiş Residential Proxy Rotation Havuzu.

Desteklenen vendor formatları:
  - BrightData (Luminati)
  - Oxylabs
  - SmartProxy
  - IPRoyal
  - Generic HTTP/SOCKS5 proxy

Özellikler:
  - Sağlık kontrolü (paralel, zaman aşımlı)
  - Başarısızlık sayacı → otomatik devre dışı bırakma
  - Çoklu strateji: round_robin, weighted_random, sticky, lru
  - Ülke bazlı hedefleme
  - Vendor'a özel URL oluşturucu
"""
from __future__ import annotations

import hashlib
import logging
import random
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence
from urllib.parse import urlparse

_logger = logging.getLogger(__name__)

# Bir proxy'nin devre dışı bırakılması için izin verilen arka arkaya hata sayısı
DEFAULT_FAILURE_THRESHOLD = 3
# Sağlık kontrolü zaman aşımı (saniye)
HEALTH_CHECK_TIMEOUT = 8.0
# Sağlık kontrolü için kullanılan test URL'si
HEALTH_CHECK_URL = "https://api.ipify.org?format=json"


# ---------------------------------------------------------------------------
# Vendor URL Oluşturucular
# ---------------------------------------------------------------------------

def build_brightdata_url(
    customer: str,
    zone: str,
    password: str,
    country: Optional[str] = None,
    session_id: Optional[str] = None,
) -> str:
    """
    BrightData (Luminati) proxy URL formatı.
    Örnek: http://brd-customer-CUST-zone-ZONE-country-us:PASS@brd.superproxy.io:22225
    """
    username = f"brd-customer-{customer}-zone-{zone}"
    if country:
        username += f"-country-{country.lower()}"
    if session_id:
        username += f"-session-{session_id}"
    return f"http://{username}:{password}@brd.superproxy.io:22225"


def build_oxylabs_url(
    username: str,
    password: str,
    country: Optional[str] = None,
    session_id: Optional[str] = None,
) -> str:
    """
    Oxylabs proxy URL formatı.
    Örnek: http://user-cc-US:PASS@pr.oxylabs.io:7777
    """
    user = username
    if country:
        user = f"{username}-cc-{country.upper()}"
    if session_id:
        user = f"{user}-sessid-{session_id}"
    return f"http://{user}:{password}@pr.oxylabs.io:7777"


def build_smartproxy_url(
    username: str,
    password: str,
    country: Optional[str] = None,
    port: int = 7000,
) -> str:
    """
    SmartProxy URL formatı.
    Örnek: http://user:PASS@gate.smartproxy.com:7000
    """
    host = "gate.smartproxy.com"
    if country:
        host = f"{country.lower()}.smartproxy.com"
    return f"http://{username}:{password}@{host}:{port}"


def build_iproyal_url(
    username: str,
    password: str,
    country: Optional[str] = None,
    session_id: Optional[str] = None,
) -> str:
    """
    IPRoyal URL formatı.
    Örnek: http://user_cc-US:PASS@geo.iproyal.com:12321
    """
    user = username
    if country:
        user = f"{username}_cc-{country.upper()}"
    if session_id:
        user = f"{user}_session-{session_id}"
    return f"http://{user}:{password}@geo.iproyal.com:12321"


def build_proxy_url(
    vendor: str,
    username: str,
    password: str,
    country: Optional[str] = None,
    session_id: Optional[str] = None,
    **kwargs,
) -> str:
    """
    Vendor adına göre doğru proxy URL formatını oluşturur.

    vendor: "brightdata" | "oxylabs" | "smartproxy" | "iproyal" | "generic"
    """
    v = vendor.lower().strip()
    if v in ("brightdata", "luminati", "brd"):
        customer = kwargs.get("customer", username)
        zone = kwargs.get("zone", "residential")
        return build_brightdata_url(customer, zone, password, country, session_id)
    if v == "oxylabs":
        return build_oxylabs_url(username, password, country, session_id)
    if v in ("smartproxy", "smart"):
        return build_smartproxy_url(username, password, country)
    if v in ("iproyal", "ipr"):
        return build_iproyal_url(username, password, country, session_id)
    # generic: URL'yi aynen döndür
    return username  # generic durumda username=url olarak geçilir


# ---------------------------------------------------------------------------
# Veri Sınıfları
# ---------------------------------------------------------------------------

@dataclass
class ProxyEntry:
    """Tek bir proxy kaydı."""
    url: str
    vendor: str = "generic"
    country: Optional[str] = None
    weight: int = 1
    sticky_ttl: int = 0          # saniye; 0 = her istekte rotate
    consecutive_failures: int = field(default=0, compare=False)
    last_used: float = field(default=0.0, compare=False)
    last_success: float = field(default=0.0, compare=False)
    disabled: bool = field(default=False, compare=False)

    def as_requests_dict(self) -> Dict[str, str]:
        """requests kütüphanesi için proxies sözlüğü."""
        return {"http": self.url, "https": self.url}

    @property
    def scheme(self) -> str:
        p = urlparse(self.url)
        return p.scheme.lower()

    @property
    def is_socks(self) -> bool:
        return self.scheme.startswith("socks")


@dataclass
class _StickySlot:
    entry: ProxyEntry
    expires_at: float


# ---------------------------------------------------------------------------
# Ana Havuz Sınıfı
# ---------------------------------------------------------------------------

class ResidentialProxyPool:
    """
    Residential proxy rotation havuzu.

    config.json yapısı::

        "network": {
            "proxies": {
                "rotate": "weighted_random",
                "failure_threshold": 3,
                "health_check_on_init": false,
                "pool": [
                    "http://user:pass@host:port",
                    {
                        "url": "socks5h://user:pass@host:1080",
                        "vendor": "brightdata",
                        "country": "us",
                        "weight": 3,
                        "sticky_ttl": 300
                    }
                ]
            }
        }
    """

    def __init__(self, cfg: dict) -> None:
        self._lock = threading.Lock()
        self._entries: List[ProxyEntry] = []
        self._rr_idx: int = 0
        self._sticky: Dict[str, _StickySlot] = {}
        self._failure_threshold: int = DEFAULT_FAILURE_THRESHOLD
        self.strategy: str = "round_robin"

        self._load(cfg)

    # ------------------------------------------------------------------
    # Config yükleme
    # ------------------------------------------------------------------

    def _load(self, cfg: dict) -> None:
        net = cfg.get("network") or {}
        p = net.get("proxies") or {}
        if not isinstance(p, dict):
            return

        self.strategy = str(p.get("rotate", "round_robin"))
        self._failure_threshold = int(p.get("failure_threshold", DEFAULT_FAILURE_THRESHOLD))
        do_health = bool(p.get("health_check_on_init", False))

        raw_pool = p.get("pool") or []
        for item in raw_pool:
            entry = self._parse_entry(item)
            if entry:
                self._entries.append(entry)

        _logger.info(f"[ProxyPool] {len(self._entries)} proxy yüklendi, strateji={self.strategy}")

        if do_health and self._entries:
            self._run_health_check_all(remove_dead=True)

    @staticmethod
    def _parse_entry(item) -> Optional[ProxyEntry]:
        if isinstance(item, str) and item.strip():
            return ProxyEntry(url=item.strip())
        if isinstance(item, dict):
            url = item.get("url", "").strip()
            if not url:
                return None
            return ProxyEntry(
                url=url,
                vendor=str(item.get("vendor", "generic")),
                country=item.get("country"),
                weight=int(item.get("weight", 1)),
                sticky_ttl=int(item.get("sticky_ttl", 0)),
            )
        return None

    # ------------------------------------------------------------------
    # Strateji metodları
    # ------------------------------------------------------------------

    @property
    def enabled(self) -> bool:
        with self._lock:
            return any(not e.disabled for e in self._entries)

    def _active(self) -> List[ProxyEntry]:
        """Devre dışı olmayan girişleri döner."""
        return [e for e in self._entries if not e.disabled]

    def next(
        self,
        key: str = "",
        strategy: Optional[str] = None,
        country: Optional[str] = None,
    ) -> Optional[ProxyEntry]:
        """
        Strateji'ye göre bir sonraki proxy'yi seçer.

        key     : sticky/hash stratejileri için anahtar (genellikle hedef URL)
        strategy: override; None ise self.strategy kullanılır
        country : ülke filtreleme (None = filtre yok)
        """
        with self._lock:
            pool = self._active()
            if country:
                filtered = [e for e in pool if e.country and e.country.lower() == country.lower()]
                if filtered:
                    pool = filtered

            if not pool:
                return None

            s = (strategy or self.strategy).lower()

            if s == "sticky" and key:
                return self._pick_sticky(key, pool)
            if s == "weighted_random":
                return self._pick_weighted(pool)
            if s == "lru":
                return self._pick_lru(pool)
            if s == "per_target" and key:
                idx = int(hashlib.md5(key.encode()).hexdigest(), 16) % len(pool)
                entry = pool[idx]
                entry.last_used = time.monotonic()
                return entry
            # round_robin (varsayılan)
            return self._pick_rr(pool)

    def _pick_rr(self, pool: List[ProxyEntry]) -> ProxyEntry:
        self._rr_idx = (self._rr_idx + 1) % len(pool)
        e = pool[self._rr_idx % len(pool)]
        e.last_used = time.monotonic()
        return e

    def _pick_weighted(self, pool: List[ProxyEntry]) -> ProxyEntry:
        weights = [e.weight for e in pool]
        e = random.choices(pool, weights=weights, k=1)[0]
        e.last_used = time.monotonic()
        return e

    def _pick_lru(self, pool: List[ProxyEntry]) -> ProxyEntry:
        e = min(pool, key=lambda x: x.last_used)
        e.last_used = time.monotonic()
        return e

    def _pick_sticky(self, key: str, pool: List[ProxyEntry]) -> ProxyEntry:
        now = time.monotonic()
        slot = self._sticky.get(key)
        if slot and not slot.entry.disabled and now < slot.expires_at:
            slot.entry.last_used = now
            return slot.entry
        # Yeni sticky seçimi
        e = self._pick_weighted(pool)
        ttl = e.sticky_ttl or 300
        self._sticky[key] = _StickySlot(entry=e, expires_at=now + ttl)
        return e

    # ------------------------------------------------------------------
    # Sağlık takibi
    # ------------------------------------------------------------------

    def record_success(self, entry: ProxyEntry) -> None:
        with self._lock:
            entry.consecutive_failures = 0
            entry.last_success = time.monotonic()
            entry.disabled = False

    def record_failure(self, entry: ProxyEntry) -> None:
        with self._lock:
            entry.consecutive_failures += 1
            if entry.consecutive_failures >= self._failure_threshold:
                entry.disabled = True
                _logger.warning(
                    f"[ProxyPool] Proxy devre dışı bırakıldı "
                    f"({entry.consecutive_failures} hata): {entry.url[:40]}"
                )

    def reenable_all(self) -> None:
        """Tüm proxy'leri yeniden etkinleştirir (hata sayaçlarını sıfırlar)."""
        with self._lock:
            for e in self._entries:
                e.consecutive_failures = 0
                e.disabled = False
        _logger.info("[ProxyPool] Tüm proxy'ler yeniden etkinleştirildi.")

    # ------------------------------------------------------------------
    # Sağlık kontrolü
    # ------------------------------------------------------------------

    def health_check_all(
        self,
        timeout: float = HEALTH_CHECK_TIMEOUT,
        test_url: str = HEALTH_CHECK_URL,
        remove_dead: bool = False,
        max_workers: int = 10,
    ) -> Dict[str, dict]:
        """
        Tüm proxy'leri paralel olarak kontrol eder.

        Dönüş::

            {
                "http://proxy:port": {
                    "ok": True,
                    "ip": "1.2.3.4",
                    "latency_ms": 312,
                    "error": None
                },
                ...
            }
        """
        results: Dict[str, dict] = {}
        entries = list(self._entries)

        def _check(entry: ProxyEntry) -> tuple[str, dict]:
            import requests as _req
            t0 = time.monotonic()
            try:
                r = _req.get(
                    test_url,
                    proxies=entry.as_requests_dict(),
                    timeout=timeout,
                    verify=False,
                )
                latency = int((time.monotonic() - t0) * 1000)
                ip = ""
                try:
                    ip = r.json().get("ip", r.text.strip()[:20])
                except Exception:
                    ip = r.text.strip()[:20]
                return entry.url, {"ok": True, "ip": ip, "latency_ms": latency, "error": None}
            except Exception as exc:
                latency = int((time.monotonic() - t0) * 1000)
                return entry.url, {"ok": False, "ip": "", "latency_ms": latency, "error": str(exc)[:80]}

        with ThreadPoolExecutor(max_workers=max_workers) as ex:
            futures = {ex.submit(_check, e): e for e in entries}
            for fut in as_completed(futures):
                url, info = fut.result()
                results[url] = info

        if remove_dead:
            self._run_health_check_all(remove_dead=True, _results=results)
        return results

    def _run_health_check_all(
        self, remove_dead: bool = False, _results: Optional[Dict] = None
    ) -> None:
        if _results is None:
            _results = self.health_check_all(remove_dead=False)
        if remove_dead:
            with self._lock:
                for entry in self._entries:
                    info = _results.get(entry.url, {})
                    if not info.get("ok"):
                        entry.disabled = True
                        _logger.warning(f"[ProxyPool] Sağlık kontrolü başarısız: {entry.url[:40]}")
                    else:
                        entry.disabled = False
                        entry.consecutive_failures = 0

    # ------------------------------------------------------------------
    # Yardımcılar
    # ------------------------------------------------------------------

    def add(self, entry: ProxyEntry) -> None:
        with self._lock:
            if not any(e.url == entry.url for e in self._entries):
                self._entries.append(entry)

    def remove(self, url: str) -> None:
        with self._lock:
            self._entries = [e for e in self._entries if e.url != url]

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            total = len(self._entries)
            active = sum(1 for e in self._entries if not e.disabled)
            return {
                "total": total,
                "active": active,
                "disabled": total - active,
                "strategy": self.strategy,
            }

    def __len__(self) -> int:
        return len(self._entries)

    def __repr__(self) -> str:
        s = self.stats()
        return (
            f"<ResidentialProxyPool total={s['total']} active={s['active']} "
            f"strategy={s['strategy']}>"
        )


# ---------------------------------------------------------------------------
# İzole tip import (stats Dict içinde Any kullanıldı)
# ---------------------------------------------------------------------------
from typing import Any  # noqa: E402 — döngüsel import önlemi için altta
