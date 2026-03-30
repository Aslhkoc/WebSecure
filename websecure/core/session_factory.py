"""
websecure.core.session_factory
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
HTTP session oluşturma ve yapılandırma.
main.py'deki ensure_session() ve ilgili yardımcılar bu modüle taşındı.

FAZ 4.2: main.py'den ayrıştırıldı.
FAZ-EK: Proxy/session helpers (proxy validation + _setup_session_from_config) taşındı.
Geriye dönük uyumluluk: main.py bu modülden import edip re-export eder.
"""
from __future__ import annotations

import importlib
import importlib.util
import logging
import os
import re
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


def _spec_exists(name: str) -> bool:
    """Modülün import edilebilir olup olmadığını kontrol eder."""
    try:
        return importlib.util.find_spec(name) is not None
    except (ModuleNotFoundError, ValueError):
        return False


def ensure_session(cfg: Dict[str, Any]):
    """
    Yapılandırmaya göre geliştirilmiş bir requests.Session döndürür.

    - websecure.core.http mevcutsa: hardened_session + instrument_requests_session
    - Yoksa: temel requests.Session

    FAZ 4.2: main.py:503'ten taşındı.
    """
    if _spec_exists("websecure.core.http"):
        from websecure.core.http import hardened_session, instrument_requests_session  # type: ignore

        http_cfg: Dict[str, Any] = {}
        if isinstance(cfg, dict):
            http_cfg = dict(cfg.get("http") or {})
            # Backward-compat: top-level HTTP anahtarlarını da kabul et
            for k in (
                "headers", "proxies", "verify", "timeout", "pool_maxsize",
                "retries", "rate_limit", "idempotent_first", "default_headers",
                "identity_pools",
            ):
                if k in cfg and k not in http_cfg:
                    http_cfg[k] = cfg[k]

        s = hardened_session(http_cfg)
        instrument_requests_session(s, cfg or {})
        return s

    # Fallback: basic session
    import requests
    return requests.Session()


def build_session_from_config(config: Dict[str, Any]):
    """
    Yapılandırma dosyasından tam özellikli session oluşturur.
    Proxy ayarları, retry politikası ve SSL doğrulaması dahil.

    FAZ 4.2: main.py:1484'teki _setup_session_from_config eşdeğeri.
    FAZ-EK: Artık gerçek implementasyon bu modülde.
    """
    return _setup_session_from_config(config)


# ---------------------------------------------------------------------------
# FAZ-EK: Proxy/session helpers — main.py'den taşındı
# ---------------------------------------------------------------------------

def _parse_host_port_from_proxy(url: str) -> tuple[str, int]:
    u = str(url or "").strip()
    if not u:
        return "", 0
    # allow forms like socks5h://127.0.0.1:9150 or http://127.0.0.1:8080
    # very small parser
    if "://" in u:
        rest = u.split("://", 1)[1]
    else:
        rest = u
    # strip userinfo if any
    if "@" in rest:
        rest = rest.rsplit("@", 1)[-1]
    host = rest
    port = 0
    if "[" in rest and "]" in rest:
        # IPv6 literal like [::1]:9150
        host_part = rest.split("]", 1)[0] + "]"
        tail = rest.split("]", 1)[1]
        host = host_part
        if tail.startswith(":"):
            p = tail[1:]
            port = int(p) if p.isdigit() else 0
    else:
        if ":" in rest:
            host, p = rest.rsplit(":", 1)
            port = int(p) if p.isdigit() else 0
        else:
            host = rest
            port = 0
    return host.strip(), port


def _tcp_port_open(host: str, port: int, timeout_s: float = 1.0) -> bool:
    if not host or port <= 0 or port > 65535:
        return False
    import socket as _socket
    s = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
    try_set = getattr(s, "settimeout", None)
    if try_set:
        try_set(timeout_s)
    rc = s.connect_ex((host, port))
    try_close = getattr(s, "close", None)
    if try_close:
        try_close()
    return rc == 0


def _proxy_alive(url: str) -> bool:
    host, port = _parse_host_port_from_proxy(url)
    return _tcp_port_open(host, port, 1.0)


def _setup_session_from_config(config: dict):
    def _to_bool(x, default: bool) -> bool:
        if isinstance(x, bool):
            return x
        if isinstance(x, (int, float)):
            return x != 0
        if isinstance(x, str):
            s = x.strip().lower()
            if s in ("1", "true", "yes", "on"):  return True
            if s in ("0", "false", "no", "off"): return False
        return default

    def _to_int(x, default: int) -> int:
        if isinstance(x, int):
            return x
        if isinstance(x, float) and x.is_integer():
            return int(x)
        if isinstance(x, str) and re.fullmatch(r"[+-]?\d+", x.strip() or ""):
            return int(x.strip())
        return default

    def _to_float(x, default: float) -> float:
        if isinstance(x, (int, float)):
            return float(x)
        if isinstance(x, str) and re.fullmatch(r"[+-]?(?:\d+(?:\.\d*)?|\.\d+)", x.strip() or ""):
            return float(x.strip())
        return default

    def _to_upper_methods(x, default: list[str]) -> set[str]:
        if isinstance(x, (list, tuple)):
            out = []
            for m in x:
                if isinstance(m, str) and m.strip():
                    out.append(m.strip().upper())
            return set(out) if out else set(default)
        return set(default)

    def _to_int_list(x, default: list[int]) -> list[int]:
        if isinstance(x, (list, tuple)):
            out: list[int] = []
            for v in x:
                iv = _to_int(v, None)  # type: ignore[arg-type]
                if isinstance(iv, int):
                    out.append(iv)
            return out if out else list(default)
        return list(default)

    def _pick_from_config(cfg: dict, key: str, default=None):
        v = cfg.get(key)
        return default if v is None else v

    cfg = config if isinstance(config, dict) else {}

    s = ensure_session(cfg)

    # User-Agent
    import random as _r_ua
    _default_uas = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    ]
    ua_cfg = _pick_from_config(cfg, "user_agent", "")
    ua = ua_cfg if isinstance(ua_cfg, str) and ua_cfg.strip() and "WebSec" not in ua_cfg else _r_ua.choice(_default_uas)
    s.headers.update({"User-Agent": ua})

    # TLS verify
    verify_cfg = _pick_from_config(cfg, "tls_verify", True)
    s.verify = _to_bool(verify_cfg, True)

    # --- WS3: Privacy Identity selection ---
    try:
        from websecure.core.utils import current_identity
        ident = current_identity()
    except Exception as exc:
        ident = {}
    ident = ident if isinstance(ident, dict) else {}

    ua_id = str(ident.get("ua") or "") if ident.get("ua") is not None else ""
    al_id = str(ident.get("accept_language") or "") if ident.get("accept_language") is not None else ""
    if ua_id:
        s.headers.update({"User-Agent": ua_id})
    if al_id:
        s.headers.update({"Accept-Language": al_id})

    px = ident.get("proxy_url")
    if isinstance(px, (str, bytes)):
        pxs = px.decode() if isinstance(px, bytes) else px
    else:
        pxs = None
    if pxs and _proxy_alive(str(pxs)):
        s.proxies.update({"http": str(pxs), "https": str(pxs)})

    if pxs:
        os.environ["WEBSEC_PROXY"] = str(pxs)
    if al_id:
        os.environ["WEBSEC_ACCEPT_LANGUAGE"] = al_id
    if ua_id:
        os.environ["WEBSEC_UA"] = ua_id

    # Proxies (settings.proxy_pool ilkini kullan)
    settings = cfg.get("settings")
    if isinstance(settings, dict):
        proxy_pool = settings.get("proxy_pool") or []
        if isinstance(proxy_pool, (list, tuple)) and proxy_pool:
            first = proxy_pool[0]
            if isinstance(first, (str, bytes)):
                purl = first.decode() if isinstance(first, bytes) else first
                s.proxies.update({"http": purl, "https": purl})

    # Retry (opsiyonel, istisnasız)
    # Yalnızca modüller mevcutsa etkinleştir.
    has_retry = _spec_exists("urllib3.util.retry")
    has_adapter = _spec_exists("requests.adapters")
    if has_retry and has_adapter:
        Retry = importlib.import_module("urllib3.util.retry").Retry  # type: ignore[attr-defined]
        HTTPAdapter = importlib.import_module("requests.adapters").HTTPAdapter  # type: ignore[attr-defined]

        http_total = _to_int(cfg.get("http_retries"), 2)
        if http_total < 0:
            http_total = 0

        backoff = _to_float(cfg.get("http_backoff"), 0.3)
        if backoff < 0.0:
            backoff = 0.0

        status_list = _to_int_list(cfg.get("retry_status_forcelist"), [429, 500, 502, 503, 504])
        allowed = cfg.get("retry_allowed_methods")
        allowed_methods = _to_upper_methods(allowed, ["HEAD", "GET", "OPTIONS"])

        policy = Retry(
            total=http_total,
            read=http_total,
            connect=http_total,
            backoff_factor=backoff,
            status_forcelist=tuple(status_list),
            allowed_methods=frozenset(allowed_methods),
            raise_on_status=False,
            respect_retry_after_header=True,
        )
        pool_max = _to_int(cfg.get("pool_maxsize"), 10)
        if pool_max < 1:
            pool_max = 1
        adapter = HTTPAdapter(max_retries=policy, pool_maxsize=pool_max)
        s.mount("http://", adapter)
        s.mount("https://", adapter)

    # Configured HTTP proxies (e.g., Tor SOCKS) take precedence if provided
    http_cfg = cfg.get("http")
    if isinstance(http_cfg, dict):
        http_proxies = http_cfg.get("proxies") or {}
        if isinstance(http_proxies, dict):
            purl = http_proxies.get("http") or http_proxies.get("https")
            if isinstance(purl, (str, bytes)):
                purls = purl.decode() if isinstance(purl, bytes) else purl
                if _proxy_alive(str(purls)):
                    s.proxies.update({"http": purls, "https": purls})

    return s


__all__ = [
    "ensure_session",
    "build_session_from_config",
    "_parse_host_port_from_proxy",
    "_tcp_port_open",
    "_proxy_alive",
    "_setup_session_from_config",
]
