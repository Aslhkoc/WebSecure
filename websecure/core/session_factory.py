"""
websecure.core.session_factory
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
HTTP session oluşturma ve yapılandırma.
main.py'deki ensure_session() ve ilgili yardımcılar bu modüle taşındı.

FAZ 4.2: main.py'den ayrıştırıldı.
Geriye dönük uyumluluk: main.py bu modülden import edip re-export eder.
"""
from __future__ import annotations

import importlib
import importlib.util
import logging
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
    Gerçek implementasyon hâlâ main.py'de — bu fonksiyon ona delege eder.
    """
    try:
        from websecure import main as _main
        fn = getattr(_main, "_setup_session_from_config", None)
        if callable(fn):
            return fn(config)
    except Exception as exc:
        logger.warning(f"[session_factory] _setup_session_from_config yüklenemedi: {exc!r}")

    # Fallback
    return ensure_session(config)


__all__ = [
    "ensure_session",
    "build_session_from_config",
]
