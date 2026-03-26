"""
websecure.core.scan_runner
~~~~~~~~~~~~~~~~~~~~~~~~~~~
Scanner orchestration yardımcıları.
`_call_scanner_if_available()` ve `_bind_offensive()` main.py'den taşındı.

FAZ 4.2: main.py'den ayrıştırıldı.
Geriye dönük uyumluluk: main.py bu modülden import edip re-export eder.
"""
from __future__ import annotations

import importlib
import importlib.util
import inspect
import logging
from typing import Any, Callable, Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Modül keşif yardımcısı
# ---------------------------------------------------------------------------

def _spec_exists(name: str):
    """Modülün import edilebilir olup olmadığını kontrol eder (None veya ModuleSpec döner)."""
    try:
        return importlib.util.find_spec(name)
    except (ImportError, ModuleNotFoundError, AttributeError, ValueError):
        return None


# ---------------------------------------------------------------------------
# Scanner çağırma
# ---------------------------------------------------------------------------

def _call_scanner_if_available(
    mod_name: str,
    url: str,
    session=None,
    debug: bool = False,
    auth_ctx=None,
) -> Any:
    """
    Bir scanner modülünü dinamik olarak yükler ve `run()` fonksiyonunu çağırır.
    Modül bulunamazsa `None` döner — hata fırlatmaz.

    Parametre keşfi: `inspect.signature` ile `run()` imzasına bakılır;
    sadece desteklenen parametreler iletilir.

    FAZ 4.2: main.py:906'dan taşındı.
    """
    spec = _spec_exists(mod_name)
    mod = None

    if spec is not None:
        try:
            mod = importlib.import_module(mod_name)
        except ImportError as exc:
            logger.warning(f"[scan_runner] {mod_name} import edilemedi: {exc!r}")
            return None
    else:
        # Fallback: "websecure.scanners.xxx" → "scanners.xxx" → "xxx"
        if "." in mod_name:
            fallback = mod_name.split(".", 1)[1]
            fb_spec = _spec_exists(fallback)
            if fb_spec is not None:
                try:
                    mod = importlib.import_module(fallback)
                except ImportError as exc:
                    logger.debug(f"[scan_runner] {fallback} fallback import başarısız: {exc!r}")

    if mod is None:
        logger.debug(f"[scan_runner] Modül bulunamadı, atlanıyor: {mod_name}")
        return None

    run_fn = getattr(mod, "run", None)
    if not callable(run_fn):
        logger.debug(f"[scan_runner] {mod_name}.run() çağrılabilir değil")
        return None

    try:
        sig = inspect.signature(run_fn)
        params = sig.parameters
    except (TypeError, ValueError) as exc:
        logger.warning(f"[scan_runner] {mod_name}.run() imzası alınamadı: {exc!r}")
        return None

    kw: dict = {}
    if "url" in params:
        kw["url"] = url
    if "session" in params:
        kw["session"] = session
    if "debug" in params:
        kw["debug"] = debug
    if "auth_ctx" in params:
        kw["auth_ctx"] = auth_ctx

    try:
        return run_fn(**kw)
    except Exception as exc:
        logger.error(f"[scan_runner] {mod_name}.run() çalışırken hata: {exc!r}", exc_info=True)
        return None


# ---------------------------------------------------------------------------
# Offensive scanner bağlama
# ---------------------------------------------------------------------------

def _bind_offensive(modname: str, fallback_name: str) -> Callable:
    """
    Bir offensive scanner modülünü yükler ve `run` fonksiyonunu döner.
    Modül yoksa veya `run` bulunamazsa, sessiz bir no-op fallback döner.

    FAZ 4.2: main.py:938'den taşındı.
    """
    fn: Optional[Callable] = None

    if _spec_exists(modname) is not None:
        try:
            _m = importlib.import_module(modname)
            _r = getattr(_m, "run", None)
            if callable(_r):
                fn = _r
            else:
                logger.debug(f"[scan_runner] {modname}.run() bulunamadı veya çağrılabilir değil")
        except ImportError as exc:
            logger.debug(f"[scan_runner] {modname} import edilemedi: {exc!r}")

    if fn is None:
        def _fallback(*a, **k):
            return None

        _fallback.__name__ = fallback_name
        return _fallback

    return fn


__all__ = [
    "_call_scanner_if_available",
    "_bind_offensive",
]
