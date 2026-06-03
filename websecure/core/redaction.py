"""
websecure.core.redaction
~~~~~~~~~~~~~~~~~~~~~~~~~
Hassas veri maskeleme (redaction) sistemi.
Tüm tarama bulgularındaki password, token, secret, cookie gibi değerler
raporlamadan önce bu modül tarafından temizlenir.

FAZ 4.1: reporting.py'den ayrıştırıldı.
Geriye dönük uyumluluk: reporting.py bu modülden import edip re-export eder.
"""
from __future__ import annotations

import logging
import re
from typing import Any, Dict

# ---------------------------------------------------------------------------
# Maskelenecek anahtar adları
# ---------------------------------------------------------------------------
REDACT_KEYS: frozenset = frozenset({
    "password", "passwd", "token", "authorization", "auth", "secret",
    "api_key", "apikey", "access_token", "refresh_token", "session",
    "cookie", "set-cookie", "csrf", "csrf_token", "xsrf",
})

_MASK = "<redacted>"

# ---------------------------------------------------------------------------
# Regex desenleri
# ---------------------------------------------------------------------------
_JWT_RE    = re.compile(r"\beyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}\b")
_BEARER_RE = re.compile(r"\bBearer\s+[A-Za-z0-9_\-\.]{20,}\b", re.I)
_HEX_RE    = re.compile(r"\b[0-9a-fA-F]{32,}\b")
_EMAIL_RE  = re.compile(r"[\w\.-]+@[\w\.-]+\.\w+")
# Group(1) captures the separator + name + "=" so the replacement preserves ";\s*name="
_RE_COOKIE = re.compile(r"((?:^|;\s*)[A-Za-z0-9_\-]{1,64}=)[^;]+", re.IGNORECASE)

# Pre-compiled per-key patterns to avoid recompiling on every _redact_str() call
_KEY_RE_PAIRS = [
    (
        re.compile(fr'("{re.escape(k)}"\s*:\s*")([^"]+)"', re.IGNORECASE),
        re.compile(fr'({re.escape(k)})=([^\s;&]+)', re.IGNORECASE),
    )
    for k in REDACT_KEYS
]


# ---------------------------------------------------------------------------
# Temel maskeleme işlevleri
# ---------------------------------------------------------------------------

def _redact_str(s: str) -> str:
    """Tek bir string değerini yerleşik pattern'lara göre maskeler."""
    if not s:
        return s
    t = s
    t = _JWT_RE.sub(_MASK, t)
    t = _BEARER_RE.sub("Bearer " + _MASK, t)
    t = _HEX_RE.sub(_MASK, t)
    t = _EMAIL_RE.sub(_MASK, t)
    t = _RE_COOKIE.sub(lambda m: m.group(1) + _MASK, t)
    for json_re, eq_re in _KEY_RE_PAIRS:
        t = json_re.sub(fr'\1{_MASK}"', t)
        t = eq_re.sub(r'\1=' + _MASK, t)
    return t


def redact_sensitive(val: Any, _depth: int = 0, _max: int = 6) -> Any:
    """
    Herhangi bir Python değerini (dict, list, str, bytes) yinelemeli olarak maskeler.
    Raporlama sistemine girmeden önce her bulguya uygulanır.
    """
    if _depth > _max:
        return _MASK
    if isinstance(val, dict):
        out: Dict[str, Any] = {}
        for k, v in val.items():
            if str(k).lower() in REDACT_KEYS:
                out[k] = _MASK
            else:
                out[k] = redact_sensitive(v, _depth + 1, _max)
        return out
    if isinstance(val, (list, tuple, set)):
        typ = type(val)
        return typ(redact_sensitive(x, _depth + 1, _max) for x in val)
    if isinstance(val, (bytes, str)):
        s = val.decode("utf-8", "ignore") if isinstance(val, bytes) else val
        return _redact_str(s)
    return val


# ---------------------------------------------------------------------------
# Logging filter — log mesajlarında hassas verileri maskeler
# ---------------------------------------------------------------------------

class RedactFilter(logging.Filter):
    """
    Python logging pipeline'ına eklenerek tüm log mesajlarındaki
    hassas verilerin (token, password vb.) maskelenmesini sağlar.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.args, tuple) and record.args:
            record.args = tuple(redact_sensitive(a) for a in record.args)
        elif isinstance(record.args, dict) and record.args:
            record.args = {k: redact_sensitive(v) for k, v in record.args.items()}
        if isinstance(record.msg, str):
            record.msg = _redact_str(record.msg)
        return True


__all__ = [
    "REDACT_KEYS",
    "redact_sensitive",
    "RedactFilter",
    "_redact_str",
    "_MASK",
]
