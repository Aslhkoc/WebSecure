"""
websecure.core.utils.helpers
-----------------------------
Combined text utilities, auth helpers, and TTL cache.
(Merged from text.py + cache.py)
"""
import inspect
import re
import random
import string
import time
from typing import Any, Callable, Dict, Optional, Set, Tuple
from urllib.parse import urlparse

# ========================== Strings & Redaction ==========================
_SENSITIVE_KEYS = {"password", "token", "secret", "key", "auth", "credential", "jwt"}
_SENSITIVE_VALUES_RE = re.compile(r"(ey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*|AKIA[0-9A-Z]{16})")

def redact_sensitive(data: Any) -> Any:
    """Redacts sensitive information from dictionaries/strings recursively."""
    if isinstance(data, dict):
        return {k: redact_sensitive(v) if k.lower() not in _SENSITIVE_KEYS else "***REDACTED***" for k, v in data.items()}
    if isinstance(data, list):
        return [redact_sensitive(x) for x in data]
    if isinstance(data, str):
        return _SENSITIVE_VALUES_RE.sub("[REDACTED]", data)
    return data

def random_string(length: int = 8, chars: str = string.ascii_letters + string.digits) -> str:
    return "".join(random.choice(chars) for _ in range(length))

def slugify(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")

def _truthy(v: Any, default: bool = False) -> bool:
    return bool(v) if v is not None else default

# ========================== Identity / Headers ==========================
def apply_auth_context(
    headers: Dict[str, str],
    cookies: Dict[str, str],
    auth_ctx: Dict[str, Any]
) -> tuple:
    """Merges auth context headers/cookies into base headers/cookies."""
    h = headers.copy() if headers else {}
    c = cookies.copy() if cookies else {}

    if auth_ctx:
        if "headers" in auth_ctx:
            h.update(auth_ctx["headers"])
        if "cookies" in auth_ctx:
            c.update(auth_ctx["cookies"])

    return h, c

def normalize_idn_host(host: str) -> tuple:
    """Simple IDN normalization wrapper."""
    try:
        return host.encode("idna").decode("ascii"), []
    except Exception:
        return host, ["IDN normalization failed"]

# ========================== TTL Cache ==========================
_TTL_CACHE_STORE: Dict[str, Tuple[float, Any]] = {}

def ttl_cache_set(key: str, value: Any, ttl: int = 60) -> None:
    """Sets a value in the cache with a TTL (seconds)."""
    expiry = time.time() + ttl
    _TTL_CACHE_STORE[key] = (expiry, value)

def ttl_cache_get(key: str) -> Optional[Any]:
    """Gets a value from cache if not expired."""
    if key not in _TTL_CACHE_STORE:
        return None

    expiry, value = _TTL_CACHE_STORE[key]
    if time.time() > expiry:
        del _TTL_CACHE_STORE[key]
        return None

    return value


# ========================== Callable Helpers ==========================

def sig_params(fn: Callable) -> Set[str]:
    """Return the parameter names of a callable as a set."""
    return set(inspect.signature(fn).parameters.keys()) if callable(fn) else set()


def kw_filter(fn: Callable, **kw: Any) -> Dict[str, Any]:
    """Filter kwargs to only those accepted by fn's signature.

    If fn accepts **kwargs (VAR_KEYWORD), all kw items are returned unchanged.
    Otherwise, only items whose key matches a named parameter are returned.
    """
    if not callable(fn):
        return {}
    try:
        params = inspect.signature(fn).parameters
        # If any parameter is VAR_KEYWORD (**kwargs), pass everything through
        if any(p.kind == inspect.Parameter.VAR_KEYWORD for p in params.values()):
            return dict(kw)
        accepted = {
            name for name, p in params.items()
            if p.kind not in (inspect.Parameter.VAR_POSITIONAL,)
        }
        return {k: v for k, v in kw.items() if k in accepted}
    except (TypeError, ValueError):
        return dict(kw)


# ========================== URL Helpers ==========================

def guess_host_from_url(url: str) -> str:
    """Extract hostname from a URL string. Returns empty string on failure."""
    try:
        return urlparse(url).hostname or ""
    except (ValueError, AttributeError):
        return ""
