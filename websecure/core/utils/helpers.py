"""
websecure.core.utils.helpers
-----------------------------
Auth helpers, callable inspection utilities, and URL helpers.
"""
import logging
import inspect
import random
import string
from typing import Any, Callable, Dict, Optional, Set
from urllib.parse import urlparse

_logger = logging.getLogger(__name__)

# ========================== Strings ==========================

def random_string(length: int = 8, chars: str = string.ascii_letters + string.digits) -> str:
    return "".join(random.choice(chars) for _ in range(length))

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
