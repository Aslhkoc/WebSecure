
import time
from typing import Any, Dict, Optional, Tuple

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
