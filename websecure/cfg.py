# cfg.py - Config Shim
from __future__ import annotations
from typing import Any, Dict
from websecure.core.utils.config import load_config, get_active_profile

# Singleton instance
CONFIG: Dict[str, Any] = load_config()

def get(key: str, default: Any = None) -> Any:
    """Helper to access config values safely."""
    return CONFIG.get(key, default)

def reload_config(path: str = "config.json") -> Dict[str, Any]:
    """Reloads the global configuration."""
    global CONFIG
    CONFIG = load_config(path)
    return CONFIG

def current_profile() -> Dict[str, Any]:
    return get_active_profile(CONFIG)

# Expose config keys as attributes for backward compat (discouraged but supported)
def __getattr__(name: str) -> Any:
    return CONFIG.get(name)

__all__ = ["CONFIG", "get", "reload_config", "current_profile"]
