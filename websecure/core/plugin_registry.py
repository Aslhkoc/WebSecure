"""
websecure.core.plugin_registry
--------------------------------
Plugin discovery and registration system.
Built-in scanners register here; third-party scanners can also register
via Python entry points (group: 'websecure.scanners').
"""
from __future__ import annotations
import importlib
import importlib.util
import logging
import os
from pathlib import Path
from typing import Dict, List, Optional, Type, TYPE_CHECKING

_logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from websecure.scanners.base import BaseScanner


class PluginRegistry:
    """
    Central registry for scanner plugins.
    Maps scanner name → class.
    """

    def __init__(self):
        self._registry: Dict[str, type] = {}
        self._phase_map: Dict[str, List[str]] = {}  # phase → [scanner names]

    def register(self, cls: type, phase: str = "offensive") -> None:
        """Register a scanner class."""
        name = getattr(cls, "name", cls.__name__.lower())
        self._registry[name] = cls
        self._phase_map.setdefault(phase, [])
        if name not in self._phase_map[phase]:
            self._phase_map[phase].append(name)
        _logger.debug(f"[PluginRegistry] Registered: {name} → {cls.__name__} (phase={phase})")

    def get(self, name: str) -> Optional[type]:
        return self._registry.get(name)

    def list_all(self) -> List[str]:
        return list(self._registry.keys())

    def get_scanners_for_phase(self, phase: str) -> List[type]:
        names = self._phase_map.get(phase, [])
        return [self._registry[n] for n in names if n in self._registry]

    def discover_entry_points(self) -> int:
        """Discover and load scanners registered via Python entry points."""
        loaded = 0
        try:
            import importlib.metadata as _meta
            eps = _meta.entry_points(group="websecure.scanners")
            for ep in eps:
                try:
                    cls = ep.load()
                    phase = getattr(cls, "phase", "offensive")
                    self.register(cls, phase=phase)
                    loaded += 1
                    _logger.info(f"[PluginRegistry] Loaded entry-point plugin: {ep.name}")
                except Exception as e:
                    _logger.warning(f"[PluginRegistry] Failed to load entry point '{ep.name}': {e}")
        except Exception as e:
            _logger.debug(f"[PluginRegistry] Entry point discovery error: {e}")
        return loaded

    def load_from_directory(self, plugin_dir: str) -> int:
        """
        Load all .py files from a directory as plugins.
        Each file must contain a class with 'name' and 'run' attributes.
        """
        loaded = 0
        plugin_path = Path(plugin_dir)
        if not plugin_path.exists():
            _logger.warning(f"[PluginRegistry] Plugin directory not found: {plugin_dir}")
            return 0

        for py_file in plugin_path.glob("*.py"):
            if py_file.name.startswith("_"):
                continue
            try:
                spec = importlib.util.spec_from_file_location(py_file.stem, py_file)
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                # Find classes that look like scanners
                for attr_name in dir(module):
                    attr = getattr(module, attr_name)
                    if (isinstance(attr, type) and hasattr(attr, "run")
                            and hasattr(attr, "name") and attr_name != "BaseScanner"):
                        phase = getattr(attr, "phase", "offensive")
                        self.register(attr, phase=phase)
                        loaded += 1
                        _logger.info(f"[PluginRegistry] Loaded from file: {py_file.name}::{attr_name}")
            except Exception as e:
                _logger.warning(f"[PluginRegistry] Error loading {py_file}: {e}")
        return loaded

    def register_builtins(self) -> None:
        """Register all built-in scanners."""
        _BUILTIN_SCANNERS = [
            # (module_path, class_name, phase)
            ("websecure.scanners.xss",              "XSSScanner",           "offensive"),
            ("websecure.scanners.sqli",             "SQLInjectionScanner",  "offensive"),
            ("websecure.scanners.nosqli",           None,                   "offensive"),
            ("websecure.scanners.ssti",             "SSTIScanner",          "offensive"),
            ("websecure.scanners.idor",             "IDORScanner",          "offensive"),
            ("websecure.scanners.ssrf_xxe",         "SSRFScanner",          "offensive"),
            ("websecure.scanners.csrf",             None,                   "offensive"),
            ("websecure.scanners.jwt",              "JWTScanner",           "offensive"),
            ("websecure.scanners.graphql",          "GraphQLScanner",       "offensive"),
            ("websecure.scanners.file_upload",      None,                   "offensive"),
            ("websecure.scanners.mass_assignment",  None,                   "offensive"),
            ("websecure.scanners.request_smuggling", None,                  "offensive"),
            ("websecure.scanners.ws_fuzz",          "WebSocketFuzzer",      "offensive"),
            ("websecure.scanners.session_hunter",   "SessionHunter",        "offensive"),
            ("websecure.scanners.auth_matrix",      "AuthMatrixScanner",    "offensive"),
            ("websecure.scanners.dom_xss",          "DOMXSSScanner",        "browser"),
            ("websecure.scanners.passive_recon",    None,                   "discovery"),
            ("websecure.scanners.headers",          None,                   "sec_headers"),
            ("websecure.scanners.tls",              None,                   "tls"),
            ("websecure.scanners.infrastructure",   None,                   "tls"),
            ("websecure.scanners.js_analyzer",      "JSAnalyzer",           "offensive"),
            ("websecure.scanners.prototype_pollution", None,                 "offensive"),
            ("websecure.scanners.crlf_injection",   None,                   "offensive"),
            ("websecure.scanners.race_condition",    None,                   "offensive"),
        ]

        for module_path, class_name, phase in _BUILTIN_SCANNERS:
            try:
                mod = importlib.import_module(module_path)
                if class_name:
                    cls = getattr(mod, class_name, None)
                    if cls:
                        self.register(cls, phase=phase)
                else:
                    # Register the module's 'run' function as a pseudo-plugin
                    run_fn = getattr(mod, "run", None)
                    if run_fn:
                        # Create a lightweight wrapper class
                        scanner_name = module_path.split(".")[-1]

                        class _FnPlugin:
                            name = scanner_name
                            phase_name = phase

                            def run(self, target, **kwargs):
                                return run_fn(target, **kwargs)

                        _FnPlugin.__name__ = f"{scanner_name}_plugin"
                        self.register(_FnPlugin, phase=phase)
            except ImportError:
                _logger.debug(f"[PluginRegistry] Optional scanner not available: {module_path}")
            except Exception as e:
                _logger.warning(f"[PluginRegistry] Failed to register {module_path}: {e}")


# Global singleton
_REGISTRY: Optional[PluginRegistry] = None


def get_registry(auto_discover: bool = True) -> PluginRegistry:
    """Get the global plugin registry, initializing if needed."""
    global _REGISTRY
    if _REGISTRY is None:
        _REGISTRY = PluginRegistry()
        if auto_discover:
            _REGISTRY.register_builtins()
            _REGISTRY.discover_entry_points()
    return _REGISTRY


def reset_registry() -> None:
    """Reset the global registry (mainly for testing)."""
    global _REGISTRY
    _REGISTRY = None
