"""
tests/test_system_smoke.py
---------------------------
Smoke tests — verifies that all core modules import without errors.
"""
import importlib
import pytest

MODULES = [
    "websecure.scanners.csrf",
    "websecure.core.chain_reactor",
    "websecure.scanners.sqli",
    "websecure.scanners.xss",
    "websecure.scanners.nosqli",
    "websecure.scanners.ssrf_xxe",
    "websecure.scanners.mass_assignment",
    "websecure.scanners.ws_fuzz",
    "websecure.core.reporting",
    # Previously listed under OPTIONAL_MODULES with stale names
    # ("core.nuclei_integration", "scanners.rate_limit") that never resolved
    # and thus silently skipped. These are the real, always-present modules.
    "websecure.integrations.nuclei",
    "websecure.core.rate_controller",
]


@pytest.mark.parametrize("mod_name", MODULES)
def test_module_imports(mod_name):
    """Each listed module must be importable without raising an exception."""
    importlib.import_module(mod_name)
