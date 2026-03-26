"""
tests/test_system_smoke.py
---------------------------
Smoke tests — verifies that all core modules import without errors.
"""
import importlib
import importlib.util
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
]

OPTIONAL_MODULES = [
    "websecure.core.nuclei_integration",
    "websecure.scanners.rate_limit",
]


@pytest.mark.parametrize("mod_name", MODULES)
def test_module_imports(mod_name):
    """Each listed module must be importable without raising an exception."""
    importlib.import_module(mod_name)


@pytest.mark.parametrize("mod_name", OPTIONAL_MODULES)
def test_optional_module_imports(mod_name):
    """Optional modules are skipped if not present on disk."""
    if importlib.util.find_spec(mod_name) is None:
        pytest.skip(f"{mod_name} not present — skipped")
    importlib.import_module(mod_name)
