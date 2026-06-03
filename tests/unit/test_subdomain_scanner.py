"""
tests/unit/test_subdomain_scanner.py
--------------------------------------
Unit tests for SubdomainScanner — verifies BaseScanner inheritance
and the run() delegation pattern.
"""
from __future__ import annotations

from unittest.mock import patch


from websecure.scanners.subdomain import SubdomainScanner
from websecure.scanners.base import BaseScanner


# ---------------------------------------------------------------------------
# Inheritance
# ---------------------------------------------------------------------------

def test_subdomain_scanner_extends_base_scanner():
    assert issubclass(SubdomainScanner, BaseScanner)


def test_subdomain_scanner_has_name():
    assert SubdomainScanner.name == "subdomain"


def test_subdomain_scanner_init_defaults():
    scanner = SubdomainScanner()
    assert scanner.threads == 50
    assert scanner.use_crtsh is True
    assert scanner.use_subfinder is True
    assert scanner.use_amass is True
    assert scanner.passive_only is True
    assert scanner.results == {}
    assert scanner.debug is False


def test_subdomain_scanner_init_custom():
    scanner = SubdomainScanner(threads=10, use_subfinder=False, debug=True)
    assert scanner.threads == 10
    assert scanner.use_subfinder is False
    assert scanner.debug is True


# ---------------------------------------------------------------------------
# run() delegates to scan()
# ---------------------------------------------------------------------------

def test_run_delegates_to_scan():
    scanner = SubdomainScanner()
    mock_results = [{"subdomain": "api.example.com", "ip": "1.2.3.4"}]

    with patch.object(scanner, "scan", return_value=mock_results) as mock_scan:
        result = scanner.run("http://example.com")

    mock_scan.assert_called_once_with("http://example.com")
    assert result == mock_results


def test_run_with_empty_target():
    scanner = SubdomainScanner()
    with patch.object(scanner, "scan", return_value=[]) as mock_scan:
        result = scanner.run("")
    mock_scan.assert_called_once_with("")
    assert result == []


# ---------------------------------------------------------------------------
# BaseScanner interface
# ---------------------------------------------------------------------------

def test_subdomain_scanner_has_add_method():
    scanner = SubdomainScanner()
    assert callable(getattr(scanner, "add", None))


def test_subdomain_scanner_has_fetch_baseline():
    scanner = SubdomainScanner()
    assert callable(getattr(scanner, "fetch_baseline", None))


def test_results_isolated_between_instances():
    s1 = SubdomainScanner()
    s2 = SubdomainScanner()
    s1.add("subdomains", {"subdomain": "test.example.com"})
    assert "subdomains" in s1.results
    assert "subdomains" not in s2.results
