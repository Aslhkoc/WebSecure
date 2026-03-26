"""
tests/unit/test_header_scanner.py
-----------------------------------
Unit tests for HeaderScanner — verifies BaseScanner inheritance,
run() delegation, and header analysis logic.
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from websecure.scanners.infrastructure import HeaderScanner
from websecure.scanners.base import BaseScanner


# ---------------------------------------------------------------------------
# Inheritance
# ---------------------------------------------------------------------------

def test_header_scanner_extends_base_scanner():
    assert issubclass(HeaderScanner, BaseScanner)


def test_header_scanner_has_name():
    assert HeaderScanner.name == "headers"


def test_header_scanner_init_defaults():
    scanner = HeaderScanner()
    assert scanner.timeout == 15.0
    assert scanner.verify_tls is True
    assert scanner.results == {}
    assert scanner.debug is False


def test_header_scanner_init_custom():
    scanner = HeaderScanner(timeout=5.0, verify_tls=False, debug=True)
    assert scanner.timeout == 5.0
    assert scanner.verify_tls is False
    assert scanner.debug is True


# ---------------------------------------------------------------------------
# run() delegates to scan_url()
# ---------------------------------------------------------------------------

def test_run_delegates_to_scan_url():
    scanner = HeaderScanner()
    mock_result = {"url": "http://example.com", "findings": []}

    with patch.object(scanner, "scan_url", return_value=mock_result) as mock_scan:
        result = scanner.run("http://example.com")

    mock_scan.assert_called_once_with("http://example.com")
    assert result == mock_result


# ---------------------------------------------------------------------------
# BaseScanner methods available
# ---------------------------------------------------------------------------

def test_header_scanner_has_report_finding():
    scanner = HeaderScanner()
    assert callable(getattr(scanner, "report_finding", None))


def test_header_scanner_has_fetch_baseline():
    scanner = HeaderScanner()
    assert callable(getattr(scanner, "fetch_baseline", None))


def test_header_scanner_has_inject_param():
    scanner = HeaderScanner()
    assert callable(getattr(scanner, "inject_param", None))


def test_inject_param_works():
    scanner = HeaderScanner()
    url = scanner.inject_param("http://example.com?a=1", "a", "evil")
    assert "a=evil" in url


# ---------------------------------------------------------------------------
# add() result storage (thread-safe)
# ---------------------------------------------------------------------------

def test_add_stores_finding():
    scanner = HeaderScanner(results={})
    scanner.add("test_bucket", {"type": "TestFinding", "severity": "High", "url": "http://x.com"})
    assert "test_bucket" in scanner.results
    assert len(scanner.results["test_bucket"]) == 1
