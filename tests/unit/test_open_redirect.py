"""
tests/unit/test_open_redirect.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Open Redirect scanner testleri: BaseScanner inheritance, redirect detect, no false positive.
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
import requests

from websecure.scanners.open_redirect import OpenRedirectScanner, _is_open_redirect


@pytest.fixture
def or_scanner(mock_session):
    return OpenRedirectScanner(session=mock_session, results={}, debug=False)


class TestOpenRedirectInheritance:
    def test_inherits_basescanner(self, or_scanner):
        from websecure.scanners.base import BaseScanner
        assert isinstance(or_scanner, BaseScanner)

    def test_has_run_method(self, or_scanner):
        assert callable(or_scanner.run)

    def test_has_inject_param(self, or_scanner):
        """inject_param BaseScanner'dan miras alınmalı."""
        url = or_scanner.inject_param("http://t.test/?next=/home", "next", "//evil.test")
        assert "next=" in url

    def test_results_dict_initialized(self, or_scanner):
        assert isinstance(or_scanner.results, dict)

    def test_session_from_basescanner(self, mock_session, or_scanner):
        assert or_scanner.session is mock_session


class TestIsOpenRedirect:
    def test_location_header_with_canary(self):
        from websecure.scanners.open_redirect import _CANARY
        resp = MagicMock()
        resp.headers = {"Location": f"https://{_CANARY}/path"}
        resp.text = ""
        assert _is_open_redirect(resp, f"https://{_CANARY}") is True

    def test_no_canary_in_location(self):
        resp = MagicMock()
        resp.headers = {"Location": "https://legitimate.com/path"}
        resp.text = ""
        assert _is_open_redirect(resp, "https://evil.test") is False

    def test_canary_in_js_redirect(self):
        from websecure.scanners.open_redirect import _CANARY
        resp = MagicMock()
        resp.headers = {}
        resp.text = f'<script>window.location = "https://{_CANARY}";</script>'
        assert _is_open_redirect(resp, f"https://{_CANARY}") is True


class TestOpenRedirectScan:
    def test_no_crash_on_timeout(self, or_scanner, mock_session):
        mock_session.get.side_effect = requests.exceptions.Timeout("timed out")
        or_scanner.run("http://target.test/login?next=/home")  # no raise

    def test_no_crash_on_connection_error(self, or_scanner, mock_session):
        mock_session.get.side_effect = requests.exceptions.ConnectionError("refused")
        or_scanner.run("http://target.test/login?next=/home")  # no raise
