"""
tests/unit/test_js_analyzer.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
JavaScript analiz scanner birim testleri.

JSAnalyzer, integrity (SRI) içermeyen cross-origin <script> etiketlerini tespit
eder (CDN compromise -> XSS). HTML mock'u ile deterministik test edilir.
"""
from __future__ import annotations

import pytest
import requests

from websecure.scanners.js_analyzer import JSAnalyzer


_TARGET = "http://target.test/"


@pytest.fixture
def jsa(mock_session):
    return JSAnalyzer(session=mock_session, results={}, debug=False)


class TestJSDetection:
    def test_missing_sri_reported(self, jsa, mock_session):
        """integrity'siz cross-origin CDN script → SRI eksikliği bulgusu."""
        html = (
            "<html><head>"
            '<script src="https://cdn.jsdelivr.net/npm/lib@1/lib.min.js"></script>'
            "</head><body>app</body></html>"
        )
        mock_session.get.return_value = mock_session._make_response(status_code=200, text=html)
        findings = jsa.run(_TARGET)
        assert findings, "SRI eksikliği tespit edilmedi (detection kopuk)"
        blob = " ".join(str(f) for f in findings).lower()
        assert "sri" in blob or "integrity" in blob, f"SRI bulgusu beklenildi: {findings}"

    def test_same_origin_with_integrity_clean(self, jsa, mock_session):
        """Same-origin script + dış kaynak yok → SRI bulgusu ÜRETİLMEMELİ."""
        html = (
            "<html><head>"
            '<script src="/static/app.js"></script>'
            "</head><body>app</body></html>"
        )
        mock_session.get.return_value = mock_session._make_response(status_code=200, text=html)
        findings = jsa.run(_TARGET)
        blob = " ".join(str(f) for f in findings).lower()
        assert "sri" not in blob and "integrity" not in blob, \
            f"Same-origin script için sahte SRI bulgusu: {findings}"

    def test_no_crash_on_timeout(self, jsa, mock_session):
        mock_session.get.side_effect = requests.exceptions.Timeout("timed out")
        jsa.run(_TARGET)  # no raise

    def test_no_crash_on_connection_error(self, jsa, mock_session):
        mock_session.get.side_effect = requests.exceptions.ConnectionError("refused")
        jsa.run(_TARGET)  # no raise


class TestStructure:
    def test_run_returns_list(self, jsa, mock_session):
        # JSAnalyzer BaseScanner DEĞİL — bulgu listesi döndürür (caller add_result yapar).
        mock_session.get.return_value = mock_session._make_response(status_code=200, text="<html></html>")
        out = jsa.run(_TARGET)
        assert isinstance(out, list)

    def test_run_callable(self, jsa):
        assert callable(jsa.run)
