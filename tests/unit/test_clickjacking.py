"""
tests/unit/test_clickjacking.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Clickjacking (X-Frame-Options) scanner testleri.

FrameOptionsAnalyzer yanıt başlıklarını inceler:
  - XFO yok            → Missing X-Frame-Options (High/Medium)
  - XFO: DENY          → güvenli, bulgu yok
Bu yüzden mock_session başlıklarıyla deterministik pozitif/negatif test edilebilir.
"""
from __future__ import annotations

from unittest.mock import patch

import pytest
import requests

from websecure.scanners.clickjacking import FrameOptionsAnalyzer


@pytest.fixture
def analyzer(mock_session):
    return FrameOptionsAnalyzer(session=mock_session, results={}, debug=False)


class TestFrameOptionsDetection:
    def test_missing_xfo_reported(self, analyzer, mock_session):
        """XFO başlığı olmayan sayfa → 'Missing X-Frame-Options' bulgusu."""
        mock_session.get.return_value = mock_session._make_response(
            status_code=200, text="<html><body>home</body></html>", headers={}
        )
        with patch.object(analyzer, "report_finding") as rep:
            analyzer.run("http://target.test")
        assert rep.called, "XFO eksikliği raporlanmadı (detection kopuk)"
        vtypes = [str(c.kwargs.get("vuln_type", "")) for c in rep.call_args_list]
        assert any("X-Frame-Options" in t for t in vtypes), f"Beklenen XFO bulgusu yok: {vtypes}"

    def test_deny_is_safe_no_finding(self, analyzer, mock_session):
        """XFO: DENY → tam korumalı, bulgu ÜRETİLMEMELİ."""
        mock_session.get.return_value = mock_session._make_response(
            status_code=200, text="<html><body>home</body></html>",
            headers={"X-Frame-Options": "DENY"},
        )
        with patch.object(analyzer, "report_finding") as rep:
            analyzer.run("http://target.test")
        rep.assert_not_called()

    def test_no_crash_on_timeout(self, analyzer, mock_session):
        mock_session.get.side_effect = requests.exceptions.Timeout("timed out")
        analyzer.run("http://target.test")  # no raise

    def test_no_crash_on_connection_error(self, analyzer, mock_session):
        mock_session.get.side_effect = requests.exceptions.ConnectionError("refused")
        analyzer.run("http://target.test")  # no raise


class TestStructure:
    def test_inherits_basescanner(self, analyzer):
        from websecure.scanners.base import BaseScanner
        assert isinstance(analyzer, BaseScanner)

    def test_run_callable(self, analyzer):
        assert callable(analyzer.run)
