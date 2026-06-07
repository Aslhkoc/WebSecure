"""
tests/unit/test_cors.py
~~~~~~~~~~~~~~~~~~~~~~~~~
CORS misconfiguration scanner testleri.

CORSWildcardProber yanıt başlıklarını inceler:
  - ACAO: *                  → CORS Wildcard (Medium)
  - ACAO: * + ACAC: true     → Critical
  - CORS başlığı yok         → bulgu yok
Deterministik pozitif/negatif için mock_session başlıkları yeterlidir.
"""
from __future__ import annotations

from unittest.mock import patch

import pytest
import requests

from websecure.scanners.cors import CORSWildcardProber


@pytest.fixture
def cors(mock_session):
    return CORSWildcardProber(session=mock_session, results={}, debug=False)


class TestCORSWildcard:
    def test_wildcard_with_credentials_critical(self, cors, mock_session):
        """ACAO:* + ACAC:true → Critical CORS misconfig raporlanmalı."""
        mock_session.get.return_value = mock_session._make_response(
            status_code=200, text="{}",
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Credentials": "true",
            },
        )
        with patch.object(cors, "report_finding") as rep:
            cors.run("http://target.test")
        assert rep.called, "ACAO:* tespit edilmedi (detection kopuk)"
        vtypes = [str(c.kwargs.get("vuln_type", "")) for c in rep.call_args_list]
        assert any("CORS Wildcard" in t for t in vtypes), f"Beklenen CORS bulgusu yok: {vtypes}"
        sevs = [str(c.kwargs.get("severity", "")) for c in rep.call_args_list]
        assert "Critical" in sevs, f"ACAC:true ile Critical beklenildi: {sevs}"

    def test_no_cors_headers_no_finding(self, cors, mock_session):
        """CORS başlığı olmayan yanıt → bulgu ÜRETİLMEMELİ."""
        mock_session.get.return_value = mock_session._make_response(
            status_code=200, text="{}", headers={},
        )
        with patch.object(cors, "report_finding") as rep:
            cors.run("http://target.test")
        rep.assert_not_called()

    def test_no_crash_on_timeout(self, cors, mock_session):
        mock_session.get.side_effect = requests.exceptions.Timeout("timed out")
        cors.run("http://target.test")  # no raise

    def test_no_crash_on_connection_error(self, cors, mock_session):
        mock_session.get.side_effect = requests.exceptions.ConnectionError("refused")
        cors.run("http://target.test")  # no raise


class TestStructure:
    def test_inherits_basescanner(self, cors):
        from websecure.scanners.base import BaseScanner
        assert isinstance(cors, BaseScanner)

    def test_run_callable(self, cors):
        assert callable(cors.run)
