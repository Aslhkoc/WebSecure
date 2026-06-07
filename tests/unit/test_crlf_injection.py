"""
tests/unit/test_crlf_injection.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
CRLF injection scanner birim testleri.

Gerçek pozitif tespit, enjekte edilen rastgele canary başlığının yanıt
başlıklarında yansımasını gerektirir (canlı/yansıtıcı sunucu — entegrasyon
kapsamı). Bu birim testler import + yapısal + temiz-yanıtta-FP-yok + no-crash korur.
"""
from __future__ import annotations

from unittest.mock import patch

import pytest
import requests

from websecure.scanners.crlf_injection import CRLFScanner

_TARGET = "http://target.test/page?redirect=/home"


@pytest.fixture
def crlf(mock_session):
    return CRLFScanner(session=mock_session, results={}, debug=False)


class TestCRLFNoFalsePositive:
    def test_clean_response_no_finding(self, crlf, mock_session):
        """Enjekte başlık yansımayan temiz yanıt → bulgu ÜRETİLMEMELİ."""
        mock_session.get.return_value = mock_session._make_response(
            status_code=200, text="<html>home</html>", headers={"Content-Type": "text/html"},
        )
        with patch.object(crlf, "report_finding") as rep:
            crlf.run(_TARGET)
        rep.assert_not_called()

    def test_no_crash_on_timeout(self, crlf, mock_session):
        mock_session.get.side_effect = requests.exceptions.Timeout("timed out")
        crlf.run(_TARGET)  # no raise

    def test_no_crash_on_connection_error(self, crlf, mock_session):
        mock_session.get.side_effect = requests.exceptions.ConnectionError("refused")
        crlf.run(_TARGET)  # no raise


class TestStructure:
    def test_inherits_basescanner(self, crlf):
        from websecure.scanners.base import BaseScanner
        assert isinstance(crlf, BaseScanner)

    def test_run_callable(self, crlf):
        assert callable(crlf.run)
