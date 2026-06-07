"""
tests/unit/test_cmdi.py
~~~~~~~~~~~~~~~~~~~~~~~~~
OS Command Injection scanner birim testleri.

CmdiScanner._test_param, enjekte edilmiş istek yanıtında komut çıktısı imzası
(uid=0(root) gid=0(root) ...) baseline'da YOKKEN bulunursa Critical bulgu üretir.
Baseline→marker mock'u ile deterministik test edilir.
(Entegrasyon kapsamı da vardır — bu birim test izole detection/no-FP korur.)
"""
from __future__ import annotations

import threading
from unittest.mock import patch

import pytest
import requests

from websecure.scanners.cmdi import CmdiScanner

_TARGET = "http://target.test/ping?host=127.0.0.1"


@pytest.fixture
def cmdi(mock_session):
    return CmdiScanner(session=mock_session, results={}, debug=False)


class TestCmdiDetection:
    def test_command_output_reported(self, cmdi, mock_session):
        """Enjekte istek 'uid=0(root)...' döndürünce (baseline temiz) Critical CMDI bulgusu."""
        served_baseline = {"v": False}
        lock = threading.Lock()

        def _resp(url, *a, **kw):
            # scan_url'deki İLK GET fetch_baseline (payload'sız) → temiz; sonraki
            # tüm payload'lı prob'lar komut çıktısı imzasını yansıtır.
            with lock:
                if not served_baseline["v"]:
                    served_baseline["v"] = True
                    return mock_session._make_response(status_code=200, text="pong 127.0.0.1")
            return mock_session._make_response(
                status_code=200, text="uid=0(root) gid=0(root) groups=0(root)"
            )

        mock_session.get.side_effect = _resp
        with patch.object(cmdi, "report_finding") as rep:
            cmdi.run(_TARGET)
        assert rep.called, "Komut enjeksiyonu çıktısı tespit edilmedi (detection kopuk)"
        vtypes = [str(c.kwargs.get("vuln_type", "")) for c in rep.call_args_list]
        assert any("Command Injection" in t for t in vtypes), f"Beklenen CMDI bulgusu yok: {vtypes}"

    def test_clean_response_no_finding(self, cmdi, mock_session):
        """Komut çıktısı imzası içermeyen yanıt → bulgu ÜRETİLMEMELİ."""
        mock_session.get.return_value = mock_session._make_response(
            status_code=200, text="pong 127.0.0.1 — host is alive",
        )
        with patch.object(cmdi, "report_finding") as rep:
            cmdi.run(_TARGET)
        rep.assert_not_called()

    def test_no_crash_on_timeout(self, cmdi, mock_session):
        mock_session.get.side_effect = requests.exceptions.Timeout("timed out")
        cmdi.run(_TARGET)  # no raise

    def test_no_crash_on_connection_error(self, cmdi, mock_session):
        mock_session.get.side_effect = requests.exceptions.ConnectionError("refused")
        cmdi.run(_TARGET)  # no raise


class TestStructure:
    def test_inherits_basescanner(self, cmdi):
        from websecure.scanners.base import BaseScanner
        assert isinstance(cmdi, BaseScanner)

    def test_run_callable(self, cmdi):
        assert callable(cmdi.run)
