"""
tests/unit/test_lfi.py
~~~~~~~~~~~~~~~~~~~~~~~
LFI / directory traversal scanner birim testleri.

LFIDirectoryTraversalProber, yanıt gövdesinde /etc/passwd vb. hassas içerik
imzalarını (root:.*:0:0:) arar. Mock gövde ile deterministik test edilebilir.
(Entegrasyon kapsamı da vardır — bu birim test izole detection/no-FP korur.)
"""
from __future__ import annotations

from unittest.mock import patch

import pytest
import requests

from websecure.scanners.lfi import LFIDirectoryTraversalProber

_TARGET = "http://target.test/download?file=readme.txt"


@pytest.fixture
def lfi(mock_session):
    return LFIDirectoryTraversalProber(session=mock_session, results={}, debug=False)


class TestLFIDetection:
    def test_passwd_content_reported(self, lfi, mock_session):
        """Yanıtta /etc/passwd içeriği (root:x:0:0:) → Critical LFI bulgusu."""
        mock_session.get.return_value = mock_session._make_response(
            status_code=200,
            text="root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
        )
        with patch.object(lfi, "report_finding") as rep:
            lfi.run(_TARGET)
        assert rep.called, "LFI passwd içeriği tespit edilmedi (detection kopuk)"
        vtypes = [str(c.kwargs.get("vuln_type", "")) for c in rep.call_args_list]
        assert any("LFI" in t for t in vtypes), f"Beklenen LFI bulgusu yok: {vtypes}"

    def test_clean_response_no_finding(self, lfi, mock_session):
        """Hassas içerik olmayan yanıt → bulgu ÜRETİLMEMELİ."""
        mock_session.get.return_value = mock_session._make_response(
            status_code=200, text="<html><body>File not found</body></html>",
        )
        with patch.object(lfi, "report_finding") as rep:
            lfi.run(_TARGET)
        rep.assert_not_called()

    def test_no_crash_on_timeout(self, lfi, mock_session):
        mock_session.get.side_effect = requests.exceptions.Timeout("timed out")
        lfi.run(_TARGET)  # no raise

    def test_no_crash_on_connection_error(self, lfi, mock_session):
        mock_session.get.side_effect = requests.exceptions.ConnectionError("refused")
        lfi.run(_TARGET)  # no raise


class TestStructure:
    def test_inherits_basescanner(self, lfi):
        from websecure.scanners.base import BaseScanner
        assert isinstance(lfi, BaseScanner)

    def test_run_callable(self, lfi):
        assert callable(lfi.run)
