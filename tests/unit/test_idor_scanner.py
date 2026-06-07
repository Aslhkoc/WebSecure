"""
tests/unit/test_idor_scanner.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
IDOR scanner testleri: dual-role detection, sequential enum, no false positive.
"""
from __future__ import annotations

from unittest.mock import patch

import pytest
import requests

from websecure.scanners.idor import IDORScanner


@pytest.fixture
def idor(mock_session):
    return IDORScanner(session=mock_session, results={}, debug=False)


class TestIDORDetection:
    def test_different_content_signals_idor(self, idor, mock_session):
        """Komşu ID (/user/2) HASSAS veri içeren yeterince FARKLI yanıt verince
        sıralı-numaralandırma IDOR'u raporlanmalı.

        REGRESYON: Önceki sürüm yalnız 'crash olmasın' diyor, sonucu doğrulamıyordu;
        üstelik yanıtlar (user_data_owner/other) _contains_sensitive ile eşleşmediği
        için detection zaten hiç tetiklenmezdi. Artık /user/2 yanıtı e-posta+SSN
        içerir (hassas), baseline'dan farklıdır → finding deterministik doğrulanır.
        """
        def _resp(url, *a, **kw):
            # Path-enum /user/1 -> /user/2 dener; komşu kaynak başkasının PII'sini sızdırır.
            if url.rstrip("/").endswith("/user/2"):
                return mock_session._make_response(
                    text="<html>Other user: victim@example.com SSN 123-45-6789</html>"
                )
            return mock_session._make_response(text="<html>Your own profile</html>")

        mock_session.get.side_effect = _resp

        with patch.object(idor, "report_finding") as mock_report:
            idor.run("http://target.test/user/1")

        assert mock_report.called, "Sıralı IDOR tespit edilemedi (detection kopuk)"
        vtypes = [str(c.kwargs.get("vuln_type", "")) for c in mock_report.call_args_list]
        assert any("IDOR" in t for t in vtypes), f"IDOR bulgusu beklenildi, gelen: {vtypes}"

    def test_same_content_no_idor(self, idor, mock_session):
        """Aynı yanıt → IDOR bulunmamalı."""
        mock_session.get.return_value = mock_session._make_response(
            text="<html>Access denied</html>", status_code=403
        )
        with patch.object(idor, "report_finding") as mock_report:
            idor.run("http://target.test/user/1", urls=["http://target.test/user/1"])
        # Identical denied responses must NOT be reported as IDOR.
        mock_report.assert_not_called()

    def test_no_crash_on_timeout(self, idor, mock_session):
        mock_session.get.side_effect = requests.exceptions.Timeout("timed out")
        idor.run("http://target.test/user/1", urls=["http://target.test/user/1"])

    def test_no_crash_on_connection_error(self, idor, mock_session):
        mock_session.get.side_effect = requests.exceptions.ConnectionError("refused")
        idor.run("http://target.test/user/1", urls=["http://target.test/user/1"])

    def test_inherits_basescanner(self, idor):
        from websecure.scanners.base import BaseScanner
        assert isinstance(idor, BaseScanner)

    def test_run_method_callable(self, idor):
        assert callable(idor.run)
