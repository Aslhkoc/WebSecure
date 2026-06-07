"""
tests/unit/test_xss_scanner.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
XSS scanner testleri.
"""
from __future__ import annotations

from unittest.mock import patch

import pytest

from websecure.scanners.xss import XSSScanner


@pytest.fixture
def xss(mock_session):
    return XSSScanner(session=mock_session, results={}, debug=False)


class TestXSSDetection:
    def test_reflected_xss_detected(self, xss, mock_session):
        """Enjekte edilen değer yanıtta HAM (executable) yansıyınca XSS raporlanmalı.

        REGRESYON: Önceki sürüm 'if mock_report.called:' ile KOŞULLU assert ediyordu
        — detection bozulup hiç çağrılmasa bile test geçiyordu (kopuk). Ayrıca sabit
        yanıt, scanner'ın rastgele canary'sini yansıtmadığından tetiklemiyordu. Artık
        yansıtıcı (echo) mock canary'yi ve payload'ları HAM geri verir → koşulsuz doğrulama.
        """
        from urllib.parse import urlparse as _up, parse_qsl as _pq

        def _echo(url, *a, **kw):
            reflected = " ".join(v for _, v in _pq(_up(url).query, keep_blank_values=True))
            return mock_session._make_response(
                text=f"<html><body>Results for {reflected}</body></html>"
            )

        mock_session.get.side_effect = _echo

        with patch.object(xss, "report_finding") as mock_report:
            xss.scan_url("http://target.test/search?q=test")

        assert mock_report.called, "Reflected XSS tespit edilemedi (detection kopuk)"

    def test_no_false_positive_on_clean_response(self, xss, mock_session):
        """Enjekte edilen değeri YANSITMAYAN temiz yanıt → XSS bulgusu olmamalı.

        REGRESYON: Önceki sürümün döngü gövdesi 'pass' idi — hiçbir şey doğrulamıyor,
        her durumda geçiyordu. Canary hiç yansımadığından scanner fuzzing'e geçmemeli
        ve report_finding ASLA çağrılmamalı.
        """
        mock_session.get.return_value = mock_session._make_response(
            text="<html><body>Hello World</body></html>"
        )

        with patch.object(xss, "report_finding") as mock_report:
            xss.scan_url("http://target.test/search?q=test")

        mock_report.assert_not_called()

    def test_scan_url_handles_timeout_gracefully(self, xss, mock_session):
        """Timeout durumunda exception fırlatılmamalı."""
        import requests
        mock_session.get.side_effect = requests.exceptions.Timeout("timed out")

        # Should not raise
        xss.scan_url("http://target.test/search?q=test")

    def test_scan_url_handles_connection_error_gracefully(self, xss, mock_session):
        """ConnectionError durumunda exception fırlatılmamalı."""
        import requests
        mock_session.get.side_effect = requests.exceptions.ConnectionError("refused")

        # Should not raise
        xss.scan_url("http://target.test/search?q=test")

    def test_xss_scanner_inherits_basescanner(self, xss):
        from websecure.scanners.base import BaseScanner
        assert isinstance(xss, BaseScanner)

    def test_run_method_exists(self, xss):
        assert hasattr(xss, "run") and callable(xss.run)

    def test_inject_param_used(self, xss):
        """inject_param mevcut olmalı (BaseScanner'dan miras)."""
        url = xss.inject_param("http://t.test/?q=1", "q", "PAYLOAD")
        assert "q=PAYLOAD" in url

    def test_empty_url_list_no_crash(self, xss):
        """URL listesi boş → crash olmamalı."""
        xss.run("http://target.test", urls=[])
