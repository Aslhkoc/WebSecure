"""
tests/unit/test_session_scanner.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Session/cookie güvenlik scanner testleri.

CookieFlagScanner, Set-Cookie başlıklarını CookieSecurityAnalyzer ile çözümler:
  - HttpOnly/Secure/SameSite eksikse  → 'Cookie Security Flag' bulgusu
  - Tüm bayraklar varsa               → bulgu yok
analyze_response başlıkları response.headers.items() üzerinden okuduğundan
düz dict'li mock yanıt yeterlidir.
"""
from __future__ import annotations

from unittest.mock import patch

import pytest
import requests

from websecure.scanners.session_scanner import CookieFlagScanner


@pytest.fixture
def cookie_scanner(mock_session):
    return CookieFlagScanner(session=mock_session, results={}, debug=False)


class TestCookieFlags:
    def test_insecure_cookie_reported(self, cookie_scanner, mock_session):
        """HttpOnly/Secure/SameSite'siz Set-Cookie → güvenlik bulgusu."""
        mock_session.get.return_value = mock_session._make_response(
            status_code=200, text="ok",
            headers={"Set-Cookie": "SESSIONID=abc123def456; Path=/"},
        )
        with patch.object(cookie_scanner, "report_finding") as rep:
            cookie_scanner.run("http://target.test")
        assert rep.called, "Güvensiz cookie bayrakları raporlanmadı (detection kopuk)"
        types = [str(c.kwargs.get("type", "")) for c in rep.call_args_list]
        assert any("Cookie" in t for t in types), f"Beklenen cookie bulgusu yok: {types}"

    def test_hardened_cookie_no_finding(self, cookie_scanner, mock_session):
        """Tüm güvenlik bayrakları olan (hassas-olmayan) cookie → bulgu ÜRETİLMEMELİ.

        NOT: hassas adlı (SESSIONID vb.) cookie'ler bayraklar tam olsa bile
        Max-Age/Expires yoksa ayrı kural tetikler; bu yüzden tam-temiz negatif
        için hassas-olmayan 'theme' adı + tüm bayraklar kullanılır.
        """
        mock_session.get.return_value = mock_session._make_response(
            status_code=200, text="ok",
            headers={"Set-Cookie": "theme=dark; Path=/; HttpOnly; Secure; SameSite=Strict"},
        )
        with patch.object(cookie_scanner, "report_finding") as rep:
            cookie_scanner.run("http://target.test")
        rep.assert_not_called()

    def test_no_cookie_no_finding(self, cookie_scanner, mock_session):
        """Set-Cookie yok → analiz edilecek cookie yok, bulgu olmamalı."""
        mock_session.get.return_value = mock_session._make_response(
            status_code=200, text="ok", headers={},
        )
        with patch.object(cookie_scanner, "report_finding") as rep:
            cookie_scanner.run("http://target.test")
        rep.assert_not_called()

    def test_no_crash_on_timeout(self, cookie_scanner, mock_session):
        mock_session.get.side_effect = requests.exceptions.Timeout("timed out")
        cookie_scanner.run("http://target.test")  # no raise

    def test_no_crash_on_connection_error(self, cookie_scanner, mock_session):
        mock_session.get.side_effect = requests.exceptions.ConnectionError("refused")
        cookie_scanner.run("http://target.test")  # no raise


class TestStructure:
    def test_inherits_basescanner(self, cookie_scanner):
        from websecure.scanners.base import BaseScanner
        assert isinstance(cookie_scanner, BaseScanner)

    def test_run_callable(self, cookie_scanner):
        assert callable(cookie_scanner.run)
