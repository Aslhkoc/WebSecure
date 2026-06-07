"""
tests/unit/test_csrf.py
~~~~~~~~~~~~~~~~~~~~~~~~~
CSRF scanner birim testleri.

csrf modülü fonksiyon-tabanlıdır (BaseScanner sınıfı yok); bulgular global
reporting.add_result ile yazılır, bu yüzden reporting kovalarından doğrulanır.
Tespit: hassas POST formu anti-CSRF token'ı YOKSA → 'CSRF' Medium bulgusu.
"""
from __future__ import annotations

import requests

from websecure.core import reporting
from websecure.scanners.csrf import check_csrf_protection, _get_forms

_URL = "http://target.test/settings"


def _csrf_medium_findings():
    out = []
    for _bucket, items in reporting.get_bucket_results().items():
        for it in items:
            if isinstance(it, dict) and str(it.get("type")) == "CSRF" \
                    and str(it.get("severity")) == "Medium":
                out.append(it)
    return out


class TestCSRFDetection:
    def test_sensitive_form_without_token_reported(self, mock_session):
        """Token'sız hassas POST formu → CSRF (Medium) bulgusu."""
        html = (
            '<html><form action="/account/password/change" method="POST">'
            '<input name="new_password" type="password">'
            '<input name="submit" type="submit"></form></html>'
        )
        mock_session.get.return_value = mock_session._make_response(text=html)
        reporting.reset()
        try:
            check_csrf_protection(_URL, mock_session, results={}, debug=False)
            assert _csrf_medium_findings(), \
                "Token'sız hassas form için CSRF bulgusu üretilmedi (detection kopuk)"
        finally:
            reporting.reset()

    def test_form_with_token_no_finding(self, mock_session):
        """Anti-CSRF token içeren form → sahte CSRF bulgusu ÜRETİLMEMELİ."""
        html = (
            '<html><form action="/account/password/change" method="POST">'
            '<input name="new_password" type="password">'
            '<input name="csrf_token" type="hidden" value="abc123"></form></html>'
        )
        mock_session.get.return_value = mock_session._make_response(text=html)
        reporting.reset()
        try:
            check_csrf_protection(_URL, mock_session, results={}, debug=False)
            assert not _csrf_medium_findings(), "Token mevcutken CSRF false-positive üretildi"
        finally:
            reporting.reset()

    def test_no_crash_on_network_error(self, mock_session):
        mock_session.get.side_effect = requests.exceptions.ConnectionError("refused")
        reporting.reset()
        try:
            check_csrf_protection("http://target.test/x", mock_session, results={}, debug=False)
        finally:
            reporting.reset()  # no raise == pass


class TestFormParser:
    def test_get_forms_parses_method_action_inputs(self):
        forms = _get_forms(
            '<form action="/x" method="post"><input name="a" type="text"></form>'
        )
        assert len(forms) == 1
        assert forms[0]["method"] == "POST"
        assert forms[0]["action"] == "/x"
        assert any(i["name"] == "a" for i in forms[0]["inputs"])
