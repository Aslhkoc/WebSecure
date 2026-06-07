"""
tests/unit/test_ssti_scanner.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
SSTI scanner testleri: polyglot detect, engine fingerprint, header injection.
"""
from __future__ import annotations

from unittest.mock import patch

import pytest
import requests

from websecure.scanners.ssti import SSTIScanner


@pytest.fixture
def ssti(mock_session):
    return SSTIScanner(session=mock_session, results={}, debug=False)


class TestSSTIDetection:
    def test_polyglot_marker_detected(self, ssti, mock_session):
        """Sunucu {{A*B}} ifadesini DEĞERLENDİRİP rastgele-canary çarpımını yanıta
        koyunca SSTI raporlanmalı.

        REGRESYON: Önceki sürüm sabit '49' döndürüp report_finding'i patch'liyor
        ama HİÇBİR ŞEY assert etmiyordu (yorum bile 'engine'e bağlı, crash olmasın'
        diyordu). SSTI rastgele-canary doğrulaması kullandığından sabit '49' zaten
        tetiklemez; gerçek tespiti ölçmek için mock şablonu değerlendirir. Düz sayı
        (reflection-check) yansıtılmaz → canary 'eval != reflection' kontrolü geçer.
        """
        import re as _re
        from urllib.parse import urlparse as _up, parse_qsl as _pq

        def _tmpl_eval(url, *a, **kw):
            products = []
            for _, v in _pq(_up(url).query, keep_blank_values=True):
                m = _re.search(r"[{$#]\{?\s*(\d+)\s*\*\s*(\d+)\s*\}?\}", v)
                if m:
                    products.append(str(int(m.group(1)) * int(m.group(2))))
            body = ("<html>=" + " ".join(products) + "</html>") if products else "<html>ok</html>"
            return mock_session._make_response(text=body)

        mock_session.get.side_effect = _tmpl_eval

        with patch.object(ssti, "report_finding") as mock_report:
            ssti._scan_url("http://target.test/page?name=test")

        assert mock_report.called, "SSTI canary-onaylı tespit edilemedi (detection kopuk)"

    def test_no_crash_on_timeout(self, ssti, mock_session):
        mock_session.get.side_effect = requests.exceptions.Timeout("timed out")
        ssti._scan_url("http://target.test/page?name=test")  # no raise

    def test_no_crash_on_connection_error(self, ssti, mock_session):
        mock_session.get.side_effect = requests.exceptions.ConnectionError("refused")
        ssti._scan_url("http://target.test/page?name=test")  # no raise

    def test_inherits_basescanner(self, ssti):
        from websecure.scanners.base import BaseScanner
        assert isinstance(ssti, BaseScanner)

    def test_run_method_callable(self, ssti):
        assert callable(ssti.run)

    def test_no_false_positive_on_number_in_text(self, ssti, mock_session):
        """'49' sayısı şablon sonucu olmadan mevcut → false positive olmamalı."""
        mock_session.get.return_value = mock_session._make_response(
            text="<html>You have 49 messages</html>"
        )
        with patch.object(ssti, "report_finding") as mock_report:
            ssti._scan_url("http://target.test/search?q=hello")
        # A literal "49" with no template evaluation must NOT trigger SSTI — the
        # random-canary confirmation rejects static reflections (see FAZ 12).
        mock_report.assert_not_called()

    def test__scan_url_returns_list(self, ssti, mock_session):
        mock_session.get.return_value = mock_session._make_response(text="safe response")
        result = ssti._scan_url("http://target.test/page?name=test")
        assert result is None or isinstance(result, list)

    def test_json_injection_no_crash(self, ssti, mock_session):
        """JSON body injection denemesi → crash olmamalı."""
        mock_session.post.return_value = mock_session._make_response(text="{}")
        ssti._scan_url("http://target.test/api?param=test")  # no raise
