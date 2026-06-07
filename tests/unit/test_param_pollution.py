"""
tests/unit/test_param_pollution.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
HTTP Parameter Pollution (HPP) scanner birim testleri.

QueryStringHPPProber, polluted parametre değerini (canary) yanıtta yansıtılırsa
HPP raporlar. Yansıtıcı (echo) mock ile deterministik test edilir.
"""
from __future__ import annotations

from urllib.parse import urlparse
from unittest.mock import patch

import pytest
import requests

from websecure.scanners.param_pollution import QueryStringHPPProber

_TARGET = "http://target.test/page?id=1"


@pytest.fixture
def hpp(mock_session):
    return QueryStringHPPProber(session=mock_session, results={}, debug=False)


class TestHPPDetection:
    def test_canary_reflection_reported(self, hpp, mock_session):
        """Polluted parametre canary'si yanıtta yansıyınca HPP bulgusu."""
        def _echo(url, *a, **kw):
            # Sunucu polluted query'yi gövdeye yansıtıyor → canary geri görünür.
            return mock_session._make_response(
                status_code=200, text=f"<html>query={urlparse(url).query}</html>"
            )
        mock_session.get.side_effect = _echo
        with patch.object(hpp, "report_finding") as rep:
            hpp.run(_TARGET)
        assert rep.called, "HPP canary yansıması tespit edilmedi (detection kopuk)"
        vtypes = [str(c.kwargs.get("vuln_type", "")) for c in rep.call_args_list]
        assert any("Parameter Pollution" in t for t in vtypes), f"Beklenen HPP bulgusu yok: {vtypes}"

    def test_no_reflection_no_finding(self, hpp, mock_session):
        """Canary yansımayan sabit yanıt → bulgu ÜRETİLMEMELİ."""
        mock_session.get.return_value = mock_session._make_response(
            status_code=200, text="<html>static page, nothing reflected</html>",
        )
        with patch.object(hpp, "report_finding") as rep:
            hpp.run(_TARGET)
        rep.assert_not_called()

    def test_no_crash_on_timeout(self, hpp, mock_session):
        mock_session.get.side_effect = requests.exceptions.Timeout("timed out")
        hpp.run(_TARGET)  # no raise

    def test_no_crash_on_connection_error(self, hpp, mock_session):
        mock_session.get.side_effect = requests.exceptions.ConnectionError("refused")
        hpp.run(_TARGET)  # no raise


class TestStructure:
    def test_inherits_basescanner(self, hpp):
        from websecure.scanners.base import BaseScanner
        assert isinstance(hpp, BaseScanner)

    def test_run_callable(self, hpp):
        assert callable(hpp.run)
