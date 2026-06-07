"""
tests/unit/test_bypass_403.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
403 bypass (path normalisation) scanner birim testleri.

PathNormalizationBypass, engellenmiş bir yola ait varyant HTTP 200/301/302
dönerse bypass raporlar. blocked_paths verilerek keşif atlanır → deterministik.
"""
from __future__ import annotations

from unittest.mock import patch

import pytest
import requests

from websecure.scanners.bypass_403 import PathNormalizationBypass

_TARGET = "http://target.test"
_BLOCKED = [("/admin", 403)]


@pytest.fixture
def bypass(mock_session):
    return PathNormalizationBypass(session=mock_session, results={}, debug=False)


class TestBypassDetection:
    def test_variant_returns_200_reported(self, bypass, mock_session):
        """Engelli yolun varyantı 200 dönerse → 403 Bypass (Confirmed) bulgusu."""
        mock_session.get.return_value = mock_session._make_response(
            status_code=200, text="<html>admin panel</html>",
        )
        with patch.object(bypass, "report_finding") as rep:
            bypass.run(_TARGET, blocked_paths=_BLOCKED)
        assert rep.called, "403 bypass tespit edilmedi (detection kopuk)"
        vtypes = [str(c.kwargs.get("vuln_type", "")) for c in rep.call_args_list]
        assert any("403 Bypass" in t for t in vtypes), f"Beklenen bypass bulgusu yok: {vtypes}"

    def test_still_blocked_no_finding(self, bypass, mock_session):
        """Varyantlar hâlâ 403 dönerse → bypass yok, bulgu ÜRETİLMEMELİ."""
        mock_session.get.return_value = mock_session._make_response(
            status_code=403, text="<html>Forbidden</html>",
        )
        with patch.object(bypass, "report_finding") as rep:
            bypass.run(_TARGET, blocked_paths=_BLOCKED)
        rep.assert_not_called()

    def test_no_crash_on_timeout(self, bypass, mock_session):
        mock_session.get.side_effect = requests.exceptions.Timeout("timed out")
        bypass.run(_TARGET, blocked_paths=_BLOCKED)  # no raise

    def test_no_crash_on_connection_error(self, bypass, mock_session):
        mock_session.get.side_effect = requests.exceptions.ConnectionError("refused")
        bypass.run(_TARGET, blocked_paths=_BLOCKED)  # no raise


class TestStructure:
    def test_inherits_basescanner(self, bypass):
        from websecure.scanners.base import BaseScanner
        assert isinstance(bypass, BaseScanner)

    def test_run_callable(self, bypass):
        assert callable(bypass.run)
