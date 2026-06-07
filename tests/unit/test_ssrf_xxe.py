"""
tests/unit/test_ssrf_xxe.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
SSRF/XXE scanner birim testleri.

Gerçek tespit OOB (out-of-band) callback altyapısı gerektirir (entegrasyon
kapsamı; SSRF entegrasyon testi test_scanner_chain'de de var). Bu birim testler
import + yapısal + ağ hatasında çökmeme/FP-üretmeme korur.
"""
from __future__ import annotations

from unittest.mock import patch

import pytest
import requests

from websecure.scanners.ssrf_xxe import SSRFScanner

_TARGET = "http://target.test/fetch?url=http://example.com"


@pytest.fixture
def ssrf(mock_session):
    return SSRFScanner(session=mock_session, results={}, debug=False)


class TestRobustness:
    def test_no_crash_and_no_fp_when_unreachable(self, ssrf, mock_session):
        err = requests.exceptions.ConnectionError("refused")
        for m in (mock_session.get, mock_session.post):
            m.side_effect = err
        with patch.object(ssrf, "report_finding") as rep:
            ssrf.run(_TARGET)  # no raise
        rep.assert_not_called()

    def test_no_crash_on_timeout(self, ssrf, mock_session):
        for m in (mock_session.get, mock_session.post):
            m.side_effect = requests.exceptions.Timeout("t")
        ssrf.run(_TARGET)  # no raise


class TestStructure:
    def test_inherits_basescanner(self, ssrf):
        from websecure.scanners.base import BaseScanner
        assert isinstance(ssrf, BaseScanner)

    def test_run_callable(self, ssrf):
        assert callable(ssrf.run)
