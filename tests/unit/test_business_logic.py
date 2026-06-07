"""
tests/unit/test_business_logic.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Business logic (negatif değer / iş akışı atlama) scanner birim testleri.

Gerçek tespit canlı uygulama davranışı gerektirir (entegrasyon kapsamı). Bu
birim testler import + yapısal + ağ hatasında çökmeme/FP-üretmeme korur.
"""
from __future__ import annotations

from unittest.mock import patch

import pytest
import requests

from websecure.scanners.business_logic import NegativeValueProber

_TARGET = "http://target.test/checkout?qty=1&price=10"


@pytest.fixture
def bl(mock_session):
    return NegativeValueProber(session=mock_session, results={}, debug=False)


class TestRobustness:
    def test_no_crash_and_no_fp_when_unreachable(self, bl, mock_session):
        err = requests.exceptions.ConnectionError("refused")
        for m in (mock_session.get, mock_session.post, mock_session.put, mock_session.patch):
            m.side_effect = err
        with patch.object(bl, "report_finding") as rep:
            bl.run(_TARGET)  # no raise
        rep.assert_not_called()

    def test_no_crash_on_timeout(self, bl, mock_session):
        for m in (mock_session.get, mock_session.post):
            m.side_effect = requests.exceptions.Timeout("t")
        bl.run(_TARGET)  # no raise


class TestStructure:
    def test_inherits_basescanner(self, bl):
        from websecure.scanners.base import BaseScanner
        assert isinstance(bl, BaseScanner)

    def test_run_callable(self, bl):
        assert callable(bl.run)
