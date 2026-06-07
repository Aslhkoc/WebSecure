"""
tests/unit/test_infrastructure.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Infrastructure / security-header scanner birim testleri.

HeaderScanner yanıt güvenlik başlıklarını çözümler. Ağ hatasında çökmemeli ve
FP üretmemeli; başlık analizi import + yapısal olarak korunur.
"""
from __future__ import annotations

from unittest.mock import patch

import pytest
import requests

from websecure.scanners.infrastructure import HeaderScanner

_TARGET = "http://target.test"


@pytest.fixture
def hdr(mock_session):
    return HeaderScanner(session=mock_session, results={}, debug=False)


class TestRobustness:
    def test_no_crash_and_no_fp_when_unreachable(self, hdr, mock_session):
        err = requests.exceptions.ConnectionError("refused")
        for m in (mock_session.get, mock_session.head):
            m.side_effect = err
        with patch.object(hdr, "report_finding") as rep:
            hdr.run(_TARGET)  # no raise
        rep.assert_not_called()

    def test_no_crash_on_timeout(self, hdr, mock_session):
        for m in (mock_session.get, mock_session.head):
            m.side_effect = requests.exceptions.Timeout("t")
        hdr.run(_TARGET)  # no raise


class TestStructure:
    def test_inherits_basescanner(self, hdr):
        from websecure.scanners.base import BaseScanner
        assert isinstance(hdr, BaseScanner)

    def test_run_callable(self, hdr):
        assert callable(hdr.run)
