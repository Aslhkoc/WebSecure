"""
tests/unit/test_mass_assignment.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Mass Assignment scanner birim testleri.

Gerçek tespit, enjekte edilen ayrıcalıklı alanı (is_admin vb.) yansıtan canlı
API gerektirir (entegrasyon kapsamı). Bu birim testler import + yapısal + hata
dayanıklılığını (ağ hatasında çökmeme + FP üretmeme) korur.
"""
from __future__ import annotations

from unittest.mock import patch

import pytest
import requests

from websecure.scanners.mass_assignment import MassAssignmentScanner

_TARGET = "http://target.test/api/user"


@pytest.fixture
def ma(mock_session):
    return MassAssignmentScanner(session=mock_session, results={}, debug=False)


class TestRobustness:
    def test_no_crash_and_no_fp_when_unreachable(self, ma, mock_session):
        """Tüm HTTP metodları ağ hatası verince: çökme yok VE bulgu yok."""
        err = requests.exceptions.ConnectionError("refused")
        mock_session.get.side_effect = err
        mock_session.post.side_effect = err
        mock_session.put.side_effect = err
        mock_session.patch.side_effect = err
        with patch.object(ma, "report_finding") as rep:
            ma.run(_TARGET)  # no raise
        rep.assert_not_called()

    def test_no_crash_on_timeout(self, ma, mock_session):
        err = requests.exceptions.Timeout("timed out")
        for m in (mock_session.get, mock_session.post, mock_session.put, mock_session.patch):
            m.side_effect = err
        ma.run(_TARGET)  # no raise


class TestStructure:
    def test_inherits_basescanner(self, ma):
        from websecure.scanners.base import BaseScanner
        assert isinstance(ma, BaseScanner)

    def test_run_callable(self, ma):
        assert callable(ma.run)
