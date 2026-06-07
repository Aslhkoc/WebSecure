"""
tests/unit/test_auth_scanners.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Authorization matrix scanner birim testleri.

Gerçek tespit, rol-tabanlı erişim farkları olan canlı uygulama gerektirir
(entegrasyon kapsamı). Bu birim testler import + yapısal + ağ hatasında
çökmeme/FP-üretmeme korur.
"""
from __future__ import annotations

from unittest.mock import patch

import pytest
import requests

from websecure.scanners.auth_scanners import AuthMatrixScanner

_TARGET = "http://target.test/admin"


@pytest.fixture
def auth(mock_session):
    return AuthMatrixScanner(session=mock_session, results={}, debug=False)


class TestRobustness:
    def test_no_crash_and_no_fp_when_unreachable(self, auth, mock_session):
        err = requests.exceptions.ConnectionError("refused")
        for m in (mock_session.get, mock_session.post, mock_session.head):
            m.side_effect = err
        with patch.object(auth, "report_finding") as rep:
            auth.run(_TARGET)  # no raise
        rep.assert_not_called()

    def test_no_crash_on_timeout(self, auth, mock_session):
        for m in (mock_session.get, mock_session.post):
            m.side_effect = requests.exceptions.Timeout("t")
        auth.run(_TARGET)  # no raise


class TestStructure:
    def test_inherits_basescanner(self, auth):
        from websecure.scanners.base import BaseScanner
        assert isinstance(auth, BaseScanner)

    def test_run_callable(self, auth):
        assert callable(auth.run)
