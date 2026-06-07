"""
tests/unit/test_prototype_pollution.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Server-side prototype pollution scanner birim testleri.

Gerçek tespit, kirletilen prototip etkisini yansıtan canlı uygulama gerektirir
(entegrasyon kapsamı). Bu birim testler import + yapısal + ağ hatasında
çökmeme/FP-üretmeme korur.
"""
from __future__ import annotations

from unittest.mock import patch

import pytest
import requests

from websecure.scanners.prototype_pollution import ServerSidePPProber

_TARGET = "http://target.test/api/profile"


@pytest.fixture
def pp(mock_session):
    return ServerSidePPProber(session=mock_session, results={}, debug=False)


class TestRobustness:
    def test_no_crash_and_no_fp_when_unreachable(self, pp, mock_session):
        err = requests.exceptions.ConnectionError("refused")
        for m in (mock_session.get, mock_session.post, mock_session.put, mock_session.patch):
            m.side_effect = err
        with patch.object(pp, "report_finding") as rep:
            pp.run(_TARGET)  # no raise
        rep.assert_not_called()

    def test_no_crash_on_timeout(self, pp, mock_session):
        for m in (mock_session.get, mock_session.post):
            m.side_effect = requests.exceptions.Timeout("t")
        pp.run(_TARGET)  # no raise


class TestStructure:
    def test_inherits_basescanner(self, pp):
        from websecure.scanners.base import BaseScanner
        assert isinstance(pp, BaseScanner)

    def test_run_callable(self, pp):
        assert callable(pp.run)
