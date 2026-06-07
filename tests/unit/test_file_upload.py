"""
tests/unit/test_file_upload.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Dosya yükleme scanner birim testleri.

Gerçek tespit, yükleme kabul eden + yüklenen dosyayı erişilebilir kılan canlı
uygulama gerektirir (entegrasyon kapsamı). Bu birim testler import + yapısal +
ağ hatasında çökmeme/FP-üretmeme korur.
"""
from __future__ import annotations

from unittest.mock import patch

import pytest
import requests

from websecure.scanners.file_upload import FileUploadScanner

_TARGET = "http://target.test/upload"


@pytest.fixture
def fu(mock_session):
    return FileUploadScanner(session=mock_session, results={}, debug=False)


class TestRobustness:
    def test_no_crash_and_no_fp_when_unreachable(self, fu, mock_session):
        err = requests.exceptions.ConnectionError("refused")
        for m in (mock_session.get, mock_session.post, mock_session.put):
            m.side_effect = err
        with patch.object(fu, "report_finding") as rep:
            fu.run(_TARGET)  # no raise
        rep.assert_not_called()

    def test_no_crash_on_timeout(self, fu, mock_session):
        for m in (mock_session.get, mock_session.post):
            m.side_effect = requests.exceptions.Timeout("t")
        fu.run(_TARGET)  # no raise


class TestStructure:
    def test_inherits_basescanner(self, fu):
        from websecure.scanners.base import BaseScanner
        assert isinstance(fu, BaseScanner)

    def test_run_callable(self, fu):
        assert callable(fu.run)
