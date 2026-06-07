"""
tests/unit/test_passive_recon.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Pasif JS keşif scanner birim testleri (yapısal).

PassiveJSScanner gerçek tespiti, harici JS dosyalarını indirip sır/endpoint
çıkarımı gerektirir (entegrasyon kapsamı). Birim test import + sınıf sözleşmesini korur.
"""
from __future__ import annotations

import pytest

from websecure.scanners.passive_recon import PassiveJSScanner
from websecure.scanners.base import BaseScanner


@pytest.fixture
def pr(mock_session):
    return PassiveJSScanner(session=mock_session, results={}, debug=False)


def test_inherits_basescanner(pr):
    assert isinstance(pr, BaseScanner)


def test_run_callable(pr):
    assert callable(pr.run)
