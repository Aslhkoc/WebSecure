"""
tests/unit/test_request_smuggling.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
HTTP request smuggling scanner birim testleri (yapısal).

H2CLSmugglingProber gerçek tespiti ham soket / HTTP-2 trafiği gerektirir
(entegrasyon kapsamı); run() gerçek bağlantı açar. Birim test import + sınıf
sözleşmesini korur.
"""
from __future__ import annotations

import pytest

from websecure.scanners.request_smuggling import H2CLSmugglingProber
from websecure.scanners.base import BaseScanner


@pytest.fixture
def smug(mock_session):
    return H2CLSmugglingProber(session=mock_session, results={}, debug=False)


def test_inherits_basescanner(smug):
    assert isinstance(smug, BaseScanner)


def test_run_callable(smug):
    assert callable(smug.run)


def test_module_has_run():
    from websecure.scanners import request_smuggling
    assert callable(request_smuggling.run)
