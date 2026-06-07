"""
tests/unit/test_tls.py
~~~~~~~~~~~~~~~~~~~~~~~
TLS zayıflık scanner birim testleri (yapısal).

TLSBEASTPoodleProber gerçek tespiti ham TLS soketi / handshake gerektirir
(entegrasyon kapsamı); run() gerçek bağlantı açar. Birim test import + sınıf
sözleşmesini korur.
"""
from __future__ import annotations

import pytest

from websecure.scanners.tls import TLSBEASTPoodleProber
from websecure.scanners.base import BaseScanner


@pytest.fixture
def tls(mock_session):
    return TLSBEASTPoodleProber(session=mock_session, results={}, debug=False)


def test_inherits_basescanner(tls):
    assert isinstance(tls, BaseScanner)


def test_run_callable(tls):
    assert callable(tls.run)


def test_name_attribute(tls):
    assert tls.name == "tls_beast_poodle"
