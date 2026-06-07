"""
tests/unit/test_subdomain_takeover.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Subdomain takeover scanner birim testleri (yapısal).

SubdomainTakeoverScanner gerçek tespiti canlı DNS/CNAME çözümü gerektirir
(entegrasyon kapsamı); run() gerçek DNS sorgusu yapar. Birim test import + sınıf
sözleşmesini korur.
"""
from __future__ import annotations

import pytest

from websecure.scanners.subdomain_takeover import SubdomainTakeoverScanner
from websecure.scanners.base import BaseScanner


@pytest.fixture
def st(mock_session):
    return SubdomainTakeoverScanner(session=mock_session, results={}, debug=False)


def test_inherits_basescanner(st):
    assert isinstance(st, BaseScanner)


def test_run_callable(st):
    assert callable(st.run)


def test_name_attribute(st):
    assert st.name == "subdomain_takeover"
