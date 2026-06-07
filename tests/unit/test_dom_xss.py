"""
tests/unit/test_dom_xss.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~
DOM XSS scanner birim testleri (yapısal).

DOMXSSScanner gerçek tespiti Playwright tarayıcısı gerektirir (entegrasyon/opsiyonel
kapsam); run() çağrılması tarayıcı başlatır. Bu yüzden birim test import + sınıf
sözleşmesini (BaseScanner + run) korur — refactor'da kopan import/yapıyı yakalar.
"""
from __future__ import annotations

import pytest

from websecure.scanners.dom_xss import DOMXSSScanner
from websecure.scanners.base import BaseScanner


@pytest.fixture
def dom(mock_session):
    return DOMXSSScanner(session=mock_session, results={}, debug=False)


def test_inherits_basescanner(dom):
    assert isinstance(dom, BaseScanner)


def test_run_callable(dom):
    assert callable(dom.run)


def test_name_attribute(dom):
    assert dom.name == "dom_xss"
