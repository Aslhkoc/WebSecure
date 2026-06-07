"""
tests/unit/test_race_condition.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Race condition scanner birim testleri (yapısal).

GateTechniqueExploiter gerçek tespiti, çok-iş-parçacıklı eşzamanlı isteklerle
canlı durum-bağımlı uygulama gerektirir (entegrasyon kapsamı); run() gerçek ağ
bağlantıları açar. Birim test import + sınıf sözleşmesini korur.
"""
from __future__ import annotations

import pytest

from websecure.scanners.race_condition import GateTechniqueExploiter
from websecure.scanners.base import BaseScanner


@pytest.fixture
def race(mock_session):
    return GateTechniqueExploiter(session=mock_session, results={}, debug=False)


def test_inherits_basescanner(race):
    assert isinstance(race, BaseScanner)


def test_run_callable(race):
    assert callable(race.run)


def test_module_has_run():
    from websecure.scanners import race_condition
    assert callable(race_condition.run)
