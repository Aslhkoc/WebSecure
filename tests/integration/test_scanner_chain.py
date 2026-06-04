# -*- coding: utf-8 -*-
"""
Entegrasyon Testleri — Scanner → Runner → Bulgu Zinciri (Hamle 2)
=================================================================
Yerel zafiyetli hedefe (tests/benchmark/vulnapp) karşı scanner'ları uçtan uca
çalıştırır. Amaç: birim testlerin yakalamadığı ENTEGRASYON yollarını korumak —
bu oturumda düzeltilen bug'lar bir daha REGRESSION yapmasın:

  * XSS report_finding(severity=..., **dict) çökmesi (taramayı komple bozuyordu)
  * CMDi/SQLi SAHTE-OOB false-positive (callback olmadan High raporlama)
  * http idempotent-first politikası saldırı fazlarında POST'u bloklaması
  * SSRF runner'ın url'siz çağrılması

Hızlı: hedef localhost (ağ gecikmesi yok). reporting.reset() ile her test izole.
"""
from __future__ import annotations

import pathlib
import sys

import pytest

# vulnapp tests/benchmark/ altında — path'e ekle
_BENCH = pathlib.Path(__file__).resolve().parents[1] / "benchmark"
if str(_BENCH) not in sys.path:
    sys.path.insert(0, str(_BENCH))

from vulnapp import start_vulnapp  # noqa: E402
from websecure.core import reporting  # noqa: E402

_VULN_SEVS = {"critical", "high", "medium", "low"}


@pytest.fixture(scope="module")
def target():
    httpd, base = start_vulnapp()
    try:
        yield base
    finally:
        httpd.shutdown()
        httpd.server_close()


@pytest.fixture
def session():
    import requests
    s = requests.Session()
    s.headers.update({"User-Agent": "WebSecure-IntegrationTest/1.0"})
    return s


def _run(mod_name: str, url: str, session):
    """Scanner'ı çalıştır, üretilen TÜM bulguları (vuln + meta) döndür."""
    import importlib
    reporting.reset()
    mod = importlib.import_module(mod_name)
    mod.run(url, session=session, results={}, debug=False)
    findings = []
    for bucket, items in reporting.get_global_results().items():
        for it in items:
            if isinstance(it, dict):
                findings.append({"bucket": bucket, **it})
    return findings


def _vuln_findings(findings):
    return [f for f in findings
            if str(f.get("severity", "")).lower() in _VULN_SEVS]


# ----------------------------------------------------------------------------
# TP — zafiyetli endpoint'ler tespit edilmeli
# ----------------------------------------------------------------------------

def test_sqli_detects_error_based(target, session):
    f = _vuln_findings(_run("websecure.scanners.sqli", target + "/product?id=1", session))
    assert f, "Error-based SQLi (/product) tespit edilemedi"


def test_xss_does_not_crash_and_detects(target, session):
    # REGRESYON: report_finding(severity=..., **dict) çökmesi XSS'i komple bozuyordu.
    f = _vuln_findings(_run("websecure.scanners.xss", target + "/search?q=test", session))
    assert f, "Reflected XSS (/search) tespit edilemedi (report_finding regresyonu?)"


def test_open_redirect_detects(target, session):
    f = _vuln_findings(_run("websecure.scanners.open_redirect", target + "/redirect?url=test", session))
    assert f, "Open Redirect (/redirect) tespit edilemedi"


def test_lfi_detects(target, session):
    f = _vuln_findings(_run("websecure.scanners.lfi", target + "/download?file=readme.txt", session))
    assert f, "LFI (/download) tespit edilemedi"


def test_cmdi_detects(target, session):
    f = _vuln_findings(_run("websecure.scanners.cmdi", target + "/ping?host=127.0.0.1", session))
    assert f, "Command Injection (/ping) tespit edilemedi"


# ----------------------------------------------------------------------------
# FP REGRESYON — sahte-OOB bulgusu callback olmadan ÜRETİLMEMELİ
# ----------------------------------------------------------------------------

def test_cmdi_no_fake_oob_on_safe(target, session):
    # REGRESYON: CMDiOOBDNSProber callback olmadan "OOB/DNS Probe" High raporluyordu.
    f = _run("websecure.scanners.cmdi", target + "/safe_ping?host=127.0.0.1", session)
    oob = [x for x in f if "oob" in str(x.get("type", "")).lower()
           and str(x.get("severity", "")).lower() in _VULN_SEVS]
    assert not oob, f"Sahte-OOB CMDi FP geri geldi: {[x.get('type') for x in oob]}"


def test_sqli_no_fake_oob_on_safe(target, session):
    # REGRESYON: SQLi OOB "Pending Callback" callback olmadan High raporluyordu.
    f = _run("websecure.scanners.sqli", target + "/safe_product?id=1", session)
    oob = [x for x in f if "pending callback" in str(x.get("type", "")).lower()]
    assert not oob, f"Sahte-OOB SQLi FP geri geldi: {[x.get('type') for x in oob]}"


# ----------------------------------------------------------------------------
# POLİTİKA REGRESYON — saldırı fazlarında POST izinli olmalı
# ----------------------------------------------------------------------------

@pytest.mark.parametrize("phase", ["xxe", "ssrf", "sqli", "cmdi", "graphql"])
def test_post_allowed_in_attack_phases(phase):
    # REGRESYON: idempotent-first politikası tüm POST'ları bloklayıp XXE'yi çökertiyordu.
    from websecure.core.http import _respect_idempotent_first
    assert _respect_idempotent_first(phase, "POST", False) is True, \
        f"'{phase}' fazında POST bloklandı (idempotent-first regresyonu)"


def test_discovery_phase_stays_get_only():
    # Erken keşif fazı hâlâ idempotent (GET-only) kalmalı.
    from websecure.core.http import _respect_idempotent_first
    assert _respect_idempotent_first("discovery", "POST", False) is False
    assert _respect_idempotent_first("discovery", "GET", False) is True
