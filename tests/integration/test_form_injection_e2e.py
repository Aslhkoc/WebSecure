# -*- coding: utf-8 -*-
"""
Uçtan-uca FORM/INPUT-ALANI enjeksiyon doğrulaması
==================================================
Kullanıcı tespiti: program kullanıcı-verisi girilen alanlara (name/email/password/
kart) denemiyordu, sadece URL'de oynuyordu. Bu test, formların gerçekten KEŞFEDİLİP
alanlarının POST/JSON gövdede fuzz'landığını ve zafiyetin ALANDA (URL'de değil)
tespit edildiğini canlı bir hedefe karşı kanıtlar.

Kapsanan zincir:
  crawl/extract → infer_form_method (method YOK → POST) → relatif action urljoin →
  scan_forms → submit_form_variants (form-encoded + JSON) → tespit.

Hedef: tests/benchmark/vulnapp.py
  /register_page    → form (method YOK) action=/auth/register, name HAM yansır (form-alanı XSS)
  /json_login_page  → form (method YOK) action=/api/auth/login, email SADECE JSON gövdede SQLi
"""
from __future__ import annotations

import os
import sys

import pytest
import requests

# tests paketini import edilebilir kıl
_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from tests.benchmark.vulnapp import start_vulnapp  # noqa: E402
from websecure.core.analysis import detect_get_parameters_and_forms  # noqa: E402


def _discover_forms(sess, base, pages):
    """Statik form çıkarımı (infer_form_method + urljoin uygulanır)."""
    forms_meta = []
    for page in pages:
        _, _, forms = detect_get_parameters_and_forms(
            base + page, fetcher=lambda u: sess.get(u, timeout=5).text
        )
        if forms:
            forms_meta.append({"url": base + page, "forms": forms})
    return forms_meta


def _offensive(results):
    return [f for f in (results.get("offensive") or []) if isinstance(f, dict)]


def test_form_field_injection_end_to_end():
    httpd, base = start_vulnapp()
    try:
        sess = requests.Session()

        # ── 1. Form keşfi: method ATTRIBUTE YOK → POST çıkarılmalı, action absolute olmalı
        forms_meta = _discover_forms(sess, base, ["/register_page", "/json_login_page"])
        all_forms = [f for p in forms_meta for f in p["forms"]]
        assert all_forms, "Hiç form keşfedilemedi (extraction kırık)"
        assert all(f["method"] == "POST" for f in all_forms), (
            "Method çıkarımı başarısız — auth/register/login formları POST olmalı: "
            + repr([(f["action"], f["method"]) for f in all_forms])
        )
        assert all(f["action"].startswith("http") for f in all_forms), (
            "Relatif action absolute'a çevrilmedi (urljoin): "
            + repr([f["action"] for f in all_forms])
        )

        # ── 2. XSS: /auth/register `name` alanı (form-encoded gövde) ──────────────
        import websecure.core.reporting as _rep
        try:
            _rep.reset()
        except Exception:
            pass
        import websecure.scanners.xss as xssmod
        xss_results = {"forms_meta": forms_meta, "endpoints": [base + "/"], "tech_stack": []}
        xssmod.run([base + "/"], session=sess, results=xss_results, debug=False)
        xss_hits = _offensive(xss_results)
        xss_form = [
            f for f in xss_hits
            if "xss" in str(f.get("type", "")).lower()
            and str(f.get("param") or f.get("parameter") or "").lower() in ("name", "email", "password")
        ]
        assert xss_form, (
            "FORM-ALANI XSS bulunamadı — name alanına POST gövdede payload girmiyor. "
            f"Tüm XSS bulguları: {[(f.get('type'), f.get('param')) for f in xss_hits]}"
        )

        # ── 3. SQLi: /api/auth/login `email` alanı — YALNIZ JSON gövde tetikler ────
        try:
            _rep.reset()
        except Exception:
            pass
        import websecure.scanners.sqli as sqlimod
        sqli_results = {"forms_meta": forms_meta, "endpoints": [base + "/"], "tech_stack": []}
        sqlimod.run([base + "/"], session=sess, results=sqli_results, debug=False)
        sqli_hits = _offensive(sqli_results)
        sqli_form = [
            f for f in sqli_hits
            if "sql" in str(f.get("type", "")).lower()
            and "form" in str(f.get("type", "")).lower()
        ]
        assert sqli_form, (
            "JSON-gövde FORM SQLi bulunamadı — submit_form_variants JSON stratejisi "
            "çalışmıyor (endpoint yalnız JSON gövdede tetikliyor). "
            f"Tüm SQLi bulguları: {[(f.get('type'), f.get('param')) for f in sqli_hits]}"
        )
    finally:
        httpd.shutdown()
        httpd.server_close()


if __name__ == "__main__":
    test_form_field_injection_end_to_end()
    print("[OK] Form-alanı enjeksiyon uçtan-uca doğrulandı.")
