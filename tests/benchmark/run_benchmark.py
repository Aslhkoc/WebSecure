# -*- coding: utf-8 -*-
"""
WebSecure Benchmark Koşucusu — Hamle 1: Ölçülebilir Doğrulama
=============================================================
Yerel zafiyetli hedefe (vulnapp) karşı WebSecure scanner'larını çalıştırır,
bulguları ground-truth ile karşılaştırır ve TP/FP/FN + precision/recall/F1
hesaplar. "Ne kadar iyi?" sorusunun SAYISAL cevabı.

Çalıştırma (proje kökünden, venv ile):
    python tests/benchmark/run_benchmark.py
    python tests/benchmark/run_benchmark.py --json   # makine-okur çıktı

Mantık:
  - Her kategori için scanner ZAFİYETLİ URL'de çalışır → bulgu beklenir (TP).
  - Aynı scanner GÜVENLİ URL'de çalışır → bulgu beklenmez (bulursa FP).
  - reporting.reset() her run'dan önce → bulgular o run'a izole.
"""
from __future__ import annotations

import argparse
import importlib
import json
import os
import sys
import time
from pathlib import Path

# --- path kurulumu: proje kökü + benchmark dizini ---
_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parent.parent
sys.path.insert(0, str(_ROOT))
sys.path.insert(0, str(_HERE))

from vulnapp import start_vulnapp  # noqa: E402

_VULN_SEVS = {"critical", "high", "medium", "low"}

# (etiket, scanner_modülü, zafiyetli_path, güvenli_path)
CASES = [
    ("SQLi",          "websecure.scanners.sqli",          "/product?id=1",                  "/safe_product?id=1"),
    ("XSS",           "websecure.scanners.xss",           "/search?q=test",                 "/safe_search?q=test"),
    ("Open Redirect", "websecure.scanners.open_redirect", "/redirect?url=test",             "/safe_redirect?url=test"),
    ("LFI",           "websecure.scanners.lfi",           "/download?file=readme.txt",      "/safe_download?file=readme.txt"),
    ("CMDi",          "websecure.scanners.cmdi",          "/ping?host=127.0.0.1",           "/safe_ping?host=127.0.0.1"),
]


def _make_session():
    import requests
    s = requests.Session()
    s.headers.update({"User-Agent": "WebSecure-Benchmark/1.0"})
    return s


def _vuln_findings(reporting) -> list[dict]:
    """get_global_results()'tan yalnız gerçek-vuln severity'li bulguları topla."""
    out = []
    for bucket, items in reporting.get_global_results().items():
        for it in items:
            if not isinstance(it, dict):
                continue
            sev = str(it.get("severity") or it.get("cvss_severity") or "").lower()
            if sev in _VULN_SEVS:
                out.append({"bucket": bucket, **it})
    return out


def _run_scanner(mod_name: str, url: str, session, reporting) -> list[dict]:
    """Tek scanner'ı tek URL'de çalıştır, ürettiği vuln bulgularını döndür."""
    reporting.reset()
    try:
        mod = importlib.import_module(mod_name)
    except Exception as e:
        return [{"_error": f"import: {e}"}]
    run_fn = getattr(mod, "run", None)
    if not callable(run_fn):
        return [{"_error": "run() yok"}]
    try:
        ret = run_fn(url, session=session, results={}, debug=False)
    except TypeError:
        try:
            ret = run_fn(url)
        except Exception as e:
            return [{"_error": f"run: {e}"}]
    except Exception as e:
        return [{"_error": f"run: {e}"}]
    findings = _vuln_findings(reporting)
    # Bazı scanner'lar bulguları return da edebilir
    if isinstance(ret, list):
        for it in ret:
            if isinstance(it, dict) and str(it.get("severity", "")).lower() in _VULN_SEVS:
                findings.append({"bucket": "return", **it})
    return findings


def main() -> int:
    ap = argparse.ArgumentParser(description="WebSecure benchmark")
    ap.add_argument("--json", action="store_true", help="JSON çıktı")
    args = ap.parse_args()

    os.chdir(_ROOT)  # config.json + wordlists kökten çözülsün
    from websecure.core import reporting

    httpd, base = start_vulnapp()
    session = _make_session()

    rows = []
    tp = fp = fn = tn = 0
    t0 = time.time()
    try:
        for label, mod_name, vuln_path, safe_path in CASES:
            vuln_hits = _run_scanner(mod_name, base + vuln_path, session, reporting)
            safe_hits = _run_scanner(mod_name, base + safe_path, session, reporting)
            errs = [h["_error"] for h in (vuln_hits + safe_hits) if "_error" in h]
            vuln_det = any("_error" not in h for h in vuln_hits)
            safe_det = any("_error" not in h for h in safe_hits)

            tp_c = 1 if vuln_det else 0
            fn_c = 0 if vuln_det else 1
            fp_c = 1 if safe_det else 0
            tn_c = 0 if safe_det else 1
            tp += tp_c; fn += fn_c; fp += fp_c; tn += tn_c

            rows.append({
                "category": label,
                "vuln_detected": vuln_det,     # TP olmalı
                "safe_flagged": safe_det,      # FP olmamalı
                "result": ("TP" if vuln_det else "FN") + " / " + ("FP" if safe_det else "TN"),
                "vuln_findings": len([h for h in vuln_hits if "_error" not in h]),
                "errors": errs or None,
            })
    finally:
        httpd.shutdown(); httpd.server_close()

    elapsed = round(time.time() - t0, 1)
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    summary = {
        "cases": len(CASES), "TP": tp, "FP": fp, "FN": fn, "TN": tn,
        "precision": round(precision, 3), "recall": round(recall, 3),
        "f1": round(f1, 3), "elapsed_sec": elapsed,
    }

    if args.json:
        print(json.dumps({"summary": summary, "rows": rows}, ensure_ascii=False, indent=2))
        return 0

    print("\n" + "=" * 64)
    print("  WebSecure Benchmark — Yerel Zafiyetli Hedef")
    print("=" * 64)
    print(f"  {'Kategori':<16}{'Zafiyet?':<10}{'Güvenli?':<10}{'Sonuç':<12}{'#bulgu'}")
    print("  " + "-" * 60)
    for r in rows:
        vd = "TESPİT" if r["vuln_detected"] else "KAÇTI"
        sf = "TEMİZ" if not r["safe_flagged"] else "YANLIŞ!"
        print(f"  {r['category']:<16}{vd:<10}{sf:<10}{r['result']:<12}{r['vuln_findings']}")
        if r["errors"]:
            for e in r["errors"]:
                print(f"      [hata] {e}")
    print("  " + "-" * 60)
    print(f"  TP={tp}  FP={fp}  FN={fn}  TN={tn}   ({elapsed}s)")
    print(f"  Precision={precision:.0%}  Recall={recall:.0%}  F1={f1:.2f}")
    print("=" * 64)
    print("  Hedef: Recall yüksek (kaçırma az) + FP=0 (yanlış alarm yok)")
    print("=" * 64 + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
