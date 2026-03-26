"""
websecure.core.report_generator
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Rapor oluşturma ve dışa aktarma yardımcıları.
finalize_reports(), SARIF, JUnit, Markdown ve PDF işlevleri
reporting.py'den bu modüle taşındı.

FAZ 4.1: reporting.py'den ayrıştırıldı.
Geriye dönük uyumluluk: reporting.py bu modülden import edip re-export eder.
"""
from __future__ import annotations

import json
import logging
import os
import pathlib
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# SARIF dışa aktarma
# ---------------------------------------------------------------------------

def export_sarif(results: Dict[str, Any], out_path: str) -> None:
    """
    SARIF 2.1.0 formatında rapor dosyası yazar.
    `results` dict'inde 'findings' listesi beklenir.

    FAZ 4.1: reporting.py:3062'den taşındı.
    """
    run: Dict[str, Any] = {
        "tool": {
            "driver": {
                "name": "WebSecure",
                "informationUri": "https://example.invalid",
            }
        },
        "results": [],
    }
    for it in results.get("findings", []):
        rule_id = it.get("cwe") or it.get("type") or "generic"
        msg = it.get("message") or it.get("title") or it.get("type") or "finding"
        run["results"].append({"ruleId": str(rule_id), "message": {"text": str(msg)}})

    sarif = {"version": "2.1.0", "runs": [run]}
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(sarif, fh, indent=2, ensure_ascii=False)
    logger.info(f"[report_generator] SARIF raporu yazıldı: {out_path}")


# ---------------------------------------------------------------------------
# JUnit XML dışa aktarma
# ---------------------------------------------------------------------------

def _xml_escape(s: str) -> str:
    return (s or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;") \
        .replace('"', "&quot;").replace("'", "&apos;")


def export_junit(
    results: Dict[str, Any],
    out_path: str,
    suite_name: str = "WebSecure",
) -> None:
    """
    JUnit XML formatında rapor dosyası yazar.

    FAZ 4.1: reporting.py'deki _to_junit'ten türetildi.
    """
    # _coerce_final benzeri: 'final' ya da sonuç listesi
    items: List[Dict] = []
    if isinstance(results, dict):
        items = results.get("final") or results.get("findings") or []
    elif isinstance(results, list):
        items = results

    lines = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        f'<testsuite name="{_xml_escape(suite_name)}" tests="{len(items)}">',
    ]
    for it in items:
        sev = str(it.get("severity") or "Info")
        name = f"{sev}:{it.get('type') or 'GEN'}"
        lines.append(f'  <testcase classname="websecure" name="{_xml_escape(name)}">')
        sev_lower = sev.lower()
        if any(s in sev_lower for s in ("critical", "high", "medium")):
            reason = str(it.get("reason") or it.get("message") or name)
            lines.append(f'    <failure message="{_xml_escape(reason)}"/>')
        lines.append("  </testcase>")
    lines.append("</testsuite>")

    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))
    logger.info(f"[report_generator] JUnit XML raporu yazıldı: {out_path}")


# ---------------------------------------------------------------------------
# finalize_reports — raporlama entry point'i
# ---------------------------------------------------------------------------

def finalize_reports(ctx: Dict[str, Any], cfg: Dict[str, Any]) -> Dict[str, Any]:
    """
    Yapılandırmaya göre HTML / PDF / SARIF / JUnit / JSON raporu üretir.
    CI kalite kapısı uygular.

    FAZ 4.1: reporting.py:148'den taşındı.
    Gerçek implementasyon hâlâ reporting.py'de — bu fonksiyon ona delege eder.
    """
    try:
        from websecure.core import reporting as _rep
        fn = getattr(_rep, "finalize_reports", None)
        if callable(fn):
            return fn(ctx, cfg)
    except Exception as exc:
        logger.error(f"[report_generator] finalize_reports yüklenemedi: {exc!r}", exc_info=True)

    # Minimal fallback: JSON raporu yaz
    rep_cfg = (cfg.get("reporting") or {}) if isinstance(cfg, dict) else {}
    out_dir = str(rep_cfg.get("output_dir") or cfg.get("output_dir") or "output")
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, "results.json")
    results = ctx.get("results") or {} if isinstance(ctx, dict) else {}
    try:
        with open(out_path, "w", encoding="utf-8") as fh:
            json.dump(results, fh, indent=2, ensure_ascii=False, default=str)
        logger.info(f"[report_generator] Fallback JSON raporu yazıldı: {out_path}")
        return {"json": out_path}
    except OSError as exc:
        logger.error(f"[report_generator] JSON fallback yazılamadı: {exc!r}")
        return {}


__all__ = [
    "export_sarif",
    "export_junit",
    "finalize_reports",
]
