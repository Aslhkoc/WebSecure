"""
websecure.integrations.sarif
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
SARIF 2.1.0 (Static Analysis Results Interchange Format) normalizasyonu.

Tüm harici araç çıktıları ve WebSecure native bulgular bu modül üzerinden
SARIF formatına dönüştürülür. GitHub Code Scanning, VS Code SARIF Viewer,
Azure DevOps gibi platformlarla tam uyumluluk.

Referans: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
"""
from __future__ import annotations

import hashlib
import json
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from websecure.integrations.base import (
    FindingCorrelator,
    ToolFinding,
    ToolResult,
    ToolSeverity,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Sabitler
# ---------------------------------------------------------------------------

_SARIF_SCHEMA   = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
_SARIF_VERSION  = "2.1.0"
_TOOL_NAME      = "WebSecure"
_TOOL_VERSION   = "2.0"

# WebSecure severity → SARIF level
_SEV_TO_SARIF_LEVEL: Dict[ToolSeverity, str] = {
    ToolSeverity.CRITICAL: "error",
    ToolSeverity.HIGH:     "error",
    ToolSeverity.MEDIUM:   "warning",
    ToolSeverity.LOW:      "note",
    ToolSeverity.INFO:     "none",
}

# WebSecure severity → SARIF security-severity (CVSS benzeri 0-10)
_SEV_TO_SECURITY_SEVERITY: Dict[ToolSeverity, float] = {
    ToolSeverity.CRITICAL: 9.5,
    ToolSeverity.HIGH:     7.5,
    ToolSeverity.MEDIUM:   5.0,
    ToolSeverity.LOW:      3.0,
    ToolSeverity.INFO:     0.0,
}


# ---------------------------------------------------------------------------
# SARIF veri modelleri
# ---------------------------------------------------------------------------

@dataclass
class SARIFRule:
    """
    SARIF `reportingDescriptor` — bir tarama kuralı.

    Her benzersiz bulgu tipi için bir kural oluşturulur.
    """
    rule_id: str
    name: str
    short_description: str
    full_description: str
    severity: ToolSeverity
    tags: List[str] = field(default_factory=list)
    cwe_ids: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)

    def to_sarif(self) -> Dict[str, Any]:
        sec_sev = _SEV_TO_SECURITY_SEVERITY.get(self.severity, 5.0)
        sarif: Dict[str, Any] = {
            "id": self.rule_id,
            "name": self.name,
            "shortDescription": {"text": self.short_description},
            "fullDescription": {"text": self.full_description},
            "defaultConfiguration": {
                "level": _SEV_TO_SARIF_LEVEL.get(self.severity, "warning"),
            },
            "properties": {
                "security-severity": str(sec_sev),
                "tags": self.tags,
            },
        }
        if self.cwe_ids:
            sarif["relationships"] = [
                {"target": {"id": cwe, "toolComponent": {"name": "CWE"}}}
                for cwe in self.cwe_ids
            ]
        if self.references:
            sarif["helpUri"] = self.references[0]
            sarif["help"] = {
                "text": "References:\n" + "\n".join(self.references),
            }
        return sarif


@dataclass
class SARIFResult:
    """SARIF `result` — tek bir bulgu."""
    rule_id: str
    message: str
    level: str
    uri: str
    tool_source: str
    fingerprint: str
    properties: Dict[str, Any] = field(default_factory=dict)

    def to_sarif(self) -> Dict[str, Any]:
        return {
            "ruleId": self.rule_id,
            "level": self.level,
            "message": {"text": self.message},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": self.uri, "uriBaseId": "%SRCROOT%"},
                    }
                }
            ],
            "fingerprints": {
                "websecureV1": self.fingerprint,
            },
            "properties": {
                "source": self.tool_source,
                **self.properties,
            },
        }


# ---------------------------------------------------------------------------
# SARIFReport
# ---------------------------------------------------------------------------

class SARIFReport:
    """
    Tam bir SARIF 2.1.0 raporu oluşturur.

    Kullanım
    --------
    ```python
    report = SARIFReport()
    report.add_findings(nuclei_result.findings)
    report.add_findings(dalfox_result.findings)
    report.add_native_findings(websecure_findings)
    sarif_doc = report.build()
    report.save("output.sarif.json")
    ```
    """

    def __init__(
        self,
        tool_name: str = _TOOL_NAME,
        tool_version: str = _TOOL_VERSION,
    ) -> None:
        self._tool_name = tool_name
        self._tool_version = tool_version
        self._rules: Dict[str, SARIFRule] = {}
        self._results: List[SARIFResult] = []
        self._seen_fps: Set[str] = set()

    # ------------------------------------------------------------------
    # Bulgu ekleme
    # ------------------------------------------------------------------

    def add_findings(self, findings: List[ToolFinding]) -> int:
        """
        ToolFinding listesini SARIF formatına ekle.

        Döndürür
        --------
        int — Eklenen yeni bulgu sayısı (çakışanlar hariç).
        """
        added = 0
        for f in findings:
            fp = f.fingerprint()
            if fp in self._seen_fps:
                continue
            self._seen_fps.add(fp)
            rule_id = self._ensure_rule(f)
            sr = SARIFResult(
                rule_id=rule_id,
                message=f.description or f.title,
                level=_SEV_TO_SARIF_LEVEL.get(f.severity, "warning"),
                uri=f.url,
                tool_source=f.tool,
                fingerprint=fp,
                properties={
                    "confidence": f.confidence,
                    "verified": f.verified,
                    "cve": f.cve_ids,
                    "cvss": f.cvss_score,
                    "evidence": f.evidence[:500] if f.evidence else "",
                },
            )
            self._results.append(sr)
            added += 1
        return added

    def add_native_findings(
        self,
        findings: List[Dict[str, Any]],
        tool_source: str = "websecure",
    ) -> int:
        """
        WebSecure native finding dict listesini SARIF formatına ekle.

        Döndürür
        --------
        int — Eklenen yeni bulgu sayısı.
        """
        converted = [_native_to_tool_finding(f, tool_source) for f in findings]
        return self.add_findings(converted)

    # ------------------------------------------------------------------
    # SARIF dökümanı üretme
    # ------------------------------------------------------------------

    def build(self) -> Dict[str, Any]:
        """SARIF 2.1.0 uyumlu tam dökümanı döndür."""
        rules = [r.to_sarif() for r in self._rules.values()]
        results = [r.to_sarif() for r in self._results]

        return {
            "$schema": _SARIF_SCHEMA,
            "version": _SARIF_VERSION,
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": self._tool_name,
                            "version": self._tool_version,
                            "informationUri": "https://github.com/Aslhkoc/WebSecure",
                            "rules": rules,
                        }
                    },
                    "results": results,
                    "properties": {
                        "generated_at": _utc_iso(),
                        "total_findings": len(results),
                    },
                }
            ],
        }

    def save(self, path: str | Path, indent: int = 2) -> Path:
        """SARIF dökümanını dosyaya yaz."""
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        sarif_doc = self.build()
        p.write_text(
            json.dumps(sarif_doc, indent=indent, ensure_ascii=False),
            encoding="utf-8",
        )
        logger.info(f"[SARIF] Rapor kaydedildi: {p}  ({len(self._results)} bulgu)")
        return p

    def to_json(self, indent: int = 2) -> str:
        """SARIF dökümanını JSON string olarak döndür."""
        return json.dumps(self.build(), indent=indent, ensure_ascii=False)

    # ------------------------------------------------------------------
    # İstatistik
    # ------------------------------------------------------------------ #

    def stats(self) -> Dict[str, int]:
        """Önem seviyesine göre bulgu sayıları."""
        counts: Dict[str, int] = {
            "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0,
        }
        for sr in self._results:
            if sr.level == "error":
                # critical / high ayrımı rule properties'den
                rule = self._rules.get(sr.rule_id)
                if rule and rule.severity == ToolSeverity.CRITICAL:
                    counts["critical"] += 1
                else:
                    counts["high"] += 1
            elif sr.level == "warning":
                counts["medium"] += 1
            elif sr.level == "note":
                counts["low"] += 1
            else:
                counts["info"] += 1
        counts["total"] = len(self._results)
        return counts

    # ------------------------------------------------------------------
    # Yardımcılar
    # ------------------------------------------------------------------

    def _ensure_rule(self, f: ToolFinding) -> str:
        """Bulgu için kural oluştur veya mevcut kuralı döndür."""
        rule_id = _make_rule_id(f.tool, f.title)
        if rule_id not in self._rules:
            self._rules[rule_id] = SARIFRule(
                rule_id=rule_id,
                name=f.title,
                short_description=f.title,
                full_description=f.description or f.title,
                severity=f.severity,
                tags=list(f.tags),
                cwe_ids=list(f.cwe_ids),
                references=list(f.references),
            )
        return rule_id


# ---------------------------------------------------------------------------
# SARIFNormalizer — ToolResult → SARIF (tek adım)
# ---------------------------------------------------------------------------

class SARIFNormalizer:
    """
    Birden fazla ToolResult'u tek bir SARIF raporuna dönüştürür.

    Kullanım
    --------
    ```python
    norm = SARIFNormalizer()
    norm.ingest(nuclei_result)
    norm.ingest(dalfox_result)
    norm.ingest_native(websecure_findings)
    norm.save("report.sarif.json")
    ```
    """

    def __init__(self) -> None:
        self._report = SARIFReport()
        self._tool_counts: Dict[str, int] = {}

    def ingest(self, result: ToolResult) -> int:
        """ToolResult'u SARIF raporuna ekle."""
        added = self._report.add_findings(result.findings)
        self._tool_counts[result.tool] = added
        return added

    def ingest_native(
        self,
        findings: List[Dict[str, Any]],
        tool_source: str = "websecure",
    ) -> int:
        """WebSecure native bulgularını SARIF raporuna ekle."""
        return self._report.add_native_findings(findings, tool_source)

    def save(self, path: str | Path) -> Path:
        return self._report.save(path)

    def build(self) -> Dict[str, Any]:
        return self._report.build()

    def stats(self) -> Dict[str, Any]:
        s = self._report.stats()
        s["by_tool"] = dict(self._tool_counts)
        return s


# ---------------------------------------------------------------------------
# Yardımcı fonksiyonlar
# ---------------------------------------------------------------------------

def _make_rule_id(tool: str, title: str) -> str:
    """Araç ve başlıktan deterministik kural ID'si üret."""
    key = f"{tool}:{title}".lower()
    short = hashlib.md5(key.encode()).hexdigest()[:8]  # noqa: S324
    safe_title = "".join(c if c.isalnum() else "_" for c in title[:30])
    return f"WS/{tool.upper()}/{safe_title}_{short}"


def _native_to_tool_finding(data: Dict[str, Any], tool: str) -> ToolFinding:
    """WebSecure native finding dict'ini ToolFinding'e çevir."""
    ev = data.get("evidence") or {}
    if isinstance(ev, str):
        ev_text = ev
        ev = {}
    else:
        ev_text = ev.get("text", "")

    sev_str = data.get("severity", "info")
    sev = ToolSeverity.from_str(sev_str)

    return ToolFinding(
        title=data.get("type", "Unknown"),
        severity=sev,
        url=data.get("url", ""),
        tool=data.get("source", tool),
        description=data.get("detail", ""),
        evidence=ev_text,
        cve_ids=ev.get("cve", []) if isinstance(ev, dict) else [],
        cwe_ids=ev.get("cwe", []) if isinstance(ev, dict) else [],
        cvss_score=ev.get("cvss") if isinstance(ev, dict) else None,
        confidence=data.get("confidence", "medium"),
        verified=data.get("verified", False),
        tags=data.get("tags", []),
        references=ev.get("refs", []) if isinstance(ev, dict) else [],
        raw=data,
    )


def _utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def findings_to_sarif(
    findings: List[Dict[str, Any]],
    output_path: Optional[str | Path] = None,
    tool_source: str = "websecure",
) -> Dict[str, Any]:
    """
    WebSecure native bulgularını SARIF'a dönüştüren kısayol fonksiyon.

    Parametreler
    ------------
    findings    : WebSecure native finding dict listesi
    output_path : Belirtilirse dosyaya yazar
    tool_source : Kaynak araç adı

    Döndürür
    --------
    SARIF dökümanı dict.
    """
    report = SARIFReport()
    report.add_native_findings(findings, tool_source)
    if output_path:
        report.save(output_path)
    return report.build()


def merge_tool_results_to_sarif(
    results: List[ToolResult],
    output_path: Optional[str | Path] = None,
) -> Dict[str, Any]:
    """
    Birden fazla ToolResult'u tek SARIF raporuna birleştiren kısayol.

    Parametreler
    ------------
    results     : ToolResult listesi
    output_path : Belirtilirse dosyaya yazar

    Döndürür
    --------
    SARIF dökümanı dict.
    """
    norm = SARIFNormalizer()
    for r in results:
        norm.ingest(r)
    if output_path:
        norm.save(output_path)
    return norm.build()


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

__all__ = [
    "SARIFRule",
    "SARIFResult",
    "SARIFReport",
    "SARIFNormalizer",
    "findings_to_sarif",
    "merge_tool_results_to_sarif",
]
