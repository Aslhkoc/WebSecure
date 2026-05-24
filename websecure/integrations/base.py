"""
websecure.integrations.base
~~~~~~~~~~~~~~~~~~~~~~~~~~~
Tüm harici araç entegrasyonları için temel soyut sınıflar ve veri modelleri.

SOLID Tasarım
-------------
- SRP  : Her sınıfın tek sorumluluğu var.
- OCP  : Yeni araç eklemek için ToolIntegration alt sınıfı yeter — base değişmez.
- LSP  : Her alt sınıf ToolIntegration yerine kullanılabilir.
- ISP  : Saveable / Correlatable ayrı protocol — araçlar sadece ihtiyaçlarını impl eder.
- DIP  : ToolManager soyut ToolIntegration'a bağımlı, somut sınıflara değil.
"""
from __future__ import annotations

import hashlib
import logging
import shutil
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, FrozenSet, List, Optional, Set

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Enumlar
# ---------------------------------------------------------------------------

class ToolSeverity(str, Enum):
    CRITICAL = "Critical"
    HIGH     = "High"
    MEDIUM   = "Medium"
    LOW      = "Low"
    INFO     = "Info"

    @classmethod
    def from_str(cls, s: str) -> "ToolSeverity":
        _map = {
            "critical": cls.CRITICAL,
            "high":     cls.HIGH,
            "medium":   cls.MEDIUM,
            "moderate": cls.MEDIUM,
            "low":      cls.LOW,
            "info":     cls.INFO,
            "informational": cls.INFO,
            "unknown":  cls.INFO,
        }
        return _map.get((s or "info").lower(), cls.INFO)


class ToolStatus(str, Enum):
    SUCCESS   = "success"
    TIMEOUT   = "timeout"
    ERROR     = "error"
    SKIPPED   = "skipped"
    NOT_FOUND = "not_found"


# ---------------------------------------------------------------------------
# Veri modelleri
# ---------------------------------------------------------------------------

@dataclass
class ToolFinding:
    """
    Harici araç bulgusu — standartlaştırılmış WebSecure format.

    Bu sınıf tüm araçlardan gelen ham bulgular için ortak bir arayüz sağlar.
    SARIF, WebSecure native format, ve raporlama sistemiyle uyumludur.
    """
    title: str
    severity: ToolSeverity
    url: str
    tool: str                               # "nuclei", "dalfox", "amass" vb.

    description: str = ""
    evidence: str = ""
    remediation: str = ""
    cve_ids: List[str] = field(default_factory=list)
    cwe_ids: List[str] = field(default_factory=list)
    cvss_score: Optional[float] = None
    cvss_vector: str = ""
    confidence: str = "medium"             # high / medium / low
    verified: bool = False
    tags: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    raw: Dict[str, Any] = field(default_factory=dict)
    found_at: float = field(default_factory=time.time)

    # ------------------------------------------------------------------ #
    # Parmak izi ve tekilleştirme
    # ------------------------------------------------------------------ #

    def fingerprint(self) -> str:
        """SHA256 tabanlı benzersiz parmak izi (deduplication için)."""
        key = f"{self.tool}:{self.title}:{self.url}:{self.severity.value}"
        return hashlib.sha256(key.encode()).hexdigest()[:16]

    def to_dict(self) -> Dict[str, Any]:
        """WebSecure native raporlama formatına dönüştür."""
        # CWE boşsa finding tipinden otomatik doldur
        cwe = list(self.cwe_ids)
        if not cwe:
            try:
                from websecure.core.cvss import lookup_cwe
                cwe = lookup_cwe(self.title)
            except Exception as _fix_e:
                logger.debug(f"[integrations.base] {type(_fix_e).__name__}: {_fix_e!r}")

        return {
            "type":        self.title,
            "severity":    self.severity.value,
            "url":         self.url,
            "detail":      self.description,
            "evidence":    {
                "text":     self.evidence,
                "cve":      self.cve_ids,
                "cwe":      cwe,
                "cvss":     self.cvss_score,
                "refs":     self.references,
                "raw":      self.raw,
            },
            "confidence":  self.confidence,
            "verified":    self.verified,
            "source":      self.tool,
            "tags":        self.tags,
        }


@dataclass
class ToolResult:
    """
    Bir araç çalıştırmasının sonucu.

    Hem ham çıktıyı hem de ayrıştırılmış bulguları içerir.
    """
    tool: str
    target: str
    status: ToolStatus
    findings: List[ToolFinding] = field(default_factory=list)
    raw_output: str = ""
    stderr: str = ""
    duration_s: float = 0.0
    extra: Dict[str, Any] = field(default_factory=dict)

    @property
    def success(self) -> bool:
        return self.status == ToolStatus.SUCCESS

    @property
    def finding_count(self) -> int:
        return len(self.findings)

    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == ToolSeverity.CRITICAL)

    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == ToolSeverity.HIGH)


# ---------------------------------------------------------------------------
# Soyut temel sınıf
# ---------------------------------------------------------------------------

class ToolIntegration(ABC):
    """
    Tüm harici araç entegrasyonları için soyut temel sınıf.

    Alt sınıflar şu metotları implement etmelidir:
    - `tool_name` property
    - `is_available()` -> araç sistemde kurulu mu?
    - `run(target, **kwargs)` -> ToolResult

    Opsiyonel override:
    - `to_sarif(result)` -> SARIF formatında dict
    - `correlate(result, existing_findings)` -> deduplicated ToolResult
    """

    def __init__(self, binary_name: str = "") -> None:
        self._binary_name = binary_name
        self._binary_path: Optional[str] = None
        if binary_name:
            self._resolve_binary(binary_name)

    # ------------------------------------------------------------------ #
    # Soyut metotlar (alt sınıflar ZORUNLU implement eder)
    # ------------------------------------------------------------------ #

    @property
    @abstractmethod
    def tool_name(self) -> str:
        """Araç adı (küçük harf, örn. 'nuclei', 'amass')."""
        ...

    @abstractmethod
    def is_available(self) -> bool:
        """Araç binary'si sistemde mevcut mu?"""
        ...

    @abstractmethod
    def run(self, target: str, **kwargs) -> ToolResult:
        """Aracı çalıştır ve ToolResult döndür."""
        ...

    # ------------------------------------------------------------------ #
    # Ortak yardımcılar (alt sınıflar override edebilir)
    # ------------------------------------------------------------------ #

    def to_findings(self, result: ToolResult) -> List[Dict[str, Any]]:
        """ToolResult'u WebSecure native finding listesine dönüştür."""
        return [f.to_dict() for f in result.findings]

    def correlate(
        self,
        result: ToolResult,
        existing_fingerprints: FrozenSet[str],
    ) -> ToolResult:
        """
        Mevcut bulgularla çakışanları filtrele (deduplication).

        Parametreler
        ------------
        result               : Araç çalışma sonucu
        existing_fingerprints: Zaten bilinen parmak izleri

        Döndürür
        --------
        Yeni bulgular içeren ToolResult (kopyası).
        """
        new_findings = [
            f for f in result.findings
            if f.fingerprint() not in existing_fingerprints
        ]
        dedup_count = len(result.findings) - len(new_findings)
        if dedup_count:
            logger.debug(
                f"[{self.tool_name}] {dedup_count} tekrar bulgu çıkarıldı "
                f"({len(new_findings)} yeni kaldı)"
            )
        result.findings = new_findings
        return result

    def version(self) -> Optional[str]:
        """Araç versiyonunu döndür (opsiyonel)."""
        return None

    # ------------------------------------------------------------------ #
    # Binary keşif
    # ------------------------------------------------------------------ #

    def _resolve_binary(self, name: str) -> None:
        """Binary'yi önce tools/ dizininde, sonra PATH'ta ara."""
        # 0. Tam yol verilmişse (ör. tools/httpx/httpx.exe) — direkt kullan
        p = Path(name)
        if p.is_absolute() and p.exists():
            self._binary_path = str(p)
            return

        # 1. Proje tools/ dizini — öncelikli (PATH'ta Python CLI'ları olabilir)
        root = Path(__file__).resolve().parent.parent.parent
        candidates = [
            root / "tools" / name / f"{name}.exe",
            root / "tools" / name / name,
            root / "tools" / f"{name}.exe",
            root / "tools" / name,
        ]
        for c in candidates:
            if c.exists():
                self._binary_path = str(c)
                return

        # 2. PATH (son çare)
        found = shutil.which(name)
        if found:
            self._binary_path = found
            return

        logger.debug(f"[{name}] Binary bulunamadı (tools/ ve PATH tarandı)")

    @property
    def binary(self) -> str:
        """Çözümlenmiş binary yolu (yoksa orijinal adı döner)."""
        return self._binary_path or self._binary_name

    def __repr__(self) -> str:
        avail = "[OK]" if self.is_available() else "[FAIL]"
        return f"<{self.__class__.__name__} [{avail}] binary={self.binary!r}>"


# ---------------------------------------------------------------------------
# FindingCorrelator — araçlar arası tekilleştirme
# ---------------------------------------------------------------------------

class FindingCorrelator:
    """
    Birden fazla araçtan gelen bulguları tekilleştirir.

    Kullanım
    --------
    ```python
    correlator = FindingCorrelator()
    nuclei_result = correlator.add(nuclei_result)   # yeni bulgular işaretlendi
    dalfox_result = correlator.add(dalfox_result)   # çakışanlar çıkarıldı
    all_new = correlator.all_findings()
    ```
    """

    def __init__(self) -> None:
        self._seen: Set[str] = set()
        self._all_findings: List[ToolFinding] = []

    def add(self, result: ToolResult, tool: ToolIntegration) -> ToolResult:
        """Sonucu ekle, mevcut bulgularla çakışanları filtrele."""
        result = tool.correlate(result, frozenset(self._seen))
        for f in result.findings:
            fp = f.fingerprint()
            self._seen.add(fp)
            self._all_findings.append(f)
        return result

    def seed(self, fingerprints: Set[str]) -> None:
        """Mevcut WebSecure bulgu parmak izlerini ekle (başlangıç noktası)."""
        self._seen.update(fingerprints)

    def all_findings(self) -> List[ToolFinding]:
        return list(self._all_findings)

    def seen_count(self) -> int:
        return len(self._seen)


# ---------------------------------------------------------------------------
# ToolRegistry — Singleton araç kayıt sistemi
# ---------------------------------------------------------------------------

class ToolRegistry:
    """
    Mevcut tüm araç entegrasyonlarını yöneten singleton kayıt.

    Kullanım
    --------
    ```python
    registry = ToolRegistry.instance()
    registry.register(NucleiIntegration())
    available = registry.available_tools()
    result = registry.run("nuclei", target="https://example.com")
    ```
    """

    _instance: Optional["ToolRegistry"] = None

    def __init__(self) -> None:
        self._tools: Dict[str, ToolIntegration] = {}

    @classmethod
    def instance(cls) -> "ToolRegistry":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def register(self, tool: ToolIntegration) -> None:
        self._tools[tool.tool_name] = tool
        logger.debug(f"[ToolRegistry] Kayıtlı: {tool.tool_name} (mevcut={tool.is_available()})")

    def get(self, name: str) -> Optional[ToolIntegration]:
        return self._tools.get(name)

    def available_tools(self) -> List[str]:
        return [n for n, t in self._tools.items() if t.is_available()]

    def all_tools(self) -> List[str]:
        return list(self._tools.keys())

    def run(self, name: str, target: str, **kwargs) -> Optional[ToolResult]:
        tool = self._tools.get(name)
        if tool is None:
            logger.warning(f"[ToolRegistry] Araç bulunamadı: {name!r}")
            return None
        if not tool.is_available():
            logger.info(f"[ToolRegistry] Araç mevcut değil (atlanıyor): {name}")
            return ToolResult(
                tool=name, target=target, status=ToolStatus.NOT_FOUND
            )
        return tool.run(target, **kwargs)

    def run_all(
        self,
        target: str,
        tools: Optional[List[str]] = None,
        correlator: Optional[FindingCorrelator] = None,
        **kwargs,
    ) -> Dict[str, ToolResult]:
        """
        Tüm (veya seçili) araçları çalıştır.

        Parametreler
        ------------
        target     : Hedef URL
        tools      : None -> tüm mevcut araçlar
        correlator : Varsa tekilleştirme yapılır
        """
        names = tools or self.available_tools()
        results: Dict[str, ToolResult] = {}

        for name in names:
            tool = self._tools.get(name)
            if tool is None or not tool.is_available():
                continue
            try:
                result = tool.run(target, **kwargs)
                if correlator is not None:
                    result = correlator.add(result, tool)
                results[name] = result
                logger.info(
                    f"[ToolRegistry] {name}: {result.status.value}  "
                    f"{result.finding_count} bulgu  "
                    f"{result.duration_s:.1f}s"
                )
            except Exception as exc:
                logger.error(f"[ToolRegistry] {name} hata: {exc!r}", exc_info=True)

        return results


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

__all__ = [
    "ToolSeverity",
    "ToolStatus",
    "ToolFinding",
    "ToolResult",
    "ToolIntegration",
    "FindingCorrelator",
    "ToolRegistry",
]
