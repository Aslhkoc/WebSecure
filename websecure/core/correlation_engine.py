"""
websecure.core.correlation_engine
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Çapraz tarama korelasyon motoru.

Özellikler
----------
* Fingerprint eşleşmesi (aynı bulgu farklı taramalarda)
* Escalation tespiti (aynı URL, daha yüksek severity)
* Zincir tespiti (SQLi+IDOR -> Veri Sızıntısı, XSS+CSRF vb.)
* Persistence tespiti (n tarama boyunca düzelmemiş bulgu)
* Strategy Pattern — yeni korelasyon stratejisi eklemek OCP uyumlu

SOLID
-----
- SRP  : Her strateji tek tür korelasyon yapar.
- OCP  : CorrelationEngine yeni strateji eklendiğinde değişmez.
- LSP  : Tüm stratejiler CorrelationStrategy sözleşmesini uygular.
- DIP  : Motor somut strateji sınıflarına değil, soyutlamaya bağlıdır.
"""
from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Severity sırası
# ---------------------------------------------------------------------------

_SEV_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# ---------------------------------------------------------------------------
# Tehlikeli zincir çiftleri
# ---------------------------------------------------------------------------

_CHAIN_PAIRS: List[Tuple[Set[str], Set[str], str]] = [
    # (set1_keywords, set2_keywords, chain_name)
    ({"sql injection", "sqli"},     {"idor", "broken access"},  "SQLi -> IDOR -> Data Leak"),
    ({"xss", "cross-site script"},  {"csrf"},                    "XSS -> CSRF"),
    ({"lfi", "local file"},         {"rce", "remote code"},      "LFI -> RCE"),
    ({"ssrf"},                      {"cloud", "metadata"},       "SSRF -> Cloud Metadata"),
    ({"file upload", "unrestrict"}, {"rce", "remote code"},      "Upload -> RCE"),
    ({"auth bypass", "broken auth"},{"sql injection"},           "Auth Bypass -> SQLi"),
    ({"ssti", "template inject"},   {"rce", "remote code"},      "SSTI -> RCE"),
    ({"open redirect"},             {"xss", "cross-site script"},"Open Redirect -> XSS"),
]


# ---------------------------------------------------------------------------
# CorrelationMatch modeli
# ---------------------------------------------------------------------------

@dataclass
class CorrelationMatch:
    """Tek bir korelasyon eşleşmesi."""
    type: str                           # repeat / escalation / chain / persistence
    confidence: float                   # 0.0–1.0
    scan1_id: str
    scan2_id: str
    finding1_id: str
    finding2_id: str
    description: str = ""
    chain_name: str = ""
    extra: Dict[str, Any] = field(default_factory=dict)

    @property
    def is_escalation(self) -> bool:
        return self.type == "escalation"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.type,
            "confidence": round(self.confidence, 3),
            "scan1_id": self.scan1_id,
            "scan2_id": self.scan2_id,
            "finding1_id": self.finding1_id,
            "finding2_id": self.finding2_id,
            "description": self.description,
            "chain_name": self.chain_name,
        }


# ---------------------------------------------------------------------------
# Strateji soyutlaması
# ---------------------------------------------------------------------------

class CorrelationStrategy(ABC):
    """Korelasyon stratejisi sözleşmesi."""

    @abstractmethod
    def correlate(
        self,
        findings1: List[Dict[str, Any]],
        findings2: List[Dict[str, Any]],
        scan1_id: str,
        scan2_id: str,
    ) -> List[CorrelationMatch]:
        """İki tarama bulgusunu karşılaştır, eşleşmeleri döndür."""


# ---------------------------------------------------------------------------
# Strateji 1 — Fingerprint korelasyonu
# ---------------------------------------------------------------------------

class FingerprintCorrelation(CorrelationStrategy):
    """Aynı SHA256 fingerprint -> aynı bulgu, tekrar eden sorun."""

    def correlate(
        self,
        findings1: List[Dict[str, Any]],
        findings2: List[Dict[str, Any]],
        scan1_id: str,
        scan2_id: str,
    ) -> List[CorrelationMatch]:
        fp_map: Dict[str, Dict] = {
            f.get("fingerprint", f.get("id", "")): f
            for f in findings1
            if f.get("fingerprint") or f.get("id")
        }

        matches = []
        for f2 in findings2:
            fp = f2.get("fingerprint", f2.get("id", ""))
            if fp and fp in fp_map:
                f1 = fp_map[fp]
                matches.append(CorrelationMatch(
                    type="repeat",
                    confidence=0.95,
                    scan1_id=scan1_id,
                    scan2_id=scan2_id,
                    finding1_id=f1.get("id", ""),
                    finding2_id=f2.get("id", ""),
                    description=(
                        f"Tekrar eden bulgu: '{f2.get('title', '?')}' "
                        f"({f2.get('url', '')})"
                    ),
                ))
        return matches


# ---------------------------------------------------------------------------
# Strateji 2 — Escalation korelasyonu
# ---------------------------------------------------------------------------

class EscalationCorrelation(CorrelationStrategy):
    """Aynı URL'de daha yüksek severity -> risk tırmandı."""

    def correlate(
        self,
        findings1: List[Dict[str, Any]],
        findings2: List[Dict[str, Any]],
        scan1_id: str,
        scan2_id: str,
    ) -> List[CorrelationMatch]:
        # URL -> (finding, severity_order)
        url_map: Dict[str, Tuple[Dict, int]] = {}
        for f in findings1:
            url = f.get("url", "")
            sev = _SEV_ORDER.get(f.get("severity", "info").lower(), 0)
            if url and (url not in url_map or sev > url_map[url][1]):
                url_map[url] = (f, sev)

        matches = []
        for f2 in findings2:
            url = f2.get("url", "")
            sev2 = _SEV_ORDER.get(f2.get("severity", "info").lower(), 0)
            if url in url_map:
                f1, sev1 = url_map[url]
                if sev2 > sev1:
                    diff = sev2 - sev1
                    confidence = min(0.9, 0.5 + diff * 0.2)
                    matches.append(CorrelationMatch(
                        type="escalation",
                        confidence=confidence,
                        scan1_id=scan1_id,
                        scan2_id=scan2_id,
                        finding1_id=f1.get("id", ""),
                        finding2_id=f2.get("id", ""),
                        description=(
                            f"Risk tırmandı: {f1.get('severity')} -> {f2.get('severity')} "
                            f"({url})"
                        ),
                    ))
        return matches


# ---------------------------------------------------------------------------
# Strateji 3 — Zincir korelasyonu
# ---------------------------------------------------------------------------

class ChainCorrelation(CorrelationStrategy):
    """Tehlikeli bulgu kombinasyonu -> exploit zinciri."""

    def correlate(
        self,
        findings1: List[Dict[str, Any]],
        findings2: List[Dict[str, Any]],
        scan1_id: str,
        scan2_id: str,
    ) -> List[CorrelationMatch]:
        all_findings = list(findings1) + list(findings2)
        if len(all_findings) < 2:
            return []

        # Tüm başlıkları küçük harfe indir
        titled: List[Tuple[str, Dict]] = [
            (f.get("title", "").lower(), f) for f in all_findings
        ]

        matches = []
        for set1_kws, set2_kws, chain_name in _CHAIN_PAIRS:
            group1 = [
                f for title, f in titled
                if any(kw in title for kw in set1_kws)
            ]
            group2 = [
                f for title, f in titled
                if any(kw in title for kw in set2_kws)
            ]
            if group1 and group2:
                # İlk çifti al
                f1, f2 = group1[0], group2[0]
                # Aynı bulgu olmasın
                if f1.get("id") == f2.get("id"):
                    continue
                # Hangi taramada olduğunu belirle
                s1_id = f1.get("scan_id", scan1_id)
                s2_id = f2.get("scan_id", scan2_id)
                matches.append(CorrelationMatch(
                    type="chain",
                    confidence=0.75,
                    scan1_id=s1_id,
                    scan2_id=s2_id,
                    finding1_id=f1.get("id", ""),
                    finding2_id=f2.get("id", ""),
                    description=f"Exploit zinciri tespit edildi: {chain_name}",
                    chain_name=chain_name,
                ))
        return matches


# ---------------------------------------------------------------------------
# Strateji 4 — Persistence korelasyonu
# ---------------------------------------------------------------------------

class PersistenceCorrelation(CorrelationStrategy):
    """Birden fazla taramada düzelmeyen bulgu -> kalıcı sorun."""

    def correlate(
        self,
        findings1: List[Dict[str, Any]],
        findings2: List[Dict[str, Any]],
        scan1_id: str,
        scan2_id: str,
    ) -> List[CorrelationMatch]:
        # Başlık + URL kombinasyonu ile eşleştir
        key1: Dict[str, Dict] = {}
        for f in findings1:
            key = f"{f.get('title', '').lower()}|{f.get('url', '')}"
            key1[key] = f

        matches = []
        for f2 in findings2:
            key = f"{f2.get('title', '').lower()}|{f2.get('url', '')}"
            if key in key1:
                f1 = key1[key]
                matches.append(CorrelationMatch(
                    type="persistence",
                    confidence=0.80,
                    scan1_id=scan1_id,
                    scan2_id=scan2_id,
                    finding1_id=f1.get("id", ""),
                    finding2_id=f2.get("id", ""),
                    description=(
                        f"Kalıcı sorun: '{f2.get('title', '?')}' hâlâ düzeltilmedi "
                        f"({f2.get('url', '')})"
                    ),
                ))
        return matches


# ---------------------------------------------------------------------------
# CorrelationEngine — ana motor
# ---------------------------------------------------------------------------

class CorrelationEngine:
    """
    Çapraz tarama korelasyon motoru.

    Kullanım
    --------
    ```python
    engine = CorrelationEngine()
    matches = engine.correlate(findings1, findings2, "scan1", "scan2")
    report  = engine.report(matches)
    ```
    """

    def __init__(
        self,
        strategies: Optional[List[CorrelationStrategy]] = None,
        db=None,
    ) -> None:
        self._strategies = strategies or [
            FingerprintCorrelation(),
            EscalationCorrelation(),
            ChainCorrelation(),
            PersistenceCorrelation(),
        ]
        self._db = db  # opsiyonel DB erişimi

    def correlate(
        self,
        findings1: List[Dict[str, Any]],
        findings2: List[Dict[str, Any]],
        scan1_id: str,
        scan2_id: str,
        min_confidence: float = 0.5,
    ) -> List[CorrelationMatch]:
        """
        İki tarama bulgusunu tüm stratejilerle karşılaştır.

        Parametreler
        ------------
        findings1      : Birinci taramanın bulguları (dict list)
        findings2      : İkinci taramanın bulguları (dict list)
        scan1_id       : Birinci tarama ID
        scan2_id       : İkinci tarama ID
        min_confidence : Minimum güven skoru filtresi

        Döndürür
        --------
        List[CorrelationMatch] — confidence'a göre sıralı
        """
        all_matches: List[CorrelationMatch] = []

        for strategy in self._strategies:
            try:
                matches = strategy.correlate(findings1, findings2, scan1_id, scan2_id)
                all_matches.extend(matches)
            except Exception as exc:
                logger.warning(
                    f"[Correlation] {strategy.__class__.__name__} hatası: {exc}"
                )

        # Filtrele ve sırala
        result = [m for m in all_matches if m.confidence >= min_confidence]
        result.sort(key=lambda m: m.confidence, reverse=True)

        logger.info(
            f"[Correlation] {scan1_id} ↔ {scan2_id}: "
            f"{len(result)} eşleşme ({len(findings1)} + {len(findings2)} bulgu)"
        )
        return result

    def correlate_from_db(
        self,
        scan1_id: str,
        scan2_id: str,
        min_confidence: float = 0.5,
    ) -> List[CorrelationMatch]:
        """DB'den bulguları çekip korelasyon yap."""
        if not self._db:
            logger.warning("[Correlation] DB bağlantısı yok, boş döndürülüyor.")
            return []

        try:
            from websecure.db.repository import FindingRepository
            repo = FindingRepository(self._db)
            findings1 = [self._finding_to_dict(f) for f in repo.list_by_scan(scan1_id)]
            findings2 = [self._finding_to_dict(f) for f in repo.list_by_scan(scan2_id)]
            return self.correlate(findings1, findings2, scan1_id, scan2_id, min_confidence)
        except Exception as exc:
            logger.error(f"[Correlation] DB korelasyon hatası: {exc}")
            return []

    def report(self, matches: List[CorrelationMatch]) -> Dict[str, Any]:
        """Korelasyon özet raporu."""
        by_type: Dict[str, List[Dict]] = {}
        escalations = 0
        chains: List[str] = []

        for m in matches:
            by_type.setdefault(m.type, []).append(m.to_dict())
            if m.is_escalation:
                escalations += 1
            if m.chain_name:
                chains.append(m.chain_name)

        return {
            "total": len(matches),
            "by_type": {k: len(v) for k, v in by_type.items()},
            "escalations": escalations,
            "chains": list(set(chains)),
            "avg_confidence": (
                round(sum(m.confidence for m in matches) / len(matches), 3)
                if matches else 0
            ),
            "matches": [m.to_dict() for m in matches],
        }

    @staticmethod
    def _finding_to_dict(finding) -> Dict[str, Any]:
        """Finding dataclass -> dict."""
        try:
            from dataclasses import asdict
            return asdict(finding)
        except Exception:
            return vars(finding)


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------

_engine_instance: Optional[CorrelationEngine] = None


def get_correlation_engine(db=None) -> CorrelationEngine:
    """Global CorrelationEngine singleton'ını döndür."""
    global _engine_instance
    if _engine_instance is None:
        _engine_instance = CorrelationEngine(db=db)
    return _engine_instance


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

__all__ = [
    "CorrelationMatch",
    "CorrelationStrategy",
    "FingerprintCorrelation",
    "EscalationCorrelation",
    "ChainCorrelation",
    "PersistenceCorrelation",
    "CorrelationEngine",
    "get_correlation_engine",
]
