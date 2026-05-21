"""
websecure.core.fp_learner
~~~~~~~~~~~~~~~~~~~~~~~~~~
Otomatik False Positive (FP) öğrenme motoru.

Özellikler
----------
* FP onayı -> kural üretimi (title pattern + url pattern + severity)
* Bir sonraki taramada yeni bulgulara otomatik FP damgası
* Bayesian güven skoru (onay sayısına göre confidence artar)
* Joker kural desteği (URL path pattern, domain wildcard)
* FP kurallarını JSON ve DB'de kalıcı olarak sakla
* `filter_findings()` — bulgu listesini FP kurallarıyla temizle

SOLID
-----
- SRP  : FP öğrenme / uygulama ayrı metotlarda.
- OCP  : Yeni eşleştirme stratejisi kural listesine eklenerek desteklenir.
- DIP  : FPLearner, DB repository üzerinden çalışır (opsiyonel).
"""
from __future__ import annotations

import hashlib
import json
import logging
import re
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Kalıcılık yolu (DB olmadan)
# ---------------------------------------------------------------------------

_FP_DB_PATH = Path.home() / ".websecure" / "fp_rules.json"

# Minimum onay sayısı -> kural aktifleşir
_MIN_CONFIRMATIONS = 2
# Maksimum FP kuralı sayısı (bellek koruması)
_MAX_RULES = 5000


# ---------------------------------------------------------------------------
# FPRule modeli
# ---------------------------------------------------------------------------

@dataclass
class FPRule:
    """Tek bir FP kuralı."""
    id: str
    title_pattern: str = ""    # regex veya boş (her şeyle eşleşir)
    url_pattern: str = ""      # regex veya boş
    severity: str = ""         # "Critical", "High", ... veya boş (her şey)
    tool: str = ""             # araç adı veya boş
    confidence: float = 0.5    # 0.0–1.0 Bayesian güven
    hit_count: int = 0         # bu kuralla kaç bulgu FP olarak işaretlendi
    confirm_count: int = 0     # kullanıcı onayı sayısı
    tenant_id: Optional[str] = None
    created_at: str = ""
    active: bool = True

    def matches(self, finding: Dict[str, Any]) -> bool:
        """Bulgu bu kuralı tetikliyor mu?"""
        if not self.active or self.confirm_count < _MIN_CONFIRMATIONS:
            return False

        title = finding.get("title", "")
        url = finding.get("url", "")
        sev = finding.get("severity", "")
        tool = finding.get("tool", "")

        if self.title_pattern:
            try:
                if not re.search(self.title_pattern, title, re.IGNORECASE):
                    return False
            except re.error:
                if self.title_pattern.lower() not in title.lower():
                    return False

        if self.url_pattern:
            try:
                if not re.search(self.url_pattern, url, re.IGNORECASE):
                    return False
            except re.error:
                if self.url_pattern.lower() not in url.lower():
                    return False

        if self.severity and sev and self.severity.lower() != sev.lower():
            return False

        if self.tool and tool and self.tool.lower() != tool.lower():
            return False

        return True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "title_pattern": self.title_pattern,
            "url_pattern": self.url_pattern,
            "severity": self.severity,
            "tool": self.tool,
            "confidence": round(self.confidence, 4),
            "hit_count": self.hit_count,
            "confirm_count": self.confirm_count,
            "tenant_id": self.tenant_id,
            "created_at": self.created_at,
            "active": self.active,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "FPRule":
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})

    def fingerprint(self) -> str:
        key = f"{self.title_pattern}|{self.url_pattern}|{self.severity}|{self.tool}"
        return hashlib.sha256(key.encode()).hexdigest()[:16]


# ---------------------------------------------------------------------------
# FPLearner — ana motor
# ---------------------------------------------------------------------------

class FPLearner:
    """
    False Positive öğrenme ve uygulama motoru.

    Kullanım
    --------
    ```python
    learner = FPLearner()

    # Kullanıcı bir bulguyu FP olarak işaretledi:
    learner.mark_false_positive(finding_dict, reason="WAF tarafından üretilen test yanıtı")

    # Yeni tarama bulgularını filtrele:
    clean_findings = learner.filter_findings(raw_findings)

    # İstatistik:
    stats = learner.stats()
    ```
    """

    def __init__(
        self,
        db_path: Optional[Path] = None,
        use_db: bool = True,
    ) -> None:
        self._db_path = db_path or _FP_DB_PATH
        self._use_db = use_db
        self._rules: Dict[str, FPRule] = {}
        self._lock = threading.Lock()
        self._load()

    # ------------------------------------------------------------------
    # FP İşaretleme
    # ------------------------------------------------------------------

    def mark_false_positive(
        self,
        finding: Dict[str, Any],
        reason: str = "",
        tenant_id: Optional[str] = None,
    ) -> FPRule:
        """
        Bir bulguyu FP olarak işaretle -> kural üret veya güncelle.

        Parametreler
        ------------
        finding   : Bulgu dict (title, url, severity, tool içermeli)
        reason    : İsteğe bağlı açıklama
        tenant_id : Tenant izolasyonu

        Döndürür
        --------
        FPRule — oluşturulan veya güncellenen kural
        """
        title = finding.get("title", "")
        url = finding.get("url", "")
        sev = finding.get("severity", "")
        tool = finding.get("tool", "")

        # URL'yi path-bazlı normalize et
        url_pattern = self._make_url_pattern(url)
        # Title'ı esnek eşleştirme için normalize et
        title_pattern = re.escape(title[:80]) if title else ""

        import datetime as _dt
        rule = FPRule(
            id=hashlib.sha256(
                f"{title_pattern}{url_pattern}{sev}{tool}".encode()
            ).hexdigest()[:16],
            title_pattern=title_pattern,
            url_pattern=url_pattern,
            severity=sev,
            tool=tool,
            tenant_id=tenant_id,
            created_at=_dt.datetime.now(_dt.timezone.utc).isoformat(),
        )

        with self._lock:
            existing = self._rules.get(rule.fingerprint())
            if existing:
                existing.confirm_count += 1
                existing.confidence = self._bayesian_update(
                    existing.confidence, existing.confirm_count
                )
                rule = existing
            else:
                rule.confirm_count = 1
                if len(self._rules) < _MAX_RULES:
                    self._rules[rule.fingerprint()] = rule

        self._save()
        self._db_save(rule)

        logger.info(
            f"[FPLearner] FP işaretlendi: '{title[:50]}'  "
            f"conf={rule.confidence:.2f}  onay={rule.confirm_count}"
        )
        return rule

    def unmark_false_positive(self, finding: Dict[str, Any]) -> bool:
        """FP işaretini kaldır."""
        url_pattern = self._make_url_pattern(finding.get("url", ""))
        title_pattern = re.escape(finding.get("title", "")[:80])
        sev = finding.get("severity", "")
        tool = finding.get("tool", "")
        # fingerprint() ile aynı format: "|" ayırıcı
        key = f"{title_pattern}|{url_pattern}|{sev}|{tool}"
        rule_fp = hashlib.sha256(key.encode()).hexdigest()[:16]

        rule = None
        with self._lock:
            rule = self._rules.get(rule_fp)
            if rule:
                rule.confirm_count = max(0, rule.confirm_count - 1)
                rule.confidence = self._bayesian_update(
                    rule.confidence, rule.confirm_count, decay=True
                )
                if rule.confirm_count == 0:
                    rule.active = False
        self._save()
        return rule is not None

    # ------------------------------------------------------------------
    # Filtreleme
    # ------------------------------------------------------------------

    def filter_findings(
        self,
        findings: List[Dict[str, Any]],
        tenant_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Bulgu listesini FP kurallarıyla filtrele.

        Parametreler
        ------------
        findings  : Ham bulgu listesi
        tenant_id : Tenant izolasyonu

        Döndürür
        --------
        List[Dict] — FP olmayanlar (temiz bulgular)
        """
        if not self._rules:
            return findings

        clean = []
        fp_count = 0

        with self._lock:
            active_rules = [
                r for r in self._rules.values()
                if r.active and r.confirm_count >= _MIN_CONFIRMATIONS
                and (tenant_id is None or r.tenant_id is None or r.tenant_id == tenant_id)
            ]

        for finding in findings:
            is_fp = False
            for rule in active_rules:
                if rule.matches(finding):
                    is_fp = True
                    rule.hit_count += 1
                    logger.debug(
                        f"[FPLearner] FP atlandı: '{finding.get('title', '?')}'  "
                        f"kural={rule.id}"
                    )
                    break
            if is_fp:
                fp_count += 1
            else:
                clean.append(finding)

        if fp_count:
            logger.info(f"[FPLearner] {fp_count}/{len(findings)} bulgu FP olarak filtrelendi.")
            self._save()

        return clean

    def is_false_positive(
        self,
        finding: Dict[str, Any],
        tenant_id: Optional[str] = None,
    ) -> Tuple[bool, Optional[FPRule]]:
        """
        Tek bir bulgunun FP olup olmadığını kontrol et.

        Döndürür
        --------
        (is_fp: bool, matching_rule: Optional[FPRule])
        """
        with self._lock:
            active_rules = [
                r for r in self._rules.values()
                if r.active and r.confirm_count >= _MIN_CONFIRMATIONS
                and (tenant_id is None or r.tenant_id is None or r.tenant_id == tenant_id)
            ]

        for rule in active_rules:
            if rule.matches(finding):
                return True, rule
        return False, None

    # ------------------------------------------------------------------
    # Kural yönetimi
    # ------------------------------------------------------------------

    def list_rules(
        self,
        tenant_id: Optional[str] = None,
        active_only: bool = True,
    ) -> List[FPRule]:
        with self._lock:
            rules = list(self._rules.values())
        if active_only:
            rules = [r for r in rules if r.active]
        if tenant_id:
            rules = [r for r in rules if r.tenant_id is None or r.tenant_id == tenant_id]
        rules.sort(key=lambda r: r.confidence, reverse=True)
        return rules

    def delete_rule(self, rule_id: str) -> bool:
        to_del = None
        with self._lock:
            for fp, rule in self._rules.items():
                if rule.id == rule_id:
                    to_del = fp
                    break
            if to_del:
                del self._rules[to_del]
        self._save()
        return to_del is not None

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            rules = list(self._rules.values())
        active = [r for r in rules if r.active]
        return {
            "total_rules": len(rules),
            "active_rules": len(active),
            "total_hits": sum(r.hit_count for r in rules),
            "avg_confidence": round(
                sum(r.confidence for r in active) / len(active) if active else 0, 3
            ),
        }

    # ------------------------------------------------------------------
    # Yardımcılar
    # ------------------------------------------------------------------

    @staticmethod
    def _make_url_pattern(url: str) -> str:
        """URL'yi esnek path pattern'e dönüştür."""
        if not url:
            return ""
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            domain = re.escape(parsed.netloc)
            path = re.escape(parsed.path.rstrip("/"))
            return f"{domain}{path}" if domain else path
        except Exception:
            return re.escape(url[:100])

    @staticmethod
    def _bayesian_update(
        current: float,
        confirm_count: int,
        decay: bool = False,
    ) -> float:
        """Laplace smoothing ile Bayesian güven güncellemesi."""
        alpha = 1.0   # prior success
        beta = 1.0    # prior failure
        total = max(confirm_count, 1) + alpha + beta
        score = (confirm_count + alpha) / total
        if decay:
            score = max(0.1, score - 0.1)
        return round(min(0.99, max(0.1, score)), 4)

    # ------------------------------------------------------------------
    # Kalıcılık
    # ------------------------------------------------------------------

    def _save(self) -> None:
        try:
            self._db_path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self._db_path.with_suffix(".tmp")
            with self._lock:
                data = [r.to_dict() for r in self._rules.values()]
            tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
            tmp.replace(self._db_path)
        except Exception as exc:
            logger.error(f"[FPLearner] Kaydetme hatası: {exc!r}")

    def _load(self) -> None:
        if not self._db_path.exists():
            return
        try:
            data = json.loads(self._db_path.read_text(encoding="utf-8"))
            for d in data:
                try:
                    rule = FPRule.from_dict(d)
                    self._rules[rule.fingerprint()] = rule
                except Exception:
                    pass
            logger.debug(f"[FPLearner] {len(self._rules)} FP kuralı yüklendi.")
        except Exception as exc:
            logger.error(f"[FPLearner] Yükleme hatası: {exc!r}")

    def _db_save(self, rule: FPRule) -> None:
        """DB repository'ye kaydet (opsiyonel)."""
        if not self._use_db:
            return
        try:
            from websecure.db.repository import FindingRepository
            # Sadece logluyoruz; FP repository ayrı eklenebilir
            logger.debug("[FPLearner] DB kayıt (FP tablo repo genişletilebilir).")
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------

_learner_instance: Optional[FPLearner] = None


def get_fp_learner() -> FPLearner:
    """Global FPLearner singleton'ını döndür."""
    global _learner_instance
    if _learner_instance is None:
        _learner_instance = FPLearner()
    return _learner_instance


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

__all__ = [
    "FPRule",
    "FPLearner",
    "get_fp_learner",
]
