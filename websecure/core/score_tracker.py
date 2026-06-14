"""
websecure.core.score_tracker
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Güvenlik skoru trendi hesaplama ve izleme motoru.

Özellikler
----------
* CVSS-ağırlıklı 0–100 güvenlik skoru
* Tarama başına skor kaydı (DB veya JSON)
* Trend analizi: yükseliyor / düşüyor / stabil
* Delta: son iki tarama arasındaki skor farkı
* Hedef bazlı veya proje bazlı trend görünümü
* Risk seviyesi etiketleme (Critical / High / Medium / Low / Minimal)

SOLID
-----
- SRP  : ScoreCalculator sadece hesaplar; ScoreTracker sadece kaydeder/sorgular.
- OCP  : Yeni ağırlık şeması ScoreWeights override ile desteklenir.
- DIP  : ScoreTracker, DB repository'ye interface üzerinden bağlanır.
"""
from __future__ import annotations

import datetime as _dt
import json
import logging
import math
import threading
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# Skor hesaplama sabitleri
_BASE_SCORE = 100.0
_MAX_PENALTY = 100.0  # skor hiçbir zaman negatif olamaz


# ---------------------------------------------------------------------------
# ScoreWeights — özelleştirilebilir ağırlıklar
# ---------------------------------------------------------------------------

@dataclass
class ScoreWeights:
    """
    Severity başına ceza ağırlıkları (CVSS 3.1 uyumlu kalibre edilmiş).

    Kalibrasyon hedefleri (logaritmik sıkıştırma sonrası):
      1 Critical → ~62/100 (Medium risk)
      2 Critical → ~30/100 (High risk)
      1 High     → ~83/100 (Low risk)
      3 High     → ~65/100 (Medium risk)
      1 Medium   → ~93/100 (Minimal risk)
     10 Medium   → ~55/100 (Medium risk)
    """
    critical: float = 50.0   # CVSS 9.0-10.0 bandıyla orantılı
    high: float = 20.0       # CVSS 7.0-8.9 bandıyla orantılı
    medium: float = 6.0      # CVSS 4.0-6.9 bandıyla orantılı
    low: float = 1.0
    info: float = 0.0

    def get(self, severity: str) -> float:
        sev = severity.strip().lower()
        return getattr(self, sev, 0.0)


# ---------------------------------------------------------------------------
# ScoreSnapshot — tek tarama skoru
# ---------------------------------------------------------------------------

@dataclass
class ScoreSnapshot:
    """Tek tarama için skor anlık görüntüsü."""
    scan_id: str
    target: str
    score: float                         # 0–100
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0
    recorded_at: str = ""
    project_id: Optional[str] = None
    tenant_id: Optional[str] = None

    @property
    def risk_level(self) -> str:
        """Skor -> risk seviyesi etiketi."""
        if self.score >= 90:
            return "Minimal"
        if self.score >= 70:
            return "Low"
        if self.score >= 50:
            return "Medium"
        if self.score >= 25:
            return "High"
        return "Critical"

    @property
    def total_findings(self) -> int:
        return self.critical + self.high + self.medium + self.low + self.info

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "target": self.target,
            "score": round(self.score, 2),
            "risk_level": self.risk_level,
            "counts": {
                "critical": self.critical,
                "high": self.high,
                "medium": self.medium,
                "low": self.low,
                "info": self.info,
                "total": self.total_findings,
            },
            "recorded_at": self.recorded_at,
            "project_id": self.project_id,
            "tenant_id": self.tenant_id,
        }


# ---------------------------------------------------------------------------
# TrendResult — trend analizi sonucu
# ---------------------------------------------------------------------------

@dataclass
class TrendResult:
    """Trend analizi özeti."""
    target: str
    snapshots: List[ScoreSnapshot]
    direction: str = "stable"   # "improving" / "degrading" / "stable"
    delta: float = 0.0          # son - ilk skor
    min_score: float = 100.0
    max_score: float = 100.0
    avg_score: float = 100.0

    @property
    def is_improving(self) -> bool:
        return self.direction == "improving"

    @property
    def is_degrading(self) -> bool:
        return self.direction == "degrading"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "direction": self.direction,
            "delta": round(self.delta, 2),
            "min_score": round(self.min_score, 2),
            "max_score": round(self.max_score, 2),
            "avg_score": round(self.avg_score, 2),
            "latest_score": round(self.snapshots[-1].score, 2) if self.snapshots else None,
            "latest_risk": self.snapshots[-1].risk_level if self.snapshots else "Unknown",
            "scan_count": len(self.snapshots),
            "snapshots": [s.to_dict() for s in self.snapshots],
        }


# ---------------------------------------------------------------------------
# ScoreCalculator
# ---------------------------------------------------------------------------

class ScoreCalculator:
    """
    Bulgu listesinden güvenlik skoru hesaplar.

    Kullanım
    --------
    ```python
    calc = ScoreCalculator()
    snapshot = calc.calculate(scan_id, target, findings)
    print(snapshot.score, snapshot.risk_level)
    ```
    """

    def __init__(self, weights: Optional[ScoreWeights] = None) -> None:
        self._weights = weights or ScoreWeights()

    def calculate(
        self,
        scan_id: str,
        target: str,
        findings: List[Dict[str, Any]],
        project_id: Optional[str] = None,
        tenant_id: Optional[str] = None,
    ) -> ScoreSnapshot:
        """
        Bulgu listesinden puan üret.

        Formül
        ------
        penalty = sum(weight[sev] * count[sev])
        score   = max(0, BASE_SCORE - min(penalty, MAX_PENALTY))
        """
        counts: Dict[str, int] = {
            "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0
        }

        for finding in findings:
            sev = finding.get("severity", "info").strip().lower()
            if sev in counts:
                counts[sev] += 1
            else:
                counts["info"] += 1

        penalty = sum(
            self._weights.get(sev) * cnt
            for sev, cnt in counts.items()
        )
        # Boundary fix: baskılama çarpanı (1-0.3*log10(1+p/10)) MONOTONİK DEĞİL —
        # ~raw>21000'de dibe vurup negatife döner → min(penalty,MAX) negatif/küçük
        # kalıp score'u 100'ün ÜSTÜNE veya ters yöne (çok-bulgu=yüksek skor) çıkarırdı.
        # Ham penalty'yi log'dan ÖNCE doygunluk bölgesine sınırla: MAX*3=300'de
        # compressed≈166>MAX → skor 0; bu sınır kalibre düşük aralığı (raw<300)
        # etkilemez (4+ Critical zaten skor 0), dip'e asla girilmez, skor 0–100.
        raw_penalty = min(penalty, _MAX_PENALTY * 3)
        if raw_penalty > 0:
            penalty = raw_penalty * (1 - 0.3 * math.log10(1 + raw_penalty / 10))
        else:
            penalty = 0.0

        score = max(0.0, _BASE_SCORE - min(penalty, _MAX_PENALTY))

        return ScoreSnapshot(
            scan_id=scan_id,
            target=target,
            score=round(score, 2),
            critical=counts["critical"],
            high=counts["high"],
            medium=counts["medium"],
            low=counts["low"],
            info=counts["info"],
            recorded_at=_dt.datetime.now(_dt.timezone.utc).isoformat(),
            project_id=project_id,
            tenant_id=tenant_id,
        )

    def calculate_from_severity_counts(
        self,
        scan_id: str,
        target: str,
        counts: Dict[str, int],
        project_id: Optional[str] = None,
        tenant_id: Optional[str] = None,
    ) -> ScoreSnapshot:
        """Doğrudan severity sayılarından hesapla."""
        findings = []
        for sev, cnt in counts.items():
            findings.extend([{"severity": sev}] * cnt)
        return self.calculate(scan_id, target, findings, project_id, tenant_id)


# ---------------------------------------------------------------------------
# ScoreTracker
# ---------------------------------------------------------------------------

class ScoreTracker:
    """
    Güvenlik skoru kaydı ve trend analizi.

    Kullanım
    --------
    ```python
    tracker = ScoreTracker()

    # Tarama sonrası kayıt:
    snapshot = tracker.record(scan_id, target, findings)

    # Trend sorgula:
    trend = tracker.trend("https://example.com")
    print(trend.direction, trend.delta)
    ```
    """

    def __init__(
        self,
        json_path: Optional[Path] = None,
        db=None,
        weights: Optional[ScoreWeights] = None,
    ) -> None:
        self._json_path = json_path or (Path.home() / ".websecure" / "score_history.json")
        self._db = db
        self._calc = ScoreCalculator(weights)
        self._history: List[ScoreSnapshot] = []
        self._lock = threading.Lock()
        self._load()

    # ------------------------------------------------------------------
    # Kayıt
    # ------------------------------------------------------------------

    def record(
        self,
        scan_id: str,
        target: str,
        findings: List[Dict[str, Any]],
        project_id: Optional[str] = None,
        tenant_id: Optional[str] = None,
    ) -> ScoreSnapshot:
        """Tarama bulgularından skor hesapla ve kaydet."""
        snapshot = self._calc.calculate(scan_id, target, findings, project_id, tenant_id)

        with self._lock:
            self._history.append(snapshot)

        self._save()
        self._db_record(snapshot)

        logger.info(
            f"[ScoreTracker] {target}: {snapshot.score:.1f}/100 "
            f"({snapshot.risk_level})  C={snapshot.critical} H={snapshot.high} "
            f"M={snapshot.medium} L={snapshot.low}"
        )
        return snapshot

    def record_snapshot(self, snapshot: ScoreSnapshot) -> ScoreSnapshot:
        """Hazır snapshot'ı kaydet (dış hesaplama)."""
        with self._lock:
            self._history.append(snapshot)
        self._save()
        self._db_record(snapshot)
        return snapshot

    # ------------------------------------------------------------------
    # Sorgulama
    # ------------------------------------------------------------------

    def latest(self, target: str) -> Optional[ScoreSnapshot]:
        """Son tarama skoru."""
        with self._lock:
            snaps = [s for s in self._history if s.target == target]
        return snaps[-1] if snaps else None

    def trend(
        self,
        target: str,
        limit: int = 20,
    ) -> TrendResult:
        """Hedef için skor trendi."""
        with self._lock:
            snaps = [s for s in self._history if s.target == target]

        snaps = sorted(snaps, key=lambda s: s.recorded_at)[-limit:]

        if not snaps:
            return TrendResult(target=target, snapshots=[])

        scores = [s.score for s in snaps]
        direction = self._calc_direction(scores)
        delta = scores[-1] - scores[0] if len(scores) > 1 else 0.0

        return TrendResult(
            target=target,
            snapshots=snaps,
            direction=direction,
            delta=round(delta, 2),
            min_score=round(min(scores), 2),
            max_score=round(max(scores), 2),
            avg_score=round(sum(scores) / len(scores), 2),
        )

    def project_trend(
        self,
        project_id: str,
        limit: int = 20,
    ) -> TrendResult:
        """Proje için birleşik trend."""
        with self._lock:
            snaps = [s for s in self._history if s.project_id == project_id]
        snaps = sorted(snaps, key=lambda s: s.recorded_at)[-limit:]

        if not snaps:
            return TrendResult(target=f"project:{project_id}", snapshots=[])

        scores = [s.score for s in snaps]
        return TrendResult(
            target=f"project:{project_id}",
            snapshots=snaps,
            direction=self._calc_direction(scores),
            delta=round(scores[-1] - scores[0], 2) if len(scores) > 1 else 0.0,
            min_score=round(min(scores), 2),
            max_score=round(max(scores), 2),
            avg_score=round(sum(scores) / len(scores), 2),
        )

    def delta(self, target: str) -> Optional[float]:
        """Son iki tarama arasındaki skor farkı (pozitif = iyileşme)."""
        with self._lock:
            snaps = [s for s in self._history if s.target == target]
        if len(snaps) < 2:
            return None
        return round(snaps[-1].score - snaps[-2].score, 2)

    def all_targets(self) -> List[str]:
        """Skor geçmişi olan tüm hedefler."""
        with self._lock:
            return list({s.target for s in self._history})

    def stats(self) -> Dict[str, Any]:
        """Genel istatistikler."""
        with self._lock:
            snaps = list(self._history)
        if not snaps:
            return {"total_records": 0}
        scores = [s.score for s in snaps]
        return {
            "total_records": len(snaps),
            "targets": len({s.target for s in snaps}),
            "global_avg": round(sum(scores) / len(scores), 2),
            "global_min": round(min(scores), 2),
            "global_max": round(max(scores), 2),
        }

    # ------------------------------------------------------------------
    # Yardımcılar
    # ------------------------------------------------------------------

    @staticmethod
    def _calc_direction(scores: List[float]) -> str:
        """Basit lineer regresyon ile yön tespiti."""
        if len(scores) < 2:
            return "stable"
        n = len(scores)
        xs = list(range(n))
        x_mean = sum(xs) / n
        y_mean = sum(scores) / n
        num = sum((x - x_mean) * (y - y_mean) for x, y in zip(xs, scores))
        den = sum((x - x_mean) ** 2 for x in xs)
        if den == 0:
            return "stable"
        slope = num / den
        if slope > 0.5:
            return "improving"
        if slope < -0.5:
            return "degrading"
        return "stable"

    # ------------------------------------------------------------------
    # Kalıcılık
    # ------------------------------------------------------------------

    def _save(self) -> None:
        try:
            self._json_path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self._json_path.with_name(
                f"{self._json_path.stem}_{uuid.uuid4().hex[:8]}.tmp"
            )
            with self._lock:
                data = [s.to_dict() for s in self._history]
            tmp.write_text(
                json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8"
            )
            tmp.replace(self._json_path)
        except Exception as exc:
            logger.error(f"[ScoreTracker] Kaydetme hatası: {exc!r}")

    def _load(self) -> None:
        if not self._json_path.exists():
            return
        try:
            data = json.loads(self._json_path.read_text(encoding="utf-8"))
            for d in data:
                try:
                    counts = d.get("counts", {})
                    snap = ScoreSnapshot(
                        scan_id=d.get("scan_id", ""),
                        target=d.get("target", ""),
                        score=d.get("score", 100.0),
                        critical=counts.get("critical", 0),
                        high=counts.get("high", 0),
                        medium=counts.get("medium", 0),
                        low=counts.get("low", 0),
                        info=counts.get("info", 0),
                        recorded_at=d.get("recorded_at", ""),
                        project_id=d.get("project_id"),
                        tenant_id=d.get("tenant_id"),
                    )
                    self._history.append(snap)
                except Exception as _fix_e:
                    logger.debug(f"[core.score_tracker] {type(_fix_e).__name__}: {_fix_e!r}")
            logger.debug(f"[ScoreTracker] {len(self._history)} skor yüklendi.")
        except Exception as exc:
            logger.error(f"[ScoreTracker] Yükleme hatası: {exc!r}")

    def _db_record(self, snapshot: ScoreSnapshot) -> None:
        """DB'ye kaydet (opsiyonel)."""
        if not self._db:
            return
        try:
            from websecure.db.repository import ScoreRepository, ScoreRecord
            repo = ScoreRepository(self._db)
            rec = ScoreRecord(
                scan_id=snapshot.scan_id,
                tenant_id=snapshot.tenant_id,
                project_id=snapshot.project_id,
                target=snapshot.target,
                score=snapshot.score,
                critical=snapshot.critical,
                high=snapshot.high,
                medium=snapshot.medium,
                low=snapshot.low,
                info=snapshot.info,
                recorded_at=snapshot.recorded_at,
            )
            repo.record(rec)
        except Exception as exc:
            logger.warning(f"[ScoreTracker] DB kayıt atlandı: {exc!r}")


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------

_tracker_instance: Optional[ScoreTracker] = None
_singleton_lock = threading.Lock()


def get_score_tracker(db=None) -> ScoreTracker:
    """
    Global ScoreTracker singleton'ını döndür.
    db parametresi verilirse ve singleton henüz DB'siz ise DB güncellenir.
    """
    global _tracker_instance
    with _singleton_lock:
        if _tracker_instance is None:
            # DB verilmezse otomatik olarak get_db() dene
            if db is None:
                try:
                    from websecure.db import get_db
                    db = get_db()
                except Exception as _fix_e:
                    logger.debug(f"[core.score_tracker] {type(_fix_e).__name__}: {_fix_e!r}")
            _tracker_instance = ScoreTracker(db=db)
        elif db is not None and _tracker_instance._db is None:
            # Mevcut singleton'a DB bağla
            _tracker_instance._db = db
    return _tracker_instance


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

__all__ = [
    "ScoreWeights",
    "ScoreSnapshot",
    "TrendResult",
    "ScoreCalculator",
    "ScoreTracker",
    "get_score_tracker",
]
