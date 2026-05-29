"""
websecure.db.repository
~~~~~~~~~~~~~~~~~~~~~~~~
SQLite CRUD repository'leri — Tenant, Project, Scan, Finding, FPRule, Score.

SOLID
-----
- SRP  : Her repository tek bir model'den sorumlu.
- OCP  : Yeni sorgu yöntemi eklemek mevcut kodu değiştirmez.
- DIP  : Repository'ler Database soyutlamasına bağımlı.
"""
from __future__ import annotations

import hashlib
import json
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from websecure.db.database import Database, get_db

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Yardımcı
# ---------------------------------------------------------------------------

def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _new_id() -> str:
    return uuid.uuid4().hex[:16]


# ---------------------------------------------------------------------------
# Model dataclass'ları
# ---------------------------------------------------------------------------

@dataclass
class Tenant:
    id: str = field(default_factory=_new_id)
    name: str = ""
    api_key: str = field(default_factory=lambda: hashlib.sha256(uuid.uuid4().bytes).hexdigest()[:32])
    created_at: str = field(default_factory=_now)
    settings: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Project:
    id: str = field(default_factory=_new_id)
    tenant_id: str = ""
    name: str = ""
    description: str = ""
    created_at: str = field(default_factory=_now)


@dataclass
class Scan:
    id: str = field(default_factory=_new_id)
    project_id: Optional[str] = None
    tenant_id: Optional[str] = None
    target: str = ""
    profile: str = "default"
    status: str = "running"
    started_at: str = field(default_factory=_now)
    completed_at: Optional[str] = None
    duration_s: float = 0.0
    finding_count: int = 0
    score: Optional[float] = None
    config_json: Dict[str, Any] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)


@dataclass
class Finding:
    id: str = field(default_factory=_new_id)
    scan_id: str = ""
    tenant_id: Optional[str] = None
    project_id: Optional[str] = None
    fingerprint: str = ""
    title: str = ""
    severity: str = "Info"
    url: str = ""
    tool: str = "websecure"
    category: str = ""
    description: str = ""
    evidence: str = ""
    cwe: str = ""
    cvss: Optional[float] = None
    verified: bool = False
    false_positive: bool = False
    remediation: str = ""
    tags: List[str] = field(default_factory=list)
    created_at: str = field(default_factory=_now)
    extra: Dict[str, Any] = field(default_factory=dict)


@dataclass
class FPRule:
    id: str = field(default_factory=_new_id)
    tenant_id: Optional[str] = None
    title_pattern: str = ""
    url_pattern: str = ""
    severity: str = ""
    tool: str = ""
    confidence: float = 0.5
    hit_count: int = 0
    confirm_count: int = 0
    active: bool = True
    created_at: str = field(default_factory=_now)
    created_by: str = "system"


@dataclass
class ScoreRecord:
    id: str = field(default_factory=_new_id)
    scan_id: str = ""
    tenant_id: Optional[str] = None
    project_id: Optional[str] = None
    target: str = ""
    score: float = 100.0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0
    recorded_at: str = field(default_factory=_now)


# ---------------------------------------------------------------------------
# TenantRepository
# ---------------------------------------------------------------------------

class TenantRepository:
    def __init__(self, db: Optional[Database] = None) -> None:
        self._db = db or get_db()

    def create(self, tenant: Tenant) -> Tenant:
        with self._db.connection() as conn:
            conn.execute(
                "INSERT INTO tenants(id, name, api_key, created_at, settings) VALUES (?,?,?,?,?)",
                (tenant.id, tenant.name, tenant.api_key, tenant.created_at,
                 json.dumps(tenant.settings)),
            )
        return tenant

    def get(self, tenant_id: str) -> Optional[Tenant]:
        with self._db.connection() as conn:
            row = conn.execute("SELECT * FROM tenants WHERE id=?", (tenant_id,)).fetchone()
        return self._row_to_tenant(row) if row else None

    def get_by_api_key(self, api_key: str) -> Optional[Tenant]:
        with self._db.connection() as conn:
            row = conn.execute("SELECT * FROM tenants WHERE api_key=?", (api_key,)).fetchone()
        return self._row_to_tenant(row) if row else None

    def list_all(self) -> List[Tenant]:
        with self._db.connection() as conn:
            rows = conn.execute("SELECT * FROM tenants ORDER BY created_at").fetchall()
        return [self._row_to_tenant(r) for r in rows]

    def delete(self, tenant_id: str) -> bool:
        with self._db.connection() as conn:
            c = conn.execute("DELETE FROM tenants WHERE id=?", (tenant_id,))
        return c.rowcount > 0

    def get_or_create_default(self) -> Tenant:
        """Default tenant al veya oluştur."""
        with self._db.connection() as conn:
            row = conn.execute("SELECT * FROM tenants WHERE name='default'").fetchone()
        if row:
            return self._row_to_tenant(row)
        tenant = Tenant(name="default")
        return self.create(tenant)

    @staticmethod
    def _row_to_tenant(row) -> Tenant:
        return Tenant(
            id=row["id"],
            name=row["name"],
            api_key=row["api_key"],
            created_at=row["created_at"],
            settings=json.loads(row["settings"] or "{}"),
        )


# ---------------------------------------------------------------------------
# ProjectRepository
# ---------------------------------------------------------------------------

class ProjectRepository:
    def __init__(self, db: Optional[Database] = None) -> None:
        self._db = db or get_db()

    def create(self, project: Project) -> Project:
        with self._db.connection() as conn:
            conn.execute(
                "INSERT INTO projects(id, tenant_id, name, description, created_at) VALUES (?,?,?,?,?)",
                (project.id, project.tenant_id, project.name, project.description, project.created_at),
            )
        return project

    def get(self, project_id: str) -> Optional[Project]:
        with self._db.connection() as conn:
            row = conn.execute("SELECT * FROM projects WHERE id=?", (project_id,)).fetchone()
        return self._row_to_project(row) if row else None

    def list_by_tenant(self, tenant_id: str) -> List[Project]:
        with self._db.connection() as conn:
            rows = conn.execute(
                "SELECT * FROM projects WHERE tenant_id=? ORDER BY created_at DESC",
                (tenant_id,),
            ).fetchall()
        return [self._row_to_project(r) for r in rows]

    def delete(self, project_id: str) -> bool:
        with self._db.connection() as conn:
            c = conn.execute("DELETE FROM projects WHERE id=?", (project_id,))
        return c.rowcount > 0

    @staticmethod
    def _row_to_project(row) -> Project:
        return Project(
            id=row["id"],
            tenant_id=row["tenant_id"],
            name=row["name"],
            description=row["description"],
            created_at=row["created_at"],
        )


# ---------------------------------------------------------------------------
# ScanRepository
# ---------------------------------------------------------------------------

class ScanRepository:
    def __init__(self, db: Optional[Database] = None) -> None:
        self._db = db or get_db()

    def create(self, scan: Scan) -> Scan:
        with self._db.connection() as conn:
            conn.execute(
                """INSERT INTO scans(id, project_id, tenant_id, target, profile, status,
                   started_at, completed_at, duration_s, finding_count, score,
                   config_json, tags)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (scan.id, scan.project_id, scan.tenant_id, scan.target,
                 scan.profile, scan.status, scan.started_at, scan.completed_at,
                 scan.duration_s, scan.finding_count, scan.score,
                 json.dumps(scan.config_json), json.dumps(scan.tags)),
            )
        return scan

    def update(self, scan: Scan) -> Scan:
        with self._db.connection() as conn:
            conn.execute(
                """UPDATE scans SET status=?, completed_at=?, duration_s=?,
                   finding_count=?, score=?, tags=? WHERE id=?""",
                (scan.status, scan.completed_at, scan.duration_s,
                 scan.finding_count, scan.score, json.dumps(scan.tags), scan.id),
            )
        return scan

    def get(self, scan_id: str) -> Optional[Scan]:
        with self._db.connection() as conn:
            row = conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
        return self._row_to_scan(row) if row else None

    def list_recent(
        self,
        tenant_id: Optional[str] = None,
        project_id: Optional[str] = None,
        limit: int = 50,
    ) -> List[Scan]:
        query = "SELECT * FROM scans WHERE 1=1"
        params: List[Any] = []
        if tenant_id:
            query += " AND tenant_id=?"
            params.append(tenant_id)
        if project_id:
            query += " AND project_id=?"
            params.append(project_id)
        query += " ORDER BY started_at DESC LIMIT ?"
        params.append(limit)
        with self._db.connection() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row_to_scan(r) for r in rows]

    def delete(self, scan_id: str) -> bool:
        with self._db.connection() as conn:
            c = conn.execute("DELETE FROM scans WHERE id=?", (scan_id,))
        return c.rowcount > 0

    def count_by_target(self, target: str) -> int:
        with self._db.connection() as conn:
            row = conn.execute("SELECT COUNT(*) FROM scans WHERE target=?", (target,)).fetchone()
        return row[0] if row else 0

    @staticmethod
    def _row_to_scan(row) -> Scan:
        return Scan(
            id=row["id"],
            project_id=row["project_id"],
            tenant_id=row["tenant_id"],
            target=row["target"],
            profile=row["profile"],
            status=row["status"],
            started_at=row["started_at"],
            completed_at=row["completed_at"],
            duration_s=row["duration_s"],
            finding_count=row["finding_count"],
            score=row["score"],
            config_json=json.loads(row["config_json"] or "{}"),
            tags=json.loads(row["tags"] or "[]"),
        )


# ---------------------------------------------------------------------------
# FindingRepository
# ---------------------------------------------------------------------------

class FindingRepository:
    def __init__(self, db: Optional[Database] = None) -> None:
        self._db = db or get_db()

    def create(self, finding: Finding) -> Finding:
        with self._db.connection() as conn:
            conn.execute(
                """INSERT OR IGNORE INTO findings(
                    id, scan_id, tenant_id, project_id, fingerprint, title,
                    severity, url, tool, category, description, evidence, cwe,
                    cvss, verified, false_positive, remediation, tags,
                    created_at, extra_json)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (finding.id, finding.scan_id, finding.tenant_id, finding.project_id,
                 finding.fingerprint, finding.title, finding.severity, finding.url,
                 finding.tool, finding.category, finding.description, finding.evidence,
                 finding.cwe, finding.cvss, int(finding.verified),
                 int(finding.false_positive), finding.remediation,
                 json.dumps(finding.tags), finding.created_at,
                 json.dumps(finding.extra)),
            )
        return finding

    def bulk_create(self, findings: List[Finding]) -> int:
        """Toplu kayıt — daha hızlı."""
        count = 0
        with self._db.connection() as conn:
            for f in findings:
                try:
                    conn.execute(
                        """INSERT OR IGNORE INTO findings(
                            id, scan_id, tenant_id, project_id, fingerprint, title,
                            severity, url, tool, category, description, evidence, cwe,
                            cvss, verified, false_positive, remediation, tags,
                            created_at, extra_json)
                           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                        (f.id, f.scan_id, f.tenant_id, f.project_id,
                         f.fingerprint, f.title, f.severity, f.url,
                         f.tool, f.category, f.description, f.evidence,
                         f.cwe, f.cvss, int(f.verified),
                         int(f.false_positive), f.remediation,
                         json.dumps(f.tags), f.created_at, json.dumps(f.extra)),
                    )
                    count += 1
                except Exception as exc:
                    logger.warning(f"[FindingRepo] bulk_create hata: {exc}")
        return count

    def get(self, finding_id: str) -> Optional[Finding]:
        with self._db.connection() as conn:
            row = conn.execute("SELECT * FROM findings WHERE id=?", (finding_id,)).fetchone()
        return self._row_to_finding(row) if row else None

    def list_by_scan(
        self,
        scan_id: str,
        include_fp: bool = False,
    ) -> List[Finding]:
        query = "SELECT * FROM findings WHERE scan_id=?"
        params: List[Any] = [scan_id]
        if not include_fp:
            query += " AND false_positive=0"
        # P7 fix: alphabetical ORDER BY severity sorts Critical < High < Info < Low < Medium
        # which is wrong. Use CASE expression for correct Critical→High→Medium→Low→Info order.
        query += (
            " ORDER BY CASE severity"
            " WHEN 'Critical' THEN 1"
            " WHEN 'High'     THEN 2"
            " WHEN 'Medium'   THEN 3"
            " WHEN 'Low'      THEN 4"
            " ELSE 5 END, created_at"
        )
        with self._db.connection() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row_to_finding(r) for r in rows]

    def list_by_fingerprint(self, fingerprint: str) -> List[Finding]:
        with self._db.connection() as conn:
            rows = conn.execute(
                "SELECT * FROM findings WHERE fingerprint=? ORDER BY created_at DESC",
                (fingerprint,),
            ).fetchall()
        return [self._row_to_finding(r) for r in rows]

    def mark_false_positive(self, finding_id: str, is_fp: bool = True) -> bool:
        with self._db.connection() as conn:
            c = conn.execute(
                "UPDATE findings SET false_positive=? WHERE id=?",
                (int(is_fp), finding_id),
            )
        return c.rowcount > 0

    def mark_verified(self, finding_id: str, verified: bool = True) -> bool:
        with self._db.connection() as conn:
            c = conn.execute(
                "UPDATE findings SET verified=? WHERE id=?",
                (int(verified), finding_id),
            )
        return c.rowcount > 0

    def count_by_severity(self, scan_id: str) -> Dict[str, int]:
        with self._db.connection() as conn:
            rows = conn.execute(
                """SELECT severity, COUNT(*) as cnt FROM findings
                   WHERE scan_id=? AND false_positive=0
                   GROUP BY severity""",
                (scan_id,),
            ).fetchall()
        counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
        for row in rows:
            counts[row["severity"]] = row["cnt"]
        return counts

    def search(
        self,
        keyword: str,
        tenant_id: Optional[str] = None,
        severity: Optional[str] = None,
        limit: int = 100,
    ) -> List[Finding]:
        query = "SELECT * FROM findings WHERE (title LIKE ? OR url LIKE ?)"
        params: List[Any] = [f"%{keyword}%", f"%{keyword}%"]
        if tenant_id:
            query += " AND tenant_id=?"
            params.append(tenant_id)
        if severity:
            query += " AND severity=?"
            params.append(severity)
        query += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)
        with self._db.connection() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row_to_finding(r) for r in rows]

    @staticmethod
    def _row_to_finding(row) -> Finding:
        return Finding(
            id=row["id"],
            scan_id=row["scan_id"],
            tenant_id=row["tenant_id"],
            project_id=row["project_id"],
            fingerprint=row["fingerprint"],
            title=row["title"],
            severity=row["severity"],
            url=row["url"],
            tool=row["tool"],
            category=row["category"],
            description=row["description"],
            evidence=row["evidence"],
            cwe=row["cwe"],
            cvss=row["cvss"],
            verified=bool(row["verified"]),
            false_positive=bool(row["false_positive"]),
            remediation=row["remediation"],
            tags=json.loads(row["tags"] or "[]"),
            created_at=row["created_at"],
            extra=json.loads(row["extra_json"] or "{}"),
        )


# ---------------------------------------------------------------------------
# FPRuleRepository
# ---------------------------------------------------------------------------

class FPRuleRepository:
    def __init__(self, db: Optional[Database] = None) -> None:
        self._db = db or get_db()

    def create(self, rule: FPRule) -> FPRule:
        with self._db.connection() as conn:
            conn.execute(
                """INSERT OR REPLACE INTO fp_rules(
                    id, tenant_id, title_pattern, url_pattern, severity, tool,
                    confidence, hit_count, confirm_count, active, created_at, created_by)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                (rule.id, rule.tenant_id, rule.title_pattern, rule.url_pattern,
                 rule.severity, rule.tool, rule.confidence, rule.hit_count,
                 rule.confirm_count, int(rule.active), rule.created_at, rule.created_by),
            )
        return rule

    def get(self, rule_id: str) -> Optional[FPRule]:
        with self._db.connection() as conn:
            row = conn.execute("SELECT * FROM fp_rules WHERE id=?", (rule_id,)).fetchone()
        return self._row_to_fprule(row) if row else None

    def update(self, rule: FPRule) -> FPRule:
        with self._db.connection() as conn:
            conn.execute(
                """UPDATE fp_rules SET confidence=?, hit_count=?, confirm_count=?,
                   active=? WHERE id=?""",
                (rule.confidence, rule.hit_count, rule.confirm_count,
                 int(rule.active), rule.id),
            )
        return rule

    def list_by_tenant(
        self,
        tenant_id: Optional[str] = None,
        active_only: bool = True,
    ) -> List[FPRule]:
        query = "SELECT * FROM fp_rules WHERE 1=1"
        params: List[Any] = []
        if tenant_id:
            query += " AND (tenant_id=? OR tenant_id IS NULL)"
            params.append(tenant_id)
        if active_only:
            query += " AND active=1"
        query += " ORDER BY confidence DESC"
        with self._db.connection() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row_to_fprule(r) for r in rows]

    def delete(self, rule_id: str) -> bool:
        with self._db.connection() as conn:
            c = conn.execute("DELETE FROM fp_rules WHERE id=?", (rule_id,))
        return c.rowcount > 0

    @staticmethod
    def _row_to_fprule(row) -> FPRule:
        return FPRule(
            id=row["id"],
            tenant_id=row["tenant_id"],
            title_pattern=row["title_pattern"],
            url_pattern=row["url_pattern"],
            severity=row["severity"],
            tool=row["tool"],
            confidence=row["confidence"],
            hit_count=row["hit_count"],
            confirm_count=row["confirm_count"],
            active=bool(row["active"]),
            created_at=row["created_at"],
            created_by=row["created_by"],
        )


# ---------------------------------------------------------------------------
# ScoreRepository
# ---------------------------------------------------------------------------

class ScoreRepository:
    def __init__(self, db: Optional[Database] = None) -> None:
        self._db = db or get_db()

    def record(self, rec: ScoreRecord) -> ScoreRecord:
        with self._db.connection() as conn:
            conn.execute(
                """INSERT INTO score_history(id, scan_id, tenant_id, project_id,
                   target, score, critical, high, medium, low, info, recorded_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                (rec.id, rec.scan_id, rec.tenant_id, rec.project_id,
                 rec.target, rec.score, rec.critical, rec.high,
                 rec.medium, rec.low, rec.info, rec.recorded_at),
            )
        return rec

    def trend(
        self,
        target: Optional[str] = None,
        project_id: Optional[str] = None,
        limit: int = 30,
    ) -> List[ScoreRecord]:
        """Son N tarama için skor trendi."""
        query = "SELECT * FROM score_history WHERE 1=1"
        params: List[Any] = []
        if target:
            query += " AND target=?"
            params.append(target)
        if project_id:
            query += " AND project_id=?"
            params.append(project_id)
        query += " ORDER BY recorded_at DESC LIMIT ?"
        params.append(limit)
        with self._db.connection() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row_to_record(r) for r in rows]

    def global_trend(self, tenant_id: str, limit: int = 30) -> List[ScoreRecord]:
        with self._db.connection() as conn:
            rows = conn.execute(
                """SELECT * FROM score_history WHERE tenant_id=?
                   ORDER BY recorded_at DESC LIMIT ?""",
                (tenant_id, limit),
            ).fetchall()
        return [self._row_to_record(r) for r in rows]

    @staticmethod
    def _row_to_record(row) -> ScoreRecord:
        return ScoreRecord(
            id=row["id"],
            scan_id=row["scan_id"],
            tenant_id=row["tenant_id"],
            project_id=row["project_id"],
            target=row["target"],
            score=row["score"],
            critical=row["critical"],
            high=row["high"],
            medium=row["medium"],
            low=row["low"],
            info=row["info"],
            recorded_at=row["recorded_at"],
        )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

__all__ = [
    "Tenant", "Project", "Scan", "Finding", "FPRule", "ScoreRecord",
    "TenantRepository", "ProjectRepository", "ScanRepository",
    "FindingRepository", "FPRuleRepository", "ScoreRepository",
]
