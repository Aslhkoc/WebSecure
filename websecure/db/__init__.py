"""
websecure.db
~~~~~~~~~~~~
Merkezi SQLite bulgu veritabanı — Adım 20.

Bileşenler
----------
database   : Bağlantı havuzu, şema, migration
repository : CRUD repository'ler (Tenant, Project, Scan, Finding, Score)

Hızlı Kullanım
--------------
```python
from websecure.db import get_db, ScanRepository, FindingRepository, Scan, Finding

db = get_db()  # ~/.websecure/websecure.db

scan_repo = ScanRepository(db)
find_repo = FindingRepository(db)

# Tarama kaydet
scan = Scan(id="abc123", target="https://example.com")
scan_repo.create(scan)

# Bulgu kaydet
finding = Finding(
    id="f001", scan_id="abc123",
    fingerprint="sha256[:16]",
    title="SQL Injection", severity="Critical",
    url="https://example.com/login",
)
find_repo.create(finding)

# Sorgula
findings = find_repo.list_by_scan("abc123")
```
"""
from websecure.db.database import Database, get_db
from websecure.db.repository import (
    Tenant, Project, Scan, Finding, FPRule, ScoreRecord,
    TenantRepository, ProjectRepository, ScanRepository,
    FindingRepository, FPRuleRepository, ScoreRepository,
)

__all__ = [
    "Database", "get_db",
    "Tenant", "Project", "Scan", "Finding", "FPRule", "ScoreRecord",
    "TenantRepository", "ProjectRepository", "ScanRepository",
    "FindingRepository", "FPRuleRepository", "ScoreRepository",
]
