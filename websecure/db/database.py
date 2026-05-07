"""
websecure.db.database
~~~~~~~~~~~~~~~~~~~~~~
SQLite tabanlı merkezi bulgu veritabanı — şema, bağlantı havuzu, migration.

Bağımlılık yok (sqlite3 stdlib).

Tablolar
--------
tenants      : proje/ekip izolasyonu
projects     : her tenant için proje
scans        : tarama meta bilgisi
findings     : bireysel bulgular
fp_rules     : false positive kuralları
score_history: güvenlik skoru geçmişi

SOLID
-----
- SRP  : Database sadece bağlantı/şema yönetimi.
- OCP  : Yeni tablo/migration eklemek mevcut kodu değiştirmez.
- DIP  : Repository'ler bu modülden bağımsız çalışabilir.
"""
from __future__ import annotations

import logging
import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Generator, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Varsayılan DB yolu
# ---------------------------------------------------------------------------

_DEFAULT_DB = Path.home() / ".websecure" / "websecure.db"

# ---------------------------------------------------------------------------
# DDL — tablo şemaları
# ---------------------------------------------------------------------------

_SCHEMA_SQL = """
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS schema_version (
    version   INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS tenants (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    api_key     TEXT NOT NULL UNIQUE,
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    settings    TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS projects (
    id          TEXT PRIMARY KEY,
    tenant_id   TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(tenant_id, name)
);

CREATE TABLE IF NOT EXISTS scans (
    id              TEXT PRIMARY KEY,
    project_id      TEXT REFERENCES projects(id) ON DELETE SET NULL,
    tenant_id       TEXT REFERENCES tenants(id) ON DELETE SET NULL,
    target          TEXT NOT NULL,
    profile         TEXT NOT NULL DEFAULT 'default',
    status          TEXT NOT NULL DEFAULT 'running',
    started_at      TEXT NOT NULL DEFAULT (datetime('now')),
    completed_at    TEXT,
    duration_s      REAL NOT NULL DEFAULT 0,
    finding_count   INTEGER NOT NULL DEFAULT 0,
    score           REAL,
    config_json     TEXT NOT NULL DEFAULT '{}',
    tags            TEXT NOT NULL DEFAULT '[]'
);

CREATE TABLE IF NOT EXISTS findings (
    id              TEXT PRIMARY KEY,
    scan_id         TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    tenant_id       TEXT REFERENCES tenants(id) ON DELETE SET NULL,
    project_id      TEXT REFERENCES projects(id) ON DELETE SET NULL,
    fingerprint     TEXT NOT NULL,
    title           TEXT NOT NULL,
    severity        TEXT NOT NULL,
    url             TEXT NOT NULL,
    tool            TEXT NOT NULL DEFAULT 'websecure',
    category        TEXT NOT NULL DEFAULT '',
    description     TEXT NOT NULL DEFAULT '',
    evidence        TEXT NOT NULL DEFAULT '',
    cwe             TEXT NOT NULL DEFAULT '',
    cvss            REAL,
    verified        INTEGER NOT NULL DEFAULT 0,
    false_positive  INTEGER NOT NULL DEFAULT 0,
    remediation     TEXT NOT NULL DEFAULT '',
    tags            TEXT NOT NULL DEFAULT '[]',
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    extra_json      TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS fp_rules (
    id              TEXT PRIMARY KEY,
    tenant_id       TEXT REFERENCES tenants(id) ON DELETE CASCADE,
    title_pattern   TEXT NOT NULL DEFAULT '',
    url_pattern     TEXT NOT NULL DEFAULT '',
    severity        TEXT NOT NULL DEFAULT '',
    tool            TEXT NOT NULL DEFAULT '',
    confidence      REAL NOT NULL DEFAULT 1.0,
    hit_count       INTEGER NOT NULL DEFAULT 0,
    confirm_count   INTEGER NOT NULL DEFAULT 0,
    active          INTEGER NOT NULL DEFAULT 1,
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    created_by      TEXT NOT NULL DEFAULT 'system'
);

CREATE TABLE IF NOT EXISTS score_history (
    id          TEXT PRIMARY KEY,
    scan_id     TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    tenant_id   TEXT REFERENCES tenants(id) ON DELETE SET NULL,
    project_id  TEXT REFERENCES projects(id) ON DELETE SET NULL,
    target      TEXT NOT NULL,
    score       REAL NOT NULL,
    critical    INTEGER NOT NULL DEFAULT 0,
    high        INTEGER NOT NULL DEFAULT 0,
    medium      INTEGER NOT NULL DEFAULT 0,
    low         INTEGER NOT NULL DEFAULT 0,
    info        INTEGER NOT NULL DEFAULT 0,
    recorded_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- İndeksler
CREATE INDEX IF NOT EXISTS idx_findings_scan    ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_fp      ON findings(fingerprint);
CREATE INDEX IF NOT EXISTS idx_findings_sev     ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_scans_tenant     ON scans(tenant_id);
CREATE INDEX IF NOT EXISTS idx_scans_project    ON scans(project_id);
CREATE INDEX IF NOT EXISTS idx_score_project    ON score_history(project_id);
CREATE INDEX IF NOT EXISTS idx_fp_tenant        ON fp_rules(tenant_id);
"""

_CURRENT_VERSION = 1


# ---------------------------------------------------------------------------
# Database — bağlantı yöneticisi
# ---------------------------------------------------------------------------

class Database:
    """
    SQLite bağlantı havuzu ve şema yöneticisi.

    Kullanım
    --------
    ```python
    db = Database()
    db.initialize()

    with db.connection() as conn:
        conn.execute("SELECT * FROM scans")
    ```
    """

    def __init__(self, db_path: Optional[Path] = None) -> None:
        self._path = db_path or _DEFAULT_DB
        self._local = threading.local()
        self._init_lock = threading.Lock()
        self._initialized = False

    # ------------------------------------------------------------------
    # Başlatma
    # ------------------------------------------------------------------

    def initialize(self) -> None:
        """Şemayı oluştur / migrate et."""
        with self._init_lock:
            if self._initialized:
                return
            self._path.parent.mkdir(parents=True, exist_ok=True)
            conn = self._raw_conn()
            try:
                conn.executescript(_SCHEMA_SQL)
                self._apply_migrations(conn)
                conn.commit()
            finally:
                conn.close()
            self._initialized = True
            logger.info(f"[DB] Başlatıldı: {self._path}")

    def _apply_migrations(self, conn: sqlite3.Connection) -> None:
        """Migration tablosunu güncelle."""
        row = conn.execute("SELECT MAX(version) FROM schema_version").fetchone()
        current = row[0] or 0

        if current < _CURRENT_VERSION:
            conn.execute(
                "INSERT OR IGNORE INTO schema_version(version) VALUES (?)",
                (_CURRENT_VERSION,),
            )
            logger.debug(f"[DB] Şema v{_CURRENT_VERSION} uygulandı.")

    # ------------------------------------------------------------------
    # Bağlantı
    # ------------------------------------------------------------------

    def _raw_conn(self) -> sqlite3.Connection:
        """Doğrudan bağlantı."""
        conn = sqlite3.connect(
            str(self._path),
            check_same_thread=False,
            timeout=30,
        )
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA foreign_keys = ON")
        return conn

    @contextmanager
    def connection(self) -> Generator[sqlite3.Connection, None, None]:
        """
        Thread-local bağlantı — auto-commit ve hata durumunda rollback.

        ```python
        with db.connection() as conn:
            conn.execute("INSERT INTO ...")
        ```
        """
        if not self._initialized:
            self.initialize()

        if not hasattr(self._local, "conn") or self._local.conn is None:
            self._local.conn = self._raw_conn()

        conn = self._local.conn
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise

    def close(self) -> None:
        """Thread-local bağlantıyı kapat."""
        conn = getattr(self._local, "conn", None)
        if conn:
            conn.close()
            self._local.conn = None

    def vacuum(self) -> None:
        """Veritabanını optimize et."""
        with self.connection() as conn:
            conn.execute("VACUUM")
        logger.info("[DB] VACUUM tamamlandı.")

    def stats(self) -> dict:
        """Tablo satır sayılarını döndür."""
        tables = ["tenants", "projects", "scans", "findings", "fp_rules", "score_history"]
        result = {}
        with self.connection() as conn:
            for t in tables:
                row = conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()
                result[t] = row[0] if row else 0
        return result


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------

_db_instance: Optional[Database] = None
_db_lock = threading.Lock()


def get_db(db_path: Optional[Path] = None) -> Database:
    """Global Database singleton'ını döndür."""
    global _db_instance
    with _db_lock:
        if _db_instance is None:
            _db_instance = Database(db_path)
            _db_instance.initialize()
    return _db_instance


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

__all__ = [
    "Database",
    "get_db",
]
