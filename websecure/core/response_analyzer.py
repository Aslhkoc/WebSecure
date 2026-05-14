"""
websecure.core.response_analyzer
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Nessus-inspired response behaviour analysis engine.

Analyses HOW responses change after injection — not just IF a payload reflects.
Provides the foundational primitives consumed by all attack scanners.

Architecture:
  BaselineCapture      — captures clean response fingerprint
  ResponseDifferential — computes delta between baseline and injected response
  SQLErrorDetector     — 13+ DB error pattern library
  FrameworkErrorDetector — stack traces, framework error pages
  ResponseBehaviorAnalyzer — orchestrates all of the above; clean scanner API

Design goals (Nessus parity):
  - Structural diff, not just keyword match
  - Per-parameter baseline isolation (not per-URL)
  - Confidence scoring tied to differential evidence
  - Zero false positive: only flag when multiple independent signals agree
"""
from __future__ import annotations

import hashlib
import logging
import re
import statistics
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, List, Optional, Set, Tuple

import requests as _requests

_logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class BaselineCapture:
    """Fingerprint of a clean (non-injected) HTTP response."""
    url: str
    param: str
    status_code: int
    body_length: int
    body_hash: str                       # SHA-256 hex of response body
    content_type: str
    headers: Dict[str, str]
    elapsed_s: float
    error_fingerprints: FrozenSet[str]   # DB/framework error patterns present in clean response
    title: str                           # <title>…</title> or first 80 chars
    word_count: int
    timestamp: float = field(default_factory=time.time)

    @classmethod
    def from_response(cls, resp: _requests.Response, url: str, param: str) -> "BaselineCapture":
        body = resp.text or ""
        digest = hashlib.sha256(body.encode("utf-8", errors="replace")).hexdigest()
        words = len(body.split())
        title_m = re.search(r"<title[^>]*>([^<]{1,200})</title>", body, re.I)
        title = (title_m.group(1).strip() if title_m else body[:80]).strip()
        ct = resp.headers.get("Content-Type", "")
        hdrs = {k.lower(): v for k, v in resp.headers.items()}
        elapsed = resp.elapsed.total_seconds() if resp.elapsed else 0.0
        fps = SQLErrorDetector.extract_fingerprints(body) | FrameworkErrorDetector.extract_fingerprints(body)
        return cls(
            url=url,
            param=param,
            status_code=resp.status_code,
            body_length=len(body),
            body_hash=digest,
            content_type=ct,
            headers=hdrs,
            elapsed_s=elapsed,
            error_fingerprints=frozenset(fps),
            title=title,
            word_count=words,
        )


@dataclass
class ResponseDifferential:
    """
    Computed delta between a baseline capture and an injected response.
    Confidence is a 0.0–1.0 float; ≥0.6 is reportable.
    """
    payload: str
    status_changed: bool
    new_status: int
    size_delta: int          # bytes — positive means larger
    size_delta_pct: float    # fraction of baseline size
    hash_changed: bool
    new_db_errors: Set[str]  # error labels NOT in baseline
    new_framework_errors: Set[str]
    error_count_delta: int   # how many new error lines appeared
    title_changed: bool
    word_delta: int
    elapsed_delta: float     # seconds above baseline
    confidence: float        # 0.0 – 1.0 composite signal strength
    evidence_summary: str

    @property
    def is_significant(self) -> bool:
        return self.confidence >= 0.50

    @property
    def is_reportable(self) -> bool:
        return self.confidence >= 0.65


# ---------------------------------------------------------------------------
# SQL Error Detector
# ---------------------------------------------------------------------------

class SQLErrorDetector:
    """
    Expanded SQL error pattern library covering 13+ databases.
    Returns a set of (db_label, pattern_label) pairs for any match.
    """

    # Each entry: db_label -> list of compiled patterns
    _PATTERNS: Dict[str, List[re.Pattern]] = {}

    _RAW: Dict[str, List[str]] = {
        "MySQL": [
            r"SQL syntax.*MySQL",
            r"Warning.*mysql_",
            r"valid MySQL result",
            r"MySqlClient\.",
            r"com\.mysql\.jdbc",
            r"Zend_Db_(Adapter|Statement)_Mysqli_Exception",
            r"SQLSTATE\[HY000\].*MySQL",
            r"check the manual that (corresponds to|matches) your MySQL server version",
        ],
        "MariaDB": [
            r"You have an error in your SQL syntax.*MariaDB",
            r"Warning.*mariadb_",
        ],
        "PostgreSQL": [
            r"PostgreSQL.*ERROR",
            r"Warning.*\Wpg_",
            r"valid PostgreSQL result",
            r"Npgsql\.",
            r"PG::SyntaxError",
            r"org\.postgresql\.util\.PSQLException",
            r"ERROR:\s+syntax error at or near",
            r"ERROR:\s+column .* does not exist",
            r"ERROR:\s+operator does not exist",
        ],
        "MSSQL": [
            r"Driver.*SQL[\-_ ]*Server",
            r"OLE DB.*SQL Server",
            r"(\W|\A)SQL Server.*Driver",
            r"Warning.*mssql_",
            r"(\W|\A)SQL Server.*[0-9a-fA-F]{8}",
            r"(?s)Exception.*\WSystem\.Data\.SqlClient\.",
            r"Unclosed quotation mark after the character string",
            r"com\.microsoft\.sqlserver\.jdbc",
            r"Microsoft OLE DB Provider for SQL Server",
        ],
        "Access": [
            r"Microsoft Access Driver",
            r"JET Database Engine",
            r"Access Database Engine",
            r"ODBC Microsoft Access",
        ],
        "Oracle": [
            r"\bORA-[0-9]{4,5}",
            r"Oracle error",
            r"Oracle.*Driver",
            r"Warning.*\Woci_",
            r"Warning.*\Wora_",
            r"oracle\.jdbc\.driver",
            r"quoted string not properly terminated",
        ],
        "IBM_DB2": [
            r"CLI Driver.*DB2",
            r"DB2 SQL error",
            r"\bdb2_\w+\(",
            r"SQLSTATE=\d{5}",
            r"com\.ibm\.db2\.jcc",
        ],
        "SQLite": [
            r"SQLite/JDBCDriver",
            r"SQLite\.Exception",
            r"System\.Data\.SQLite\.SQLiteException",
            r"Warning.*sqlite_",
            r"Warning.*SQLite3::",
            r"\[SQLITE_ERROR\]",
            r"SQLite3::query\(\)",
        ],
        "Sybase": [
            r"(?i)Sybase message",
            r"Sybase.*Server message",
            r"SybSQLException",
            r"com\.sybase\.jdbc",
        ],
        "H2": [
            r"Syntax error in SQL statement",
            r"Column .* not found",
            r"org\.h2\.jdbc",
        ],
        "HSQL": [
            r"Unexpected token.*in statement",
            r"org\.hsqldb",
        ],
        "Firebird": [
            r"Dynamic SQL Error",
            r"SQL error code = -\d+",
            r"org\.firebirdsql",
        ],
        "Informix": [
            r"A syntax error has occurred",
            r"Informix",
            r"com\.informix\.jdbc",
        ],
        "MongoDB": [
            r"MongoError",
            r"Failed to parse",
            r"\"errmsg\"",
            r"MongoCommandException",
            r"\$where.*JavaScript",
        ],
        "Redis": [
            r"ERR syntax error",
            r"WRONGTYPE Operation against a key",
        ],
        "Cassandra": [
            r"com\.datastax\.driver",
            r"SyntaxException",
        ],
        "ElasticSearch": [
            r"ElasticsearchException",
            r"\"type\":\s*\"parse_exception\"",
        ],
    }

    @classmethod
    def _ensure_compiled(cls) -> None:
        if cls._PATTERNS:
            return
        for db, raws in cls._RAW.items():
            cls._PATTERNS[db] = [re.compile(r, re.I) for r in raws]

    @classmethod
    def extract_fingerprints(cls, body: str) -> Set[str]:
        """Return set of 'DB:pattern_index' labels matching body."""
        cls._ensure_compiled()
        found: Set[str] = set()
        for db, patterns in cls._PATTERNS.items():
            for idx, pat in enumerate(patterns):
                if pat.search(body):
                    found.add(f"{db}:{idx}")
        return found

    @classmethod
    def detect(cls, body: str) -> List[Tuple[str, str]]:
        """
        Return list of (db_label, matched_pattern_string) for all matches.
        Suitable for evidence strings.
        """
        cls._ensure_compiled()
        results: List[Tuple[str, str]] = []
        for db, patterns in cls._PATTERNS.items():
            for pat in patterns:
                m = pat.search(body)
                if m:
                    results.append((db, m.group(0)[:120]))
        return results


# ---------------------------------------------------------------------------
# Framework Error Detector
# ---------------------------------------------------------------------------

class FrameworkErrorDetector:
    """
    Detects framework-level error pages: stack traces, exception dumps,
    debug pages for Django/Flask/Rails/Laravel/Spring/ASP.NET etc.
    """

    _RAW: Dict[str, List[str]] = {
        "Django": [
            r"Django.*Exception",
            r"Traceback \(most recent call last\)",
            r"django\.core\.exceptions",
            r"DJANGO_SETTINGS_MODULE",
            r"Page not found.*Django",
        ],
        "Flask": [
            r"werkzeug\.exceptions",
            r"werkzeug\.routing",
            r"flask\.exceptions",
            r"Traceback \(most recent call last\).*flask",
        ],
        "Rails": [
            r"ActionController::RoutingError",
            r"ActionView::Template::Error",
            r"ActiveRecord::StatementInvalid",
            r"app/controllers/.*\.rb:\d+",
        ],
        "Laravel": [
            r"Illuminate\\Database\\QueryException",
            r"SQLSTATE\[.*\].*laravel",
            r"vendor/laravel/framework",
            r"ErrorException in.*\.php",
        ],
        "Spring": [
            r"org\.springframework",
            r"java\.lang\.NullPointerException",
            r"java\.sql\.SQLException",
            r"Whitelabel Error Page",
            r"There was an unexpected error",
        ],
        "ASP.NET": [
            r"System\.Web\.HttpException",
            r"Server Error in.*Application",
            r"Exception Details: System\.",
            r"Stack Trace:.*at System\.",
            r"Microsoft\.CSharp\.RuntimeBinder",
        ],
        "PHP": [
            r"Fatal error:.*on line \d+",
            r"Warning:.*\(.*\) on line \d+",
            r"Parse error:.*on line \d+",
            r"Uncaught.*Exception.*Stack trace",
            r"Call to a member function.*on null",
        ],
        "Node": [
            r"TypeError:.*is not a function",
            r"UnhandledPromiseRejectionWarning",
            r"at Object\.<anonymous>.*\.js:\d+:\d+",
            r"ReferenceError:.*is not defined",
        ],
        "Java_Generic": [
            r"java\.lang\.\w+Exception",
            r"at \w+\.\w+\.\w+\(.*\.java:\d+\)",
            r"com\.sun\..*Exception",
        ],
        "ColdFusion": [
            r"ColdFusion.*Error",
            r"An error occurred at.*\.cfm",
            r"coldfusion\.runtime",
        ],
    }

    _PATTERNS: Dict[str, List[re.Pattern]] = {}

    @classmethod
    def _ensure_compiled(cls) -> None:
        if cls._PATTERNS:
            return
        for fw, raws in cls._RAW.items():
            cls._PATTERNS[fw] = [re.compile(r, re.I | re.S) for r in raws]

    @classmethod
    def extract_fingerprints(cls, body: str) -> Set[str]:
        cls._ensure_compiled()
        found: Set[str] = set()
        for fw, patterns in cls._PATTERNS.items():
            for idx, pat in enumerate(patterns):
                if pat.search(body):
                    found.add(f"fw:{fw}:{idx}")
        return found

    @classmethod
    def detect(cls, body: str) -> List[Tuple[str, str]]:
        cls._ensure_compiled()
        results: List[Tuple[str, str]] = []
        for fw, patterns in cls._PATTERNS.items():
            for pat in patterns:
                m = pat.search(body)
                if m:
                    results.append((fw, m.group(0)[:120]))
        return results


# ---------------------------------------------------------------------------
# Differential Computer
# ---------------------------------------------------------------------------

class _DifferentialComputer:
    """Computes the differential between a baseline capture and an injected response."""

    @staticmethod
    def compute(
        baseline: BaselineCapture,
        resp: _requests.Response,
        payload: str,
        elapsed_s: float,
    ) -> ResponseDifferential:
        body = resp.text or ""
        new_len = len(body)
        new_hash = hashlib.sha256(body.encode("utf-8", errors="replace")).hexdigest()
        new_words = len(body.split())

        status_changed = resp.status_code != baseline.status_code
        size_delta = new_len - baseline.body_length
        size_delta_pct = abs(size_delta) / max(baseline.body_length, 1)
        hash_changed = new_hash != baseline.body_hash
        elapsed_delta = elapsed_s - baseline.elapsed_s

        # Error fingerprints in injected response
        new_db_fps = SQLErrorDetector.extract_fingerprints(body)
        new_fw_fps = FrameworkErrorDetector.extract_fingerprints(body)
        all_new_fps = new_db_fps | new_fw_fps
        all_baseline_fps = baseline.error_fingerprints

        new_db_errors = {fp for fp in new_db_fps if fp not in all_baseline_fps}
        new_fw_errors = {fp for fp in new_fw_fps if fp not in all_baseline_fps}
        error_count_delta = len(all_new_fps - all_baseline_fps)

        title_m = re.search(r"<title[^>]*>([^<]{1,200})</title>", body, re.I)
        new_title = (title_m.group(1).strip() if title_m else body[:80]).strip()
        title_changed = new_title != baseline.title

        word_delta = new_words - baseline.word_count

        # Composite confidence scoring
        confidence = 0.0
        evidence_parts: List[str] = []

        if new_db_errors:
            # DB errors not present in baseline — very strong signal
            db_labels = {fp.split(":")[0] for fp in new_db_errors}
            confidence += 0.45
            evidence_parts.append(f"New DB errors: {', '.join(sorted(db_labels))}")

        if new_fw_errors:
            fw_labels = {fp.split(":")[1] for fp in new_fw_errors if ":" in fp}
            confidence += 0.30
            evidence_parts.append(f"Framework error: {', '.join(sorted(fw_labels))}")

        if status_changed and resp.status_code in (500, 502, 503):
            confidence += 0.20
            evidence_parts.append(f"Status: {baseline.status_code} → {resp.status_code}")

        if size_delta_pct > 0.15 and abs(size_delta) > 200:
            confidence += 0.15
            evidence_parts.append(f"Size Δ: {size_delta:+d}B ({size_delta_pct:.1%})")

        if title_changed:
            confidence += 0.10
            evidence_parts.append(f"Title changed")

        if word_delta > 20 or word_delta < -20:
            confidence += 0.05
            evidence_parts.append(f"Word Δ: {word_delta:+d}")

        confidence = min(confidence, 1.0)
        evidence_summary = " | ".join(evidence_parts) if evidence_parts else "No significant change"

        return ResponseDifferential(
            payload=payload,
            status_changed=status_changed,
            new_status=resp.status_code,
            size_delta=size_delta,
            size_delta_pct=size_delta_pct,
            hash_changed=hash_changed,
            new_db_errors=new_db_errors,
            new_framework_errors=new_fw_errors,
            error_count_delta=error_count_delta,
            title_changed=title_changed,
            word_delta=word_delta,
            elapsed_delta=elapsed_delta,
            confidence=confidence,
            evidence_summary=evidence_summary,
        )


# ---------------------------------------------------------------------------
# ResponseBehaviorAnalyzer — main public API
# ---------------------------------------------------------------------------

class ResponseBehaviorAnalyzer:
    """
    Nessus-inspired response behaviour analysis engine.

    Usage (from any scanner):
        rba = ResponseBehaviorAnalyzer(session)
        baseline = rba.capture_baseline(url, param)
        diff = rba.analyse(baseline, injected_url, payload)
        if diff.is_reportable:
            report_finding(...)

    The analyzer is stateless between scans — each baseline is a separate
    dataclass instance, so multiple scanners can run concurrently safely.
    """

    def __init__(self, session: Any) -> None:
        self.session = session
        self._baseline_cache: Dict[str, BaselineCapture] = {}
        self._cache_lock = threading.Lock()

    def capture_baseline(
        self,
        url: str,
        param: str,
        *,
        n_samples: int = 2,
        timeout: int = 10,
    ) -> Optional[BaselineCapture]:
        """
        Capture n_samples clean responses and return the most stable one.
        Caches per (url, param) key to avoid redundant requests.
        """
        cache_key = f"{url}|{param}"
        with self._cache_lock:
            if cache_key in self._baseline_cache:
                return self._baseline_cache[cache_key]

        captures: List[BaselineCapture] = []
        for _ in range(n_samples):
            try:
                t0 = time.time()
                resp = self.session.get(url, timeout=timeout)
                elapsed = time.time() - t0
                resp.elapsed = type("E", (), {"total_seconds": lambda self: elapsed})()
                cap = BaselineCapture.from_response(resp, url, param)
                captures.append(cap)
            except Exception as exc:
                _logger.debug(f"[RBA] Baseline capture failed for {url}: {exc!r}")

        if not captures:
            return None

        # Use the capture with the median body length (most representative)
        captures.sort(key=lambda c: c.body_length)
        baseline = captures[len(captures) // 2]

        with self._cache_lock:
            self._baseline_cache[cache_key] = baseline

        return baseline

    def analyse(
        self,
        baseline: BaselineCapture,
        injected_url: str,
        payload: str,
        *,
        timeout: int = 12,
    ) -> Optional[ResponseDifferential]:
        """
        Fetch injected_url and compute differential against baseline.
        Returns None if the request fails.
        """
        try:
            t0 = time.time()
            resp = self.session.get(injected_url, timeout=timeout)
            elapsed = time.time() - t0
        except Exception as exc:
            _logger.debug(f"[RBA] Injected request failed {injected_url}: {exc!r}")
            return None

        return _DifferentialComputer.compute(baseline, resp, payload, elapsed)

    def analyse_post(
        self,
        baseline: BaselineCapture,
        url: str,
        payload: str,
        data: Dict[str, str],
        *,
        timeout: int = 12,
    ) -> Optional[ResponseDifferential]:
        """POST variant of analyse() for form injection."""
        try:
            t0 = time.time()
            resp = self.session.post(url, data=data, timeout=timeout)
            elapsed = time.time() - t0
        except Exception as exc:
            _logger.debug(f"[RBA] POST injected request failed {url}: {exc!r}")
            return None

        return _DifferentialComputer.compute(baseline, resp, payload, elapsed)

    def is_error_reflected(
        self,
        url: str,
        param: str,
        payload: str,
        *,
        timeout: int = 12,
    ) -> Tuple[bool, List[Tuple[str, str]]]:
        """
        Quick error reflection check: inject payload, return (found, matches).
        Does NOT compare to baseline — for fast pre-screening.
        """
        try:
            resp = self.session.get(url, timeout=timeout)
            body = resp.text or ""
        except Exception:
            return False, []

        db_hits = SQLErrorDetector.detect(body)
        fw_hits = FrameworkErrorDetector.detect(body)
        all_hits = db_hits + fw_hits
        return bool(all_hits), all_hits

    def batch_scan_errors(
        self,
        url: str,
        param: str,
        payloads: List[str],
        inject_fn: Any,
        *,
        timeout: int = 12,
    ) -> List[Tuple[str, ResponseDifferential]]:
        """
        Run all payloads and return list of (payload, diff) for reportable differentials.
        Baseline is captured once; payloads are tested sequentially.
        Uses baseline comparison to eliminate false positives from pages that already
        contain error text.
        """
        baseline = self.capture_baseline(url, param, timeout=timeout)
        if baseline is None:
            return []

        results: List[Tuple[str, ResponseDifferential]] = []
        for payload in payloads:
            injected = inject_fn(url, param, payload)
            diff = self.analyse(baseline, injected, payload, timeout=timeout)
            if diff and diff.is_reportable:
                results.append((payload, diff))
        return results

    def confidence_label(self, confidence: float) -> str:
        if confidence >= 0.85:
            return "confirmed"
        if confidence >= 0.70:
            return "high"
        if confidence >= 0.55:
            return "medium"
        return "low"


__all__ = [
    "BaselineCapture",
    "ResponseDifferential",
    "SQLErrorDetector",
    "FrameworkErrorDetector",
    "ResponseBehaviorAnalyzer",
]
