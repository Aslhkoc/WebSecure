import time
import logging
import random
import re
from typing import List, Dict, Any, Optional, Tuple
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse

import requests as _requests

from websecure.scanners.base import BaseScanner
from websecure.core.mutator import Mutator

logger = logging.getLogger(__name__)

class SQLInjectionScanner(BaseScanner):
    """
    Robust SQL Injection Scanner.
    Features:
    - Error-based detection with baseline comparison (no false positives)
    - Boolean-based blind detection (content length/hash comparison)
    - Time-based blind detection with dynamic threshold (baseline + delta)
    - WAF Evasion integration via Mutator
    - Parallel payload testing via BaseScanner.run_parallel_probes()
    """

    name = "sqli"
    phase = "offensive"

    MAX_WORKERS = 5          # parallel threads for payload testing
    TIME_DELTA = 3.0         # seconds above baseline to flag time-based
    MAX_FORM_PAYLOADS = 12   # payload cap per form input

    # Signatures for Error-Based SQLi
    ERRORS = {
        "MySQL": (
            r"SQL syntax.*MySQL", r"Warning.*mysql_.*",
            r"valid MySQL result", r"MySqlClient\.",
        ),
        "PostgreSQL": (
            r"PostgreSQL.*ERROR", r"Warning.*\Wpg_.*",
            r"valid PostgreSQL result", r"Npgsql\.",
        ),
        "Microsoft SQL Server": (
            r"Driver.* SQL[\-\_\ ]*Server", r"OLE DB.* SQL Server",
            r"(\W|\A)SQL Server.*Driver", r"Warning.*mssql_.*",
            r"(\W|\A)SQL Server.*[0-9a-fA-F]{8}",
            r"(?s)Exception.*\WSystem\.Data\.SqlClient\.",
        ),
        "Microsoft Access": (
            r"Microsoft Access Driver", r"JET Database Engine",
            r"Access Database Engine",
        ),
        "Oracle": (
            r"\bORA-[0-9][0-9][0-9][0-9]", r"Oracle error",
            r"Oracle.*Driver", r"Warning.*\Woci_.*", r"Warning.*\Wora_.*",
        ),
        "IBM DB2": (r"CLI Driver.*DB2", r"DB2 SQL error", r"\bdb2_\w+\("),
        "SQLite": (
            r"SQLite/JDBCDriver", r"SQLite.Exception",
            r"System.Data.SQLite.SQLiteException", r"Warning.*sqlite_.*",
            r"Warning.*SQLite3::", r"\[SQLITE_ERROR\]",
        ),
        "Sybase": (
            r"(?i)Sybase message", r"Sybase.*Server message",
            r"SybSQLException",
        ),
    }

    def __init__(self, session=None, results=None, debug=False):
        super().__init__(session, results, debug)
        self.payloads = self._load_payloads()

    def _load_payloads(self) -> List[str]:
        """Loads SQLi payloads. Falls back to built-in list if wordlist unavailable."""
        try:
            from websecure.core.payloads import get_payloads
            loaded = get_payloads("sqli")
            if loaded:
                return loaded
        except (ImportError, OSError, ValueError) as exc:
            logger.warning(f"[SQLi] Could not load external payloads, using built-in: {exc!r}")
        return [
            "'", '"', "')", '");',
            "' OR '1'='1", '" OR "1"="1',
            "' OR 1=1--", '" OR 1=1--',
            "' UNION SELECT 1,2,3--", '" UNION SELECT 1,2,3--',
            "' AND 1=0 UNION SELECT 1,version()--",
            "'; WAITFOR DELAY '0:0:5'--",   # MSSQL time-based
            "'; SELECT SLEEP(5)--",          # MySQL time-based
            "' || pg_sleep(5)--",            # PostgreSQL time-based
        ]

    def _extract_error_fingerprints(self, text: str) -> set:
        """Returns the set of (db, regex) pairs matching the given text."""
        found = set()
        for db, regexes in self.ERRORS.items():
            for r in regexes:
                if re.search(r, text, re.I):
                    found.add((db, r))
        return found

    def _is_time_payload(self, payload: str) -> bool:
        p = payload.upper()
        return any(kw in p for kw in ("SLEEP", "WAITFOR", "PG_SLEEP"))

    # Boolean-blind payloads: (true_payload, false_payload)
    _BOOL_PAIRS: List[Tuple[str, str]] = [
        ("' AND 1=1--",   "' AND 1=2--"),
        ("' AND 'a'='a",  "' AND 'a'='b"),
        ("\" AND 1=1--",  "\" AND 1=2--"),
        ("1 AND 1=1",     "1 AND 1=2"),
        ("' OR 1=1--",    "' OR 1=2--"),
    ]
    _BOOL_DIFF_THRESHOLD = 0.12  # 12% content-length change flags as vuln

    def _is_boolean_blind(self, url: str, param: str,
                          baseline_len: int) -> Optional[Tuple[str, str]]:
        """Compare TRUE vs FALSE condition response lengths. Returns (payload, evidence) if vuln."""
        for true_pl, false_pl in self._BOOL_PAIRS:
            try:
                true_url  = self.inject_param(url, param, true_pl)
                false_url = self.inject_param(url, param, false_pl)
                r_true  = self.session.get(true_url,  timeout=10)
                r_false = self.session.get(false_url, timeout=10)
                len_true  = len(r_true.text)
                len_false = len(r_false.text)
                diff_tf = abs(len_true - len_false)
                if baseline_len > 0 and diff_tf / max(baseline_len, 1) >= self._BOOL_DIFF_THRESHOLD:
                    evidence = (
                        f"Boolean-blind: TRUE response={len_true}B "
                        f"FALSE response={len_false}B diff={diff_tf}B "
                        f"({diff_tf/max(baseline_len,1)*100:.1f}% change)"
                    )
                    return true_pl, evidence
            except _requests.exceptions.Timeout as exc:
                logger.debug(f"[SQLi] Boolean-blind probe timed out for {url}: {exc!r}")
                continue
            except _requests.exceptions.ConnectionError as exc:
                logger.debug(f"[SQLi] Boolean-blind probe connection error for {url}: {exc!r}")
                continue
            except _requests.exceptions.RequestException as exc:
                logger.warning(f"[SQLi] Boolean-blind probe failed for {url}: {exc!r}")
                continue
        return None

    def run(self, url, **kwargs):
        urls = url if isinstance(url, list) else [url]
        for u in urls:
            self.scan_url(u)
            self.scan_cmdi_url(u)

        pages_with_forms = self.results.get("forms_meta", [])
        if pages_with_forms:
            all_forms = []
            for page in pages_with_forms:
                if "forms" in page:
                    all_forms.extend(page["forms"])
            if all_forms:
                self.scan_forms(all_forms)

    def scan_url(self, url: str):
        parsed = urlparse(url)
        params = parse_qsl(parsed.query)
        if not params:
            return

        logger.info(f"[SQLi] Scanning URL params: {url}")

        # Baseline — proper error handling via fetch_baseline()
        t0 = time.time()
        baseline_resp = self.fetch_baseline(url, timeout=10)
        if not baseline_resp:
            return
        baseline_time = time.time() - t0
        baseline_errors = self._extract_error_fingerprints(baseline_resp.text)
        time_threshold = baseline_time + self.TIME_DELTA
        baseline_len = len(baseline_resp.text) if baseline_resp.text else 0

        for param_name, _ in params:
            found = self._test_param_parallel(
                url, param_name, baseline_errors, time_threshold
            )
            if found:
                break

            # Boolean-blind fallback
            bool_result = self._is_boolean_blind(url, param_name, baseline_len)
            if bool_result:
                payload, evidence = bool_result
                self.report_finding(
                    vuln_type="SQL Injection (Boolean-Blind)",
                    url=url,
                    param=param_name,
                    payload=payload,
                    severity="Critical",
                    evidence=evidence,
                )
                break

    def _test_param_parallel(
        self,
        url: str,
        param_name: str,
        baseline_errors: set,
        time_threshold: float,
    ) -> bool:
        """Tests all payloads for one parameter using a thread pool. Returns True if vuln found."""
        def probe(payload: str) -> Optional[Dict]:
            if random.random() < 0.3:
                mutated = Mutator.mutate_sql(payload)
                curr = random.choice(mutated) if mutated else payload
            else:
                curr = payload

            injected = self.inject_param(url, param_name, curr)
            t0 = time.time()
            try:
                res = self.session.get(injected, timeout=12)
                elapsed = time.time() - t0
            except _requests.exceptions.Timeout as exc:
                logger.debug(f"[SQLi] Probe timed out for {injected}: {exc!r}")
                return None
            except _requests.exceptions.ConnectionError as exc:
                logger.debug(f"[SQLi] Probe connection error for {injected}: {exc!r}")
                return None
            except _requests.exceptions.RequestException as exc:
                logger.warning(f"[SQLi] Probe request failed for {injected}: {exc!r}")
                return None

            # Error-based: only flag NEW errors not seen in baseline
            new_errors = self._extract_error_fingerprints(res.text) - baseline_errors
            if new_errors:
                db = next(iter(new_errors))[0]
                return {
                    "vuln_type": "SQL Injection (Error)",
                    "url": url,
                    "param": param_name,
                    "payload": curr,
                    "evidence": f"DB: {db} — new error signature in response",
                }

            # Time-based
            if self._is_time_payload(curr) and elapsed > time_threshold:
                return {
                    "vuln_type": "SQL Injection (Time-Based)",
                    "url": url,
                    "param": param_name,
                    "payload": curr,
                    "evidence": f"Response {elapsed:.2f}s > threshold {time_threshold:.2f}s",
                }
            return None

        hits = self.run_parallel_probes(probe, self.payloads, max_workers=self.MAX_WORKERS)
        for hit in hits:
            self.report_finding(severity="Critical", **hit)
        return bool(hits)

    def scan_forms(self, forms: List[Dict]):
        logger.info(f"[SQLi] Scanning {len(forms)} forms...")
        for form in forms:
            action = form.get("action")
            method = (form.get("method") or "GET").upper()
            inputs = form.get("inputs", [])
            if not action or not inputs:
                continue

            skipped = {"submit", "button", "image", "reset", "file", "checkbox", "radio"}
            fuzzable = [i for i in inputs if i.get("type", "text") not in skipped]

            # Form baseline
            base_data = {i.get("name"): i.get("value", "") for i in inputs if i.get("name")}
            t0 = time.time()
            baseline_resp = self.fetch_baseline(action, method=method, data=base_data, timeout=10)
            baseline_time = time.time() - t0
            baseline_errors: set = set()
            if baseline_resp:
                baseline_errors = self._extract_error_fingerprints(baseline_resp.text)

            time_threshold = baseline_time + self.TIME_DELTA
            payloads = self.payloads[:self.MAX_FORM_PAYLOADS]

            for inp in fuzzable:
                p_name = inp.get("name")
                if not p_name:
                    continue
                found = self._test_form_param_parallel(
                    action, method, inputs, p_name, payloads,
                    baseline_errors, time_threshold
                )
                if found:
                    break

    def _test_form_param_parallel(
        self,
        action: str,
        method: str,
        inputs: List[Dict],
        p_name: str,
        payloads: List[str],
        baseline_errors: set,
        time_threshold: float,
    ) -> bool:
        base_data = {i.get("name"): i.get("value", "") for i in inputs if i.get("name")}

        def probe(payload: str) -> Optional[Dict]:
            form_data = dict(base_data)
            form_data[p_name] = payload
            t0 = time.time()
            try:
                if method == "POST":
                    res = self.session.post(action, data=form_data, timeout=12)
                else:
                    res = self.session.get(action, params=form_data, timeout=12)
                elapsed = time.time() - t0
            except _requests.exceptions.Timeout as exc:
                logger.debug(f"[SQLi] Form probe timed out for {action}: {exc!r}")
                return None
            except _requests.exceptions.ConnectionError as exc:
                logger.debug(f"[SQLi] Form probe connection error for {action}: {exc!r}")
                return None
            except _requests.exceptions.RequestException as exc:
                logger.warning(f"[SQLi] Form probe failed for {action}: {exc!r}")
                return None

            new_errors = self._extract_error_fingerprints(res.text) - baseline_errors
            if new_errors:
                db = next(iter(new_errors))[0]
                return {
                    "vuln_type": "SQLi (Form/Error)",
                    "url": action,
                    "param": p_name,
                    "payload": payload,
                    "evidence": f"DB: {db}",
                }

            if self._is_time_payload(payload) and elapsed > time_threshold:
                return {
                    "vuln_type": "SQLi (Form/Time)",
                    "url": action,
                    "param": p_name,
                    "payload": payload,
                    "evidence": f"Response {elapsed:.2f}s > threshold {time_threshold:.2f}s",
                }
            return None

        hits = self.run_parallel_probes(probe, payloads, max_workers=self.MAX_WORKERS)
        for hit in hits:
            self.report_finding(severity="Critical", **hit)
        return bool(hits)

    # -------------------------------------------------------------------------
    # OS Command Injection — FAZ 6.1: CmdiScanner'a delege edildi
    # -------------------------------------------------------------------------

    def scan_cmdi_url(self, url: str) -> bool:
        """
        OS Command Injection taraması.
        FAZ 6.1'de logic websecure.scanners.cmdi.CmdiScanner'a taşındı.
        Geriye dönük uyumluluk için bu metod hâlâ çağrılabilir.
        """
        try:
            from websecure.scanners.cmdi import CmdiScanner
            cmdi = CmdiScanner(
                session=self.session,
                results=self.results,
                debug=self.debug,
            )
            return cmdi.scan_url(url)
        except ImportError:
            logger.warning("[SQLi] cmdi modülü yüklenemedi, CMDI taraması atlanıyor")
            return False


def run(url, session=None, results=None, debug=False, **kwargs):
    scanner = SQLInjectionScanner(session, results, debug)
    scanner.run(url)
