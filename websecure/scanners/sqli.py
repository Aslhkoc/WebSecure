import time
import logging
import random
import re
import statistics
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
        return any(kw in p for kw in ("SLEEP", "WAITFOR", "PG_SLEEP", "DBMS_PIPE"))

    def _is_union_payload(self, payload: str) -> bool:
        p = payload.upper()
        return "UNION" in p and "SELECT" in p

    # Union-based: responses that echo column values from UNION SELECT
    _UNION_MARKERS = [
        "wsunion1337",
        "WSUNION_MARKER",
        "@@version",
        "user()",
        "database()",
    ]

    # Max columns to try for UNION-based probing
    _UNION_MAX_COLS = 10

    def _try_union_based(self, url: str, param: str) -> Optional[Tuple[str, str]]:
        """
        Attempt UNION-based SQLi by probing column counts 1-N.
        Returns (payload, evidence) if a successful UNION injection is detected.
        """
        marker = "wsunion1337"
        for cols in range(1, self._UNION_MAX_COLS + 1):
            # Build NULL-padded union select with our marker in pos 1
            null_cols = ["NULL"] * cols
            null_cols[0] = f"'{marker}'"
            union_str = ",".join(null_cols)
            for quote in ("'", '"', ""):
                payload = f"{quote} UNION SELECT {union_str}-- -"
                test_url = self.inject_param(url, param, payload)
                try:
                    resp = self.session.get(test_url, timeout=10)
                    if marker in (resp.text or ""):
                        evidence = (
                            f"Union-based: marker '{marker}' reflected in response "
                            f"with {cols}-column UNION SELECT"
                        )
                        return payload, evidence
                except _requests.exceptions.RequestException as exc:
                    logger.debug(f"[SQLi] Union probe failed for cols={cols}: {exc!r}")
                    continue
        return None

    # Boolean-blind payloads: (true_payload, false_payload)
    _BOOL_PAIRS: List[Tuple[str, str]] = [
        ("' AND 1=1--",   "' AND 1=2--"),
        ("' AND 'a'='a",  "' AND 'a'='b"),
        ("\" AND 1=1--",  "\" AND 1=2--"),
        ("1 AND 1=1",     "1 AND 1=2"),
        ("' OR 1=1--",    "' OR 1=2--"),
    ]
    # Minimum absolute difference (bytes) to consider a boolean-blind hit real.
    # The dynamic stddev guard below is the primary gate; this is a hard floor.
    _BOOL_MIN_DIFF_BYTES = 50

    def _measure_natural_variation(self, url: str, n: int = 4) -> Tuple[float, float]:
        """
        Sample n benign baseline requests and return (mean_len, stddev_len).
        This captures dynamic content churn (CSRF tokens, timestamps, ads, etc.)
        so we never flag normal variation as a boolean difference.
        """
        lengths: List[int] = []
        for _ in range(n):
            try:
                r = self.session.get(url, timeout=10)
                lengths.append(len(r.text))
            except _requests.exceptions.RequestException:
                pass
        if len(lengths) < 2:
            # Fallback: no variation data — use a conservative 15% guard
            mean = lengths[0] if lengths else 0
            return float(mean), float(mean) * 0.15
        mean = statistics.mean(lengths)
        stdev = statistics.stdev(lengths)
        return mean, stdev

    def _is_boolean_blind(self, url: str, param: str,
                          baseline_len: int) -> Optional[Tuple[str, str]]:
        """
        Compare TRUE vs FALSE condition response lengths.

        Detection requires ALL of:
          1. |len_true - len_false| >= _BOOL_MIN_DIFF_BYTES  (hard floor)
          2. diff > natural_mean + 3 * natural_stdev          (dynamic guard)
          3. Cross-validation: a second independent pair confirms the pattern
             (len_true2 ~ len_true AND len_false2 ~ len_false)

        Returns (payload, evidence) only when all gates pass.
        """
        # Measure natural content churn (4 benign requests)
        nat_mean, nat_stdev = self._measure_natural_variation(url)
        # Gate: signal must exceed natural churn by 3 sigma
        dynamic_threshold = nat_mean + 3.0 * nat_stdev

        candidate: Optional[Tuple[str, str, int, int]] = None  # (true_pl, false_pl, len_t, len_f)

        for true_pl, false_pl in self._BOOL_PAIRS:
            try:
                r_true  = self.session.get(self.inject_param(url, param, true_pl),  timeout=10)
                r_false = self.session.get(self.inject_param(url, param, false_pl), timeout=10)
                len_true  = len(r_true.text)
                len_false = len(r_false.text)
                diff = abs(len_true - len_false)

                if diff < self._BOOL_MIN_DIFF_BYTES:
                    continue
                if diff <= dynamic_threshold:
                    continue

                # First-pass hit — record for cross-validation
                candidate = (true_pl, false_pl, len_true, len_false)
                break
            except _requests.exceptions.RequestException as exc:
                logger.debug(f"[SQLi] Boolean probe error ({url}): {exc!r}")
                continue

        if candidate is None:
            return None

        true_pl, false_pl, len_true1, len_false1 = candidate

        # Cross-validation: repeat the winning pair independently
        try:
            r_true2  = self.session.get(self.inject_param(url, param, true_pl),  timeout=10)
            r_false2 = self.session.get(self.inject_param(url, param, false_pl), timeout=10)
            len_true2  = len(r_true2.text)
            len_false2 = len(r_false2.text)

            # TRUE responses should be similar to each other
            true_stable  = abs(len_true1  - len_true2)  <= max(nat_stdev * 2, 30)
            # FALSE responses should be similar to each other
            false_stable = abs(len_false1 - len_false2) <= max(nat_stdev * 2, 30)
            # TRUE and FALSE responses must still differ
            cross_diff   = abs(len_true2 - len_false2)

            if not (true_stable and false_stable and cross_diff >= self._BOOL_MIN_DIFF_BYTES):
                logger.debug(
                    f"[SQLi] Boolean-blind cross-validation FAILED for {url} param={param} "
                    f"true_stable={true_stable} false_stable={false_stable} cross_diff={cross_diff}"
                )
                return None

        except _requests.exceptions.RequestException as exc:
            logger.debug(f"[SQLi] Boolean cross-validation error ({url}): {exc!r}")
            return None

        diff_final = abs(len_true2 - len_false2)
        evidence = (
            f"Boolean-blind (cross-validated): "
            f"TRUE={len_true1}B/{len_true2}B, FALSE={len_false1}B/{len_false2}B, "
            f"diff={diff_final}B | natural_stdev={nat_stdev:.1f}B, threshold={dynamic_threshold:.0f}B"
        )
        return true_pl, evidence

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
            # Error-based + time-based (all payloads in parallel)
            self._test_param_parallel(
                url, param_name, baseline_errors, time_threshold
            )

            # Union-based detection — independent of error results
            union_result = self._try_union_based(url, param_name)
            if union_result:
                payload, evidence = union_result
                self.report_finding(
                    vuln_type="SQL Injection (Union-Based)",
                    url=url,
                    param=param_name,
                    payload=payload,
                    severity="Critical",
                    evidence=evidence,
                )

            # Boolean-blind fallback — independent, always run
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

        # JSON body injection — test params as JSON payload
        self._scan_json_body(url, params, baseline_errors, time_threshold)

        # HTTP header injection — inject into common headers
        self._scan_header_injection(url, baseline_errors, time_threshold)

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
                # Test ALL inputs — never stop early; multi-param forms may have
                # several vulnerable fields (e.g. username AND password both injectable)
                self._test_form_param_parallel(
                    action, method, inputs, p_name, payloads,
                    baseline_errors, time_threshold
                )

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
    # JSON body injection
    # -------------------------------------------------------------------------

    # Lightweight set of probes used exclusively for JSON/header injection.
    # Full wordlist already covers GET/POST form params; these are targeted
    # at the common REST API patterns where injection often lives undetected.
    _SQLI_JSON_PROBES = [
        "' OR '1'='1",
        "' OR 1=1--",
        "\" OR \"1\"=\"1",
        "1' AND SLEEP(3)--",
        "1 AND 1=CONVERT(int,@@version)--",
        "1; SELECT pg_sleep(3)--",
        "' AND extractvalue(1,concat(0x7e,version()))--",
        "ws_so_' OR '1'='1",   # second-order marker
    ]

    def _scan_json_body(
        self,
        url: str,
        params: List[Tuple[str, str]],
        baseline_errors: set,
        time_threshold: float,
    ) -> None:
        """
        Re-send the same URL parameters as a JSON body (Content-Type: application/json).
        Many REST APIs accept both forms; WAFs often miss JSON-body injection.
        """
        if not params:
            return
        base_json = {k: v for k, v in params}
        for key in list(base_json.keys()):
            for payload in self._SQLI_JSON_PROBES:
                probe_json = dict(base_json)
                probe_json[key] = payload
                t0 = time.time()
                try:
                    res = self.session.post(
                        url,
                        json=probe_json,
                        headers={"Content-Type": "application/json"},
                        timeout=12,
                    )
                    elapsed = time.time() - t0
                except _requests.exceptions.RequestException as exc:
                    logger.debug(f"[SQLi/JSON] probe error {url}: {exc!r}")
                    continue

                new_errors = self._extract_error_fingerprints(res.text) - baseline_errors
                if new_errors:
                    db = next(iter(new_errors))[0]
                    self.report_finding(
                        vuln_type="SQL Injection (JSON Body/Error)",
                        url=url,
                        param=key,
                        payload=payload,
                        severity="Critical",
                        evidence=f"DB: {db} — JSON body injection",
                    )
                    break  # one finding per key is enough

                if self._is_time_payload(payload) and elapsed > time_threshold:
                    self.report_finding(
                        vuln_type="SQL Injection (JSON Body/Time)",
                        url=url,
                        param=key,
                        payload=payload,
                        severity="Critical",
                        evidence=(
                            f"Response {elapsed:.2f}s > threshold {time_threshold:.2f}s "
                            f"(JSON body)"
                        ),
                    )
                    break

    # -------------------------------------------------------------------------
    # HTTP header injection
    # -------------------------------------------------------------------------

    _INJECTABLE_HEADERS = [
        "X-Forwarded-For",
        "X-Real-IP",
        "Referer",
        "User-Agent",
        "X-Originating-IP",
        "X-Remote-IP",
        "X-Remote-Addr",
        "X-Client-IP",
        "CF-Connecting-IP",
        "True-Client-IP",
    ]
    _HEADER_PROBES = [
        "' OR '1'='1",
        "' OR 1=1--",
        "1' AND SLEEP(3)--",
        "' AND extractvalue(1,concat(0x7e,version()))--",
        "1 AND 1=CONVERT(int,@@version)--",
    ]

    def _scan_header_injection(
        self,
        url: str,
        baseline_errors: set,
        time_threshold: float,
    ) -> None:
        """
        Inject SQLi payloads into common HTTP headers (X-Forwarded-For, Referer, etc.).
        Applications that log or DB-store request metadata are frequently vulnerable here.
        """
        for header in self._INJECTABLE_HEADERS:
            for payload in self._HEADER_PROBES:
                t0 = time.time()
                try:
                    res = self.session.get(
                        url,
                        headers={header: payload},
                        timeout=12,
                    )
                    elapsed = time.time() - t0
                except _requests.exceptions.RequestException as exc:
                    logger.debug(f"[SQLi/Header] probe error {url} header={header}: {exc!r}")
                    continue

                new_errors = self._extract_error_fingerprints(res.text) - baseline_errors
                if new_errors:
                    db = next(iter(new_errors))[0]
                    self.report_finding(
                        vuln_type="SQL Injection (Header/Error)",
                        url=url,
                        param=f"[Header] {header}",
                        payload=payload,
                        severity="Critical",
                        evidence=f"DB: {db} — header injection via {header}",
                    )
                    break

                if self._is_time_payload(payload) and elapsed > time_threshold:
                    self.report_finding(
                        vuln_type="SQL Injection (Header/Time)",
                        url=url,
                        param=f"[Header] {header}",
                        payload=payload,
                        severity="Critical",
                        evidence=(
                            f"Response {elapsed:.2f}s > threshold {time_threshold:.2f}s "
                            f"(header: {header})"
                        ),
                    )
                    break

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
