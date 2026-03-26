"""
websecure.scanners.cmdi
------------------------
OS Command Injection (CMDI) zafiyet taraması.

FAZ 6.1: sqli.py'deki CMDI kodu bu modüle taşındı.
sqli.py hâlâ `scan_cmdi_url()` metodunu taşır; bu modül ise bağımsız
CmdiScanner sınıfı ve plugin API'si sunar.

Strateji:
  1. URL parametrelerine OS komut enjeksiyonu payload'ları enjekte et
  2. Yanıtta komut çıktısı desenleri ara (error-based + time-based)
  3. Paralel probe ile hızlı tarama, BaseScanner.run_parallel_probes()
"""
from __future__ import annotations

import logging
import re
import time
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qsl, urlparse, urlencode, urlunparse

import requests as _requests

from websecure.scanners.base import BaseScanner

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Payload ve detection tanımları
# ---------------------------------------------------------------------------

_CMDI_PAYLOADS: List[Tuple[str, str]] = [
    # (payload, technique)
    ("; echo CMDI_UNIX_$(id)",             "unix_echo"),
    ("| echo CMDI_UNIX_$(id)",             "unix_pipe"),
    ("`echo CMDI_UNIX_$(whoami)`",         "unix_backtick"),
    ("$(echo CMDI_UNIX_$(id))",            "unix_subshell"),
    ("' ; echo CMDI_UNIX_$(id) #",         "unix_quote_escape"),
    ("\" ; echo CMDI_UNIX_$(id) #",        "unix_dquote_escape"),
    ("& echo CMDI_WIN_%USERNAME%",         "windows_amp"),
    ("| echo CMDI_WIN_%COMPUTERNAME%",     "windows_pipe"),
    ("; sleep 5",                          "unix_time"),
    ("| sleep 5",                          "unix_time_pipe"),
    ("& timeout /T 5 /NOBREAK",            "windows_time"),
    ("; cat /etc/passwd",                  "unix_file_read"),
    ("| cat /etc/passwd",                  "unix_file_read_pipe"),
    ("& type C:\\Windows\\win.ini",        "windows_file_read"),
]

_CMDI_SUCCESS_PATTERNS: List[Tuple[str, str]] = [
    (r"uid=\d+\(.*?\)\s+gid=\d+",          "Unix id output — command execution confirmed"),
    (r"root:.*:0:0:",                        "/etc/passwd read — LFI/CMDI confirmed"),
    (r"CMDI_UNIX_",                          "Echo marker reflected — command injection confirmed"),
    (r"\[extensions\].*for 16\-bit app",    "Windows win.ini read — CMDI confirmed"),
    (r"CMDI_WIN_\S+",                        "Windows env variable reflected — CMDI confirmed"),
    (r"(?i)(cannot run program|execvp|/bin/sh|cmd\.exe)", "Shell execution error leak"),
]

MAX_WORKERS = 5
REQUEST_TIMEOUT = 12
TIME_DELTA = 3.0  # seconds above baseline to flag time-based


# ---------------------------------------------------------------------------
# CmdiScanner
# ---------------------------------------------------------------------------

class CmdiScanner(BaseScanner):
    """
    OS Command Injection scanner.
    BaseScanner'dan türetilir — session, results, report_finding ve
    run_parallel_probes BaseScanner'dan gelir.

    FAZ 6.1: sqli.py'deki CMDI logic'i bu sınıfa taşındı.
    """

    name = "cmdi"
    phase = "offensive"

    def run(self, target: str, **kwargs) -> None:
        """BaseScanner interface — delegates to scan()."""
        urls = kwargs.get("urls") or [target]
        for url in urls:
            self.scan_url(url)

    def scan_url(self, url: str) -> bool:
        """
        Bir URL'nin parametrelerini OS komut enjeksiyonuna karşı test eder.
        Returns True if a finding was reported, False otherwise.
        """
        parsed = urlparse(url)
        params = parse_qsl(parsed.query)
        if not params:
            return False

        logger.info(f"[CMDI] Scanning URL params: {url}")

        t0 = time.time()
        baseline_resp = self.fetch_baseline(url, timeout=10)
        if not baseline_resp:
            return False

        baseline_time = time.time() - t0
        baseline_text = baseline_resp.text or ""
        time_threshold = baseline_time + TIME_DELTA

        found = False
        for param_name, _ in params:
            if self._test_param(url, params, param_name, baseline_text, time_threshold):
                found = True
                break
        return found

    def _test_param(
        self,
        url: str,
        qs: list,
        param_name: str,
        baseline_text: str,
        time_threshold: float,
    ) -> bool:
        parsed = urlparse(url)

        def probe(args: Tuple[str, str]) -> Optional[Dict]:
            payload, technique = args
            new_qs = [(p, v + payload if p == param_name else v) for p, v in qs]
            t_url = urlunparse(parsed._replace(query=urlencode(new_qs)))
            t0 = time.time()
            try:
                resp = self.session.get(t_url, timeout=REQUEST_TIMEOUT)
                elapsed = time.time() - t0
            except _requests.exceptions.Timeout as exc:
                logger.debug(f"[CMDI] Probe timed out for {t_url}: {exc!r}")
                return None
            except _requests.exceptions.ConnectionError as exc:
                logger.debug(f"[CMDI] Probe connection error for {t_url}: {exc!r}")
                return None
            except _requests.exceptions.RequestException as exc:
                logger.warning(f"[CMDI] Probe request failed for {t_url}: {exc!r}")
                return None

            atk_text = resp.text or ""
            for pattern, description in _CMDI_SUCCESS_PATTERNS:
                if re.search(pattern, atk_text, re.I | re.S):
                    if not re.search(pattern, baseline_text, re.I | re.S):
                        return {
                            "vuln_type": "OS Command Injection",
                            "url": url,
                            "param": param_name,
                            "payload": payload,
                            "evidence": f"{description} (technique: {technique})",
                        }

            if "time" in technique and elapsed > time_threshold:
                return {
                    "vuln_type": "OS Command Injection (Time-Based)",
                    "url": url,
                    "param": param_name,
                    "payload": payload,
                    "evidence": (
                        f"Response {elapsed:.2f}s > threshold {time_threshold:.2f}s"
                    ),
                }
            return None

        hits = self.run_parallel_probes(probe, _CMDI_PAYLOADS, max_workers=MAX_WORKERS)
        for hit in hits:
            self.report_finding(severity="Critical", **hit)
        return bool(hits)


# ---------------------------------------------------------------------------
# Plugin API
# ---------------------------------------------------------------------------

def run(
    url: str,
    session=None,
    results=None,
    debug: bool = False,
    urls: Optional[List[str]] = None,
    **kwargs,
) -> None:
    scanner = CmdiScanner(session=session, results=results, debug=debug)
    targets = urls or [url]
    for target in targets:
        scanner.scan_url(target)
