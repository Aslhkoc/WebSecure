import logging
import random
import re
import string
from dataclasses import dataclass
from enum import Enum, auto
from typing import List, Dict, Optional, Tuple
from urllib.parse import urlparse, parse_qsl

import requests as _requests

from websecure.scanners.base import BaseScanner
from websecure.core.mutator import Mutator

logger = logging.getLogger(__name__)


class XSSScanner(BaseScanner):
    """
    Robust Cross-Site Scripting (XSS) Scanner.
    Features:
    - Reflected XSS detection via canary with baseline comparison
    - Context-aware payload selection
    - WAF Evasion/Polyglot support
    - Parallel payload testing via BaseScanner.run_parallel_probes()
    """

    name = "xss"
    phase = "offensive"

    MAX_WORKERS = 4        # parallel threads
    MAX_URL_PAYLOADS = 25  # cap for URL param fuzzing
    MAX_FORM_PAYLOADS = 8  # cap per form input

    def __init__(self, session=None, results: Dict = None, debug=False):
        super().__init__(session, results, debug)
        self.canary_prefix = "wsxss"

    def _gen_canary(self) -> str:
        token = "".join(random.choices(string.ascii_letters + string.digits, k=8))
        return f"{self.canary_prefix}{token}"

    def run(self, url, results: Dict = None, **kwargs):
        if results is not None:
            self.results = results

        if isinstance(url, list):
            for u in url:
                self.scan_url(u)
        else:
            self.scan_url(url)

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

        logger.info(f"[XSS] Scanning URL params: {url}")

        # Baseline — uses BaseScanner.fetch_baseline() (proper error logging)
        baseline_resp = self.fetch_baseline(url, timeout=8)
        baseline_text = baseline_resp.text if baseline_resp else ""

        for param_name, _ in params:
            canary = self._gen_canary()
            if canary in baseline_text:
                continue

            invoked = self.inject_param(url, param_name, canary)
            try:
                probe_res = self.session.get(invoked, timeout=8)
                if canary not in probe_res.text:
                    continue  # param not reflected, no point fuzzing
            except _requests.exceptions.Timeout as exc:
                logger.debug(f"[XSS] Canary probe timed out for {invoked}: {exc!r}")
                continue
            except _requests.exceptions.ConnectionError as exc:
                logger.debug(f"[XSS] Canary probe connection error for {invoked}: {exc!r}")
                continue
            except _requests.exceptions.RequestException as exc:
                logger.warning(f"[XSS] Canary probe failed for {invoked}: {exc!r}")
                continue

            # Parameter reflects input — fuzz with payloads
            self._fuzz_xss_parallel(url, param_name, baseline_text)

    def _fuzz_xss_parallel(self, url: str, param_name: str, baseline_text: str):
        payloads = self.get_smart_payloads("xss", param_name)
        if not payloads:
            payloads = [
                "<script>alert(1)</script>",
                "\"><script>alert(1)</script>",
                "<img src=x onerror=alert(1)>",
                "javascript:alert(1)",
                "'-alert(1)-'",
            ]
        payloads = list(payloads) + Mutator.mutate_polyglot("alert(1)")
        if len(payloads) > self.MAX_URL_PAYLOADS:
            payloads = random.sample(payloads, self.MAX_URL_PAYLOADS)

        def probe(payload: str) -> Optional[Dict]:
            actual = payload
            if random.random() < 0.2:
                mutated = Mutator.mutate_xss(payload)
                actual = random.choice(mutated) if mutated else payload

            invoked = self.inject_param(url, param_name, actual)
            try:
                res = self.session.get(invoked, timeout=8)
            except _requests.exceptions.Timeout as exc:
                logger.debug(f"[XSS] Probe timed out for {invoked}: {exc!r}")
                return None
            except _requests.exceptions.ConnectionError as exc:
                logger.debug(f"[XSS] Probe connection error for {invoked}: {exc!r}")
                return None
            except _requests.exceptions.RequestException as exc:
                logger.warning(f"[XSS] Probe request failed for {invoked}: {exc!r}")
                return None

            if actual in res.text and actual not in baseline_text:
                return {
                    "vuln_type": "Reflected XSS",
                    "url": url,
                    "param": param_name,
                    "payload": actual,
                }
            return None

        hits = self.run_parallel_probes(probe, payloads, max_workers=self.MAX_WORKERS)
        for hit in hits:
            self.report_finding(
                severity="High",
                evidence="Payload reflected in response (not in baseline)",
                **hit,
            )

    def scan_forms(self, forms: List[Dict]):
        logger.info(f"[XSS] Scanning {len(forms)} forms...")
        for form in forms:
            action = form.get("action")
            method = (form.get("method") or "GET").upper()
            inputs = form.get("inputs", [])
            if not action or not inputs:
                continue

            skipped = {"submit", "button", "image", "reset", "file", "checkbox", "radio"}
            fuzzable = [i for i in inputs if i.get("type", "text") not in skipped]

            # Form baseline — uses fetch_baseline() with proper logging
            base_data = {i.get("name"): i.get("value", "") for i in inputs if i.get("name")}
            baseline_resp = self.fetch_baseline(action, method=method, data=base_data, timeout=8)
            baseline_text = baseline_resp.text if baseline_resp else ""

            for inp in fuzzable:
                p_name = inp.get("name")
                if not p_name:
                    continue
                self._fuzz_form_param_parallel(
                    action, method, inputs, p_name, baseline_text
                )

    def _fuzz_form_param_parallel(
        self,
        action: str,
        method: str,
        inputs: List[Dict],
        p_name: str,
        baseline_text: str,
    ):
        payloads = self.get_smart_payloads("xss", p_name)
        if not payloads:
            payloads = ["<script>alert(1)</script>", "\"><script>alert(1)</script>"]
        payloads = payloads[:self.MAX_FORM_PAYLOADS]
        base_data = {i.get("name"): i.get("value", "") for i in inputs if i.get("name")}

        def probe(payload: str) -> Optional[Dict]:
            form_data = dict(base_data)
            form_data[p_name] = payload
            req_kw = self.prepare_injection(action, p_name, payload, method, data=form_data)
            try:
                if method == "POST":
                    res = self.session.post(
                        req_kw.get("url", action),
                        data=req_kw.get("data"),
                        timeout=8,
                    )
                else:
                    res = self.session.get(req_kw.get("url", action), timeout=8)
            except _requests.exceptions.Timeout as exc:
                logger.debug(f"[XSS] Form probe timed out for {action}: {exc!r}")
                return None
            except _requests.exceptions.ConnectionError as exc:
                logger.debug(f"[XSS] Form probe connection error for {action}: {exc!r}")
                return None
            except _requests.exceptions.RequestException as exc:
                logger.warning(f"[XSS] Form probe failed for {action}: {exc!r}")
                return None

            if payload in res.text and payload not in baseline_text:
                return {
                    "vuln_type": "Reflected XSS (Form)",
                    "url": action,
                    "param": p_name,
                    "payload": payload,
                }
            return None

        hits = self.run_parallel_probes(probe, payloads, max_workers=self.MAX_WORKERS)
        for hit in hits:
            self.report_finding(
                severity="High",
                evidence="Payload reflected in form response (not in baseline)",
                **hit,
            )


def run(url, session=None, results=None, debug=False, **kwargs):
    scanner = XSSScanner(session, results, debug)
    scanner.run(url, results=results, **kwargs)


# ===========================================================================
# MERGED FROM: websecure/core/reflection.py
# Adaptive Reflection Analyzer — context-aware XSS payload selection
# ===========================================================================
"""
Adaptive Reflection Analyzer for WebSecure (Level 3)

Bu modül, bir input'un HTTP yanıtında nereye yansıdığını (HTML Body, Attribute, Script vb.) analiz eder.
Bu sayede "context-aware" payload seçimi yapılabilir.
"""


class ReflectionType(Enum):
    NONE = auto()                   # Yansıma yok
    HTML_TEXT = auto()              # <div>INPUT</div>
    HTML_ATTR_DOUBLE = auto()       # <div class="INPUT">
    HTML_ATTR_SINGLE = auto()       # <div class='INPUT'>
    HTML_ATTR_UNQUOTED = auto()     # <div class=INPUT>
    SCRIPT_BLOCK = auto()           # <script>var x = "INPUT";</script>
    SCRIPT_QUOTED = auto()          # <script>var x = "INPUT";</script>
    COMMENT = auto()                # <!-- INPUT -->


@dataclass
class ReflectionPoints:
    canary: str
    contexts: List[ReflectionType]
    raw_response: str = ""


def analyze_reflection(response_text: str, canary: str) -> ReflectionPoints:
    """
    Verilen canary değerinin response içindeki konumlarını analiz eder.
    """
    if not response_text or canary not in response_text:
        return ReflectionPoints(canary, [ReflectionType.NONE], response_text)

    contexts = []

    script_blocks = re.findall(r'<script[^>]*>(.*?)</script>', response_text, re.DOTALL | re.IGNORECASE)
    in_script = False
    for block in script_blocks:
        if canary in block:
            in_script = True
            if f'"{canary}"' in block or f"'{canary}'" in block:
                contexts.append(ReflectionType.SCRIPT_QUOTED)
            else:
                contexts.append(ReflectionType.SCRIPT_BLOCK)
            break

    if not in_script:
        if re.search(f'="[^"]*{canary}[^"]*"', response_text):
            contexts.append(ReflectionType.HTML_ATTR_DOUBLE)
        elif re.search(f"='[^']*{canary}[^']*'", response_text):
            contexts.append(ReflectionType.HTML_ATTR_SINGLE)
        elif re.search(f'=[^"\'\\s>]*{canary}[^"\'\\s>]*', response_text):
            contexts.append(ReflectionType.HTML_ATTR_UNQUOTED)
        elif re.search(f'<!--.*{canary}.*-->', response_text, re.DOTALL):
            contexts.append(ReflectionType.COMMENT)
        else:
            contexts.append(ReflectionType.HTML_TEXT)

    return ReflectionPoints(canary, list(set(contexts)), response_text)


def get_payloads_for_context(ctx: ReflectionType) -> List[str]:
    """Bulunan bağlama göre en etkili payload'ları döndürür."""
    if ctx == ReflectionType.HTML_TEXT:
        return [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg/onload=alert(1)>",
        ]
    elif ctx == ReflectionType.HTML_ATTR_DOUBLE:
        return [
            '"><script>alert(1)</script>',
            '" onmouseover="alert(1)',
            '" autofocus onfocus="alert(1)',
        ]
    elif ctx == ReflectionType.HTML_ATTR_SINGLE:
        return [
            "'><script>alert(1)</script>",
            "' onmouseover='alert(1)",
            "' autofocus onfocus='alert(1)",
        ]
    elif ctx == ReflectionType.SCRIPT_BLOCK:
        return [
            ";alert(1);//",
            "alert(1);",
            "</script><script>alert(1)</script>",
        ]
    elif ctx == ReflectionType.SCRIPT_QUOTED:
        return [
            "';alert(1);//",
            '";alert(1);//',
            "\\';alert(1);//",
        ]
    elif ctx == ReflectionType.COMMENT:
        return ["--> <script>alert(1)</script>"]
    return []
