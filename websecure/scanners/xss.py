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

        return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))

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
