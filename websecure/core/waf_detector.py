"""
websecure.core.waf_detector
----------------------------
WAF fingerprinting via probe-response analysis.
Identifies vendor, confidence level, and recommends bypass strategies.
"""
from __future__ import annotations
import logging
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

_logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# WAF Signatures
# ---------------------------------------------------------------------------
# Each entry: { "headers": [(name, pattern)], "body": [pattern], "cookies": [name],
#               "status": [int], "bypass_strategies": [...] }
_WAF_SIGNATURES: Dict[str, Dict] = {
    "cloudflare": {
        "headers": [
            ("server", r"cloudflare"),
            ("cf-ray", r".+"),
            ("cf-cache-status", r".+"),
        ],
        "body": [
            r"Attention Required! \| Cloudflare",
            r"Ray ID:",
            r"cloudflare\.com/5xx-error",
        ],
        "cookies": ["__cfduid", "cf_clearance", "__cf_bm"],
        "status": [403, 503],
        "bypass_strategies": [
            "chunked_encoding", "content_type_mismatch", "xff_internal_cidr",
            "unicode_normalization", "http2_pseudo_header_order",
            "tls_fingerprint_chrome", "random_path_suffix", "cf_clearance_wait",
        ],
    },
    "aws_waf": {
        "headers": [
            ("x-amzn-requestid", r".+"),
            ("x-amz-cf-id", r".+"),
        ],
        "body": [
            r"AWS WAF",
            r"Request blocked",
        ],
        "cookies": ["aws-waf-token", "AWSALB"],
        "status": [403],
        "bypass_strategies": [
            "header_injection_variants", "param_fragmentation",
            "json_unicode_escape", "hpp_duplicate_params",
            "overlong_utf8", "double_url_encoding",
        ],
    },
    "imperva": {
        "headers": [
            ("x-iinfo", r".+"),
            ("x-cdn", r"Imperva"),
            ("server", r"Imperva"),
        ],
        "body": [
            r"Incapsula incident ID",
            r"Request unsuccessful\. Incapsula",
            r"_Incapsula_Resource",
        ],
        "cookies": ["visid_incap", "incap_ses"],
        "status": [403],
        "bypass_strategies": [
            "chunked_small_chunks", "path_parameter_pollution",
            "accept_header_rotation", "unicode_normalization",
            "referrer_spoofing", "newline_injection",
        ],
    },
    "akamai": {
        "headers": [
            ("server", r"AkamaiGHost"),
            ("x-check-cacheable", r".+"),
        ],
        "body": [
            r"Access Denied",
            r"Reference #\d+\.\w+\.\d+",
            r"akamai",
        ],
        "cookies": ["ak_bmsc", "bm_sz"],
        "status": [403],
        "bypass_strategies": [
            "xff_internal_cidr", "case_sensitivity_bypass",
            "double_url_encoding", "content_type_mismatch",
            "http2_pseudo_header_order",
        ],
    },
    "f5_bigip": {
        "headers": [
            ("server", r"BigIP"),
            ("x-wa-info", r".+"),
        ],
        "body": [
            r"The requested URL was rejected",
            r"F5 Networks",
        ],
        "cookies": ["TS[0-9a-f]{8}", "BIGipServer"],
        "status": [403],
        "bypass_strategies": [
            "chunked_encoding", "hpp_duplicate_params",
            "unicode_normalization", "path_parameter_pollution",
        ],
    },
    "modsecurity": {
        "headers": [
            ("server", r"mod_security"),
            ("x-webobjects-loadavg", r".+"),
        ],
        "body": [
            r"ModSecurity",
            r"Not Acceptable!.*?Apache",
            r"Mod_Security",
            r"406 Not Acceptable",
        ],
        "cookies": [],
        "status": [403, 406],
        "bypass_strategies": [
            "chunked_encoding", "content_type_mismatch",
            "overlong_utf8", "newline_injection",
            "case_sensitivity_bypass", "double_url_encoding",
        ],
    },
    "sucuri": {
        "headers": [
            ("server", r"Sucuri/Cloudproxy"),
            ("x-sucuri-id", r".+"),
            ("x-sucuri-cache", r".+"),
        ],
        "body": [
            r"Sucuri WebSite Firewall",
            r"Access Denied - Sucuri",
        ],
        "cookies": ["sucuri_cloudproxy_uuid"],
        "status": [403],
        "bypass_strategies": [
            "referrer_spoofing", "xff_internal_cidr",
            "unicode_normalization", "random_path_suffix",
        ],
    },
    "barracuda": {
        "headers": [
            ("server", r"barracuda"),
        ],
        "body": [
            r"Barracuda Web Application Firewall",
            r"bwf_bl",
        ],
        "cookies": ["barra_counter_session"],
        "status": [400, 403],
        "bypass_strategies": [
            "chunked_encoding", "hpp_duplicate_params",
            "content_type_mismatch",
        ],
    },
}

# Malicious probe payload — triggers most WAFs
_PROBE_PAYLOAD = "?id=1'+OR+1=1--&cmd=cat+/etc/passwd&path=../../../../etc/passwd"


@dataclass
class WAFProfile:
    vendor: str = "unknown"
    confidence: float = 0.0
    bypass_strategies: List[str] = field(default_factory=list)
    raw_response: Optional[Dict] = None

    @property
    def detected(self) -> bool:
        return self.confidence >= 0.3


class WAFDetector:
    """
    Detects WAF presence by sending a known-malicious probe request
    and scoring the response against vendor signature databases.
    """

    def __init__(self, timeout: int = 10):
        self.timeout = timeout

    def detect(self, url: str, session=None) -> WAFProfile:
        """
        Send probe and analyze response.
        Returns WAFProfile with detected vendor and confidence.
        """
        probe_url = url.rstrip("/") + _PROBE_PAYLOAD
        headers, body, status, cookies = self._send_probe(probe_url, session)

        best_vendor = "unknown"
        best_score = 0.0
        best_strategies: List[str] = []

        for vendor, sig in _WAF_SIGNATURES.items():
            score = self._score_vendor(sig, headers, body, status, cookies)
            if score > best_score:
                best_score = score
                best_vendor = vendor
                best_strategies = sig.get("bypass_strategies", [])

        if best_score < 0.25:
            # Generic WAF detection (score for any anomalous response)
            if status in (403, 406, 429, 503) and body:
                best_vendor = "generic"
                best_score = 0.30
                best_strategies = ["chunked_encoding", "unicode_normalization",
                                   "xff_internal_cidr", "double_url_encoding"]

        profile = WAFProfile(
            vendor=best_vendor,
            confidence=round(min(best_score, 1.0), 2),
            bypass_strategies=best_strategies,
        )
        if profile.detected:
            _logger.info(f"[WAFDetector] Detected: {best_vendor} (confidence={profile.confidence:.0%})")
        else:
            _logger.debug("[WAFDetector] No WAF detected")
        return profile

    def _send_probe(self, url: str, session) -> Tuple[Dict, str, int, Dict]:
        """Send probe request and return (headers, body, status, cookies)."""
        headers: Dict = {}
        body = ""
        status = 0
        cookies: Dict = {}

        try:
            if session:
                resp = session.get(url, timeout=self.timeout, allow_redirects=True)
            else:
                import requests as _req
                resp = _req.get(url, timeout=self.timeout, allow_redirects=True,
                                headers={"User-Agent": "Mozilla/5.0 (compatible; WebSecure/3.0)"})
            headers = dict(resp.headers)
            body = resp.text[:4096]
            status = resp.status_code
            cookies = dict(resp.cookies)
        except Exception as e:
            _logger.debug(f"[WAFDetector] Probe failed: {e}")

        return headers, body, status, cookies

    def _score_vendor(self, sig: Dict, headers: Dict, body: str,
                      status: int, cookies: Dict) -> float:
        score = 0.0
        headers_lower = {k.lower(): v.lower() for k, v in headers.items()}

        # Header name presence
        for h_name, h_pattern in sig.get("headers", []):
            val = headers_lower.get(h_name.lower(), "")
            if val and re.search(h_pattern, val, re.I):
                score += 0.35

        # Body patterns
        for bp in sig.get("body", []):
            if re.search(bp, body, re.I | re.S):
                score += 0.25

        # Cookie presence
        for c_name in sig.get("cookies", []):
            for ck in cookies:
                if re.search(c_name, ck, re.I):
                    score += 0.2
                    break

        # Status code match
        if status in sig.get("status", []):
            score += 0.1

        return score


# Convenience function
def detect_waf(url: str, session=None, timeout: int = 10) -> WAFProfile:
    """Detect WAF at the given URL. Returns WAFProfile."""
    detector = WAFDetector(timeout=timeout)
    return detector.detect(url, session=session)
