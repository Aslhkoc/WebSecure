"""
websecure.core.cvss
--------------------
CVSS v3.1 scoring for WebSecure findings.
Maps finding types to base vectors, adjusts for context (auth, WAF).
"""
from __future__ import annotations

import logging
from typing import Dict, Optional, Tuple

_logger = logging.getLogger(__name__)

try:
    from cvss import CVSS3
    _CVSS_AVAILABLE = True
except ImportError:
    _CVSS_AVAILABLE = False
    _logger.debug("[CVSS] cvss library not installed. pip install cvss")


# Base CVSS v3.1 vectors for each finding type
# Format: (vector_string, base_score_fallback)
_BASE_VECTORS: Dict[str, Tuple[str, float]] = {
    # Injection vulnerabilities
    "xss":                  ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
    "reflected xss":        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
    "dom xss":              ("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N", 4.7),
    "stored xss":           ("CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N", 5.4),
    "sql injection":        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
    "sqli":                 ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
    "blind sqli":           ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", 8.1),
    "nosql injection":      ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", 9.1),
    "ssti":                 ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
    "server-side template injection": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
    "command injection":    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),

    # Access control
    "idor":                 ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", 6.5),
    "horizontal privilege escalation": ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", 6.5),
    "vertical privilege escalation":   ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 8.8),
    "missing authentication":          ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
    "broken access control":           ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N", 8.1),

    # SSRF / XXE
    "ssrf":                 ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N", 9.3),
    "xxe":                  ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L", 8.6),

    # Request smuggling
    "request smuggling":    ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H", 9.0),
    "http request smuggling": ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H", 9.0),

    # JWT
    "jwt":                  ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", 9.1),
    "jwt algorithm none":   ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", 9.1),

    # CSRF
    "csrf":                 ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", 8.8),

    # TLS / Crypto
    "tls":                  ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", 5.9),
    "weak tls":             ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", 5.9),
    "expired certificate":  ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L", 6.5),
    "self-signed certificate": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N", 4.3),

    # Headers
    "missing csp":          ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
    "missing hsts":         ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", 5.9),
    "missing security header": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", 5.3),

    # File upload
    "file upload":          ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 8.8),
    "unrestricted file upload": ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 8.8),

    # Secrets / Information Disclosure
    "js secret exposure":   ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5),
    "hardcoded secret":     ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5),
    "sensitive file exposure": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5),

    # DoS
    "rate limit bypass":    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 7.5),

    # Default / Generic
    "generic":              ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N", 6.5),

    # XSS variants
    "xss account takeover":          ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N", 8.8),
    "xss -> account takeover (poc)": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N", 8.8),
    "reflected xss (form)":          ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
    "mxss (mutation xss)":           ("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N", 4.7),
    "csp bypass xss":                ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
    "dom clobbering":                ("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:N/A:N", 4.3),
    "blind xss (oob)":               ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
    "prototype pollution -> xss":    ("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N", 4.7),
    "trusted types bypass":          ("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N", 4.7),
    "template literal injection (xss/ssti)": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
    # SQLi confirmed variants
    "sql injection — db schema extracted": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
    "sql injection (sqlmap confirmed)":    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
    "sql injection (union-based)":         ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
    "sql injection (stacked query)":       ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
    "sql injection (oob dns — pending callback)": ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", 8.1),
}

# Remediation guidance for each category
_REMEDIATION: Dict[str, str] = {
    "xss": "Encode all user-controlled output. Implement a strict Content-Security-Policy. Use frameworks that auto-escape output.",
    "sql injection": "Use parameterized queries / prepared statements. Never concatenate user input into SQL. Apply principle of least privilege to DB accounts.",
    "ssti": "Avoid passing user input to template engines. If required, use sandbox mode. Update template engine to the latest version.",
    "ssrf": "Validate and whitelist allowed URLs. Block requests to internal networks (RFC1918). Use a deny-first egress firewall policy.",
    "xxe": "Disable external entity processing in XML parsers. Use JSON where possible. Validate XML schemas strictly.",
    "idor": "Enforce object-level authorization checks on every resource access. Use indirect references (UUIDs) instead of sequential IDs.",
    "csrf": "Implement CSRF tokens on all state-changing requests. Use SameSite=Strict cookies. Validate Origin/Referer headers.",
    "jwt": "Never use the 'none' algorithm. Validate the algorithm on the server side. Use strong secrets (>=256 bits) or RS256.",
    "request smuggling": "Normalize HTTP requests at the load balancer. Configure consistent timeout settings. Prefer HTTP/2 end-to-end.",
    "file upload": "Validate file type server-side using magic bytes. Store uploads outside webroot. Randomize filenames and serve via CDN.",
    "tls": "Disable TLS 1.0 and 1.1. Enable TLS 1.3. Use strong cipher suites (AEAD). Enable HSTS with a long max-age.",
    "default": "Review application logic, validate all inputs, apply principle of least privilege, and keep dependencies updated.",
}


def _normalize_type(finding_type: str) -> str:
    """Normalize finding type to lowercase for lookup."""
    return (finding_type or "").lower().strip()


def _lookup_vector(finding_type: str) -> Tuple[str, float]:
    """Look up CVSS vector and fallback score for a finding type."""
    t = _normalize_type(finding_type)
    # Exact match first
    if t in _BASE_VECTORS:
        return _BASE_VECTORS[t]
    # Partial match
    for key, val in _BASE_VECTORS.items():
        if key in t or t in key:
            return val
    return _BASE_VECTORS["generic"]


def _lookup_remediation(finding_type: str) -> str:
    """Look up remediation guidance."""
    t = _normalize_type(finding_type)
    for key, text in _REMEDIATION.items():
        if key in t:
            return text
    return _REMEDIATION["default"]


class CVSSScorer:
    """
    Calculates CVSS v3.1 scores for findings.
    Adjusts base vectors based on context (auth required, WAF presence).
    """

    def __init__(self, auth_required: bool = False, waf_detected: bool = False):
        self.auth_required = auth_required  # If True, finding requires auth -> adjust PR
        self.waf_detected = waf_detected    # If True, adjust AC

    def score(self, finding: Dict) -> Dict:
        """
        Score a single finding. Returns finding dict with added CVSS fields.
        Does NOT modify the input dict - returns a copy with new fields.
        """
        result = dict(finding)
        finding_type = finding.get("type", "")
        vector_str, fallback_score = _lookup_vector(finding_type)

        # Adjust vector based on context
        vector_str = self._adjust_vector(vector_str, finding)

        base_score = fallback_score
        severity_label = _severity_label(fallback_score)

        if _CVSS_AVAILABLE:
            try:
                c = CVSS3(vector_str)
                base_score = float(c.base_score)
                severity_label = c.severities()[0] if c.severities() else _severity_label(base_score)
            except Exception as e:
                _logger.debug(f"[CVSS] Calculation failed for {vector_str}: {e}")

        result["cvss_score"] = round(base_score, 1)
        result["cvss_vector"] = vector_str
        result["cvss_severity"] = severity_label
        result["remediation"] = _lookup_remediation(finding_type)

        return result

    def score_all(self, findings: list) -> list:
        """Score a list of findings. Returns new list with CVSS data added."""
        return [self.score(f) if isinstance(f, dict) else f for f in findings]

    def _adjust_vector(self, vector: str, finding: Dict) -> str:
        """Adjust CVSS vector based on scan context."""
        try:
            # If finding was found while authenticated, set PR:L (privileges required: low)
            if self.auth_required and "/PR:N/" in vector:
                vector = vector.replace("/PR:N/", "/PR:L/")

            # If WAF is present and attack complexity isn't already High, raise it
            if self.waf_detected and "/AC:L/" in vector:
                vector = vector.replace("/AC:L/", "/AC:H/")

            # OAST-verified findings are more credible - keep as-is
            # Unverified findings: slightly reduce score by noting uncertainty
        except (ValueError, TypeError, AttributeError) as exc:
            _logger.debug(f"[reporting] CVSS vector adjustment failed for {vector!r}: {exc!r}")
        return vector


def _severity_label(score: float) -> str:
    if score >= 9.0:
        return "Critical"
    elif score >= 7.0:
        return "High"
    elif score >= 4.0:
        return "Medium"
    elif score >= 0.1:
        return "Low"
    return "Informational"


def score_findings(findings: list, auth_required: bool = False,
                   waf_detected: bool = False) -> list:
    """Convenience function to score a list of findings."""
    scorer = CVSSScorer(auth_required=auth_required, waf_detected=waf_detected)
    return scorer.score_all(findings)
