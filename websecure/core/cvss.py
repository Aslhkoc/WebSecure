"""
websecure.core.cvss
--------------------
CVSS v3.1 scoring for WebSecure findings.
Maps finding types to base vectors, adjusts for context (auth, WAF).
"""
from __future__ import annotations

import logging
from typing import Dict, List, Tuple

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
    "sql injection (time-based blind)":  ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", 8.1),
    "sql injection (boolean-based blind)": ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", 8.1),
    "sql injection (error-based)":       ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
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

# CWE mapping: finding type → CWE ID listesi
# Her bulgu tipi için en spesifik CWE seçildi (NVD/MITRE referans alınarak)
_CWE_MAP: Dict[str, List[str]] = {
    # XSS
    "xss":                              ["CWE-79"],
    "reflected xss":                    ["CWE-79"],
    "reflected xss (form)":             ["CWE-79"],
    "dom xss":                          ["CWE-79", "CWE-1019"],
    "stored xss":                       ["CWE-79"],
    "blind xss (oob)":                  ["CWE-79"],
    "mxss (mutation xss)":              ["CWE-79"],
    "csp bypass xss":                   ["CWE-79", "CWE-693"],
    "xss account takeover":             ["CWE-79"],
    "xss -> account takeover (poc)":    ["CWE-79"],
    "dom clobbering":                   ["CWE-79", "CWE-1321"],
    "prototype pollution -> xss":       ["CWE-1321", "CWE-79"],
    "trusted types bypass":             ["CWE-79"],
    "template literal injection (xss/ssti)": ["CWE-94", "CWE-79"],

    # SQL Injection
    "sql injection":                    ["CWE-89"],
    "sqli":                             ["CWE-89"],
    "blind sqli":                       ["CWE-89"],
    "sql injection — db schema extracted":      ["CWE-89"],
    "sql injection (sqlmap confirmed)":         ["CWE-89"],
    "sql injection (union-based)":              ["CWE-89"],
    "sql injection (stacked query)":            ["CWE-89"],
    "sql injection (oob dns — pending callback)": ["CWE-89"],
    "nosql injection":                  ["CWE-943"],

    # SSTI
    "ssti":                             ["CWE-94"],
    "server-side template injection":   ["CWE-94"],

    # Command Injection
    "command injection":                ["CWE-78"],
    "os command injection":             ["CWE-78"],

    # SSRF
    "ssrf":                             ["CWE-918"],

    # XXE
    "xxe":                              ["CWE-611"],

    # Access Control
    "idor":                             ["CWE-639", "CWE-284"],
    "insecure direct object reference": ["CWE-639", "CWE-284"],
    "broken access control":            ["CWE-284"],
    "missing authentication":           ["CWE-306"],
    "horizontal privilege escalation":  ["CWE-639"],
    "vertical privilege escalation":    ["CWE-269"],

    # CSRF
    "csrf":                             ["CWE-352"],

    # JWT
    "jwt":                              ["CWE-347"],
    "jwt algorithm none":               ["CWE-347"],

    # Request Smuggling
    "request smuggling":                ["CWE-444"],
    "http request smuggling":           ["CWE-444"],

    # File Upload
    "file upload":                      ["CWE-434"],
    "unrestricted file upload":         ["CWE-434"],

    # TLS / Crypto
    "tls":                              ["CWE-326"],
    "weak tls":                         ["CWE-326"],
    "ssl heartbleed (cve-2014-0160)":  ["CWE-125"],
    "ssl poodle (cve-2014-3566)":      ["CWE-326"],
    "expired certificate":              ["CWE-298"],
    "self-signed certificate":          ["CWE-295"],
    "ssl certificate":                  ["CWE-295"],

    # Headers / Misconfig
    "missing csp":                      ["CWE-693"],
    "missing hsts":                     ["CWE-523"],
    "missing security header":          ["CWE-693"],
    "open redirect":                    ["CWE-601"],
    "clickjacking":                     ["CWE-1021"],

    # Information Disclosure
    "js secret exposure":               ["CWE-200", "CWE-312"],
    "hardcoded secret":                 ["CWE-798"],
    "sensitive file exposure":          ["CWE-200"],
    "information disclosure":           ["CWE-200"],
    "path disclosure":                  ["CWE-200"],
    "stack trace disclosure":           ["CWE-209"],

    # Path Traversal
    "path traversal":                   ["CWE-22"],
    "directory traversal":              ["CWE-22"],

    # Rate Limiting / DoS
    "rate limit bypass":                ["CWE-770"],

    # HTTP Headers (server info)
    "http server header":               ["CWE-200"],
    "http title":                       ["CWE-200"],
}


def lookup_cwe(finding_type: str) -> List[str]:
    """Finding tipinden CWE ID listesi döndür. Bulunamazsa boş liste."""
    t = _normalize_type(finding_type)
    if t in _CWE_MAP:
        return list(_CWE_MAP[t])
    # Kısmi eşleşme: "reflected xss" → "xss" gibi
    for key, cwes in _CWE_MAP.items():
        if key in t or t in key:
            return list(cwes)
    return []


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
                # P10 fix: c.severities()[0] returns the cvss library's own naming
                # convention ("None" for 0.0, etc.) which differs from the rest of
                # the codebase ("Info"). Use _severity_label() for consistent naming.
                severity_label = _severity_label(base_score)
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
            finding_type = _normalize_type(finding.get("type", ""))

            # DOM-confirmed XSS (Playwright verified execution) → treat as account takeover path
            # CVSS: reflected xss base = 6.1 (Medium); confirmed execution = 8.8 (High)
            if finding.get("verified") and "xss" in finding_type and "/UI:R/" in vector:
                # Upgrade: scope changes to C (confidentiality high, integrity high)
                if "/S:U/" in vector:
                    vector = vector.replace("/S:U/", "/S:C/")
                if "/C:L/" in vector:
                    vector = vector.replace("/C:L/", "/C:H/")
                if "/I:L/" in vector:
                    vector = vector.replace("/I:L/", "/I:H/")

            # If finding was found while authenticated, set PR:L (privileges required: low)
            if self.auth_required and "/PR:N/" in vector:
                vector = vector.replace("/PR:N/", "/PR:L/")

            # WAF AC adjustment: ONLY apply when WAF blocked other probes but this
            # finding was NOT confirmed via bypass. If waf_bypassed=True the exploit
            # already worked through the WAF → complexity is Low (attacker succeeded).
            waf_bypassed = bool(finding.get("waf_bypassed") or finding.get("adaptive_waf_bypass"))
            # P7 fix: a verified finding (confirmed exploitation) means the attacker
            # demonstrably succeeded — AC was Low in practice. Raising AC to High
            # because a WAF is present contradicts the confirmed finding and unfairly
            # deflates the score. Only apply the WAF AC adjustment when the finding
            # has NOT been verified (i.e., still theoretical against the WAF).
            verified = bool(finding.get("verified"))
            if self.waf_detected and not waf_bypassed and not verified:
                if "/AC:L/" in vector:
                    vector = vector.replace("/AC:L/", "/AC:H/")
                # AC:M is not standard CVSS 3.x but handle defensively
                elif "/AC:M/" in vector:
                    vector = vector.replace("/AC:M/", "/AC:H/")

        except (ValueError, TypeError, AttributeError) as exc:
            _logger.debug(f"[reporting] CVSS vector adjustment failed for {vector!r}: {exc!r}")
        return vector


def cvss_to_severity(score: float) -> str:
    """Standart CVSS v3.1 skoru → severity etiketi. TEK KAYNAK (Madde 4): chain_reactor.
    _cvss_to_severity ve evidence_chain._score_to_sev artık buna delege eder (önceden 3
    kopyaydı, low-bound'da tutarsız: >0.0 / >=1.0 → standart >=0.1'e hizalandı)."""
    if score >= 9.0:
        return "Critical"
    elif score >= 7.0:
        return "High"
    elif score >= 4.0:
        return "Medium"
    elif score >= 0.1:
        return "Low"
    # Tüm kod tabanı "Info" kullanır ("Informational" değil) — severity rank lookup'larında
    # sessiz sıfıra-düşmeyi önler (P10): html_dashboard, diff.py, markdown.py "Info" anahtarlar.
    return "Info"


# Geriye dönük iç alias — cvss.py içi çağrılar _severity_label kullanıyor.
_severity_label = cvss_to_severity


def score_findings(findings: list, auth_required: bool = False,
                   waf_detected: bool = False) -> list:
    """Convenience function to score a list of findings."""
    scorer = CVSSScorer(auth_required=auth_required, waf_detected=waf_detected)
    return scorer.score_all(findings)
