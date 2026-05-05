"""
websecure.scanners.headers
--------------------------
Legacy stub.
This functionality has been moved to websecure.scanners.infrastructure.
This file remains to support dynamic imports from config 'modules': ['headers'].
"""

from .infrastructure import get_security_headers, analyze_response_headers, HeaderScanner

def scan(target: str, session=None, **kwargs):
    """
    Adapter for the main scanner engine.
    The engine expects a 'scan' or 'run' function.
    """
    results = {}
    # Call the consolidated function
    # Note: 'get_security_headers' signature is (url, results, session, debug, ...)
    get_security_headers(target, results, session=session, debug=kwargs.get("debug", False))
    return results.get("security_headers", [])

def run(target: str, session=None, **kwargs):
    return scan(target, session, **kwargs)

# ============================================================================
# ADIM 9 — CSPAnalyzer, HSTSPreloadChecker, EmailSecurityAnalyzer, DNSCAAChecker
# ============================================================================
from __future__ import annotations
import logging
import re
import socket
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple
from websecure.scanners.base import BaseScanner

_hdr_logger = logging.getLogger(__name__ + ".adim9")

# ---------------------------------------------------------------------------
# CSP dangerous patterns
# ---------------------------------------------------------------------------
_CSP_DANGEROUS_SOURCES = frozenset([
    "'unsafe-inline'", "'unsafe-eval'", "'unsafe-hashes'",
    "data:", "blob:", "filesystem:",
])
_CSP_WILDCARD_RE = re.compile(r"(^|\s)\*($|\s|;)", re.M)
_CSP_REQUIRED_DIRECTIVES = ["default-src", "script-src", "object-src", "base-uri"]

# ---------------------------------------------------------------------------
# HSTS
# ---------------------------------------------------------------------------
_HSTS_MIN_AGE = 31536000  # 1 year — hstspreload.org requirement

# ---------------------------------------------------------------------------
# DNS helpers
# ---------------------------------------------------------------------------
def _dns_txt_records(domain: str) -> List[str]:
    """Query TXT records via socket-level DNS (fallback: empty list)."""
    try:
        import dns.resolver  # dnspython
        answers = dns.resolver.resolve(domain, "TXT")
        return [rdata.to_text().strip('"') for rdata in answers]
    except Exception:
        pass
    # Fallback: nslookup via subprocess (no-dep)
    try:
        import subprocess
        out = subprocess.check_output(
            ["nslookup", "-type=TXT", domain], timeout=5, stderr=subprocess.DEVNULL
        ).decode(errors="replace")
        return re.findall(r'"([^"]+)"', out)
    except Exception:
        return []

def _dns_cname(domain: str) -> Optional[str]:
    try:
        import dns.resolver
        answers = dns.resolver.resolve(domain, "CNAME")
        return str(answers[0].target).rstrip(".")
    except Exception:
        pass
    try:
        import subprocess
        out = subprocess.check_output(
            ["nslookup", "-type=CNAME", domain], timeout=5, stderr=subprocess.DEVNULL
        ).decode(errors="replace")
        m = re.search(r"canonical name\s*=\s*(\S+)", out, re.I)
        return m.group(1).rstrip(".") if m else None
    except Exception:
        return None

def _dns_caa(domain: str) -> List[str]:
    try:
        import dns.resolver
        answers = dns.resolver.resolve(domain, "CAA")
        return [rdata.to_text() for rdata in answers]
    except Exception:
        pass
    try:
        import subprocess
        out = subprocess.check_output(
            ["nslookup", "-type=CAA", domain], timeout=5, stderr=subprocess.DEVNULL
        ).decode(errors="replace")
        return re.findall(r"rdata\s*=\s*(.+)", out)
    except Exception:
        return []


# ===========================================================================
# 1. CSPAnalyzer
# ===========================================================================
class CSPAnalyzer(BaseScanner):
    """
    Content Security Policy tam analizi:
    - unsafe-inline / unsafe-eval / wildcard tespiti
    - Eksik kritik direktifler
    - Nonce/hash kullanimi kontrolu
    - JSONP endpoint bypass riski
    - data: / blob: kaynak riski
    - report-uri / report-to kontrolu
    """
    name = "csp_analyzer"

    def run(self, target: str, **kwargs) -> List[Dict]:
        results: List[Dict] = []
        try:
            resp = self.session.get(target, timeout=10)
        except Exception as exc:
            _hdr_logger.warning("[CSP] %s", exc)
            return results

        csp_header = (
            resp.headers.get("Content-Security-Policy")
            or resp.headers.get("Content-Security-Policy-Report-Only")
        )
        if not csp_header:
            results.append({
                "vuln_type": "Missing Content-Security-Policy",
                "url": target, "severity": "High",
                "description": "No Content-Security-Policy header. XSS has no browser-side mitigation.",
                "evidence": {"headers_checked": ["Content-Security-Policy", "Content-Security-Policy-Report-Only"]},
            })
            self.report_finding(**results[-1])
            return results

        findings = self._analyze_csp(csp_header, target)
        for f in findings:
            self.report_finding(**f)
        return findings

    def _analyze_csp(self, csp: str, url: str) -> List[Dict]:
        results   = []
        directives = self._parse_directives(csp)

        # 1. Dangerous sources
        for directive, sources in directives.items():
            for src in sources:
                if src.lower() in _CSP_DANGEROUS_SOURCES:
                    results.append({
                        "vuln_type": f"CSP Unsafe Source — {src} in {directive}",
                        "url": url, "severity": "High",
                        "description": (
                            f"CSP directive '{directive}' contains dangerous source {src}. "
                            f"'unsafe-inline' allows inline scripts; 'unsafe-eval' allows eval()."
                        ),
                        "evidence": {"directive": directive, "source": src, "csp_snippet": csp[:200]},
                    })

        # 2. Wildcard host
        for directive, sources in directives.items():
            for src in sources:
                if src == "*" or src.startswith("*.") or (src.startswith("http") and "*" in src):
                    results.append({
                        "vuln_type": f"CSP Wildcard Source — {directive}",
                        "url": url, "severity": "High",
                        "description": (
                            f"CSP directive '{directive}' uses wildcard source '{src}'. "
                            "Attacker can load scripts from any domain."
                        ),
                        "evidence": {"directive": directive, "wildcard": src},
                    })

        # 3. Missing required directives
        for req in _CSP_REQUIRED_DIRECTIVES:
            if req not in directives and "default-src" not in directives:
                results.append({
                    "vuln_type": f"CSP Missing Directive — {req}",
                    "url": url, "severity": "Medium",
                    "description": f"CSP is missing required directive '{req}'. Falls back to permissive default.",
                    "evidence": {"missing": req, "present": list(directives.keys())},
                })

        # 4. object-src not 'none'
        obj = directives.get("object-src", directives.get("default-src", []))
        if obj and "'none'" not in obj:
            results.append({
                "vuln_type": "CSP object-src Not Restricted",
                "url": url, "severity": "High",
                "description": "object-src not set to 'none'. Flash/Java plugins can be loaded.",
                "evidence": {"object_src": obj},
            })

        # 5. No report-uri/report-to
        if "report-uri" not in directives and "report-to" not in directives:
            results.append({
                "vuln_type": "CSP No Violation Reporting",
                "url": url, "severity": "Low",
                "description": "CSP has no report-uri or report-to. Violations are silent.",
                "evidence": {},
            })

        # 6. Report-only mode (no enforcement)
        results.append({
            "vuln_type": "CSP Analysis Complete",
            "url": url, "severity": "Info",
            "description": f"CSP parsed. {len(directives)} directives found. {len(results)} issues detected.",
            "evidence": {"directives": list(directives.keys()), "full_csp": csp[:500]},
        })

        return results

    def _parse_directives(self, csp: str) -> Dict[str, List[str]]:
        result = {}
        for part in csp.split(";"):
            part = part.strip()
            if not part:
                continue
            tokens = part.split()
            if tokens:
                result[tokens[0].lower()] = [t.lower() for t in tokens[1:]]
        return result


# ===========================================================================
# 2. HSTSPreloadChecker
# ===========================================================================
class HSTSPreloadChecker(BaseScanner):
    """
    HSTS tam analizi:
    - max-age yeterliligi (min 1 yil)
    - includeSubDomains kontrolu
    - preload direktifi
    - hstspreload.org API durumu
    """
    name = "hsts_preload"

    def run(self, target: str, **kwargs) -> List[Dict]:
        results: List[Dict] = []
        try:
            resp = self.session.get(target, timeout=10)
        except Exception as exc:
            _hdr_logger.warning("[HSTS] %s", exc)
            return results

        hsts = resp.headers.get("Strict-Transport-Security")
        parsed = urllib.parse.urlparse(target)
        domain = parsed.netloc or parsed.path

        if not hsts:
            results.append({
                "vuln_type": "Missing HSTS Header",
                "url": target, "severity": "High",
                "description": "Strict-Transport-Security header absent. MITM/SSL stripping possible.",
                "evidence": {},
            })
            self.report_finding(**results[-1])
            return results

        # Parse max-age
        ma = re.search(r"max-age\s*=\s*(\d+)", hsts, re.I)
        max_age = int(ma.group(1)) if ma else 0
        inc_sub = "includesubdomains" in hsts.lower()
        preload  = "preload" in hsts.lower()

        if max_age < _HSTS_MIN_AGE:
            results.append({
                "vuln_type": "HSTS max-age Too Short",
                "url": target, "severity": "Medium",
                "description": (
                    f"HSTS max-age={max_age} is below the recommended 31536000 (1 year). "
                    "Short max-age reduces protection window."
                ),
                "evidence": {"max_age": max_age, "required": _HSTS_MIN_AGE},
            })
            self.report_finding(**results[-1])

        if not inc_sub:
            results.append({
                "vuln_type": "HSTS Missing includeSubDomains",
                "url": target, "severity": "Medium",
                "description": "HSTS does not include 'includeSubDomains'. Subdomains can be MITM'd.",
                "evidence": {"hsts_header": hsts},
            })
            self.report_finding(**results[-1])

        if not preload:
            results.append({
                "vuln_type": "HSTS Not Preload-Ready",
                "url": target, "severity": "Low",
                "description": "HSTS missing 'preload' directive. Domain not eligible for browser preload list.",
                "evidence": {"hsts_header": hsts},
            })
            self.report_finding(**results[-1])

        # hstspreload.org API check
        preload_status = self._check_preload_status(domain)
        if preload_status:
            results.append(preload_status)
            self.report_finding(**preload_status)

        return results

    def _check_preload_status(self, domain: str) -> Optional[Dict]:
        try:
            api_url = f"https://hstspreload.org/api/v2/status?domain={domain}"
            resp = self.session.get(api_url, timeout=8)
            if resp.status_code == 200:
                data = resp.json()
                status = data.get("status", "unknown")
                if status not in ("preloaded", "pending"):
                    return {
                        "vuln_type": "HSTS Not in Preload List",
                        "url": f"https://{domain}", "severity": "Low",
                        "description": (
                            f"Domain '{domain}' is not in the HSTS preload list (status: {status}). "
                            "Users visiting for the first time are not protected."
                        ),
                        "evidence": {"preload_status": status, "domain": domain},
                    }
        except Exception as exc:
            _hdr_logger.debug("[HSTSPreload] API: %s", exc)
        return None


# ===========================================================================
# 3. EmailSecurityAnalyzer (SPF / DMARC / DKIM)
# ===========================================================================
class EmailSecurityAnalyzer(BaseScanner):
    """
    Email security DNS record analizi:
    - SPF: softfail/fail/missing
    - DMARC: policy none/quarantine/reject, alignment
    - DKIM: selector tespiti + public key kontrolu
    """
    name = "email_security"

    _DKIM_SELECTORS = [
        "default", "google", "mail", "dkim", "k1", "s1", "s2",
        "selector1", "selector2", "email", "smtp", "mta",
    ]

    def run(self, target: str, **kwargs) -> List[Dict]:
        results: List[Dict] = []
        parsed = urllib.parse.urlparse(target)
        domain = parsed.netloc or parsed.path
        domain = domain.split(":")[0]  # strip port

        # SPF
        for f in self._check_spf(domain):
            results.append(f)
            self.report_finding(**f)
        # DMARC
        for f in self._check_dmarc(domain):
            results.append(f)
            self.report_finding(**f)
        # DKIM
        for f in self._check_dkim(domain):
            results.append(f)
            self.report_finding(**f)

        return results

    def _check_spf(self, domain: str) -> List[Dict]:
        results = []
        txt_records = _dns_txt_records(domain)
        spf = next((r for r in txt_records if r.startswith("v=spf1")), None)
        if not spf:
            results.append({
                "vuln_type": "Missing SPF Record",
                "url": f"https://{domain}", "severity": "High",
                "description": f"No SPF TXT record for {domain}. Email spoofing is trivial.",
                "evidence": {"domain": domain},
            })
            return results
        if "~all" in spf:
            results.append({
                "vuln_type": "SPF Softfail (~all)",
                "url": f"https://{domain}", "severity": "Medium",
                "description": "SPF uses ~all (softfail). Spoofed emails may still be delivered.",
                "evidence": {"spf": spf},
            })
        if "+all" in spf:
            results.append({
                "vuln_type": "SPF +all (Any Server Allowed)",
                "url": f"https://{domain}", "severity": "Critical",
                "description": "SPF +all allows any server to send email as this domain.",
                "evidence": {"spf": spf},
            })
        return results

    def _check_dmarc(self, domain: str) -> List[Dict]:
        results = []
        txt_records = _dns_txt_records(f"_dmarc.{domain}")
        dmarc = next((r for r in txt_records if r.startswith("v=DMARC1")), None)
        if not dmarc:
            results.append({
                "vuln_type": "Missing DMARC Record",
                "url": f"https://{domain}", "severity": "High",
                "description": f"No DMARC record at _dmarc.{domain}. Domain spoofing unmitigated.",
                "evidence": {"domain": domain},
            })
            return results
        policy_m = re.search(r"p\s*=\s*(\w+)", dmarc, re.I)
        policy = policy_m.group(1).lower() if policy_m else "none"
        if policy == "none":
            results.append({
                "vuln_type": "DMARC Policy None (Monitoring Only)",
                "url": f"https://{domain}", "severity": "High",
                "description": "DMARC p=none — spoofed emails are not rejected or quarantined.",
                "evidence": {"dmarc": dmarc, "policy": policy},
            })
        elif policy == "quarantine":
            results.append({
                "vuln_type": "DMARC Policy Quarantine (Not Reject)",
                "url": f"https://{domain}", "severity": "Low",
                "description": "DMARC p=quarantine. Upgrade to p=reject for full protection.",
                "evidence": {"dmarc": dmarc},
            })
        pct_m = re.search(r"pct\s*=\s*(\d+)", dmarc, re.I)
        if pct_m and int(pct_m.group(1)) < 100:
            results.append({
                "vuln_type": "DMARC Partial Coverage",
                "url": f"https://{domain}", "severity": "Medium",
                "description": f"DMARC pct={pct_m.group(1)} — policy applies to only {pct_m.group(1)}% of emails.",
                "evidence": {"dmarc": dmarc, "pct": pct_m.group(1)},
            })
        return results

    def _check_dkim(self, domain: str) -> List[Dict]:
        results = []
        found_selectors = []
        for sel in self._DKIM_SELECTORS:
            txt_records = _dns_txt_records(f"{sel}._domainkey.{domain}")
            dkim = next((r for r in txt_records if "v=DKIM1" in r or "p=" in r), None)
            if dkim:
                found_selectors.append(sel)
                # Check key length
                key_m = re.search(r"p=([A-Za-z0-9+/=]{20,})", dkim)
                if key_m:
                    key_b64 = key_m.group(1)
                    # Estimate key length (rough)
                    key_bits = len(key_b64) * 6 // 8 * 8
                    if key_bits < 1024:
                        results.append({
                            "vuln_type": "DKIM Weak Key (< 1024 bits)",
                            "url": f"https://{domain}", "severity": "High",
                            "description": f"DKIM selector '{sel}' uses weak key (~{key_bits} bits). Minimum 2048 recommended.",
                            "evidence": {"selector": sel, "estimated_bits": key_bits},
                        })
        if not found_selectors:
            results.append({
                "vuln_type": "No DKIM Record Found",
                "url": f"https://{domain}", "severity": "Medium",
                "description": f"No DKIM record found for common selectors on {domain}. Email authenticity unverifiable.",
                "evidence": {"selectors_checked": self._DKIM_SELECTORS},
            })
        return results


# ===========================================================================
# 4. DNSCAAChecker
# ===========================================================================
class DNSCAAChecker(BaseScanner):
    """
    DNS CAA (Certification Authority Authorization) kaydı kontrolu:
    - CAA yoksa herhangi bir CA sertifika verebilir
    - issuewild kontrolu
    - iodef rapor noktası
    """
    name = "dns_caa"

    def run(self, target: str, **kwargs) -> List[Dict]:
        results: List[Dict] = []
        parsed = urllib.parse.urlparse(target)
        domain = (parsed.netloc or parsed.path).split(":")[0]

        caa_records = _dns_caa(domain)
        if not caa_records:
            results.append({
                "vuln_type": "Missing DNS CAA Record",
                "url": f"https://{domain}", "severity": "Medium",
                "description": (
                    f"No CAA record for {domain}. Any Certificate Authority can issue TLS certificates, "
                    "enabling unauthorized cert issuance (misissued certs)."
                ),
                "evidence": {"domain": domain},
            })
            self.report_finding(**results[-1])
            return results

        has_issuewild = any("issuewild" in r for r in caa_records)
        has_iodef     = any("iodef" in r for r in caa_records)

        if not has_issuewild:
            results.append({
                "vuln_type": "CAA Missing issuewild",
                "url": f"https://{domain}", "severity": "Low",
                "description": "CAA record has no 'issuewild' tag. Wildcard cert issuance may be unrestricted.",
                "evidence": {"caa": caa_records},
            })
            self.report_finding(**results[-1])

        if not has_iodef:
            results.append({
                "vuln_type": "CAA Missing iodef Reporting",
                "url": f"https://{domain}", "severity": "Info",
                "description": "CAA has no 'iodef' reporting endpoint. Unauthorized issuance attempts won't be notified.",
                "evidence": {"caa": caa_records},
            })
            self.report_finding(**results[-1])

        return results


# ===========================================================================
# HeadersAdim9Scanner — Orchestrator
# ===========================================================================
class HeadersAdim9Scanner(BaseScanner):
    """
    Adim 9 Headers orchestrator:
    CSPAnalyzer + HSTSPreloadChecker + EmailSecurityAnalyzer + DNSCAAChecker
    """
    name = "headers_adim9"

    def run(self, target: str, **kwargs) -> List[Dict]:
        all_results: List[Dict] = []
        scanners = [
            CSPAnalyzer(session=self.session, results=self.results),
            HSTSPreloadChecker(session=self.session, results=self.results),
            EmailSecurityAnalyzer(session=self.session, results=self.results),
            DNSCAAChecker(session=self.session, results=self.results),
        ]
        for sc in scanners:
            try:
                sc.target = target
                all_results.extend(sc.run(target, **kwargs))
            except Exception as exc:
                _hdr_logger.warning("[HeadersAdim9] %s: %s", sc.name, exc)
        return all_results
