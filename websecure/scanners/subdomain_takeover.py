"""
websecure.scanners.subdomain_takeover
---------------------------------------
Subdomain Takeover tespiti.

Adim 9 - Siniflar:
  SubdomainTakeoverScanner(BaseScanner) -- orchestrator
  CNAMEDanglingChecker                  -- dangling CNAME → bulut servis kontrol
  CloudServiceFingerprintDB             -- 25+ bulut servis imzasi
"""
from __future__ import annotations

import logging
import re
import socket
import subprocess
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple

from websecure.scanners.base import BaseScanner

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Cloud service takeover fingerprints
# ---------------------------------------------------------------------------
_CLOUD_FINGERPRINTS: List[Dict] = [
    {"service": "GitHub Pages",    "cname_pattern": r"github\.io$",
     "error_pattern": re.compile(r"There isn't a GitHub Pages site here", re.I)},
    {"service": "Heroku",          "cname_pattern": r"herokuapp\.com$",
     "error_pattern": re.compile(r"No such app|Heroku.*not.*found", re.I)},
    {"service": "AWS S3",          "cname_pattern": r"s3\.amazonaws\.com$|s3-website",
     "error_pattern": re.compile(r"NoSuchBucket|The specified bucket does not exist", re.I)},
    {"service": "AWS CloudFront",  "cname_pattern": r"cloudfront\.net$",
     "error_pattern": re.compile(r"Bad request.*cloudfront|ERROR.*Request could not be satisfied", re.I)},
    {"service": "Azure",           "cname_pattern": r"azurewebsites\.net$|azure\.com$",
     "error_pattern": re.compile(r"404 Web Site not found|Microsoft Azure App Service", re.I)},
    {"service": "Netlify",         "cname_pattern": r"netlify\.com$|netlify\.app$",
     "error_pattern": re.compile(r"Not Found.*Netlify|netlify.*page not found", re.I)},
    {"service": "Shopify",         "cname_pattern": r"myshopify\.com$",
     "error_pattern": re.compile(r"Sorry, this shop is currently unavailable", re.I)},
    {"service": "Fastly",          "cname_pattern": r"fastly\.net$",
     "error_pattern": re.compile(r"Fastly error.*unknown domain", re.I)},
    {"service": "Pantheon",        "cname_pattern": r"pantheonsite\.io$",
     "error_pattern": re.compile(r"The gods are wise|Pantheon.*site not found", re.I)},
    {"service": "Ghost",           "cname_pattern": r"ghost\.io$",
     "error_pattern": re.compile(r"The thing you were looking for is no longer here", re.I)},
    {"service": "Surge.sh",        "cname_pattern": r"surge\.sh$",
     "error_pattern": re.compile(r"project not found", re.I)},
    {"service": "Zendesk",         "cname_pattern": r"zendesk\.com$",
     "error_pattern": re.compile(r"Help Center Closed", re.I)},
    {"service": "Freshdesk",       "cname_pattern": r"freshdesk\.com$",
     "error_pattern": re.compile(r"There is no helpdesk here", re.I)},
    {"service": "Intercom",        "cname_pattern": r"custom\.intercom\.help$",
     "error_pattern": re.compile(r"This page is reserved for|Uh oh. That page doesn", re.I)},
    {"service": "Webflow",         "cname_pattern": r"webflow\.io$",
     "error_pattern": re.compile(r"The page you are looking for doesn.*exist.*Webflow", re.I)},
    {"service": "Vercel",          "cname_pattern": r"vercel\.app$|now\.sh$",
     "error_pattern": re.compile(r"The deployment could not be found|DEPLOYMENT_NOT_FOUND", re.I)},
    {"service": "Render",          "cname_pattern": r"onrender\.com$",
     "error_pattern": re.compile(r"Not Found.*Render|deploy.*not.*found.*render", re.I)},
    {"service": "ReadTheDocs",     "cname_pattern": r"readthedocs\.io$",
     "error_pattern": re.compile(r"unknown to Read the Docs", re.I)},
    {"service": "Tumblr",          "cname_pattern": r"domains\.tumblr\.com$",
     "error_pattern": re.compile(r"Whatever you were looking for doesn.*exist", re.I)},
    {"service": "HubSpot",         "cname_pattern": r"hubspot\.net$|hs-sites\.com$",
     "error_pattern": re.compile(r"Domain not configured|this domain isn.*t configured", re.I)},
    {"service": "Squarespace",     "cname_pattern": r"squarespace\.com$",
     "error_pattern": re.compile(r"No Such Account|Site Not Found.*Squarespace", re.I)},
    {"service": "WP Engine",       "cname_pattern": r"wpengine\.com$",
     "error_pattern": re.compile(r"The site you.*looking for.*doesn.*exist", re.I)},
    {"service": "Kinsta",          "cname_pattern": r"kinsta\.cloud$",
     "error_pattern": re.compile(r"No site for this domain.*Kinsta", re.I)},
    {"service": "Fly.io",          "cname_pattern": r"fly\.dev$",
     "error_pattern": re.compile(r"404 Not Found.*fly\.io|fly.*app not found", re.I)},
    {"service": "Firebase",        "cname_pattern": r"web\.app$|firebaseapp\.com$",
     "error_pattern": re.compile(r"Firebase App.*Not Found|404.*firebase", re.I)},
]


def _resolve_cname(domain: str) -> Optional[str]:
    try:
        import dns.resolver
        answers = dns.resolver.resolve(domain, "CNAME")
        return str(answers[0].target).rstrip(".")
    except Exception:
        pass
    try:
        out = subprocess.check_output(
            ["nslookup", "-type=CNAME", domain], timeout=5, stderr=subprocess.DEVNULL
        ).decode(errors="replace")
        m = re.search(r"canonical name\s*=\s*(\S+)", out, re.I)
        return m.group(1).rstrip(".") if m else None
    except Exception:
        return None


def _nxdomain(domain: str) -> bool:
    try:
        socket.gethostbyname(domain)
        return False
    except socket.gaierror:
        return True


def _http_get_body(url: str, session, timeout: int = 8) -> Tuple[int, str]:
    try:
        r = session.get(url, timeout=timeout, allow_redirects=True)
        return r.status_code, (r.text or "")[:3000]
    except Exception:
        return 0, ""


# ===========================================================================
# CNAMEDanglingChecker
# ===========================================================================
class CNAMEDanglingChecker(BaseScanner):
    """
    Dangling CNAME tespiti:
    1. Hedef domain'in CNAME'ini coz
    2. CNAME bir bulut servise mi isaret ediyor?
    3. CNAME hedefi NXDOMAIN mi? (dangling)
    4. Bulut servis hata sayfasini HTTP ile dogrula
    """
    name = "cname_dangling"

    def run(self, target: str, subdomains: Optional[List[str]] = None, **kwargs) -> List[Dict]:
        results: List[Dict] = []
        parsed  = urllib.parse.urlparse(target)
        domain  = (parsed.netloc or parsed.path).split(":")[0]

        # Test target domain + common subdomains
        candidates = [domain] + (subdomains or []) + self._gen_subdomains(domain)

        for candidate in candidates[:50]:
            cname = _resolve_cname(candidate)
            if not cname:
                continue
            # Check if CNAME is dangling (NXDOMAIN)
            dangling = _nxdomain(cname)
            # Check cloud fingerprint
            for fp in _CLOUD_FINGERPRINTS:
                if re.search(fp["cname_pattern"], cname, re.I):
                    status, body = _http_get_body(f"http://{candidate}", self.session)
                    takeover_confirmed = bool(fp["error_pattern"].search(body))
                    sev = "Critical" if (dangling or takeover_confirmed) else "High"
                    finding = {
                        "vuln_type": "Subdomain Takeover" + (" — Confirmed" if takeover_confirmed else " — Potential"),
                        "url": f"http://{candidate}", "severity": sev,
                        "description": (
                            f"Subdomain '{candidate}' → CNAME → '{cname}' ({fp['service']}). "
                            + ("NXDOMAIN: CNAME target doesn't resolve. " if dangling else "")
                            + ("Error page confirms unclaimed service. " if takeover_confirmed else "")
                            + f"Attacker can claim '{cname}' on {fp['service']} and serve arbitrary content."
                        ),
                        "evidence": {
                            "subdomain": candidate, "cname": cname,
                            "cloud_service": fp["service"],
                            "nxdomain": dangling,
                            "takeover_confirmed": takeover_confirmed,
                            "body_snippet": body[:200] if takeover_confirmed else "",
                        },
                    }
                    results.append(finding)
                    self.report_finding(**finding)
                    break

        return results

    def _gen_subdomains(self, domain: str) -> List[str]:
        """Generate common subdomain candidates."""
        parts = domain.split(".")
        if len(parts) < 2:
            return []
        base = ".".join(parts[-2:])
        prefixes = [
            "www", "mail", "ftp", "smtp", "pop", "imap",
            "dev", "staging", "test", "beta", "demo",
            "api", "cdn", "static", "assets", "media",
            "blog", "shop", "app", "admin", "portal",
            "help", "support", "docs", "status", "jobs",
        ]
        return [f"{p}.{base}" for p in prefixes]


# ===========================================================================
# SubdomainTakeoverScanner — Orchestrator
# ===========================================================================
class SubdomainTakeoverScanner(BaseScanner):
    """
    Adim 9 Subdomain Takeover orchestrator.
    """
    name = "subdomain_takeover"

    def run(self, target: str, **kwargs) -> List[Dict]:
        checker = CNAMEDanglingChecker(session=self.session, results=self.results)
        checker.target = target
        return checker.run(target, **kwargs)


def run(url: str, session=None, debug: bool = False, **kwargs) -> List[Dict]:
    scanner = SubdomainTakeoverScanner(session=session, debug=debug)
    return scanner.run(url, **kwargs)
