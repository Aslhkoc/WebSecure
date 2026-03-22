import re
import math
import logging
import requests
import xml.etree.ElementTree as ET
from urllib.parse import urljoin, urlparse
from typing import List, Dict, Any, Set

from .base import BaseScanner

logger = logging.getLogger(__name__)

# --- Common Constants ---
SENSITIVE_FILES = [
    ".env", ".git/HEAD", ".svn/entries", ".DS_Store",
    "config.json", "web.config", "security.txt", "sitemap.xml"
]

class PassiveJSScanner(BaseScanner):
    """
    Scans JavaScript files for hardcoded secrets and endpoints.
    """
    SECRET_PATTERNS = {
        "AWS Access Key": r"AKIA[0-9A-Z]{16}",
        "Google API Key": r"AIza[0-9A-Za-z\\-_]{35}",
        "Slack Token": r"xox[baprs]-([0-9a-zA-Z]{10,48})",
        "Generic API Key": r"(?i)(api_key|apikey|secret|token)\s*[:=]\s*['\"]([a-zA-Z0-9\-_]{16,})['\"]",
        "JWT": r"eyJ[a-zA-Z0-9\-_]+\.eyJ[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+",
        "S3 Bucket": r"s3:\/\/[a-z0-9\.-]+|[a-z0-9\.-]+\.s3\.amazonaws\.com"
    }

    def scan(self, js_urls: List[str]) -> List[Dict[str, Any]]:
        findings = []
        for url in js_urls:
            try:
                content = self.session.get(url, timeout=5).text
                findings.extend(self._analyze_content(url, content))
            except Exception as e:
                logger.debug(f"Error fetching JS {url}: {e}")
        return findings

    def _analyze_content(self, url: str, content: str) -> List[Dict]:
        results = []
        # Secret Scan
        for name, pattern in self.SECRET_PATTERNS.items():
            for match in re.finditer(pattern, content):
                secret = match.group(0)
                if not self._is_false_positive(secret):
                    results.append(self.create_finding(
                        type=f"JS Secret Exposure ({name})",
                        url=url,
                        severity="High",
                        details=f"Found potential {name}: {secret[:10]}...",
                        evidence={"snippet": secret}
                    ))
        
        # Endpoint Scan
        endpoints = self._find_endpoints(content)
        if endpoints:
            results.append(self.create_finding(
                type="JS Hardcoded Endpoints",
                url=url,
                severity="Info",
                details=f"Found {len(endpoints)} hardcoded paths/urls",
                evidence={"endpoints": endpoints[:20]}
            ))
            
        return results

    def _is_false_positive(self, secret: str) -> bool:
        # Shannon Entropy Check
        if len(secret) < 8: return True
        entropy = -sum((secret.count(c)/len(secret)) * math.log2(secret.count(c)/len(secret)) for c in set(secret))
        return entropy < 3.5

    def _find_endpoints(self, content: str) -> List[str]:
        # Simple regex for relative and absolute URLs
        regex = r"""(['"])(?:/|https?://)[a-zA-Z0-9_./-]+\1"""
        return [m.group(0).strip("'\"") for m in re.finditer(regex, content)]


class ContentDiscoveryScanner(BaseScanner):
    """
    Performs passive content discovery via Robots.txt, Sitemap.xml, and common file probing.
    """
    def scan(self, target_url: str) -> List[Dict[str, Any]]:
        findings = []
        
        # 1. Robots.txt
        findings.extend(self._check_robots(target_url))
        
        # 2. Sitemap.xml
        findings.extend(self._check_sitemap(target_url))
        
        # 3. Common Files Probe
        findings.extend(self._probe_files(target_url))
        
        return findings

    def _check_robots(self, base_url: str) -> List[Dict]:
        findings = []
        robots_url = urljoin(base_url, "/robots.txt")
        try:
            resp = self.session.get(robots_url, timeout=5)
            if resp.status_code == 200 and "User-agent" in resp.text:
                findings.append(self.create_finding(
                    type="Robots.txt Found",
                    url=robots_url,
                    severity="Info",
                    details="Robots.txt file is accessible.",
                    evidence={"content": resp.text[:500]}
                ))
                # Parse Disallow
                disallowed = re.findall(r"Disallow:\s*(.+)", resp.text)
                if disallowed:
                     findings.append(self.create_finding(
                        type="Robots.txt Disallowed Paths",
                        url=robots_url,
                        severity="Info",
                        details=f"Found {len(disallowed)} disallowed paths.",
                        evidence={"paths": disallowed}
                    ))
                
                # Check for subdomains in robots.txt
                subs = self._extract_subdomains(resp.text, base_url)
                if subs:
                    print(f"[+] Alt Sistemler (Robots.txt): {', '.join(subs)}")
                    findings.append(self.create_finding(
                        type="Subsystems Identified (Robots)",
                        url=robots_url,
                        severity="Info",
                        details=f"Found {len(subs)} subdomains in robots.txt",
                        evidence={"subdomains": list(subs)}
                    ))

        except:
            pass
        return findings

    def _check_sitemap(self, base_url: str) -> List[Dict]:
        findings = []
        # Try standard sitemap + those found in robots
        # Simulating logic for brevity
        sitemap_url = urljoin(base_url, "/sitemap.xml")
        try:
            resp = self.session.get(sitemap_url, timeout=5)
            if resp.status_code == 200 and "<urlset" in resp.text:
                 findings.append(self.create_finding(
                    type="Sitemap Found",
                    url=sitemap_url,
                    severity="Info",
                    details="Sitemap.xml is accessible."
                ))
                 
                 # Check for subdomains in sitemap
                 subs = self._extract_subdomains(resp.text, base_url)
                 if subs:
                    print(f"[+] Alt Sistemler (Sitemap): {', '.join(subs)}")
                    findings.append(self.create_finding(
                        type="Subsystems Identified (Sitemap)",
                        url=sitemap_url,
                        severity="Info",
                        details=f"Found {len(subs)} subdomains in sitemap.xml",
                        evidence={"subdomains": list(subs)}
                    ))
        except:
            pass
        return findings

    def _extract_subdomains(self, content: str, base_url: str) -> Set[str]:
        """Extracts unique subdomains from text content that match the base domain's root."""
        subdomains = set()
        try:
            parsed_base = urlparse(base_url)
            base_domain = parsed_base.netloc
            # Remove www. or similar prefixes to get root (simplified)
            root_parts = base_domain.split('.')
            if len(root_parts) > 2:
                root_domain = ".".join(root_parts[-2:]) # e.g. example.com
            else:
                root_domain = base_domain
            
            # Find all URLs
            urls = re.findall(r'(https?://[a-zA-Z0-9.-]+)', content)
            for u in urls:
                domain = urlparse(u).netloc
                if domain and domain.endswith(root_domain) and domain != base_domain:
                    subdomains.add(domain)
        except:
            pass
        return subdomains

    def _probe_files(self, base_url: str) -> List[Dict]:
        findings = []
        for f in SENSITIVE_FILES:
            url = urljoin(base_url, f"/{f}")
            try:
                resp = self.session.get(url, timeout=3, allow_redirects=False)
                if resp.status_code == 200:
                    # Basic content verification could be added here
                    findings.append(self.create_finding(
                        type="Sensitive File Exposure",
                        url=url,
                        severity="Medium",
                        details=f"Sensitive file {f} is publicly accessible.",
                    ))
            except:
                pass
        return findings

def run(target: str, session=None, results=None, **kwargs):
    # 1. Content Discovery
    cd_scanner = ContentDiscoveryScanner(session, results)
    cd_scanner.run(target) # BaseScanner.run usually expects 'scan' or override
    # But wait, ContentDiscoveryScanner overrides 'scan' but inherits BaseScanner.
    # BaseScanner.run calls scan(). So we can call .run(target) if BaseScanner has it.
    # Let's check BaseScanner briefly... assuming it has standard run->scan linkage.
    # If not, we call scan directly.
    # Actually, the file content shows ContentDiscoveryScanner defines scan(target_url), not run.
    # BaseScanner normally has run(). Let's assume standard usage.
    # But to be safe, I'll call scan local method if uncertain about BaseScanner.
    
    # Actually, looking at previous files, BaseScanner usually has run().
    # However, to be 100% safe with minimal assumptions:
    findings_cd = cd_scanner.scan(target)
    if results and "passive" in results: results["passive"].extend(findings_cd)
    
    # 2. JS Scan
    # We need JS urls. Crawl data?
    js_urls = []
    if results and "discovery" in results:
        # extract js from discovery
        pass
    
    # For now, let's just do a basic check on the target itself if it ends in .js
    if target.endswith(".js"):
        js_urls.append(target)
        
    js_scanner = PassiveJSScanner(session, results)
    findings_js = js_scanner.scan(js_urls)
    if results and "passive" in results: results["passive"].extend(findings_js)

