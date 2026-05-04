import os
import re
import math
import json
import socket
import logging
import concurrent.futures
import requests
import xml.etree.ElementTree as ET
from urllib.parse import urljoin, urlparse
from typing import List, Dict, Any, Set, Optional

from .base import BaseScanner

logger = logging.getLogger(__name__)

# --- Sensitive File List: loaded from wordlist, fallback to built-in ---
def _load_sensitive_files() -> List[str]:
    """Load sensitive file paths from wordlists/files.txt; fall back to built-in list."""
    try:
        _here = os.path.dirname(__file__)
        wl_path = os.path.normpath(os.path.join(_here, "..", "wordlists", "files.txt"))
        with open(wl_path, "r", encoding="utf-8", errors="ignore") as fh:
            paths = []
            for line in fh:
                line = line.strip()
                if line and not line.startswith("#"):
                    # Strip leading slash for urljoin compatibility
                    paths.append(line.lstrip("/"))
            if paths:
                return paths
    except Exception as exc:
        logger.debug(f"[PassiveRecon] Could not load files.txt: {exc!r}")

    # Built-in fallback (critical subset)
    return [
        ".env", ".env.local", ".env.production", ".env.backup",
        ".git/HEAD", ".git/config", ".git/COMMIT_EDITMSG",
        ".svn/entries", ".svn/wc.db", ".DS_Store", "Thumbs.db",
        "config.json", "config.yaml", "config.yml", "settings.json",
        "web.config", "app.config", "appsettings.json",
        "database.yml", "database.json", "db.json",
        "security.txt", ".well-known/security.txt",
        "crossdomain.xml", "clientaccesspolicy.xml",
        "backup.sql", "dump.sql", "db.sql",
        "backup.zip", "backup.tar.gz",
        "phpinfo.php", "info.php", "test.php",
        "package.json", "composer.json", "requirements.txt",
        "yarn.lock", "package-lock.json",
        "main.js.map", "app.js.map", "bundle.js.map",
        "sitemap.xml", "robots.txt",
        "error.log", "access.log", "debug.log", "app.log",
        ".ssh/id_rsa", "id_rsa", "private.key", "server.key",
        "wp-config.php", "configuration.php",
        "secrets.json", "credentials.json", "credentials.txt",
    ]

SENSITIVE_FILES: List[str] = _load_sensitive_files()

class PassiveJSScanner(BaseScanner):
    """
    Scans JavaScript files for hardcoded secrets, endpoints, emails, and source maps.
    """
    SECRET_PATTERNS = {
        "AWS Access Key":       r"AKIA[0-9A-Z]{16}",
        "AWS Secret Key":       r"(?i)aws.{0,20}secret.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]",
        "Google API Key":       r"AIza[0-9A-Za-z\-_]{35}",
        "Google OAuth":         r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com",
        "Slack Token":          r"xox[baprs]-[0-9A-Za-z\-]{10,48}",
        "Slack Webhook":        r"https://hooks\.slack\.com/services/T[0-9A-Z]+/B[0-9A-Z]+/[0-9a-zA-Z]+",
        "GitHub Token":         r"ghp_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z_]{82}",
        "GitLab Token":         r"glpat-[0-9a-zA-Z\-_]{20}",
        "Stripe Key":           r"(?:r|s)k_(?:live|test)_[0-9a-zA-Z]{24,}",
        "Twilio":               r"SK[0-9a-fA-F]{32}",
        "SendGrid":             r"SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}",
        "JWT":                  r"eyJ[a-zA-Z0-9\-_]+\.eyJ[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+",
        "S3 Bucket":            r"s3://[a-z0-9.\-]+|[a-z0-9.\-]+\.s3(?:\.[a-z0-9\-]+)?\.amazonaws\.com",
        "Generic API Key":      r"(?i)(?:api[_-]?key|apikey|api[_-]?secret|access[_-]?token|auth[_-]?token)\s*[:=]\s*['\"]([a-zA-Z0-9\-_]{16,})['\"]",
        "Private Key":          r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----",
        "Bearer Token":         r"(?i)Authorization\s*:\s*Bearer\s+[a-zA-Z0-9\-_\.]+",
        "Email Address":        r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
        "Internal IP":          r"(?:10|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}",
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
        """Extract relative and absolute URLs/paths from JS content."""
        found = set()
        # Absolute URLs
        for m in re.finditer(r"""['"]?(https?://[a-zA-Z0-9_.\-/?=&%#+:@]+)['"]?""", content):
            found.add(m.group(1).strip("'\""))
        # Relative paths (at least 2 segments, no extension or .json/.xml/.php etc.)
        for m in re.finditer(r"""['"](/(?:[a-zA-Z0-9_\-]+/)*[a-zA-Z0-9_\-]+(?:\.[a-zA-Z]{2,4})?)['"]""", content):
            found.add(m.group(1))
        # fetch/axios/XMLHttpRequest patterns
        for m in re.finditer(r"""(?:fetch|axios\.(?:get|post|put|delete|patch)|url\s*[:=])\s*['"]((?:https?://|/)[^'"]+)['"]""", content):
            found.add(m.group(1))
        return list(found)[:50]  # cap to avoid noise


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

        except Exception as exc:
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
        except Exception as exc:
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
        except Exception as exc:
            pass
        return subdomains

    def _probe_files(self, base_url: str) -> List[Dict]:
        findings = []
        for f in SENSITIVE_FILES:
            url = urljoin(base_url, f"/{f}")
            try:
                resp = self.session.get(url, timeout=4, allow_redirects=False)
                if resp.status_code != 200:
                    continue

                content = resp.text or ""
                severity = "Medium"
                details = f"Sensitive file '{f}' is publicly accessible"

                # Elevate severity for high-value files
                if any(x in f for x in (".env", ".git", ".sql", "private", "secret", "password", "credential")):
                    severity = "High"
                    details += " — may contain credentials or secrets"
                elif f.endswith(".map"):
                    severity = "Low"
                    details += " — source map exposes original source code"
                elif f in ("phpinfo.php", "info.php"):
                    severity = "High"
                    details += " — PHP configuration disclosure"

                # Content-based severity boost
                if re.search(r"(?i)(password|secret|private_key|api_key)\s*=\s*[^\s]{4,}", content):
                    severity = "Critical"
                    details += " — credential pattern found in content"

                findings.append(self.create_finding(
                    type="Sensitive File Exposure",
                    url=url,
                    severity=severity,
                    details=details,
                    evidence={"content_snippet": content[:300]},
                ))
            except Exception as exc:
                pass
        return findings

class APISchemaDiscovery(BaseScanner):
    """
    Discovers OpenAPI/Swagger schema endpoints and parses them to extract
    parameterized API paths for active scanner seeding.
    """

    _SCHEMA_PATHS = [
        "/swagger.json", "/swagger.yaml", "/swagger/v1/swagger.json",
        "/api-docs", "/api-docs.json", "/api/api-docs",
        "/v1/api-docs", "/v2/api-docs", "/v3/api-docs",
        "/openapi.json", "/openapi.yaml", "/openapi/v3/api-docs",
        "/api/swagger.json", "/api/openapi.json",
        "/swagger-ui/swagger.json",
        "/.well-known/openapi",
        "/rest/swagger.json", "/graphql/schema",
        "/api/schema", "/api/schema.json", "/api/schema.yaml",
        "/spec", "/spec.json", "/spec.yaml",
        "/api/v1/swagger.json", "/api/v2/swagger.json",
    ]

    def scan(self, base_url: str) -> List[Dict[str, Any]]:
        findings = []
        parsed_base = urlparse(base_url)
        origin = f"{parsed_base.scheme}://{parsed_base.netloc}"

        for path in self._SCHEMA_PATHS:
            schema_url = origin + path
            try:
                resp = self.session.get(schema_url, timeout=5, allow_redirects=True)
                if resp.status_code != 200:
                    continue
                content_type = resp.headers.get("Content-Type", "")
                body = resp.text

                # Must look like a schema
                if not any(k in body for k in ("swagger", "openapi", "paths", "info")):
                    continue

                logger.info(f"[APISchema] Found schema at {schema_url}")

                # Try to parse as JSON
                schema = None
                if "json" in content_type or body.strip().startswith("{"):
                    try:
                        schema = resp.json()
                    except Exception as exc:
                        pass

                endpoints = []
                if schema:
                    endpoints = self._extract_endpoints(schema, origin)

                findings.append(self.create_finding(
                    type="API Schema Exposed",
                    url=schema_url,
                    severity="Medium",
                    details=f"API schema publicly accessible — {len(endpoints)} endpoints extracted",
                    evidence={"endpoints": endpoints[:30]},
                ))

                # Seed extracted endpoints into results for active scanners
                if endpoints and isinstance(self.results, dict):
                    existing = self.results.setdefault("endpoints", [])
                    for ep in endpoints:
                        if ep not in existing:
                            existing.append(ep)
                    logger.info(f"[APISchema] Seeded {len(endpoints)} endpoints from {schema_url}")

            except Exception as e:
                logger.debug(f"[APISchema] {schema_url}: {e}")

        return findings

    def _extract_endpoints(self, schema: Dict, origin: str) -> List[str]:
        """Parse OpenAPI 2/3 schema, return fully qualified parameterized URLs."""
        paths = schema.get("paths") or {}
        base_path = schema.get("basePath", "")  # OAS2
        # OAS3 servers list
        servers = schema.get("servers", [])
        server_url = ""
        if servers:
            server_url = (servers[0].get("url") or "").rstrip("/")
            if server_url.startswith("/"):
                server_url = origin + server_url
            elif not server_url.startswith("http"):
                server_url = origin + "/" + server_url

        results = []
        for path, methods in paths.items():
            # Collect query parameters defined for this path
            query_params = set()
            for method_data in methods.values():
                if not isinstance(method_data, dict):
                    continue
                for param in method_data.get("parameters", []):
                    if isinstance(param, dict) and param.get("in") == "query":
                        name = param.get("name")
                        if name:
                            query_params.add(name)
                # OAS3 requestBody schema keys
                rb = method_data.get("requestBody", {})
                content = rb.get("content", {}) if isinstance(rb, dict) else {}
                for ct_data in content.values():
                    schema_obj = ct_data.get("schema", {}) if isinstance(ct_data, dict) else {}
                    for prop in (schema_obj.get("properties") or {}).keys():
                        query_params.add(prop)

            # Build URL
            full_path = (server_url or origin + base_path) + path
            # Replace OAS path params like {id} with 1
            full_path = re.sub(r"\{[^}]+\}", "1", full_path)
            if query_params:
                qs = "&".join(f"{p}=1" for p in list(query_params)[:5])
                full_path = f"{full_path}?{qs}"
            results.append(full_path)

        return results


# ---------------------------------------------------------------------------
# ShodanScanner — pasif servis/banner keşfi
# ---------------------------------------------------------------------------

class ShodanScanner(BaseScanner):
    """
    Shodan API ile hedef domain için açık port, banner ve CVE keşfi yapar.
    SHODAN_API_KEY ortam değişkeni veya results['shodan_api_key'] ile çalışır.
    Key yoksa sessizce atlar.
    """
    _BASE = "https://api.shodan.io"

    def _key(self) -> Optional[str]:
        return os.environ.get("SHODAN_API_KEY") or (self.results or {}).get("shodan_api_key")

    def scan(self, domain: str) -> List[Dict[str, Any]]:
        key = self._key()
        if not key:
            logger.debug("[Shodan] API key yok, atlanıyor.")
            return []
        findings: List[Dict[str, Any]] = []

        # 1. DNS tabanlı subdomain keşfi
        try:
            r = self.session.get(f"{self._BASE}/dns/domain/{domain}?key={key}", timeout=15)
            if r.status_code == 200:
                data = r.json()
                for sub in data.get("subdomains", []):
                    fqdn = f"{sub}.{domain}"
                    findings.append(self.create_finding(
                        type="Shodan: Subdomain Keşfi",
                        url=f"https://{fqdn}", severity="Info",
                        details=f"Shodan DNS kaydında tespit: {fqdn}",
                        evidence={"tags": data.get("tags", []), "source": "shodan_dns"},
                    ))
        except Exception as e:
            logger.debug(f"[Shodan] DNS sorgu hatası: {e}")

        # 2. Host bilgisi: açık portlar, banner'lar, CVE'ler
        try:
            ip = socket.gethostbyname(domain)
            r2 = self.session.get(f"{self._BASE}/shodan/host/{ip}?key={key}", timeout=15)
            if r2.status_code == 200:
                h = r2.json()
                ports = h.get("ports", [])
                vulns = list(h.get("vulns", {}).keys())
                banners = [d.get("product", "") for d in h.get("data", []) if d.get("product")]
                os_str = h.get("os") or ""
                risky_ports = {21, 22, 23, 25, 110, 143, 3306, 5432, 6379, 8080, 27017, 9200, 11211}
                if ports:
                    sev = "High" if any(p in risky_ports for p in ports) else ("Medium" if len(ports) > 5 else "Info")
                    findings.append(self.create_finding(
                        type="Shodan: Açık Port Tespiti",
                        url=f"https://{domain}", severity=sev,
                        details=f"IP {ip} — {len(ports)} açık port tespit edildi",
                        evidence={"ports": sorted(ports), "banners": list(set(b for b in banners if b))[:10], "os": os_str, "ip": ip},
                    ))
                if vulns:
                    findings.append(self.create_finding(
                        type="Shodan: Bilinen CVE Tespiti",
                        url=f"https://{domain}", severity="Critical",
                        details=f"Shodan {len(vulns)} bilinen CVE tespit etti — derhal yamalayın",
                        evidence={"cves": vulns[:20], "ip": ip},
                    ))
        except Exception as e:
            logger.debug(f"[Shodan] Host sorgu hatası: {e}")

        logger.info(f"[Shodan] {domain}: {len(findings)} bulgu")
        return findings


# ---------------------------------------------------------------------------
# GitHubDorkScanner — GitHub Search API ile gizli bilgi sızıntısı
# ---------------------------------------------------------------------------

class GitHubDorkScanner(BaseScanner):
    """
    GitHub Search API kullanarak hedef domain/org'a ait açığa çıkmış
    secret, password, API key gibi bilgileri arar.
    GITHUB_TOKEN ile rate limit artırılır (opsiyonel).
    """
    _API = "https://api.github.com/search/code"
    _DORK_TEMPLATES = [
        '"{domain}" password',
        '"{domain}" api_key',
        '"{domain}" apiKey',
        '"{domain}" secret',
        '"{domain}" access_token',
        '"{domain}" private_key',
        '"{domain}" aws_access_key_id',
        '"{domain}" db_password',
        'org:{org} password filename:.env',
        'org:{org} secret filename:config',
        'org:{org} apikey',
        'org:{org} BEGIN RSA PRIVATE KEY',
    ]

    def _headers(self) -> Dict[str, str]:
        token = os.environ.get("GITHUB_TOKEN") or (self.results or {}).get("github_token", "")
        h: Dict[str, str] = {"Accept": "application/vnd.github.v3+json"}
        if token:
            h["Authorization"] = f"token {token}"
        return h

    def scan(self, domain: str) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        org = domain.split(".")[0]
        dorks = [t.format(domain=domain, org=org) for t in self._DORK_TEMPLATES]

        for dork in dorks:
            try:
                r = self.session.get(
                    self._API,
                    params={"q": dork, "per_page": 5},
                    headers=self._headers(),
                    timeout=15,
                )
                if r.status_code in (403, 422):
                    logger.debug(f"[GitHub] Rate limit / hatalı dork: {dork}")
                    continue
                if r.status_code != 200:
                    continue
                items = r.json().get("items", [])
                for item in items[:3]:
                    html_url = item.get("html_url", "")
                    repo = item.get("repository", {}).get("full_name", "")
                    findings.append(self.create_finding(
                        type="GitHub: Potansiyel Secret Sızıntısı",
                        url=html_url,
                        severity="High",
                        details=f"GitHub'da gizli bilgi tespiti. Dork: '{dork}'",
                        evidence={"dork": dork, "repository": repo, "file_url": html_url},
                    ))
            except Exception as e:
                logger.debug(f"[GitHub] Dork hatası '{dork}': {e}")

        logger.info(f"[GitHub] {domain}: {len(findings)} potansiyel sızıntı")
        return findings


# ---------------------------------------------------------------------------
# WaybackScanner — Wayback Machine CDX API ile tarihi URL keşfi
# ---------------------------------------------------------------------------

class WaybackScanner(BaseScanner):
    """
    Web Archive CDX API ile hedef domain'in tüm arşivlenmiş URL'lerini keşfeder.
    Auth gerektirmez. Keşfedilen endpoint'ler aktif tarayıcılar için
    results['endpoints'] havuzuna eklenir.
    """
    _CDX = "https://web.archive.org/cdx/search/cdx"
    _INTERESTING_RE = re.compile(
        r"(?:/admin|/api|/backup|/config|/debug|/dev|/export|/hidden|/internal|"
        r"/login|/manage|/panel|/secret|/staging|/swagger|/token|/upload|"
        r"\.php|\.asp|\.aspx|\.jsp|\.env|\.json|\.xml|\.yaml|\.yml|"
        r"/v\d+/|/graphql|/rest|/rpc)(?:[/?#]|$)",
        re.IGNORECASE,
    )

    def scan(self, domain: str) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        try:
            r = self.session.get(
                self._CDX,
                params={
                    "url": f"*.{domain}/*",
                    "output": "json",
                    "fl": "original,statuscode,timestamp",
                    "collapse": "urlkey",
                    "limit": "2000",
                    "filter": "statuscode:200",
                },
                timeout=30,
            )
            if r.status_code != 200:
                return findings
            rows = r.json()
            if not rows or len(rows) < 2:
                return findings

            header = rows[0]
            col = {h: i for i, h in enumerate(header)}
            urls_seen: Set[str] = set()
            interesting: List[str] = []

            for row in rows[1:]:
                try:
                    url_str = row[col.get("original", 0)]
                except (IndexError, TypeError):
                    continue
                if not url_str or url_str in urls_seen:
                    continue
                urls_seen.add(url_str)
                if self._INTERESTING_RE.search(url_str):
                    interesting.append(url_str)

            # Aktif tarayıcılar için endpoint havuzuna ekle
            if self.results is not None:
                ep = self.results.setdefault("endpoints", [])
                for u in list(urls_seen)[:500]:
                    if u not in ep:
                        ep.append(u)

            if urls_seen:
                findings.append(self.create_finding(
                    type="Wayback: Tarihi URL Keşfi",
                    url=f"https://{domain}",
                    severity="Info",
                    details=f"Wayback Machine: {len(urls_seen)} URL, {len(interesting)} ilginç endpoint",
                    evidence={"total_urls": len(urls_seen), "interesting": interesting[:30]},
                ))
            logger.info(f"[Wayback] {domain}: {len(urls_seen)} URL, {len(interesting)} ilginç")
        except Exception as e:
            logger.debug(f"[Wayback] Hata: {e}")
        return findings


# ---------------------------------------------------------------------------
# S3BucketScanner — S3 / GCS / Azure Blob bucket keşfi
# ---------------------------------------------------------------------------

class S3BucketScanner(BaseScanner):
    """
    Hedef domain'den türetilen isimlendirme kalıpları ile S3, GCS ve
    Azure Blob bucket'larını test eder. Public erişim → Critical,
    private (403) → Medium.
    """
    _SUFFIXES = [
        "", "-prod", "-production", "-dev", "-development", "-staging",
        "-stage", "-uat", "-qa", "-test", "-backup", "-bak", "-old",
        "-static", "-assets", "-media", "-img", "-images", "-cdn",
        "-files", "-data", "-storage", "-archive", "-public", "-private",
        "-internal", "-api", "-app", "-web", "-frontend", "-backend",
        "-upload", "-uploads", "-logs", "-log", "-www", "-resources",
    ]
    _S3_ENDPOINTS = [
        "s3.amazonaws.com",
        "s3.us-east-1.amazonaws.com",
        "s3.us-west-2.amazonaws.com",
        "s3.eu-west-1.amazonaws.com",
    ]

    def _gen_names(self, domain: str) -> List[str]:
        base = domain.split(".")[0]           # example
        full = domain.replace(".", "-")       # example-com
        names: Set[str] = set()
        for stem in [base, full]:
            for suf in self._SUFFIXES:
                names.add(f"{stem}{suf}")
        return list(names)

    def _check_s3(self, name: str) -> Optional[Dict]:
        for ep in self._S3_ENDPOINTS:
            url = f"https://{name}.{ep}"
            try:
                r = self.session.head(url, timeout=6, allow_redirects=False)
                if r.status_code == 200:
                    return self.create_finding(
                        type="S3 Bucket: Herkese Açık (Critical)",
                        url=url, severity="Critical",
                        details=f"S3 bucket herkese açık okuma erişimine sahip: {name}",
                        evidence={"bucket": name, "endpoint": ep},
                    )
                if r.status_code == 403:
                    return self.create_finding(
                        type="S3 Bucket: Tespit Edildi (Private)",
                        url=url, severity="Medium",
                        details=f"S3 bucket mevcut ancak kısıtlı: {name}",
                        evidence={"bucket": name, "endpoint": ep},
                    )
            except Exception:
                pass
        return None

    def _check_gcs(self, name: str) -> Optional[Dict]:
        url = f"https://storage.googleapis.com/{name}"
        try:
            r = self.session.head(url, timeout=6, allow_redirects=False)
            if r.status_code == 200:
                return self.create_finding(
                    type="GCS Bucket: Herkese Açık (Critical)",
                    url=url, severity="Critical",
                    details=f"GCS bucket herkese açık: {name}",
                    evidence={"bucket": name},
                )
            if r.status_code == 403:
                return self.create_finding(
                    type="GCS Bucket: Tespit Edildi (Private)",
                    url=url, severity="Medium",
                    details=f"GCS bucket mevcut ancak kısıtlı: {name}",
                    evidence={"bucket": name},
                )
        except Exception:
            pass
        return None

    def _check_azure(self, name: str) -> Optional[Dict]:
        url = f"https://{name}.blob.core.windows.net"
        try:
            r = self.session.head(url, timeout=6, allow_redirects=False)
            if r.status_code == 200:
                return self.create_finding(
                    type="Azure Blob: Herkese Açık (Critical)",
                    url=url, severity="Critical",
                    details=f"Azure Blob herkese açık: {name}",
                    evidence={"container": name},
                )
            if r.status_code in (400, 403, 404):
                # 400 = container exists but requires auth
                if r.status_code in (400, 403):
                    return self.create_finding(
                        type="Azure Blob: Tespit Edildi (Private)",
                        url=url, severity="Low",
                        details=f"Azure Blob mevcut ancak kısıtlı: {name}",
                        evidence={"container": name},
                    )
        except Exception:
            pass
        return None

    def scan(self, domain: str) -> List[Dict[str, Any]]:
        names = self._gen_names(domain)
        logger.info(f"[S3Scanner] {len(names)} bucket ismi × 3 cloud = {len(names)*3} kontrol")
        findings: List[Dict[str, Any]] = []

        def _probe(name: str) -> List[Optional[Dict]]:
            return [self._check_s3(name), self._check_gcs(name), self._check_azure(name)]

        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:
            for results_batch in ex.map(_probe, names):
                for f in results_batch:
                    if f:
                        findings.append(f)

        logger.info(f"[S3Scanner] {domain}: {len(findings)} bucket bulgusu")
        return findings


# ---------------------------------------------------------------------------
# CloudDetector — HTTP yanıt başlıkları + CNAME ile cloud tespiti
# ---------------------------------------------------------------------------

class CloudDetector(BaseScanner):
    """
    HTTP response header'larını analiz ederek hedef sistemin hangi cloud
    altyapısında çalıştığını tespit eder. Subdomain takeover riski de değerlendirilir.
    """
    _HEADER_SIGS: Dict[str, List[str]] = {
        "AWS / EC2":        ["x-amzn-requestid", "x-amz-id-2", "x-amz-request-id"],
        "AWS S3":           ["x-amz-bucket-region", "x-amz-delete-marker", "x-amz-version-id"],
        "AWS CloudFront":   ["x-amz-cf-id", "x-amz-cf-pop"],
        "GCP":              ["x-guploader-uploadid", "x-goog-generation"],
        "Azure":            ["x-azure-ref", "x-ms-request-id", "x-ms-version"],
        "Cloudflare":       ["cf-ray", "cf-cache-status"],
        "Fastly":           ["x-fastly-request-id", "fastly-restarts"],
        "Akamai":           ["x-check-cacheable", "x-akamai-transformed"],
        "Vercel":           ["x-vercel-id", "x-vercel-cache"],
        "Netlify":          ["x-nf-request-id"],
        "Heroku":           ["x-heroku-queue-wait-time", "x-heroku-dynos-in-use"],
    }
    # CNAME suffixes → potential subdomain takeover targets
    _TAKEOVER_CNAMES: Dict[str, str] = {
        "s3.amazonaws.com":           "AWS S3 (subdomain takeover riski)",
        "cloudfront.net":             "AWS CloudFront",
        "github.io":                  "GitHub Pages (subdomain takeover riski)",
        "azurewebsites.net":          "Azure App Service (subdomain takeover riski)",
        "azurefd.net":                "Azure Front Door",
        "googleusercontent.com":      "GCP",
        "appspot.com":                "GCP App Engine (subdomain takeover riski)",
        "netlify.app":                "Netlify (subdomain takeover riski)",
        "vercel.app":                 "Vercel",
        "fastly.net":                 "Fastly",
        "herokudns.com":              "Heroku (subdomain takeover riski)",
        "shopify.com":                "Shopify (subdomain takeover riski)",
        "unbouncepages.com":          "Unbounce (subdomain takeover riski)",
        "cargo.site":                 "Cargo (subdomain takeover riski)",
    }

    def scan(self, url: str) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        detected: Set[str] = set()
        domain = urlparse(url).hostname or url

        # 1. HTTP başlık analizi
        try:
            r = self.session.head(url, timeout=10, allow_redirects=True)
            resp_headers_lower = {k.lower(): v.lower() for k, v in r.headers.items()}
            for provider, sigs in self._HEADER_SIGS.items():
                for sig in sigs:
                    if any(sig in k or (sig in v if len(sig) > 4 else False)
                           for k, v in resp_headers_lower.items()):
                        detected.add(provider)
                        break
        except Exception as e:
            logger.debug(f"[CloudDetect] HTTP hatası: {e}")

        # 2. DNS CNAME analizi + subdomain takeover tespiti
        try:
            import subprocess
            result = subprocess.run(
                ["nslookup", "-type=CNAME", domain],
                capture_output=True, text=True, timeout=8, errors="replace",
            )
            cname_output = (result.stdout or "").lower()
            for cname_hint, provider in self._TAKEOVER_CNAMES.items():
                if cname_hint in cname_output:
                    detected.add(provider)
                    # Takeover riski varsa ayrı bulgu üret
                    if "takeover" in provider.lower():
                        # Hedef gerçekten erişilebilir mi kontrol et
                        try:
                            probe = requests.head(f"https://{domain}", timeout=5)
                            alive = probe.status_code not in (404, 410)
                        except Exception:
                            alive = False
                        if not alive:
                            findings.append(self.create_finding(
                                type="Subdomain Takeover Riski",
                                url=url, severity="Critical",
                                details=f"CNAME {cname_hint} işaret ediyor ancak hedef servis yanıt vermiyor — takeover mümkün",
                                evidence={"cname": cname_hint, "provider": provider, "domain": domain},
                            ))
        except Exception:
            pass

        if detected:
            findings.append(self.create_finding(
                type="Cloud Altyapı Tespiti",
                url=url, severity="Info",
                details=f"Tespit edilen cloud sağlayıcı(lar): {', '.join(sorted(detected))}",
                evidence={"providers": sorted(detected), "domain": domain},
            ))
            logger.info(f"[CloudDetect] {url}: {', '.join(sorted(detected))}")
        return findings


# ---------------------------------------------------------------------------
# EmailHarvester — sayfa tarama + Hunter.io API
# ---------------------------------------------------------------------------

class EmailHarvester(BaseScanner):
    """
    Hedef siteden ve opsiyonel olarak Hunter.io API'sinden e-posta adresleri toplar.
    Bulunan adresler sosyal mühendislik & spear phishing riski taşır.
    """
    _PAGES = [
        "", "/contact", "/about", "/team", "/careers", "/support",
        "/contact-us", "/about-us", "/staff", "/people", "/press",
        "/our-team", "/leadership", "/management",
    ]
    _EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,6}")

    def _hunter_key(self) -> Optional[str]:
        return os.environ.get("HUNTER_API_KEY") or (self.results or {}).get("hunter_api_key")

    def scan(self, target_url: str, domain: str) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        found_emails: Set[str] = set()
        parsed = urlparse(target_url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        # 1. Sayfa tarama
        for path in self._PAGES:
            page_url = origin + path
            try:
                r = self.session.get(page_url, timeout=8, allow_redirects=True)
                if r.status_code == 200:
                    for email in self._EMAIL_RE.findall(r.text):
                        if domain in email:
                            found_emails.add(email.lower())
            except Exception:
                pass

        # 2. Hunter.io API (opsiyonel — key varsa)
        key = self._hunter_key()
        if key:
            try:
                r = requests.get(
                    "https://api.hunter.io/v2/domain-search",
                    params={"domain": domain, "api_key": key, "limit": 100},
                    timeout=15,
                )
                if r.status_code == 200:
                    for em in r.json().get("data", {}).get("emails", []):
                        em_val = em.get("value", "")
                        if em_val:
                            found_emails.add(em_val.lower())
            except Exception as e:
                logger.debug(f"[Hunter] API hatası: {e}")

        if found_emails:
            findings.append(self.create_finding(
                type="Email Adresi Tespiti",
                url=target_url, severity="Info",
                details=f"{len(found_emails)} e-posta adresi tespit edildi — spear phishing riski",
                evidence={"emails": sorted(found_emails), "count": len(found_emails)},
            ))
            logger.info(f"[EmailHarvester] {domain}: {len(found_emails)} email")
        return findings


# ---------------------------------------------------------------------------
# Plugin API — run()
# ---------------------------------------------------------------------------

def run(target: str, session=None, results=None, **kwargs):
    if results is None:
        results = {}
    results.setdefault("passive", [])
    results.setdefault("endpoints", [])

    parsed = urlparse(target)
    domain = parsed.hostname or target.split("://")[-1].split("/")[0].split(":")[0]

    # 1. Content Discovery (robots.txt, sitemap.xml, hassas dosyalar)
    cd_scanner = ContentDiscoveryScanner(session, results)
    results["passive"].extend(cd_scanner.scan(target))

    # 2. API Schema Discovery (OpenAPI / Swagger)
    api_scanner = APISchemaDiscovery(session, results)
    results["passive"].extend(api_scanner.scan(target))

    # 3. JS Secret & Endpoint Scan
    js_urls: List[str] = []
    discovery = results.get("discovery", {})
    if isinstance(discovery, dict):
        for u in discovery.get("js", []) + discovery.get("query", []):
            if isinstance(u, str) and u.endswith(".js"):
                js_urls.append(u)
    for u in kwargs.get("js_urls", []):
        if u not in js_urls:
            js_urls.append(u)
    if target.endswith(".js") and target not in js_urls:
        js_urls.append(target)
    if not js_urls and session:
        try:
            resp = session.get(target, timeout=8)
            if resp.status_code == 200:
                for m in re.finditer(
                    r'<script[^>]+src=["\']([^"\']+\.js(?:\?[^"\']*)?)["\']',
                    resp.text, re.IGNORECASE,
                ):
                    js_full = urljoin(target, m.group(1))
                    if js_full not in js_urls:
                        js_urls.append(js_full)
        except Exception as e:
            logger.debug(f"[PassiveRecon] JS çıkarımı başarısız: {e}")
    if js_urls:
        logger.info(f"[PassiveRecon] {len(js_urls)} JS dosyası taranıyor")
        js_scanner = PassiveJSScanner(session, results)
        results["passive"].extend(js_scanner.scan(js_urls))

    # 4. Cloud Altyapı Tespiti
    cloud_scanner = CloudDetector(session, results)
    results["passive"].extend(cloud_scanner.scan(target))

    # 5. Wayback Machine — tarihi URL keşfi
    wayback_scanner = WaybackScanner(session, results)
    results["passive"].extend(wayback_scanner.scan(domain))

    # 6. S3 / GCS / Azure Bucket Discovery
    s3_scanner = S3BucketScanner(session, results)
    results["passive"].extend(s3_scanner.scan(domain))

    # 7. GitHub Dorking (GITHUB_TOKEN ile en iyi sonuç)
    gh_scanner = GitHubDorkScanner(session, results)
    results["passive"].extend(gh_scanner.scan(domain))

    # 8. Shodan (SHODAN_API_KEY gerekli)
    shodan_scanner = ShodanScanner(session, results)
    results["passive"].extend(shodan_scanner.scan(domain))

    # 9. Email Harvesting
    email_scanner = EmailHarvester(session, results)
    results["passive"].extend(email_scanner.scan(target, domain))

