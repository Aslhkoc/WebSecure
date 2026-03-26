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
    # Version control / config leaks
    ".env", ".env.local", ".env.production", ".env.backup",
    ".git/HEAD", ".git/config", ".git/COMMIT_EDITMSG",
    ".svn/entries", ".svn/wc.db",
    ".DS_Store", "Thumbs.db",
    # Application config
    "config.json", "config.yaml", "config.yml", "settings.json",
    "web.config", "app.config", "appsettings.json",
    "database.yml", "database.json", "db.json",
    # Security / disclosure files
    "security.txt", ".well-known/security.txt",
    "humans.txt", "crossdomain.xml", "clientaccesspolicy.xml",
    # Backup files
    "backup.sql", "dump.sql", "db.sql",
    "backup.zip", "backup.tar.gz",
    "index.php.bak", "index.html.bak",
    # Common admin/debug paths
    "phpinfo.php", "info.php", "test.php",
    "admin/", "phpmyadmin/", "adminer.php",
    # Dependency / build manifests
    "package.json", "composer.json", "Gemfile",
    "requirements.txt", "Pipfile",
    "yarn.lock", "package-lock.json",
    # Source maps
    "main.js.map", "app.js.map", "bundle.js.map",
    "static/js/main.chunk.js.map",
    # Sitemap / robots
    "sitemap.xml", "sitemap_index.xml", "robots.txt",
    # Log files
    "error.log", "access.log", "debug.log", "app.log",
]

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


def run(target: str, session=None, results=None, **kwargs):
    if results is None:
        results = {}
    results.setdefault("passive", [])

    # 1. Content Discovery (robots, sitemap, sensitive files)
    cd_scanner = ContentDiscoveryScanner(session, results)
    findings_cd = cd_scanner.scan(target)
    results["passive"].extend(findings_cd)

    # 1b. API Schema Discovery (OpenAPI / Swagger)
    api_scanner = APISchemaDiscovery(session, results)
    findings_api = api_scanner.scan(target)
    results["passive"].extend(findings_api)

    # 2. JS Secret & Endpoint Scan
    # Collect JS URLs from: discovery results, explicit kwarg, and page crawl
    js_urls: List[str] = []

    # From crawl/discovery results
    discovery = results.get("discovery", {})
    if isinstance(discovery, dict):
        for u in discovery.get("js", []):
            if isinstance(u, str) and u.endswith(".js"):
                js_urls.append(u)
        # Also scan any endpoint that looks like JS
        for u in discovery.get("query", []):
            if isinstance(u, str) and u.endswith(".js"):
                js_urls.append(u)

    # Explicit JS URL list from kwargs
    for u in kwargs.get("js_urls", []):
        if u not in js_urls:
            js_urls.append(u)

    # If target itself is a JS file
    if target.endswith(".js") and target not in js_urls:
        js_urls.append(target)

    # Probe the target page and extract referenced JS files
    if not js_urls and session:
        try:
            resp = session.get(target, timeout=8)
            if resp.status_code == 200:
                for m in re.finditer(r'<script[^>]+src=["\']([^"\']+\.js(?:\?[^"\']*)?)["\']', resp.text, re.IGNORECASE):
                    js_path = m.group(1)
                    js_full = urljoin(target, js_path)
                    if js_full not in js_urls:
                        js_urls.append(js_full)
        except Exception as e:
            logger.debug(f"[PassiveRecon] JS extraction from page failed: {e}")

    if js_urls:
        logger.info(f"[PassiveRecon] Scanning {len(js_urls)} JS file(s)")
        js_scanner = PassiveJSScanner(session, results)
        findings_js = js_scanner.scan(js_urls)
        results["passive"].extend(findings_js)

