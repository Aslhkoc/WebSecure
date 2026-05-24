"""
websecure.scanners.js_analyzer
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
JavaScript file analysis scanner.
- Discovers all JS files linked from target pages
- Extracts hidden API endpoints, paths, routes
- Detects hardcoded secrets, tokens, API keys
- Reports discovered files with extension-based risk analysis
"""
from __future__ import annotations

import re
import logging
from typing import Any, Dict, List, Set, Optional
from urllib.parse import urljoin, urlparse

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------

# API endpoint / path patterns inside JS
_RE_PATHS = re.compile(
    r"""["'`](\s*/(?:api|v\d|graphql|rest|rpc|internal|admin|auth|oauth|user|account|data|service|backend|endpoint|mobile|public|private|secure|upload|download|file|static|assets|config|settings|manage|panel|dashboard)[/a-zA-Z0-9_\-\.?&=%]*)["'`]""",
    re.IGNORECASE,
)

# Generic path-like strings (e.g. "/users/profile", "/checkout")
_RE_GENERIC_PATHS = re.compile(
    r"""["'`](/[a-zA-Z0-9_\-]{2,}/[a-zA-Z0-9_\-/\.]{2,})["'`]"""
)

# fetch / axios / XMLHttpRequest / jQuery AJAX URL extraction
_RE_FETCH_URLS = re.compile(
    r"""(?:fetch|axios\.(?:get|post|put|delete|patch|request)|"url"\s*:|\$\.(?:ajax|get|post))\s*\(?\s*["'`]((?:https?://|/)[^"'`\s]{3,})["'`]""",
    re.IGNORECASE,
)

# Source map reference inside JS files
_RE_SOURCEMAP = re.compile(r"//[#@]\s*sourceMappingURL=([^\s]+)", re.IGNORECASE)

# Hardcoded secret / credential patterns — genişletilmiş set (30+ pattern)
_SECRET_PATTERNS: List[tuple] = [
    # Cloud provider keys
    ("AWS Access Key",      re.compile(r"""AKIA[0-9A-Z]{16}""")),
    ("AWS Secret Key",      re.compile(r"""(?i)aws[_\-\s]?secret[_\-\s]?(?:access[_\-\s]?)?key\s*[:=]\s*["'`]([A-Za-z0-9/+=]{40})["'`]""")),
    ("Google API Key",      re.compile(r"""AIza[0-9A-Za-z\-_]{35}""")),
    ("Google OAuth",        re.compile(r"""[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com""")),
    ("Firebase URL",        re.compile(r"""https://[a-z0-9-]+\.firebaseio\.com""", re.I)),
    ("Firebase API Key",    re.compile(r"""(?:firebase[Aa]pi[Kk]ey|FIREBASE_API_KEY)\s*[:=]\s*["'`]([A-Za-z0-9_\-]{32,})["'`]""")),
    # Token patterns
    ("GitHub Token",        re.compile(r"""ghp_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z_]{82}|gho_[0-9a-zA-Z]{36}""")),
    ("GitLab Token",        re.compile(r"""glpat-[0-9a-zA-Z\-_]{20}""")),
    ("Slack Token",         re.compile(r"""xox[baprs]-[0-9A-Za-z\-]{10,48}""")),
    ("Slack Webhook",       re.compile(r"""https://hooks\.slack\.com/services/T[0-9A-Z]+/B[0-9A-Z]+/[0-9a-zA-Z]+""")),
    ("Stripe Key",          re.compile(r"""(?:r|s)k_(?:live|test)_[0-9a-zA-Z]{24,}""")),
    ("Stripe Webhook",      re.compile(r"""whsec_[0-9a-zA-Z]{32,}""")),
    ("Twilio",              re.compile(r"""SK[0-9a-fA-F]{32}""")),
    ("SendGrid",            re.compile(r"""SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}""")),
    ("NPM Token",           re.compile(r"""(?:npm_[A-Za-z0-9]{36}|//registry\.npmjs\.org/:_authToken\s*=\s*([^\s]+))""")),
    ("Docker Hub Token",    re.compile(r"""(?i)docker(?:hub)?[_\-\s]?(?:token|password|secret)\s*[:=]\s*["'`]([A-Za-z0-9_\-\.]{16,})["'`]""")),
    ("Heroku API Key",      re.compile(r"""(?i)heroku[_\-\s]?(?:api[_\-\s]?)?key\s*[:=]\s*["'`]([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})["'`]""")),
    ("Mailchimp",           re.compile(r"""[0-9a-f]{32}-us[0-9]{1,2}""")),
    ("Mailgun",             re.compile(r"""key-[0-9a-zA-Z]{32}""")),
    ("Zendesk Token",       re.compile(r"""(?i)zendesk[_\-\s]?(?:api[_\-\s]?)?(?:token|key)\s*[:=]\s*["'`]([A-Za-z0-9_\-]{20,})["'`]""")),
    ("Shopify Token",       re.compile(r"""shpss_[0-9a-fA-F]{32}|shpat_[0-9a-fA-F]{32}""")),
    # Generic credential patterns
    ("API Key",             re.compile(r"""(?:apiKey|api_key|apikey|API_KEY)\s*[:=]\s*["'`]([A-Za-z0-9_\-]{16,})["'`]""", re.I)),
    ("Access Token",        re.compile(r"""(?:access_token|accessToken|ACCESS_TOKEN)\s*[:=]\s*["'`]([A-Za-z0-9_\-\.]{16,})["'`]""", re.I)),
    ("Auth Token",          re.compile(r"""(?:auth_token|authToken|AUTH_TOKEN|bearer_token)\s*[:=]\s*["'`]([A-Za-z0-9_\-\.]{16,})["'`]""", re.I)),
    ("Secret Key",          re.compile(r"""(?:secret_key|secretKey|SECRET_KEY|app_secret|APP_SECRET)\s*[:=]\s*["'`]([A-Za-z0-9_\-\.!@#]{10,})["'`]""", re.I)),
    ("Password",            re.compile(r"""(?:password|passwd|pwd|PASSWORD|PASSWD)\s*[:=]\s*["'`]([^\s"'`]{6,})["'`]""", re.I)),
    ("Database URL",        re.compile(r"""(?:DATABASE_URL|db_url|DB_URL|connection_string)\s*[:=]\s*["'`]((?:postgres|mysql|mongodb|redis|mssql)://[^\s"'`]{8,})["'`]""", re.I)),
    ("Private Key",         re.compile(r"""-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----""")),
    ("JWT Token",           re.compile(r"""eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}""")),
    ("S3 Bucket",           re.compile(r"""s3\.amazonaws\.com/[a-zA-Z0-9_\-\.]+""", re.I)),
    ("Internal IP",         re.compile(r"""["'`]((?:10|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3})["'`]""")),
]

# JS file extensions we want to analyse
_JS_EXTENSIONS = {".js", ".mjs", ".jsx", ".ts", ".tsx", ".vue"}

# File extensions considered sensitive if discovered via fuzzing
SENSITIVE_EXTENSIONS = {
    ".env": "Critical",
    ".bak": "High",
    ".sql": "High",
    ".zip": "Medium",
    ".tar": "Medium",
    ".gz":  "Medium",
    ".log": "Medium",
    ".xml": "Low",
    ".json": "Low",
    ".config": "High",
    ".cfg": "High",
    ".ini": "Medium",
    ".swp": "Medium",
    ".old": "Medium",
    ".orig": "Medium",
    ".backup": "High",
    ".dump": "High",
    ".db": "Critical",
    ".sqlite": "Critical",
    ".key": "Critical",
    ".pem": "Critical",
    ".p12": "Critical",
    ".pfx": "Critical",
}


# ---------------------------------------------------------------------------
# Main scanner
# ---------------------------------------------------------------------------

class JSAnalyzer:
    """Discovers and analyses JavaScript files for hidden endpoints and secrets."""

    def __init__(self, session=None, results: Dict = None, debug: bool = False):
        self.session = session
        self.results = results if results is not None else {}
        self.debug = debug
        self._visited_js: Set[str] = set()

    # ------------------------------------------------------------------
    def run(self, url: str, **kwargs) -> List[Dict[str, Any]]:
        """
        Entry point.  Discovers JS files linked from *url* and all crawler
        endpoints already stored in self.results, then analyses each one.
        """
        findings: List[Dict[str, Any]] = []

        js_urls = self._collect_js_urls(url)
        logger.info(f"[JSAnalyzer] {len(js_urls)} JS file(s) found.")

        for js_url in js_urls:
            if js_url in self._visited_js:
                continue
            self._visited_js.add(js_url)
            findings.extend(self._analyse_js_file(js_url))

        return findings

    # ------------------------------------------------------------------
    def _collect_js_urls(self, base_url: str) -> Set[str]:
        """
        Collects JS file URLs from:
        1. HTML source of the base page
        2. Already crawled endpoints in self.results
        3. Common JS paths probed directly
        """
        js_urls: Set[str] = set()

        # 1. Fetch base page and extract <script src="...">
        try:
            resp = self.session.get(base_url, timeout=10)
            js_urls.update(self._extract_script_tags(resp.text, base_url))
        except Exception as e:
            logger.warning(f"[JSAnalyzer] Base page fetch failed: {e}")

        # 2. Endpoints from crawler results
        for ep in self.results.get("endpoints", []):
            if isinstance(ep, str) and any(ep.endswith(ext) for ext in _JS_EXTENSIONS):
                js_urls.add(ep if ep.startswith("http") else urljoin(base_url, ep))

        # 3. Common JS paths (genişletilmiş)
        common_js_paths = [
            "/main.js", "/app.js", "/bundle.js", "/chunk.js", "/index.js",
            "/static/js/main.js", "/assets/js/app.js", "/js/app.js",
            "/dist/main.js", "/build/static/js/main.chunk.js",
            "/webpack-runtime.js", "/vendor.js", "/common.js",
            "/runtime.js", "/polyfills.js", "/scripts.js",
            "/assets/index.js", "/dist/bundle.js", "/dist/app.js",
            "/static/bundle.js", "/public/bundle.js",
        ]
        for path in common_js_paths:
            candidate = urljoin(base_url, path)
            try:
                r = self.session.head(candidate, timeout=5, allow_redirects=True)
                if r.status_code == 200:
                    js_urls.add(candidate)
            except Exception as _fix_e:
                logger.debug(f"[scanners.js_analyzer] {type(_fix_e).__name__}: {_fix_e!r}")

        # 4. Webpack chunk discovery — numbered chunk files (0.chunk.js ... 20.chunk.js)
        parsed_base = urlparse(base_url)
        chunk_prefixes = [
            f"{parsed_base.scheme}://{parsed_base.netloc}/static/js/",
            f"{parsed_base.scheme}://{parsed_base.netloc}/assets/js/",
            f"{parsed_base.scheme}://{parsed_base.netloc}/dist/",
            f"{parsed_base.scheme}://{parsed_base.netloc}/build/static/js/",
        ]
        # Try numbered chunks in parallel
        def _probe_chunk(args):
            prefix, n = args
            for suffix in [f"{n}.chunk.js", f"chunk.{n}.js", f"{n}.js"]:
                url = prefix + suffix
                try:
                    r = self.session.head(url, timeout=4, allow_redirects=True)
                    if r.status_code == 200:
                        return url
                except Exception as _fix_e:
                    logger.debug(f"[scanners.js_analyzer] {type(_fix_e).__name__}: {_fix_e!r}")
            return None

        import concurrent.futures as _cf
        chunk_args = [(prefix, n) for prefix in chunk_prefixes for n in range(15)]
        with _cf.ThreadPoolExecutor(max_workers=10) as ex:
            for result in ex.map(_probe_chunk, chunk_args):
                if result:
                    js_urls.add(result)

        return js_urls

    def _extract_script_tags(self, html: str, base_url: str) -> Set[str]:
        urls: Set[str] = set()
        for match in re.finditer(r'<script[^>]+src=["\'](.*?)["\']', html, re.IGNORECASE):
            src = match.group(1).strip()
            if not src or src.startswith("data:"):
                continue
            full = src if src.startswith("http") else urljoin(base_url, src)
            if any(full.endswith(ext) for ext in _JS_EXTENSIONS) or ".js" in full:
                # Only same-origin or no scheme check
                if urlparse(full).netloc == urlparse(base_url).netloc or not urlparse(full).netloc:
                    urls.add(full)
        return urls

    # ------------------------------------------------------------------
    def _analyse_js_file(self, js_url: str) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        try:
            resp = self.session.get(js_url, timeout=15)
            if resp.status_code != 200:
                return findings
            content = resp.text
        except Exception as e:
            logger.warning(f"[JSAnalyzer] Could not fetch {js_url}: {e}")
            return findings

        file_size_kb = len(resp.content) / 1024

        # --- Base finding: JS file discovered ---
        findings.append({
            "type": "JS File Discovered",
            "severity": "Info",
            "url": js_url,
            "detail": f"Size: {file_size_kb:.1f} KB",
            "source": "js_analyzer",
        })

        # --- Extract API endpoints (3 yöntem) ---
        endpoints: Set[str] = set()
        # 1. API keyword path'leri
        for m in _RE_PATHS.finditer(content):
            endpoints.add(m.group(1).strip())
        # 2. Genel path pattern'ları
        for m in _RE_GENERIC_PATHS.finditer(content):
            p = m.group(1).strip()
            if len(p) > 4 and p not in endpoints:
                endpoints.add(p)
        # 3. fetch/axios/XHR URL'leri — en değerli kaynak
        for m in _RE_FETCH_URLS.finditer(content):
            ep = m.group(1).strip()
            if ep and len(ep) > 3:
                endpoints.add(ep)

        for ep in endpoints:
            findings.append({
                "type": "JS Endpoint Discovered",
                "severity": "Low",
                "url": js_url,
                "parameter": ep,
                "detail": f"Endpoint extracted from JS: {ep}",
                "source": "js_analyzer",
            })

        # --- Detect hardcoded secrets ---
        secret_count = 0
        for secret_type, pattern in _SECRET_PATTERNS:
            for m in pattern.finditer(content):
                value = m.group(1) if m.lastindex else m.group(0)
                # Shannon entropy kontrolü — düşük entropi = placeholder (false positive)
                if len(value) > 8:
                    unique = len(set(value))
                    if unique < 4:  # "AAAAAAAAAAAAAAAA" gibi placeholder -> atla
                        continue
                redacted = value[:6] + "****" + value[-2:] if len(value) > 10 else "****"
                findings.append({
                    "type": f"Hardcoded Secret: {secret_type}",
                    "severity": "Critical" if secret_type in (
                        "AWS Access Key", "AWS Secret Key", "Private Key",
                        "Database URL", "Stripe Key",
                    ) else "High",
                    "url": js_url,
                    "parameter": secret_type,
                    "detail": f"Potential {secret_type} in JS. Value (redacted): {redacted}",
                    "proof": f"Pattern matched in {js_url}",
                    "source": "js_analyzer",
                })
                secret_count += 1

        # --- Source Map analizi ---
        source_map_findings = self._analyse_source_map(js_url, content)
        findings.extend(source_map_findings)

        logger.info(
            f"[JSAnalyzer] {js_url} -> {len(endpoints)} endpoints, "
            f"{secret_count} secrets, {len(source_map_findings)} sourcemap"
        )
        return findings

    def _analyse_source_map(self, js_url: str, content: str) -> List[Dict[str, Any]]:
        """
        JS dosyasında kaynak haritası referansı varsa indirir ve
        açıkta kalan kaynak dosya yollarını raporlar.
        """
        findings: List[Dict[str, Any]] = []
        m = _RE_SOURCEMAP.search(content)
        if not m:
            return findings
        map_ref = m.group(1).strip()
        # Data URI source map (inline) — atla
        if map_ref.startswith("data:"):
            return findings
        # Tam URL veya relatif yol
        map_url = map_ref if map_ref.startswith("http") else urljoin(js_url, map_ref)
        try:
            r = self.session.get(map_url, timeout=10)
            if r.status_code != 200:
                return findings
            map_data = r.json()
            sources: List[str] = map_data.get("sources", [])
            # webpack:// veya webpack-internal:// kaynak dosya yolları filtrele
            interesting = [
                s for s in sources
                if s and not s.startswith("webpack://") and not "node_modules" in s
            ]
            if sources:
                severity = "High" if interesting else "Medium"
                findings.append({
                    "type": "JS Source Map Exposed",
                    "severity": severity,
                    "url": map_url,
                    "detail": (
                        f"Source map erişilebilir — {len(sources)} kaynak dosya açığa çıkıyor. "
                        f"Saldırgan orijinal kaynak koduna ulaşabilir."
                    ),
                    "evidence": {
                        "map_url": map_url,
                        "total_sources": len(sources),
                        "interesting_sources": interesting[:20],
                    },
                    "source": "js_analyzer",
                })
                logger.warning(f"[JSAnalyzer] Source map açığa çıkmış: {map_url} ({len(sources)} kaynak)")
        except Exception as e:
            logger.debug(f"[JSAnalyzer] Source map analiz hatası {map_url}: {e}")
        return findings


# ---------------------------------------------------------------------------
# Sensitive file classifier (used by flow_runner for FFUF results)
# ---------------------------------------------------------------------------

def classify_discovered_file(url: str, status_code: int = 200) -> Optional[Dict[str, Any]]:
    """
    Given a URL discovered by FFUF/Feroxbuster, classify it by extension
    and return a finding dict if it's sensitive, else None.
    """
    path = urlparse(url).path
    for ext, sev in SENSITIVE_EXTENSIONS.items():
        if path.endswith(ext):
            return {
                "type": f"Sensitive File Exposed: {ext}",
                "severity": sev,
                "url": url,
                "detail": f"Sensitive file accessible at {url} (HTTP {status_code})",
                "source": "file_discovery",
            }
    return None


# ---------------------------------------------------------------------------
# Bridge function
# ---------------------------------------------------------------------------

def run(url: str, session=None, results: Dict = None, debug: bool = False, **kwargs) -> None:
    from websecure.core.reporting import add_result
    analyzer = JSAnalyzer(session=session, results=results or {}, debug=debug)
    findings = analyzer.run(url)
    for f in findings:
        add_result("js", f)
        # High severity secrets also go to offensive bucket
        if f.get("severity") in ("High", "Critical"):
            add_result("offensive", f)
