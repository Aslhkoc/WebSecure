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

# Hardcoded secret / credential patterns
_SECRET_PATTERNS: List[tuple] = [
    ("API Key",        re.compile(r"""(?:apiKey|api_key|apikey)\s*[:=]\s*["'`]([A-Za-z0-9_\-]{16,})["'`]""", re.I)),
    ("Access Token",   re.compile(r"""(?:access_token|accessToken)\s*[:=]\s*["'`]([A-Za-z0-9_\-\.]{16,})["'`]""", re.I)),
    ("Auth Token",     re.compile(r"""(?:auth_token|authToken|bearer)\s*[:=]\s*["'`]([A-Za-z0-9_\-\.]{16,})["'`]""", re.I)),
    ("Secret Key",     re.compile(r"""(?:secret_key|secretKey|secret)\s*[:=]\s*["'`]([A-Za-z0-9_\-\.!@#]{10,})["'`]""", re.I)),
    ("Password",       re.compile(r"""(?:password|passwd|pwd)\s*[:=]\s*["'`]([^\s"'`]{6,})["'`]""", re.I)),
    ("AWS Key",        re.compile(r"""AKIA[0-9A-Z]{16}""")),
    ("Private Key",    re.compile(r"""-----BEGIN (?:RSA |EC )?PRIVATE KEY-----""")),
    ("Firebase URL",   re.compile(r"""https://[a-z0-9-]+\.firebaseio\.com""", re.I)),
    ("Google API Key", re.compile(r"""AIza[0-9A-Za-z\-_]{35}""")),
    ("JWT Token",      re.compile(r"""eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}""")),
    ("S3 Bucket",      re.compile(r"""s3\.amazonaws\.com/[a-zA-Z0-9_\-\.]+""", re.I)),
    ("Internal IP",    re.compile(r"""["'`]((?:10|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3})["'`]""")),
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

        # 3. Common JS paths
        common_js_paths = [
            "/main.js", "/app.js", "/bundle.js", "/chunk.js", "/index.js",
            "/static/js/main.js", "/assets/js/app.js", "/js/app.js",
            "/dist/main.js", "/build/static/js/main.chunk.js",
            "/webpack-runtime.js", "/vendor.js", "/common.js",
        ]
        for path in common_js_paths:
            candidate = urljoin(base_url, path)
            try:
                r = self.session.head(candidate, timeout=5, allow_redirects=True)
                if r.status_code == 200:
                    js_urls.add(candidate)
            except Exception as exc:
                pass

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

        # --- Extract API endpoints ---
        endpoints: Set[str] = set()
        for m in _RE_PATHS.finditer(content):
            endpoints.add(m.group(1).strip())
        for m in _RE_GENERIC_PATHS.finditer(content):
            p = m.group(1).strip()
            if len(p) > 4 and p not in endpoints:
                endpoints.add(p)

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
        for secret_type, pattern in _SECRET_PATTERNS:
            for m in pattern.finditer(content):
                # Grab matched value (group 1 if exists, else full match)
                value = m.group(1) if m.lastindex else m.group(0)
                # Redact most of the value for the report
                redacted = value[:6] + "****" + value[-2:] if len(value) > 10 else "****"
                findings.append({
                    "type": f"Hardcoded Secret: {secret_type}",
                    "severity": "High",
                    "url": js_url,
                    "parameter": secret_type,
                    "detail": f"Potential {secret_type} found in JS file. Value (redacted): {redacted}",
                    "proof": f"Pattern matched in {js_url}",
                    "source": "js_analyzer",
                })

        logger.info(
            f"[JSAnalyzer] {js_url} → {len(endpoints)} endpoints, "
            f"{sum(1 for f in findings if 'Secret' in f['type'])} secrets"
        )
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
        add_result("js_analysis", f)
        # High severity secrets also go to offensive bucket
        if f.get("severity") in ("High", "Critical"):
            add_result("offensive", f)
