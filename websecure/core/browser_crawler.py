"""
websecure.core.browser_crawler
-------------------------------
Tier-2 crawler using Playwright for JavaScript-heavy SPAs.
Used when the HTTP-only crawler finds few endpoints relative to <script> tags.
"""
from __future__ import annotations
import asyncio
import json
import logging
import random as _random
import re
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urljoin, urlparse

_logger = logging.getLogger(__name__)

try:
    from playwright.async_api import async_playwright, Page, Browser, BrowserContext
    _PLAYWRIGHT_AVAILABLE = True
except ImportError:
    _PLAYWRIGHT_AVAILABLE = False
    _logger.warning("[BrowserCrawler] Playwright not installed. Run: playwright install chromium")


@dataclass
class BrowserCrawlConfig:
    headless: bool = True
    """
    True  -> Chrome arka planda çalışır (görünmez, daha hızlı).
    False -> Chrome görünür pencerede açılır; test adımlarını, form
            doldurmayı ve payload denemelerini gerçek zamanlı izleyebilirsiniz.
    CLI'dan --show-browser / config: browser.headless=false ile değiştirin.
    """
    show_browser: bool = False   # headless=False için kısayol; True yapınca Chrome görünür
    slow_mo_ms: int = 0          # show_browser=True iken adımlar arası gecikme (ms) — izlemeyi kolaylaştırır
    max_pages: int = 50
    timeout_ms: int = 15000
    wait_after_load_ms: int = 1500
    proxy_url: Optional[str] = None
    auth_cookies: List[Dict] = field(default_factory=list)
    auth_storage_state: Optional[str] = None  # path to playwright storage state JSON
    user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"


@dataclass
class BrowserCrawlResult:
    endpoints: List[str] = field(default_factory=list)
    api_endpoints: List[str] = field(default_factory=list)
    forms_meta: List[Dict] = field(default_factory=list)
    js_files: List[str] = field(default_factory=list)
    ws_endpoints: List[str] = field(default_factory=list)
    tech_stack: List[str] = field(default_factory=list)
    secrets_found: List[Dict] = field(default_factory=list)
    console_errors: List[str] = field(default_factory=list)
    screenshots: Dict[str, bytes] = field(default_factory=dict)
    # Adım-2 eklentileri: SPA route discovery + full request interception
    spa_routes: List[str] = field(default_factory=list)
    intercepted_requests: List[Dict[str, Any]] = field(default_factory=list)


_VIEWPORTS = [
    {"width": 1920, "height": 1080},
    {"width": 1680, "height": 1050},
    {"width": 1440, "height": 900},
    {"width": 1366, "height": 768},
    {"width": 1280, "height": 800},
    {"width": 1024, "height": 768},
]

_TIMEZONES = [
    "America/New_York", "America/Chicago", "America/Los_Angeles",
    "Europe/London", "Europe/Berlin", "Europe/Paris",
    "Asia/Tokyo", "Asia/Singapore",
]

_ACCEPT_LANGUAGES = [
    "en-US,en;q=0.9",
    "en-GB,en;q=0.8,en-US;q=0.7",
    "en-US,en;q=0.9,fr;q=0.7",
    "de-DE,de;q=0.9,en;q=0.8",
    "fr-FR,fr;q=0.9,en;q=0.8",
]

_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
]


def _random_browser_fingerprint() -> Dict[str, Any]:
    """Rastgele Playwright new_context kwargs döndürür (parmak izi rotasyonu)."""
    lang = _random.choice(_ACCEPT_LANGUAGES)
    locale = lang.split(",")[0].replace("-", "_")
    return {
        "user_agent": _random.choice(_USER_AGENTS),
        "viewport": _random.choice(_VIEWPORTS),
        "timezone_id": _random.choice(_TIMEZONES),
        "locale": locale,
        "extra_http_headers": {"Accept-Language": lang},
    }


class BrowserCrawler:
    """
    Playwright-powered crawler for JS-heavy web applications.
    Intercepts all network requests, detects framework, extracts forms.
    Adım-2: SPA route extraction from JS bundles + deep XHR/fetch interception.
    """

    # SPA route patterns: React Router / Vue Router / Angular Router / Next.js
    _SPA_ROUTE_PATTERNS: List[re.Pattern] = [
        re.compile(r'''path\s*:\s*['"`]([/][^'"`\s]{2,100})['"`]'''),
        re.compile(r'''to\s*:\s*['"`]([/][a-z0-9/_:.*-]{2,80})['"`]''', re.I),
        re.compile(
            r'''(?:navigate|router\.push|router\.replace|history\.push|history\.replace)\s*\(\s*['"`]([/][^'"`\s]{2,80})['"`]''',
            re.I,
        ),
        re.compile(r'''['"`]([/][a-z][a-z0-9/_:-]{3,60})['"`]''', re.I),
    ]

    _FRAMEWORK_SIGNATURES = {
        "React": [r"react\.development\.js", r"react-dom", r"__REACT_DEVTOOLS_GLOBAL_HOOK__"],
        "Angular": [r"ng-version", r"angular\.min\.js", r"@angular/core"],
        "Vue": [r"vue\.js", r"vue\.min\.js", r"window\.Vue"],
        "Next.js": [r"_next/static", r"__NEXT_DATA__"],
        "Nuxt.js": [r"_nuxt/", r"__NUXT__"],
        "Svelte": [r"svelte/internal"],
    }

    _SECRET_PATTERNS = {
        "API Key": r'(?:api[_-]?key|apikey)\s*[=:]\s*["\']([A-Za-z0-9\-_]{20,})["\']',
        "JWT Token": r'eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+',
        "AWS Key": r'AKIA[0-9A-Z]{16}',
        "Private Key": r'-----BEGIN (?:RSA )?PRIVATE KEY-----',
        "Bearer Token": r'[Bb]earer\s+([A-Za-z0-9\-_\.]{20,})',
    }

    def __init__(self, config: Optional[BrowserCrawlConfig] = None):
        self.config = config or BrowserCrawlConfig()
        self._visited: Set[str] = set()
        self._result = BrowserCrawlResult()
        self._api_requests: List[str] = []
        self._intercepted_requests: List[Dict[str, Any]] = []

    def crawl_sync(self, base_url: str) -> BrowserCrawlResult:
        """Synchronous wrapper for use in non-async contexts."""
        if not _PLAYWRIGHT_AVAILABLE:
            _logger.warning("[BrowserCrawler] Playwright unavailable, returning empty result")
            return BrowserCrawlResult(endpoints=[base_url])
        try:
            loop = asyncio.new_event_loop()
            result = loop.run_until_complete(self.crawl(base_url))
            loop.close()
            return result
        except Exception as e:
            _logger.error(f"[BrowserCrawler] Crawl failed: {e}")
            return BrowserCrawlResult(endpoints=[base_url])

    async def crawl(self, base_url: str) -> BrowserCrawlResult:
        """Main async crawl entry point."""
        if not _PLAYWRIGHT_AVAILABLE:
            return BrowserCrawlResult(endpoints=[base_url])

        base_domain = urlparse(base_url).netloc
        to_visit = [base_url]
        self._visited = set()
        self._result = BrowserCrawlResult()

        # show_browser=True -> headless=False (görünür Chrome)
        use_headless = self.config.headless and not self.config.show_browser
        launch_opts: Dict[str, Any] = {"headless": use_headless}
        if self.config.slow_mo_ms > 0 and not use_headless:
            launch_opts["slow_mo"] = self.config.slow_mo_ms
        if self.config.proxy_url:
            launch_opts["proxy"] = {"server": self.config.proxy_url}

        if not use_headless:
            _logger.info(
                "[BrowserCrawler] Görünür mod aktif — Chrome penceresi açılıyor. "
                "Test adımlarını, form doldurmayı ve payload denemelerini izleyebilirsiniz."
            )

        async with async_playwright() as pw:
            browser: Browser = await pw.chromium.launch(**launch_opts)
            ctx_opts: Dict[str, Any] = _random_browser_fingerprint()
            if self.config.auth_storage_state:
                ctx_opts["storage_state"] = self.config.auth_storage_state

            context: BrowserContext = await browser.new_context(**ctx_opts)

            # Canvas / WebGL fingerprint randomization — evade bot-detection systems
            await context.add_init_script("""
                (function() {
                    // Canvas: add per-pixel noise so toDataURL output is unique per session
                    const _origGetContext = HTMLCanvasElement.prototype.getContext;
                    HTMLCanvasElement.prototype.getContext = function(type, attrs) {
                        const ctx = _origGetContext.apply(this, arguments);
                        if (ctx && type === '2d') {
                            const _origGetImageData = ctx.getImageData.bind(ctx);
                            ctx.getImageData = function(x, y, w, h) {
                                const d = _origGetImageData(x, y, w, h);
                                for (let i = 0; i < d.data.length; i += 4) {
                                    d.data[i]   = (d.data[i]   + (Math.random() * 4 | 0) - 2) & 0xff;
                                    d.data[i+1] = (d.data[i+1] + (Math.random() * 4 | 0) - 2) & 0xff;
                                    d.data[i+2] = (d.data[i+2] + (Math.random() * 4 | 0) - 2) & 0xff;
                                }
                                return d;
                            };
                        }
                        return ctx;
                    };
                    // WebGL: spoof UNMASKED_VENDOR / UNMASKED_RENDERER
                    const _vendors  = ['Intel Inc.', 'NVIDIA Corporation', 'AMD'];
                    const _renderers = ['Intel Iris OpenGL Engine', 'NVIDIA GeForce GTX 1060/PCIe/SSE2', 'AMD Radeon Pro 5500M OpenGL Engine'];
                    const _idx = Math.floor(Math.random() * _vendors.length);
                    function _patchWebGL(proto) {
                        const _orig = proto.getParameter;
                        proto.getParameter = function(p) {
                            if (p === 37445) return _vendors[_idx];   // UNMASKED_VENDOR_WEBGL
                            if (p === 37446) return _renderers[_idx]; // UNMASKED_RENDERER_WEBGL
                            return _orig.apply(this, arguments);
                        };
                    }
                    if (window.WebGLRenderingContext)  _patchWebGL(WebGLRenderingContext.prototype);
                    if (window.WebGL2RenderingContext) _patchWebGL(WebGL2RenderingContext.prototype);
                })();
            """)

            # Inject auth cookies if provided
            if self.config.auth_cookies:
                await context.add_cookies(self.config.auth_cookies)

            page: Page = await context.new_page()

            # Enhanced network interceptor: captures method, headers, and POST body
            async def _on_request(request):
                url = request.url
                resource_type = request.resource_type
                method = request.method

                if resource_type in ("xhr", "fetch"):
                    req_record: Dict[str, Any] = {
                        "url": url,
                        "method": method,
                        "resource_type": resource_type,
                        "headers": dict(request.headers) if request.headers else {},
                    }
                    try:
                        body = request.post_data
                        if body:
                            req_record["body"] = body[:4096]
                    except Exception:
                        pass
                    self._intercepted_requests.append(req_record)
                    if url not in self._api_requests:
                        self._api_requests.append(url)

                if resource_type == "script" and ".js" in url:
                    if url not in self._result.js_files:
                        self._result.js_files.append(url)

                if resource_type == "websocket":
                    if url not in self._result.ws_endpoints:
                        self._result.ws_endpoints.append(url)

            page.on("request", _on_request)

            # Capture console errors (potential DOM XSS indicators)
            def _on_console(msg):
                if msg.type in ("error", "warning"):
                    self._result.console_errors.append(f"[{msg.type}] {msg.text}")

            page.on("console", _on_console)

            page_count = 0
            while to_visit and page_count < self.config.max_pages:
                url = to_visit.pop(0)
                if url in self._visited:
                    continue
                self._visited.add(url)
                page_count += 1

                try:
                    try:
                        await page.goto(url, timeout=self.config.timeout_ms, wait_until="networkidle")
                    except Exception:
                        # networkidle can timeout on SPAs — fall back to domcontentloaded
                        try:
                            await page.goto(url, timeout=self.config.timeout_ms, wait_until="domcontentloaded")
                        except Exception as nav_err:
                            _logger.debug(f"[BrowserCrawler] Navigation failed for {url}: {nav_err}")
                            continue
                    await page.wait_for_timeout(self.config.wait_after_load_ms)

                    # Scroll to trigger lazy loading
                    await page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
                    await page.wait_for_timeout(500)

                    # Extract links
                    links = await page.evaluate("""
                        () => Array.from(document.querySelectorAll('a[href]'))
                              .map(a => a.href)
                              .filter(h => h.startsWith('http'))
                    """)
                    for link in links:
                        if urlparse(link).netloc == base_domain and link not in self._visited:
                            to_visit.append(link)
                            if link not in self._result.endpoints:
                                self._result.endpoints.append(link)

                    # Extract forms
                    forms_data = await page.evaluate("""
                        () => Array.from(document.querySelectorAll('form')).map(f => ({
                            action: f.action || window.location.href,
                            method: f.method || 'GET',
                            inputs: Array.from(f.querySelectorAll('input,textarea,select')).map(i => ({
                                name: i.name,
                                type: i.type || 'text',
                                value: i.value || ''
                            }))
                        }))
                    """)
                    if forms_data:
                        self._result.forms_meta.append({"url": url, "forms": forms_data})

                    # SPA: shadow DOM traversal + React/Angular/Vue loose inputs
                    try:
                        spa_forms = await page.evaluate("""
                            () => {
                                const forms = [];
                                function collectFromRoot(root) {
                                    // Shadow DOM forms
                                    Array.from(root.querySelectorAll('*')).forEach(el => {
                                        if (el.shadowRoot) {
                                            Array.from(el.shadowRoot.querySelectorAll('form')).forEach(f => {
                                                forms.push({
                                                    action: f.action || window.location.href,
                                                    method: (f.method || 'GET').toUpperCase(),
                                                    inputs: Array.from(f.querySelectorAll('input,textarea,select')).map(i => ({
                                                        name: i.name || i.getAttribute('ng-model') || i.getAttribute('v-model') || i.id || '',
                                                        type: i.type || 'text',
                                                        value: i.value || ''
                                                    })).filter(i => i.name)
                                                });
                                            });
                                            collectFromRoot(el.shadowRoot);
                                        }
                                    });
                                }
                                collectFromRoot(document);
                                // Standalone inputs outside <form> (common in React/Angular apps)
                                const loose = Array.from(document.querySelectorAll(
                                    'input[name]:not(form input), input[ng-model]:not(form input), input[v-model]:not(form input)'
                                )).filter(el => el.offsetParent !== null && el.type !== 'hidden');
                                if (loose.length) {
                                    forms.push({
                                        action: window.location.href,
                                        method: 'POST',
                                        inputs: loose.map(i => ({
                                            name: i.name || i.getAttribute('ng-model') || i.getAttribute('v-model') || i.id,
                                            type: i.type || 'text',
                                            value: i.value || ''
                                        })).filter(i => i.name)
                                    });
                                }
                                return forms;
                            }
                        """)
                        if spa_forms:
                            self._result.forms_meta.append({"url": url + "#spa", "forms": spa_forms})
                    except Exception:
                        pass

                    # Detect framework
                    tech = await self._detect_framework(page, url)
                    for t in tech:
                        if t not in self._result.tech_stack:
                            self._result.tech_stack.append(t)

                    # Check page source for secrets
                    content = await page.content()
                    self._scan_for_secrets(content, url)

                except Exception as e:
                    _logger.debug(f"[BrowserCrawler] Error on {url}: {e}")

            # -- Phase 2: SPA route extraction from JS bundles --------------
            spa_routes_discovered: List[str] = []
            for js_url in self._result.js_files[:15]:
                try:
                    js_content = await page.evaluate(
                        f"async () => {{ "
                        f"try {{ return await (await fetch({json.dumps(js_url)})).text(); }}"
                        f" catch(e) {{ return ''; }} }}"
                    )
                    if js_content:
                        for route in self._extract_spa_routes_from_js(js_content, base_url):
                            if route not in spa_routes_discovered:
                                spa_routes_discovered.append(route)
                except Exception as exc:
                    _logger.debug(f"[BrowserCrawler] JS route extraction {js_url}: {exc}")

            # -- Phase 3: Navigate to newly discovered SPA routes ------------
            for route in spa_routes_discovered[:25]:
                if urlparse(route).netloc != base_domain:
                    continue
                if route in self._visited:
                    continue
                await self._simulate_spa_navigation(page, route, base_domain)

            await browser.close()

        # Merge api_requests into result
        for ar in self._api_requests:
            if ar not in self._result.api_endpoints:
                self._result.api_endpoints.append(ar)

        # Merge intercepted request records
        self._result.intercepted_requests = list(self._intercepted_requests)

        self._result.endpoints = list(set(self._result.endpoints))
        _logger.info(
            f"[BrowserCrawler] Done: {len(self._result.endpoints)} pages, "
            f"{len(self._result.api_endpoints)} API endpoints, "
            f"{len(self._result.js_files)} JS files, "
            f"{len(self._result.spa_routes)} SPA routes, "
            f"{len(self._result.intercepted_requests)} intercepted XHR/fetch"
        )
        return self._result

    def _extract_spa_routes_from_js(self, js_content: str, base_url: str) -> List[str]:
        """
        Parse a JS bundle for route path strings (React Router, Vue Router,
        Angular Router, Next.js, plain history.push, etc.).
        Returns absolute URLs on the same origin.
        """
        routes: List[str] = []
        seen: Set[str] = set()
        for pattern in self._SPA_ROUTE_PATTERNS:
            for m in pattern.finditer(js_content):
                path = m.group(1)
                if len(path) < 2 or any(path.endswith(ext) for ext in (".js", ".css", ".png", ".jpg", ".svg")):
                    continue
                if path in seen:
                    continue
                seen.add(path)
                full_url = urljoin(base_url, path)
                if urlparse(full_url).netloc == urlparse(base_url).netloc:
                    routes.append(full_url)
        return routes

    async def _simulate_spa_navigation(
        self, page: "Page", route_url: str, base_domain: str
    ) -> None:
        """
        Navigate to a SPA route via history.pushState (no full page reload).
        Extracts new links and forms that appear after the client-side render.
        """
        parsed = urlparse(route_url)
        spa_path = parsed.path + (f"?{parsed.query}" if parsed.query else "")
        try:
            await page.evaluate(
                f"() => window.history.pushState(null, '', {json.dumps(spa_path)})"
            )
            await page.wait_for_timeout(800)

            new_links = await page.evaluate("""
                () => Array.from(document.querySelectorAll('a[href]'))
                      .map(a => a.href)
                      .filter(h => h.startsWith('http'))
            """)
            for link in new_links:
                if urlparse(link).netloc == base_domain and link not in self._result.endpoints:
                    self._result.endpoints.append(link)

            new_forms = await page.evaluate("""
                () => Array.from(document.querySelectorAll('form')).map(f => ({
                    action: f.action || window.location.href,
                    method: (f.method || 'GET').toUpperCase(),
                    inputs: Array.from(f.querySelectorAll('input,textarea,select'))
                              .map(i => ({name: i.name, type: i.type || 'text', value: i.value || ''}))
                              .filter(i => i.name)
                }))
            """)
            if new_forms:
                self._result.forms_meta.append({"url": route_url + "#spa-nav", "forms": new_forms})

            if route_url not in self._result.spa_routes:
                self._result.spa_routes.append(route_url)
            self._visited.add(route_url)
        except Exception as exc:
            _logger.debug(f"[BrowserCrawler] SPA nav {route_url}: {exc}")

    async def _detect_framework(self, page: "Page", url: str) -> List[str]:
        detected = []
        try:
            # Check for framework-specific global variables
            checks = {
                "React": "typeof window.__REACT_DEVTOOLS_GLOBAL_HOOK__ !== 'undefined'",
                "Angular": "typeof window.ng !== 'undefined' || document.querySelector('[ng-version]') !== null",
                "Vue": "typeof window.Vue !== 'undefined' || typeof window.__vue_meta_installed !== 'undefined'",
                "Next.js": "typeof window.__NEXT_DATA__ !== 'undefined'",
                "Nuxt.js": "typeof window.__NUXT__ !== 'undefined'",
            }
            for framework, expr in checks.items():
                try:
                    result = await page.evaluate(f"() => {{ try {{ return {expr}; }} catch(e) {{ return false; }} }}")
                    if result:
                        detected.append(framework)
                except Exception as exc:
                    pass
        except Exception as exc:
            pass
        return detected

    def _scan_for_secrets(self, content: str, url: str) -> None:
        for name, pattern in self._SECRET_PATTERNS.items():
            for match in re.finditer(pattern, content):
                secret_val = match.group(0)
                # Basic entropy/false-positive check
                if len(secret_val) > 8:
                    self._result.secrets_found.append({
                        "type": name,
                        "url": url,
                        "value_preview": secret_val[:20] + "...",
                        "severity": "High",
                    })


def should_use_browser_crawler(http_result: Dict) -> bool:
    """
    Heuristic: escalate to Playwright if:
    - fewer than 5 unique endpoints found by HTTP crawler
    - page source contains React/Angular/Vue script tags
    - JavaScript-heavy indicators present
    """
    endpoints = http_result.get("endpoints", [])
    if len(endpoints) < 5:
        return True
    tech = http_result.get("tech_stack", [])
    spa_techs = {"React", "Angular", "Vue", "Next.js", "Nuxt.js", "Svelte"}
    if any(t in spa_techs for t in tech):
        return True
    return False
