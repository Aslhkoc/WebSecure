"""
websecure.core.browser_crawler
-------------------------------
Tier-2 crawler using Playwright for JavaScript-heavy SPAs.
Used when the HTTP-only crawler finds few endpoints relative to <script> tags.
"""
from __future__ import annotations
import asyncio
import logging
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


class BrowserCrawler:
    """
    Playwright-powered crawler for JS-heavy web applications.
    Intercepts all network requests, detects framework, extracts forms.
    """

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

        launch_opts: Dict[str, Any] = {"headless": self.config.headless}
        if self.config.proxy_url:
            launch_opts["proxy"] = {"server": self.config.proxy_url}

        async with async_playwright() as pw:
            browser: Browser = await pw.chromium.launch(**launch_opts)
            ctx_opts: Dict[str, Any] = {"user_agent": self.config.user_agent}
            if self.config.auth_storage_state:
                ctx_opts["storage_state"] = self.config.auth_storage_state

            context: BrowserContext = await browser.new_context(**ctx_opts)

            # Inject auth cookies if provided
            if self.config.auth_cookies:
                await context.add_cookies(self.config.auth_cookies)

            page: Page = await context.new_page()

            # Intercept all network requests
            async def _on_request(request):
                url = request.url
                resource_type = request.resource_type
                if resource_type in ("xhr", "fetch", "websocket"):
                    self._api_requests.append(url)
                if resource_type == "script" and url.endswith(".js"):
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
                    await page.goto(url, timeout=self.config.timeout_ms, wait_until="networkidle")
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

            await browser.close()

        # Merge api_requests into result
        for ar in self._api_requests:
            if ar not in self._result.api_endpoints:
                self._result.api_endpoints.append(ar)

        self._result.endpoints = list(set(self._result.endpoints))
        _logger.info(
            f"[BrowserCrawler] Done: {len(self._result.endpoints)} pages, "
            f"{len(self._result.api_endpoints)} API endpoints, "
            f"{len(self._result.js_files)} JS files"
        )
        return self._result

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
                except Exception:
                    pass
        except Exception:
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
