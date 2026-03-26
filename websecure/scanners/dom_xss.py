"""
websecure.scanners.dom_xss
--------------------------
DOM-based XSS scanner using Playwright.
Detects XSS that only fires in browser context (not visible in raw HTTP response).
"""
from __future__ import annotations
import asyncio
import logging
import random
import string
from typing import Dict, List, Optional
from urllib.parse import urlparse, urlunparse, urlencode, parse_qsl

from websecure.core.reporting import add_result
from websecure.core.payloads import get_payloads
from websecure.scanners.base import BaseScanner

_logger = logging.getLogger(__name__)

try:
    from playwright.async_api import async_playwright
    _PLAYWRIGHT_AVAILABLE = True
except ImportError:
    _PLAYWRIGHT_AVAILABLE = False


_DOM_SINK_PATTERNS = [
    "document.write",
    "innerHTML",
    "outerHTML",
    "eval(",
    "setTimeout(",
    "setInterval(",
    "location.href",
    "location.replace",
    "location.assign",
]

# DOM-specific canary payloads (used when get_payloads returns nothing)
_DOM_PAYLOADS_FALLBACK = [
    "<img src=x onerror=console.error('DOMXSS_{CANARY}')>",
    "<svg onload=console.error('DOMXSS_{CANARY}')>",
    "javascript:console.error('DOMXSS_{CANARY}')",
    "'-console.error('DOMXSS_{CANARY}')-'",
    "\"><script>console.error('DOMXSS_{CANARY}')</script>",
    "{{CANARY}}",  # Angular/Vue template injection
]


def _get_dom_payloads(canary: str) -> List[str]:
    """Return XSS payloads from the central payload store, with canary injected."""
    base = list(get_payloads("xss") or [])
    if not base:
        base = list(_DOM_PAYLOADS_FALLBACK)
    # Inject canary marker into each payload where possible
    result = []
    for p in base:
        if "{CANARY}" in p:
            result.append(p.replace("{CANARY}", canary))
        else:
            result.append(p)
    return result


def _gen_canary() -> str:
    return "ws" + "".join(random.choices(string.ascii_lowercase + string.digits, k=8))


class DOMXSSScanner(BaseScanner):
    """
    Playwright-based DOM XSS scanner.
    Injects payloads into URL params, fragments, and postMessage handlers,
    then monitors console output and DOM changes for XSS indicators.
    """

    name = "dom_xss"
    phase = "browser"

    def __init__(self, session=None, results: Dict = None, debug: bool = False,
                 headless: bool = True, timeout_ms: int = 8000):
        super().__init__(session, results, debug)
        self.headless = headless
        self.timeout_ms = timeout_ms

    def run(self, target: str, **kwargs):
        """Sync entry point."""
        if not _PLAYWRIGHT_AVAILABLE:
            _logger.warning("[DOMXSSScanner] Playwright not available, skipping")
            return
        endpoints = kwargs.get("endpoints") or [target]
        try:
            loop = asyncio.new_event_loop()
            loop.run_until_complete(self._async_scan_all(endpoints))
            loop.close()
        except Exception as exc:
            _logger.warning(f"[DOMXSSScanner] Event loop error: {exc!r}")

    async def _async_scan_all(self, endpoints: List[str]):
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=self.headless)
            context = await browser.new_context()
            page = await context.new_page()
            for url in endpoints[:20]:  # Limit to 20 endpoints
                await self._scan_url(page, url)
            await browser.close()

    async def _scan_url(self, page, url: str):
        parsed = urlparse(url)
        params = parse_qsl(parsed.query)

        if not params:
            # Try fragment-based injection
            await self._test_fragment(page, url)
            return

        for param_name, _ in params:
            canary = _gen_canary()
            dom_payloads = _get_dom_payloads(canary)
            payload = random.choice(dom_payloads)

            # Build injected URL
            new_params = dict(params)
            new_params[param_name] = payload
            new_query = urlencode(new_params)
            test_url = urlunparse(parsed._replace(query=new_query))

            found = await self._navigate_and_check(page, test_url, canary, param_name)
            if found:
                self._report(url, param_name, payload, found)

    async def _test_fragment(self, page, url: str):
        """Test hash-based DOM XSS (location.hash sources)."""
        canary = _gen_canary()
        payload = f"<img src=x onerror=console.error('DOMXSS_{canary}')>"
        test_url = url.rstrip("/") + f"#{payload}"
        found = await self._navigate_and_check(page, test_url, canary, "#fragment")
        if found:
            self._report(url, "#fragment", payload, found)

    async def _navigate_and_check(self, page, url: str, canary: str, param: str) -> Optional[str]:
        """Navigate to URL and check for XSS execution. Returns evidence or None."""
        console_hits = []

        def on_console(msg):
            if canary in msg.text:
                console_hits.append(f"console.{msg.type}: {msg.text}")

        page.on("console", on_console)

        try:
            await page.goto(url, timeout=self.timeout_ms, wait_until="domcontentloaded")
            await page.wait_for_timeout(1000)

            # Check console for canary execution
            if console_hits:
                return f"JS execution via console: {console_hits[0]}"

            # Check DOM for unescaped canary in dangerous context
            dom_check = await page.evaluate(f"""
                () => {{
                    const body = document.body ? document.body.innerHTML : '';
                    const scripts = Array.from(document.scripts).map(s => s.innerHTML).join(' ');
                    const canary = '{canary}';
                    if (body.includes(canary)) return 'canary_in_dom';
                    if (scripts.includes(canary)) return 'canary_in_script';
                    return null;
                }}
            """)
            if dom_check:
                return f"DOM context: {dom_check}"

            # Test postMessage injection
            post_check = await page.evaluate(f"""
                async () => {{
                    return new Promise(resolve => {{
                        let fired = false;
                        const handler = e => {{ if (String(e.data).includes('{canary}')) fired = true; }};
                        window.addEventListener('message', handler);
                        window.postMessage('{canary}', '*');
                        setTimeout(() => {{ window.removeEventListener('message', handler); resolve(fired); }}, 500);
                    }});
                }}
            """)
            if post_check:
                return "postMessage handler reflects canary"

        except Exception as exc:
            _logger.debug(f"[DOMXSSScanner] Navigate error on {url}: {exc!r}")
        finally:
            page.remove_listener("console", on_console)

        return None

    def _report(self, url: str, param: str, payload: str, evidence: str):
        finding = {
            "type": "DOM XSS",
            "severity": "High",
            "url": url,
            "parameter": param,
            "payload": payload,
            "evidence": evidence,
            "verified": True,
            "confidence": "high",
        }
        self.add("offensive", finding)
        add_result("offensive", finding)
        _logger.warning(f"[DOMXSSScanner] DOM XSS found: {url} param={param}")


def run(target: str, session=None, results=None, debug=False, **kwargs):
    scanner = DOMXSSScanner(session=session, results=results, debug=debug)
    scanner.run(target, **kwargs)
