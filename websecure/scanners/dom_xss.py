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
    "document.writeln",
    "innerHTML",
    "outerHTML",
    "insertAdjacentHTML",
    "eval(",
    "Function(",
    "setTimeout(",
    "setInterval(",
    "setImmediate(",
    "location.href",
    "location.replace",
    "location.assign",
    "location.search",
    "location.hash",
    "location.pathname",
    "document.referrer",
    "window.name",
    "document.URL",
    "document.documentURI",
    "document.baseURI",
    "document.cookie",
    "localStorage.getItem",
    "sessionStorage.getItem",
    "postMessage",
    "jQuery.html(",
    "$(", ".html(", ".append(", ".prepend(",
    "angular.element",
    "__proto__",
    "prototype[",
]

# DOM-specific canary payloads (used when get_payloads returns nothing)
_DOM_PAYLOADS_FALLBACK = [
    "<img src=x onerror=console.error('DOMXSS_{CANARY}')>",
    "<svg onload=console.error('DOMXSS_{CANARY}')>",
    "javascript:console.error('DOMXSS_{CANARY}')",
    "'-console.error('DOMXSS_{CANARY}')-'",
    "\"><script>console.error('DOMXSS_{CANARY}')</script>",
    "{{constructor.constructor('console.error(\"DOMXSS_{CANARY}\")')()}}",   # Angular
    "${console.error('DOMXSS_{CANARY}')}",                                   # Template literal
    "</script><script>console.error('DOMXSS_{CANARY}')</script>",
    "'><img src=x onerror=console.error('DOMXSS_{CANARY}')>",
    "<details open ontoggle=console.error('DOMXSS_{CANARY}')>",
    "<input autofocus onfocus=console.error('DOMXSS_{CANARY}')>",
    "DOMXSS_{CANARY}",   # For checking reflection without execution context
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
            # No query params — test all alternative DOM sources
            await self._test_fragment(page, url)
            await self._test_window_name(page, url)
            await self._test_localstorage(page, url)
            await self._test_postmessage(page, url)
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

        # Also test fragment and postMessage on parametrised pages
        await self._test_fragment(page, url)
        await self._test_postmessage(page, url)

    async def _test_fragment(self, page, url: str):
        """Test hash-based DOM XSS (location.hash sources)."""
        canary = _gen_canary()
        payload = f"<img src=x onerror=console.error('DOMXSS_{canary}')>"
        test_url = url.rstrip("/") + f"#{payload}"
        found = await self._navigate_and_check(page, test_url, canary, "#fragment")
        if found:
            self._report(url, "#fragment", payload, found)

    async def _test_window_name(self, page, url: str):
        """Test window.name as a DOM XSS source."""
        canary = _gen_canary()
        payload = f"<img src=x onerror=console.error('DOMXSS_{canary}')>"
        try:
            # Set window.name to the payload, then navigate — window.name persists across navigations
            await page.evaluate(f"window.name = {repr(payload)}")
            found = await self._navigate_and_check(page, url, canary, "window.name")
            if found:
                self._report(url, "window.name", payload, found)
        except Exception as exc:
            _logger.debug(f"[DOMXSSScanner] window.name test error on {url}: {exc!r}")

    async def _test_localstorage(self, page, url: str):
        """Test localStorage/sessionStorage as DOM XSS sources."""
        canary = _gen_canary()
        payload = f"<img src=x onerror=console.error('DOMXSS_{canary}')>"
        storage_keys = ["xss", "data", "token", "user", "payload", "q", "search", "redirect"]
        try:
            await page.goto(url, timeout=self.timeout_ms, wait_until="domcontentloaded")
            for key in storage_keys:
                await page.evaluate(f"""
                    () => {{
                        try {{
                            localStorage.setItem({repr(key)}, {repr(payload)});
                            sessionStorage.setItem({repr(key)}, {repr(payload)});
                        }} catch(e) {{}}
                    }}
                """)
            # Reload to trigger any code that reads storage on load
            found = await self._navigate_and_check(page, url, canary, "localStorage/sessionStorage")
            if found:
                self._report(url, "localStorage/sessionStorage", payload, found)
            # Clean up
            await page.evaluate("() => { try { localStorage.clear(); sessionStorage.clear(); } catch(e) {} }")
        except Exception as exc:
            _logger.debug(f"[DOMXSSScanner] localStorage test error on {url}: {exc!r}")

    async def _test_postmessage(self, page, url: str):
        """Test postMessage-based DOM XSS (event.data sink)."""
        canary = _gen_canary()
        payloads = [
            f"<img src=x onerror=console.error('DOMXSS_{canary}')>",
            f"javascript:console.error('DOMXSS_{canary}')",
            f"DOMXSS_{canary}",
        ]
        try:
            await page.goto(url, timeout=self.timeout_ms, wait_until="domcontentloaded")
            await page.wait_for_timeout(500)
            for payload in payloads:
                result = await page.evaluate(f"""
                    async () => {{
                        return new Promise(resolve => {{
                            const canary = {repr(canary)};
                            const msgs = [];
                            const handler = e => {{
                                const d = String(e.data);
                                if (d.includes(canary)) msgs.push('postMessage reflected: ' + d.substring(0, 80));
                            }};
                            window.addEventListener('message', handler);
                            // Try sending to various origins
                            window.postMessage({repr(payload)}, '*');
                            try {{ window.postMessage({{type: 'data', data: {repr(payload)}}}, '*'); }} catch(e) {{}}
                            try {{ window.postMessage({{message: {repr(payload)}}}, '*'); }} catch(e) {{}}
                            setTimeout(() => {{
                                window.removeEventListener('message', handler);
                                resolve(msgs.length > 0 ? msgs[0] : null);
                            }}, 600);
                        }});
                    }}
                """)
                if result:
                    self._report(url, "postMessage", payload, str(result))
                    return
        except Exception as exc:
            _logger.debug(f"[DOMXSSScanner] postMessage test error on {url}: {exc!r}")

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
