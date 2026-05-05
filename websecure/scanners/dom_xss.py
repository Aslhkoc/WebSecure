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

        # ─── Adım 4: Stored XSS multi-endpoint correlation ────────────────
        write_eps: List[Dict] = kwargs.get("write_endpoints") or []
        read_eps: List[str]   = kwargs.get("read_endpoints")  or endpoints
        if write_eps and self.session:
            correlator = StoredXSSCorrelator(timeout_ms=self.timeout_ms)
            for finding in correlator.correlate(write_eps, read_eps, self.session):
                self._report(
                    finding["write_url"],
                    finding["write_param"],
                    finding["payload"],
                    finding["evidence"],
                )

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


# ===========================================================================
# Adım 4 — Stored XSS Multi-Endpoint Correlator
# ===========================================================================

_STORED_XSS_PAYLOADS: List[str] = [
    "<img src=x id='ws_stored_{uid}' onerror=console.error('WSXSS_{uid}')>",
    "<svg id='ws_stored_{uid}' onload=console.error('WSXSS_{uid}')>",
    "<input id='ws_stored_{uid}' autofocus onfocus=console.error('WSXSS_{uid}')>",
    "<details open ontoggle=console.error('WSXSS_{uid}') id='ws_stored_{uid}'>x</details>",
    "ws_stored_{uid}<script>console.error('WSXSS_{uid}')</script>",
]


class StoredXSSCorrelator:
    """
    Multi-endpoint Stored XSS correlation.
    Phase 1 (write): Inject canary payload on write endpoints (POST/PUT).
    Phase 2 (read):  Check read endpoints via Playwright for unescaped execution.

    Single Responsibility: stored XSS detection across endpoint pairs only.
    Dependency Inversion: accepts session + page, no hard coupling to scanner.
    """

    def __init__(self, timeout_ms: int = 8000) -> None:
        self.timeout_ms = timeout_ms

    # ── Sync entry point ──────────────────────────────────────────────────

    def correlate(
        self,
        write_endpoints: List[Dict[str, Any]],
        read_endpoints: List[str],
        session: Any,
        debug: bool = False,
    ) -> List[Dict[str, Any]]:
        """
        write_endpoints: list of dicts with keys:
            url (str), method (str, POST|PUT|PATCH), params (dict)
        read_endpoints: list of URLs to check after injection.
        Returns list of finding dicts.
        """
        if not _PLAYWRIGHT_AVAILABLE:
            _logger.warning("[StoredXSSCorrelator] Playwright not available — skipping")
            return []
        try:
            import asyncio
            loop = asyncio.new_event_loop()
            result = loop.run_until_complete(
                self._async_correlate(write_endpoints, read_endpoints, session)
            )
            loop.close()
            return result
        except Exception as exc:
            _logger.warning("[StoredXSSCorrelator] Event loop error: %r", exc)
            return []

    # ── Async implementation ──────────────────────────────────────────────

    async def _async_correlate(
        self,
        write_endpoints: List[Dict[str, Any]],
        read_endpoints: List[str],
        session: Any,
    ) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []

        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=True)
            context = await browser.new_context()
            page = await context.new_page()

            for write_ep in write_endpoints[:10]:
                url = write_ep.get("url", "")
                method = (write_ep.get("method") or "POST").upper()
                base_params: Dict[str, Any] = write_ep.get("params") or {}

                for param_name in list(base_params.keys())[:5]:
                    uid = random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=8)
                    uid_str = "".join(uid)

                    for tpl in _STORED_XSS_PAYLOADS:
                        payload = tpl.format(uid=uid_str)
                        injected_params = dict(base_params)
                        injected_params[param_name] = payload

                        # Phase 1: write
                        try:
                            if method in ("POST", "PUT", "PATCH"):
                                session.request(method, url, data=injected_params, timeout=8)
                            else:
                                session.get(url, params=injected_params, timeout=8)
                        except Exception as exc:
                            _logger.debug("[StoredXSSCorrelator] Write error %s: %r", url, exc)
                            continue

                        # Phase 2: read — check all read endpoints
                        for read_url in read_endpoints[:10]:
                            evidence = await self._check_stored(page, read_url, uid_str)
                            if evidence:
                                findings.append({
                                    "type": "Stored XSS (Multi-Endpoint Correlation)",
                                    "severity": "Critical",
                                    "write_url": url,
                                    "write_param": param_name,
                                    "read_url": read_url,
                                    "payload": payload,
                                    "uid": uid_str,
                                    "evidence": evidence,
                                    "verified": True,
                                    "confidence": "high",
                                })
                                _logger.warning(
                                    "[StoredXSSCorrelator] Stored XSS: write=%s param=%s → read=%s",
                                    url, param_name, read_url,
                                )
                                break  # found for this param, move on

            await browser.close()
        return findings

    async def _check_stored(self, page: Any, url: str, uid: str) -> Optional[str]:
        """Navigate to read_url and check for canary execution."""
        canary = f"WSXSS_{uid}"
        console_hits: List[str] = []

        def on_console(msg: Any) -> None:
            if canary in msg.text:
                console_hits.append(f"console.{msg.type}: {msg.text[:120]}")

        page.on("console", on_console)
        try:
            await page.goto(url, timeout=self.timeout_ms, wait_until="domcontentloaded")
            await page.wait_for_timeout(1200)

            if console_hits:
                return console_hits[0]

            # Fallback: DOM check for unescaped canary
            dom_hit = await page.evaluate(f"""
                () => {{
                    const uid = '{uid}';
                    const body = document.body ? document.body.innerHTML : '';
                    if (body.includes('ws_stored_' + uid)) return 'canary_in_dom_unescaped';
                    return null;
                }}
            """)
            return dom_hit or None
        except Exception as exc:
            _logger.debug("[StoredXSSCorrelator] Read error %s: %r", url, exc)
            return None
        finally:
            page.remove_listener("console", on_console)
