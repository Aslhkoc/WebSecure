"""
websecure.scanners.dom_xss
--------------------------
DOM-based XSS scanner using Playwright.
Detects XSS that only fires in browser context (not visible in raw HTTP response).

Includes:
  - DOMXSSScanner        — payload injection into URL params / fragment / storage / postMessage
  - DOMXSSMonkeyPatchProber — JS sink override via add_init_script + canary tracking
  - PostMessageInterceptionProber — postMessage origin-check bypass detection
  - StoredXSSCorrelator  — multi-endpoint stored XSS correlation
"""
from __future__ import annotations
import asyncio
import logging
import random
import string
from typing import Any, Dict, List, Optional
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
        self._seen_dom_findings: set = set()  # (url_path, param_name) dedup

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

        # --- MonkeyPatch prober: JS sink override + canary injection ------
        try:
            monkey_prober = DOMXSSMonkeyPatchProber(
                session=self.session,
                results=self.results,
                debug=self.debug,
                headless=self.headless,
                timeout_ms=self.timeout_ms,
            )
            monkey_prober.run(target, endpoints=endpoints)
        except Exception as exc:
            _logger.warning(f"[DOMXSSScanner] MonkeyPatchProber error: {exc!r}")

        # --- PostMessage interception prober ------------------------------
        try:
            pm_prober = PostMessageInterceptionProber(
                session=self.session,
                results=self.results,
                debug=self.debug,
                headless=self.headless,
                timeout_ms=self.timeout_ms,
            )
            pm_prober.run(target, endpoints=endpoints)
        except Exception as exc:
            _logger.warning(f"[DOMXSSScanner] PostMessageInterceptionProber error: {exc!r}")

        # --- Adım 4: Stored XSS multi-endpoint correlation ----------------
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

            # 5 çeşit payload dene, her biri farklı teknik
            _diverse = [
                next((p for p in dom_payloads if "<img" in p), dom_payloads[0]),
                next((p for p in dom_payloads if "<svg" in p or "onload" in p.lower()), dom_payloads[min(1, len(dom_payloads)-1)]),
                next((p for p in dom_payloads if "script" in p.lower()), dom_payloads[min(2, len(dom_payloads)-1)]),
                next((p for p in dom_payloads if "onerror" in p.lower()), dom_payloads[min(3, len(dom_payloads)-1)]),
                next((p for p in dom_payloads if "alert" in p.lower()), dom_payloads[min(4, len(dom_payloads)-1)]),
            ]
            _diverse = list(dict.fromkeys(_diverse))  # deduplicate preserving order

            found = None
            payload = _diverse[0]
            for payload in _diverse:
                new_params = dict(params)
                new_params[param_name] = payload
                new_query = urlencode(new_params)
                test_url = urlunparse(parsed._replace(query=new_query))
                found = await self._navigate_and_check(page, test_url, canary, param_name)
                if found:
                    break

            if found:
                _dom_key = (urlparse(url).path, param_name)
                if _dom_key not in self._seen_dom_findings:
                    self._seen_dom_findings.add(_dom_key)
                    self._report(url, param_name, payload, found)

        # Also test fragment and postMessage on parametrised pages
        await self._test_fragment(page, url)
        await self._test_postmessage(page, url)

    async def _test_fragment(self, page, url: str):
        """Test hash-based DOM XSS (location.hash sources)."""
        _key = (url, "#fragment")
        if _key in self._seen_dom_findings:
            return
        canary = _gen_canary()
        payload = f"<img src=x onerror=console.error('DOMXSS_{canary}')>"
        test_url = url.rstrip("/") + f"#{payload}"
        found = await self._navigate_and_check(page, test_url, canary, "#fragment")
        if found:
            self._seen_dom_findings.add(_key)
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
        _key = (url, "postMessage")
        if _key in self._seen_dom_findings:
            return
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
                    self._seen_dom_findings.add(_key)
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
        self.add("offensive", finding)  # self.add() already calls add_result() internally
        _logger.warning(f"[DOMXSSScanner] DOM XSS found: {url} param={param}")


def run(target: str, session=None, results=None, debug=False, **kwargs):
    scanner = DOMXSSScanner(session=session, results=results, debug=debug)
    scanner.run(target, **kwargs)


# ===========================================================================
# DOMXSSMonkeyPatchProber — JS sink override via add_init_script
# ===========================================================================

# Canary constant — unique enough to avoid false positives
_MONKEY_CANARY = "__WEBSECURE_DOMXSS_789__"

# Common parameter names used for canary injection
_CANARY_PARAM_NAMES = [
    "q", "s", "id", "url", "redirect", "next", "return",
    "ref", "path", "data", "input", "term", "search",
]

# URL-encoded and alternate encoding variants of the canary
_CANARY_ENCODED_VARIANTS = [
    _MONKEY_CANARY,                                     # raw
    "%5F%5FWEBSECURE%5FDOMXSS%5F789%5F%5F",            # URL-encoded
    "&#95;&#95;WEBSECURE&#95;DOMXSS&#95;789&#95;&#95;",  # HTML entities
    r"__WEBSECURE_DOMXSS_789__",  # JS unicode
]

# JavaScript injected as init script to override dangerous sinks
_MONKEY_PATCH_JS = r"""
(function () {
    window.__domxss_hits__ = [];

    function _record(sink, val) {
        window.__domxss_hits__.push({sink: sink, val: String(val).slice(0, 200)});
    }

    // --- Element.prototype.innerHTML ---
    var _descInner = Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML');
    if (_descInner && _descInner.set) {
        Object.defineProperty(Element.prototype, 'innerHTML', {
            get: _descInner.get,
            set: function(v) {
                if (String(v).indexOf('__WEBSECURE_DOMXSS_789__') !== -1)
                    _record('innerHTML', v);
                return _descInner.set.call(this, v);
            },
            configurable: true
        });
    }

    // --- Element.prototype.outerHTML ---
    var _descOuter = Object.getOwnPropertyDescriptor(Element.prototype, 'outerHTML');
    if (_descOuter && _descOuter.set) {
        Object.defineProperty(Element.prototype, 'outerHTML', {
            get: _descOuter.get,
            set: function(v) {
                if (String(v).indexOf('__WEBSECURE_DOMXSS_789__') !== -1)
                    _record('outerHTML', v);
                return _descOuter.set.call(this, v);
            },
            configurable: true
        });
    }

    // --- document.write ---
    var _origWrite = document.write.bind(document);
    document.write = function(v) {
        if (String(v).indexOf('__WEBSECURE_DOMXSS_789__') !== -1)
            _record('document.write', v);
        return _origWrite(v);
    };

    // --- eval ---
    var _origEval = window.eval;
    window.eval = function(v) {
        if (String(v).indexOf('__WEBSECURE_DOMXSS_789__') !== -1)
            _record('eval', v);
        return _origEval(v);
    };

    // --- Function constructor ---
    var _origFunction = window.Function;
    window.Function = function() {
        var args = Array.prototype.slice.call(arguments);
        for (var i = 0; i < args.length; i++) {
            if (String(args[i]).indexOf('__WEBSECURE_DOMXSS_789__') !== -1) {
                _record('Function', args[i]);
                break;
            }
        }
        return _origFunction.apply(this, args);
    };
    window.Function.prototype = _origFunction.prototype;

    // --- setTimeout ---
    var _origSetTimeout = window.setTimeout;
    window.setTimeout = function(fn) {
        if (typeof fn === 'string' && fn.indexOf('__WEBSECURE_DOMXSS_789__') !== -1)
            _record('setTimeout', fn);
        return _origSetTimeout.apply(this, arguments);
    };

    // --- setInterval ---
    var _origSetInterval = window.setInterval;
    window.setInterval = function(fn) {
        if (typeof fn === 'string' && fn.indexOf('__WEBSECURE_DOMXSS_789__') !== -1)
            _record('setInterval', fn);
        return _origSetInterval.apply(this, arguments);
    };

    // --- location.href ---
    var _descHref = Object.getOwnPropertyDescriptor(Location.prototype, 'href');
    if (_descHref && _descHref.set) {
        Object.defineProperty(Location.prototype, 'href', {
            get: _descHref.get,
            set: function(v) {
                if (String(v).indexOf('__WEBSECURE_DOMXSS_789__') !== -1)
                    _record('location.href', v);
                return _descHref.set.call(this, v);
            },
            configurable: true
        });
    }

    // --- location.assign ---
    var _origAssign = location.assign.bind(location);
    try {
        location.assign = function(v) {
            if (String(v).indexOf('__WEBSECURE_DOMXSS_789__') !== -1)
                _record('location.assign', v);
            return _origAssign(v);
        };
    } catch(e) {}

    // --- localStorage.setItem ---
    var _origLSSet = localStorage.setItem.bind(localStorage);
    try {
        localStorage.setItem = function(k, v) {
            if (String(v).indexOf('__WEBSECURE_DOMXSS_789__') !== -1)
                _record('localStorage.setItem', v);
            return _origLSSet(k, v);
        };
    } catch(e) {}

    // --- sessionStorage.setItem ---
    var _origSSSet = sessionStorage.setItem.bind(sessionStorage);
    try {
        sessionStorage.setItem = function(k, v) {
            if (String(v).indexOf('__WEBSECURE_DOMXSS_789__') !== -1)
                _record('sessionStorage.setItem', v);
            return _origSSSet(k, v);
        };
    } catch(e) {}

    // --- postMessage source tracking ---
    window.addEventListener('message', function(e) {
        var d = String(typeof e.data === 'object' ? JSON.stringify(e.data) : e.data);
        if (d.indexOf('__WEBSECURE_DOMXSS_789__') !== -1)
            _record('postMessage_received', d);
    });
})();
"""

# JavaScript for postMessage interception prober
_POSTMESSAGE_INTERCEPT_JS = r"""
(function() {
    window.__pm_intercept_hits__ = [];
    window.__pm_listeners__ = [];
    var _origAEL = window.addEventListener;
    window.addEventListener = function(type, handler, opts) {
        if (type === 'message') {
            window.__pm_listeners__.push({
                handler: handler.toString().slice(0, 300),
                hasOriginCheck: handler.toString().indexOf('origin') !== -1
            });
            var wrapped = function(e) {
                var d = String(typeof e.data === 'object' ? JSON.stringify(e.data) : e.data);
                if (d.indexOf('__WEBSECURE_DOMXSS_789__') !== -1) {
                    window.__pm_intercept_hits__.push({
                        listener: handler.toString().slice(0, 200),
                        hasOriginCheck: handler.toString().indexOf('origin') !== -1,
                        data: d.slice(0, 200)
                    });
                }
                return handler.apply(this, arguments);
            };
            return _origAEL.call(this, type, wrapped, opts);
        }
        return _origAEL.apply(this, arguments);
    };
})();
"""


class DOMXSSMonkeyPatchProber(BaseScanner):
    """
    JS sink override via Playwright add_init_script + canary injection.

    Strategy:
    1. Inject a monkey-patch init script that overrides dangerous JS sinks
       (innerHTML, outerHTML, document.write, eval, Function, setTimeout,
        setInterval, location.href, location.assign, localStorage.setItem,
        sessionStorage.setItem) to record canary hits in window.__domxss_hits__.
    2. Navigate to URL with canary injected into all common query params,
       hash fragment, and storage.
    3. After load, inspect window.__domxss_hits__ — any hit → Critical finding.

    Single Responsibility: only monkey-patch + canary probe logic.
    """

    name = "dom_xss_monkey"
    phase = "browser"

    def __init__(self, session=None, results: Dict = None, debug: bool = False,
                 headless: bool = True, timeout_ms: int = 8000):
        super().__init__(session, results, debug)
        self.headless = headless
        self.timeout_ms = timeout_ms

    def run(self, target: str, **kwargs) -> None:
        """Sync entry point."""
        if not _PLAYWRIGHT_AVAILABLE:
            _logger.warning("[DOMXSSMonkeyPatchProber] Playwright not available, skipping")
            return
        endpoints = kwargs.get("endpoints") or [target]
        try:
            loop = asyncio.new_event_loop()
            loop.run_until_complete(self._async_run(endpoints))
            loop.close()
        except Exception as exc:
            _logger.warning(f"[DOMXSSMonkeyPatchProber] Event loop error: {exc!r}")

    async def _async_run(self, endpoints: List[str]) -> None:
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=self.headless)
            context = await browser.new_context()
            # Inject the monkey-patch on every page before any scripts run
            await context.add_init_script(script=_MONKEY_PATCH_JS)
            page = await context.new_page()
            for url in endpoints[:20]:
                await self._probe_url(page, url)
            await browser.close()

    async def _probe_url(self, page, url: str) -> None:
        """Probe a single URL with all canary encoding variants."""
        parsed = urlparse(url)
        existing_params = dict(parse_qsl(parsed.query))

        # Build all param name candidates: existing + common param names
        param_names = list(existing_params.keys()) or _CANARY_PARAM_NAMES

        for variant in _CANARY_ENCODED_VARIANTS:
            # 1. Inject canary into all param names simultaneously
            injected_params = {p: variant for p in param_names}
            new_query = urlencode(injected_params)
            test_url_query = urlunparse(parsed._replace(query=new_query, fragment=""))

            # 2. Also test with hash fragment injection
            test_url_hash = urlunparse(parsed._replace(
                query=new_query, fragment=variant
            ))

            for test_url in (test_url_query, test_url_hash):
                hits = await self._navigate_and_collect(page, test_url)
                if hits:
                    for hit in hits:
                        self.report_finding(
                            vuln_type="DOM XSS (MonkeyPatch Sink Hit)",
                            url=test_url,
                            param=hit.get("sink", "unknown"),
                            payload=variant,
                            severity="Critical",
                            evidence=f"Sink={hit.get('sink','?')} value={hit.get('val','?')}",
                            verified=True,
                            confidence="high",
                        )
                    return  # One confirmed hit per URL is sufficient

        # 3. Storage-based canary: store canary, then reload
        await self._probe_storage(page, url, parsed)

    async def _navigate_and_collect(self, page, url: str) -> List[Dict]:
        """Navigate to URL and collect __domxss_hits__."""
        try:
            await page.goto(url, timeout=self.timeout_ms, wait_until="domcontentloaded")
            await page.wait_for_timeout(800)
            hits = await page.evaluate("window.__domxss_hits__ || []")
            # Reset for next probe
            await page.evaluate("window.__domxss_hits__ = []")
            return hits if isinstance(hits, list) else []
        except Exception as exc:
            _logger.debug(f"[DOMXSSMonkeyPatchProber] Navigate error on {url}: {exc!r}")
            return []

    async def _probe_storage(self, page, url: str, parsed) -> None:
        """Inject canary into localStorage/sessionStorage, reload and check hits."""
        base_url = urlunparse(parsed._replace(query="", fragment=""))
        try:
            await page.goto(base_url, timeout=self.timeout_ms, wait_until="domcontentloaded")
            canary = _MONKEY_CANARY
            await page.evaluate(f"""
                () => {{
                    try {{
                        var keys = ['xss','data','token','user','payload','q','search','redirect'];
                        for (var i = 0; i < keys.length; i++) {{
                            localStorage.setItem(keys[i], {repr(canary)});
                            sessionStorage.setItem(keys[i], {repr(canary)});
                        }}
                    }} catch(e) {{}}
                }}
            """)
            # Reload to trigger code that reads storage on load
            await page.reload(timeout=self.timeout_ms, wait_until="domcontentloaded")
            await page.wait_for_timeout(800)
            hits = await page.evaluate("window.__domxss_hits__ || []")
            await page.evaluate(
                "() => { try { localStorage.clear(); sessionStorage.clear(); } catch(e) {} }"
            )
            if hits:
                for hit in hits:
                    self.report_finding(
                        vuln_type="DOM XSS (MonkeyPatch Sink Hit via Storage)",
                        url=base_url,
                        param=hit.get("sink", "localStorage/sessionStorage"),
                        payload=canary,
                        severity="Critical",
                        evidence=f"Sink={hit.get('sink','?')} value={hit.get('val','?')}",
                        verified=True,
                        confidence="high",
                    )
        except Exception as exc:
            _logger.debug(f"[DOMXSSMonkeyPatchProber] Storage probe error on {url}: {exc!r}")


# ===========================================================================
# PostMessageInterceptionProber — postMessage origin check bypass
# ===========================================================================


class PostMessageInterceptionProber(BaseScanner):
    """
    Detects postMessage handlers that lack origin validation.

    Strategy:
    1. Inject an init script that wraps window.addEventListener to capture
       all 'message' event listeners and record whether they check event.origin.
    2. Navigate to the target page.
    3. Send a canary postMessage from within the page context.
    4. Check window.__pm_intercept_hits__ and window.__pm_listeners__:
       - If a listener received the canary and lacks an origin check → High
       - If the canary also reached a DOM sink (via monkey-patch) → Critical

    Single Responsibility: postMessage origin-check detection only.
    """

    name = "dom_xss_postmessage"
    phase = "browser"

    def __init__(self, session=None, results: Dict = None, debug: bool = False,
                 headless: bool = True, timeout_ms: int = 8000):
        super().__init__(session, results, debug)
        self.headless = headless
        self.timeout_ms = timeout_ms

    def run(self, target: str, **kwargs) -> None:
        """Sync entry point."""
        if not _PLAYWRIGHT_AVAILABLE:
            _logger.warning("[PostMessageInterceptionProber] Playwright not available, skipping")
            return
        endpoints = kwargs.get("endpoints") or [target]
        try:
            loop = asyncio.new_event_loop()
            loop.run_until_complete(self._async_run(endpoints))
            loop.close()
        except Exception as exc:
            _logger.warning(f"[PostMessageInterceptionProber] Event loop error: {exc!r}")

    # URL'nin DOM/postMessage handler'ı barındırabilecek bir HTML sayfası olup
    # olmadığını belirleyen pattern'ler.
    _API_PATH_PATTERNS = (
        "/api/", "/rest/", "/graphql", "/gql",
        "/v1/", "/v2/", "/v3/", "/v4/",
        ".json", ".xml", ".csv", ".txt", ".rss", ".atom",
    )
    _API_EXTENSIONS = {".json", ".xml", ".csv", ".txt", ".rss", ".atom", ".yaml", ".yml"}

    @classmethod
    def _is_html_candidate(cls, url: str) -> bool:
        """False döner → postMessage testi atlanır (JSON/API endpoint)."""
        from urllib.parse import urlparse
        try:
            parsed = urlparse(url.rstrip("\\/"))
            path_lower = parsed.path.lower()
            # Bilinen API path prefixleri
            if any(p in path_lower for p in cls._API_PATH_PATTERNS):
                return False
            # Dosya uzantısı
            ext = path_lower.rsplit(".", 1)[-1] if "." in path_lower.rsplit("/", 1)[-1] else ""
            if f".{ext}" in cls._API_EXTENSIONS:
                return False
        except Exception:
            pass
        return True

    async def _async_run(self, endpoints: List[str]) -> None:
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=self.headless)
            context = await browser.new_context()
            # Both scripts: monkey-patch sinks + postMessage interception
            await context.add_init_script(script=_MONKEY_PATCH_JS)
            await context.add_init_script(script=_POSTMESSAGE_INTERCEPT_JS)
            page = await context.new_page()
            for url in endpoints[:20]:
                if not self._is_html_candidate(url):
                    _logger.debug(
                        "[PostMessageInterceptionProber] API/data endpoint atlandı: %s", url
                    )
                    continue
                await self._probe_url(page, url)
            await browser.close()

    async def _probe_url(self, page, url: str) -> None:
        """Navigate and send canary postMessages; inspect listener hits."""
        try:
            await page.goto(url, timeout=self.timeout_ms, wait_until="domcontentloaded")

            # İkinci güvenlik katmanı: sayfanın Content-Type'ına bak.
            # JSON/XML dönen endpoint'lerde DOM veya postMessage handler olmaz.
            content_type = await page.evaluate(
                "() => { try { return document.contentType || ''; } catch(e) { return ''; } }"
            )
            if any(t in (content_type or "").lower() for t in ("json", "xml", "plain", "csv")):
                _logger.debug(
                    "[PostMessageInterceptionProber] Non-HTML content-type (%s), atlandı: %s",
                    content_type, url,
                )
                return

            await page.wait_for_timeout(600)

            canary = _MONKEY_CANARY
            # Send canary as plain string and as common object structures
            await page.evaluate(f"""
                () => {{
                    var c = {repr(canary)};
                    window.postMessage(c, '*');
                    try {{ window.postMessage({{type: 'data', data: c}}, '*'); }} catch(e) {{}}
                    try {{ window.postMessage({{message: c}}, '*'); }} catch(e) {{}}
                    try {{ window.postMessage({{payload: c}}, '*'); }} catch(e) {{}}
                    try {{ window.postMessage({{html: c}}, '*'); }} catch(e) {{}}
                    try {{ window.postMessage({{content: c}}, '*'); }} catch(e) {{}}
                }}
            """)
            await page.wait_for_timeout(800)

            # Collect interception hits and sink hits
            pm_hits = await page.evaluate("window.__pm_intercept_hits__ || []")
            pm_listeners = await page.evaluate("window.__pm_listeners__ || []")
            sink_hits = await page.evaluate("window.__domxss_hits__ || []")

            # Reset for next probe
            await page.evaluate(
                "window.__pm_intercept_hits__ = []; "
                "window.__pm_listeners__ = []; "
                "window.__domxss_hits__ = []"
            )

            if sink_hits:
                # Canary flowed through postMessage into a DOM sink → Critical
                for hit in sink_hits:
                    self.report_finding(
                        vuln_type="DOM XSS via postMessage (Sink Reached)",
                        url=url,
                        param="postMessage → " + hit.get("sink", "unknown"),
                        payload=canary,
                        severity="Critical",
                        evidence=(
                            f"postMessage canary reached sink={hit.get('sink','?')} "
                            f"value={hit.get('val','?')}"
                        ),
                        verified=True,
                        confidence="high",
                    )
                return

            if pm_hits:
                for hit in pm_hits:
                    has_origin = hit.get("hasOriginCheck", False)
                    severity = "High" if not has_origin else "Medium"
                    self.report_finding(
                        vuln_type="postMessage Handler Without Origin Check",
                        url=url,
                        param="postMessage",
                        payload=canary,
                        severity=severity,
                        evidence=(
                            f"Listener received canary; origin_check={has_origin}; "
                            f"handler={hit.get('listener','?')[:120]}"
                        ),
                        verified=True,
                        confidence="high" if not has_origin else "medium",
                    )
                return

            # No hits — report discovered listeners as informational if they lack origin check
            for listener in pm_listeners:
                if not listener.get("hasOriginCheck", True):
                    self.report_finding(
                        vuln_type="postMessage Handler Without Origin Check (Passive)",
                        url=url,
                        param="postMessage",
                        payload="",
                        severity="High",
                        evidence=(
                            f"Listener found without origin check: "
                            f"{listener.get('handler','?')[:120]}"
                        ),
                        verified=False,
                        confidence="medium",
                    )

        except Exception as exc:
            _logger.debug(f"[PostMessageInterceptionProber] Error on {url}: {exc!r}")


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

    # -- Sync entry point --------------------------------------------------

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

    # -- Async implementation ----------------------------------------------

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
                                    "[StoredXSSCorrelator] Stored XSS: write=%s param=%s -> read=%s",
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
