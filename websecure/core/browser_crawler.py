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
import time as _time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urljoin, urlparse

_logger = logging.getLogger(__name__)


def _infer_form_methods(forms, page_url: str) -> None:
    """
    Fix browser-extracted form methods in place. The DOM ``f.method`` is GET when a
    form has no explicit ``method`` attribute — which is the norm for SPA auth /
    registration / payment forms that submit via onSubmit→fetch. Left as GET, the
    injection scanners would fuzz these fields in the URL query instead of the
    request body, so name/email/password/card never get the payload. Re-infer POST
    for sensitive forms (shared logic with the static extractor).
    """
    try:
        from websecure.core.analysis import infer_form_method as _ifm
    except Exception:
        return
    for f in (forms or []):
        if not isinstance(f, dict):
            continue
        try:
            f["method"] = _ifm(f.get("action") or page_url, f.get("inputs"), f.get("method"))
        except Exception:
            pass


try:
    from websecure.core.utils.net import same_site as _same_site
except Exception:  # pragma: no cover - import güvenliği
    _same_site = None

try:
    from websecure.core.utils.net import is_junk_url as _is_junk_url
except Exception:  # pragma: no cover - import güvenliği
    def _is_junk_url(_u: str) -> bool:  # type: ignore
        return False

# Sır pattern havuzu tek kaynağı: scanners.js_analyzer._SECRET_PATTERNS (32 derlenmiş
# pattern). Aşağıdaki sınıf-içi _SECRET_PATTERNS yalnız bu import başarısız olursa (ör.
# scanners paketi yoksa) devreye giren yerel fallback'tir. [[plan_dedup_konsolidasyon]]
try:
    from websecure.scanners.js_analyzer import _SECRET_PATTERNS as _JS_SECRET_PATTERNS
except Exception:  # pragma: no cover - tek kaynak yoksa yerel fallback'e düşer
    _JS_SECRET_PATTERNS = None


def _in_scope(url: str, base_url: str) -> bool:
    """
    url'in hedef site kapsamında olup olmadığını döner (same-site / eTLD+1).
    same_site import edilemezse exact-netloc'a düşer (güvenli taraf: daha dar).
    """
    if not url:
        return False
    if _same_site is not None:
        return _same_site(url, base_url)
    try:
        return urlparse(url).netloc == urlparse(base_url).netloc
    except Exception:
        return False


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
    # Tüm browser-crawl için duvar-saati üst sınırı (sn). 0 => varsayılan mantık
    # (_effective_budget_seconds): normalde 300sn, no_timeout açıkken 900sn.
    # Browser crawler doğası gereği SINIRSIZ bir keşiftir (link/JS bundle buldukça
    # devam eder); Tor üzerinde tek bir sayfa-içi fetch veya 50-sayfalık SPA crawl'ı
    # onlarca dakika sürebilir. no_timeout faz-watchdog'unu kaldırdığından, crawl'ın
    # kendisi BİTMEYİ garanti etmeli — yoksa tüm tarama burada sonsuza dek donar.
    max_total_seconds: int = 0
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

    # FALLBACK ONLY — canlı tarama js_analyzer._SECRET_PATTERNS (tek kaynak, 32 pattern)
    # kullanır; bu küçük set yalnız o modül import edilemezse devreye girer.
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

    def overall_budget_seconds(self) -> float:
        """
        Tüm browser-crawl için duvar-saati üst sınırı (sn). Browser crawler bir
        keşif yardımcısıdır (doğrudan zafiyet bulmaz) ama sınırsız bir crawl'dır;
        no_timeout faz-watchdog'unu kaldırdığından bu sınır crawl'ın BİTMESİNİ
        garanti eder. no_timeout açıkken sınır cömertçe büyütülür ama SONLU kalır
        — böylece tarama burada asla sonsuza dek donmaz (faz atlanmaz, bulunanlar
        döndürülür).
        """
        base = float(getattr(self.config, "max_total_seconds", 0) or 0)
        if base > 0:
            return base  # açık kullanıcı tercihi — aynen onurlandır
        base = 300.0
        try:
            from websecure.core.http import no_timeout_enabled as _nt
            if _nt():
                base = 900.0
        except Exception:
            pass
        return base

    def crawl_sync(self, base_url: str) -> BrowserCrawlResult:
        """Synchronous wrapper for use in non-async contexts."""
        if not _PLAYWRIGHT_AVAILABLE:
            _logger.warning("[BrowserCrawler] Playwright unavailable, returning empty result")
            return BrowserCrawlResult(endpoints=[base_url])
        loop = asyncio.new_event_loop()
        try:
            return loop.run_until_complete(self.crawl(base_url))
        except Exception as e:
            _logger.error(f"[BrowserCrawler] Crawl failed: {e}")
            return BrowserCrawlResult(endpoints=[base_url])
        finally:
            loop.close()

    async def crawl(self, base_url: str) -> BrowserCrawlResult:
        """Main async crawl entry point."""
        if not _PLAYWRIGHT_AVAILABLE:
            return BrowserCrawlResult(endpoints=[base_url])

        base_domain = urlparse(base_url).netloc
        to_visit = [base_url]
        self._visited = set()
        self._result = BrowserCrawlResult()
        self._api_requests = []
        self._intercepted_requests = []

        # show_browser=True -> headless=False (görünür Chrome)
        use_headless = self.config.headless and not self.config.show_browser
        launch_opts: Dict[str, Any] = {"headless": use_headless}
        if self.config.slow_mo_ms > 0 and not use_headless:
            launch_opts["slow_mo"] = self.config.slow_mo_ms
        if self.config.proxy_url:
            # Chrome `socks5h://` anlamaz → `socks5://` (SOCKS5'te DNS uzaktan çözülür).
            _p = (self.config.proxy_url.replace("socks5h://", "socks5://")
                                       .replace("socks4a://", "socks4://"))
            launch_opts["proxy"] = {"server": _p}
            # WebRTC gerçek-IP sızıntısını kapat — tarayıcı Tor üzerindeyken IP gizli kalsın
            launch_opts.setdefault("args", []).extend([
                "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
                "--disable-features=WebRtcHideLocalIpsWithMdns",
                "--proxy-bypass-list=<-loopback>",
            ])
            _logger.info(f"[BrowserCrawler] Proxy/Tor üzerinden (IP gizli): {_p}")

        if not use_headless:
            _logger.info(
                "[BrowserCrawler] Görünür mod aktif — Chrome penceresi açılıyor. "
                "Test adımlarını, form doldurmayı ve payload denemelerini izleyebilirsiniz."
            )

        # Duvar-saati bütçesi: crawl'ın BİTMESİNİ garanti eder (no_timeout açıkken
        # bile). Sınırsız bir keşif + Tor yavaşlığı = aksi halde sonsuz donma.
        budget = self.overall_budget_seconds()
        deadline = (_time.monotonic() + budget) if budget > 0 else None

        def _over_budget() -> bool:
            return deadline is not None and _time.monotonic() > deadline

        async with async_playwright() as pw:
            # launch yerel bir işlemdir ama Chromium kurulu değilse/bozuksa asılı
            # kalabilir — sınırlı bekle ki burada sonsuza dek takılmasın.
            try:
                browser: Browser = await asyncio.wait_for(
                    pw.chromium.launch(**launch_opts), timeout=90
                )
            except Exception as e:
                _logger.error(f"[BrowserCrawler] Chromium başlatılamadı/zaman aşımı: {e}")
                return self._result
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

                # Scope gate: üçüncü-parti host'ları (analytics.google.com,
                # doubleclick, hotjar vb.) keşif havuzuna ALMA. Aksi halde GA4
                # 'g/collect' beacon'ları gibi binlerce alakasız URL fuzz fazına
                # sızıp taramayı saatlerce uzatır. same_site alt-domain'lere izin
                # verir (api.site.com), yalnız farklı siteyi eler.
                if not _in_scope(url, base_url):
                    return

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
                    except Exception as _fix_e:
                        _logger.debug(f"[core.browser_crawler] {type(_fix_e).__name__}: {_fix_e!r}")
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

            # Tor/proxy üzerinde 15sn navigation timeout fazla dardır (Tor HTTP
            # tabanı 20-45sn) → hem networkidle hem domcontentloaded patlar, sayfa
            # hiç yüklenmez (keşif boş döner). Proxy varsa tavanı yükselt.
            nav_timeout = (
                max(self.config.timeout_ms, 30000)
                if self.config.proxy_url else self.config.timeout_ms
            )

            page_count = 0
            while to_visit and page_count < self.config.max_pages:
                if _over_budget():
                    _logger.info(
                        "[BrowserCrawler] Süre bütçesi (%.0fs) doldu — %d sayfa sonrası "
                        "keşif durduruluyor; bulunanlar döndürülüyor (faz atlanmıyor).",
                        budget, page_count,
                    )
                    break
                url = to_visit.pop(0)
                if url in self._visited:
                    continue
                self._visited.add(url)
                page_count += 1

                try:
                    try:
                        await page.goto(url, timeout=nav_timeout, wait_until="networkidle")
                    except Exception:
                        # networkidle can timeout on SPAs — fall back to domcontentloaded
                        try:
                            await page.goto(url, timeout=nav_timeout, wait_until="domcontentloaded")
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
                        _infer_form_methods(forms_data, url)
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
                            _infer_form_methods(spa_forms, url)
                            self._result.forms_meta.append({"url": url + "#spa", "forms": spa_forms})
                    except Exception as _fix_e:
                        _logger.debug(f"[core.browser_crawler] {type(_fix_e).__name__}: {_fix_e!r}")

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
            # KRİTİK: sayfa-içi fetch()'in timeout'u YOKTUR; Tor üzerinde asılı bir
            # JS-bundle indirmesi page.evaluate'i (kendisi de timeout'suz) sonsuza
            # dek bekletir → tüm tarama donar. İki katmanlı sınır: (1) sayfa-içi
            # AbortController 20sn'de fetch'i iptal eder, (2) Python tarafında
            # asyncio.wait_for donmuş bir sekme/evaluate'e karşı son kalkan.
            spa_routes_discovered: List[str] = []
            for js_url in self._result.js_files[:15]:
                if _over_budget():
                    break
                js_content = ""
                try:
                    js_content = await asyncio.wait_for(
                        page.evaluate(
                            "async (u) => {"
                            "  try {"
                            "    const c = new AbortController();"
                            "    const t = setTimeout(() => c.abort(), 20000);"
                            "    const r = await fetch(u, {signal: c.signal});"
                            "    const txt = await r.text();"
                            "    clearTimeout(t);"
                            "    return txt;"
                            "  } catch(e) { return ''; }"
                            "}",
                            js_url,
                        ),
                        timeout=25,
                    )
                except Exception as exc:
                    _logger.debug(f"[BrowserCrawler] JS route extraction {js_url}: {exc}")
                    js_content = ""
                if js_content:
                    for route in self._extract_spa_routes_from_js(js_content, base_url):
                        if route not in spa_routes_discovered:
                            spa_routes_discovered.append(route)

            # -- Phase 3: Navigate to newly discovered SPA routes ------------
            for route in spa_routes_discovered[:25]:
                if _over_budget():
                    break
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
                if urlparse(full_url).netloc != urlparse(base_url).netloc:
                    continue
                # /[pagePath] route-şablonları ve özyinelemeli urljoin çöpünü
                # kaynakta ele — fuzz havuzuna sızmasın.
                if _is_junk_url(full_url):
                    continue
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
                _infer_form_methods(new_forms, route_url)
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
                    _logger.debug(f"[core.browser_crawler] {type(exc).__name__}: {exc!r}")
        except Exception as exc:
            _logger.debug(f"[core.browser_crawler] {type(exc).__name__}: {exc!r}")
        return detected

    def _scan_for_secrets(self, content: str, url: str) -> None:
        # Tek kaynak: js_analyzer._SECRET_PATTERNS (derlenmiş, capture-grup'lu, 32 pattern).
        # capture-grup varsa onu (gerçek sır) al, yoksa tam eşleşme. Modül yoksa yerel dict.
        if _JS_SECRET_PATTERNS:
            for name, rx in _JS_SECRET_PATTERNS:
                for match in rx.finditer(content):
                    secret_val = match.group(match.lastindex) if match.lastindex else match.group(0)
                    self._result.secrets_found.append({
                        "type": name,
                        "url": url,
                        "value_preview": secret_val[:20] + "...",
                        "severity": "High",
                    })
        else:
            for name, pattern in self._SECRET_PATTERNS.items():
                for match in re.finditer(pattern, content):
                    secret_val = match.group(0)
                    self._result.secrets_found.append({
                        "type": name,
                        "url": url,
                        "value_preview": secret_val[:20] + "...",
                        "severity": "High",
                    })


def should_use_browser_crawler(http_result: Dict) -> bool:
    """
    Heuristic: escalate to Playwright if:
    - HTTP crawler bulamadı HİÇ form (forms_found == 0) — formlar JS ile render
      ediliyor olabilir; input alanlarının (login/register/ödeme) fuzz'lanabilmesi
      için tarayıcıyla render edip keşfetmek ŞART. Statik HTML parse SPA formlarını
      göremez → bu olmadan scanner'lar yalnız URL query'sini test eder.
    - fewer than 5 unique endpoints found by HTTP crawler
    - page source contains React/Angular/Vue script tags
    - JavaScript-heavy indicators present
    """
    # Form keşfi en kritik tetikleyici: statik parse form bulamadıysa tarayıcıya yüksel.
    if not http_result.get("forms_found"):
        return True
    endpoints = http_result.get("endpoints", [])
    if len(endpoints) < 5:
        return True
    tech = http_result.get("tech_stack", [])
    spa_techs = {"React", "Angular", "Vue", "Next.js", "Nuxt.js", "Svelte"}
    if any(t in spa_techs for t in tech):
        return True
    return False


__all__ = [
    'BrowserCrawlConfig',
    'BrowserCrawlResult',
    'BrowserCrawler',
    'should_use_browser_crawler',
]
