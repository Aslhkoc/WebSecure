from __future__ import annotations
import os
import re
import time
import json
import logging
import hashlib
import threading
import contextlib
import tempfile
import warnings as _bs4_warnings
import importlib.util as _iu
from pathlib import Path
from collections import OrderedDict, deque
from dataclasses import dataclass, field
from typing import Any, Deque, Dict, List, Optional, Pattern, Set, Tuple, Callable, Iterable
from urllib.parse import urljoin, urlparse, urldefrag, parse_qsl, urlunparse, urlsplit, parse_qs
from xml.etree import ElementTree as ET

import requests
from requests import session

# WebSecure Imports
from websecure.core.utils import allowed_http_methods, canonicalize_url, is_static_asset, same_origin
from websecure.core.http import (
    verify_for_phase, HTTP_METRICS, instrument_requests_session, 
    set_trace_id, hardened_session
)
from websecure.core.reporting import (
    counters_inc, counters_add_bytes, add_result
)

# Optional dependencies
if _iu.find_spec("bs4") is not None:
    from bs4 import BeautifulSoup, XMLParsedAsHTMLWarning  # type: ignore
    _bs4_warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)
else:
    BeautifulSoup = None  # type: ignore

if _iu.find_spec("tldextract") is not None:
    from tldextract import extract as _tld_extract
else:
    _tld_extract = None


logger = logging.getLogger(__name__)

# ============================================================================
# CONSTANTS & CONFIG
# ============================================================================

_DISALLOWED_EXTS = {
    ".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz",
    ".mp4", ".webm", ".avi", ".mov",
    ".mp3", ".wav", ".flac",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".iso", ".dmg", ".bin", ".exe", ".dll", ".so", ".apk", ".msi", ".pkg",
    ".sql", ".bak", ".db", ".sqlite"
}

_MAX_BYTES = int(os.getenv("CRAWL_MAX_CONTENT_BYTES", "2500000"))  # 2.5 MiB
_CACHE_MAX = int(os.getenv("CRAWL_REQ_CACHE_MAX", "512"))
_CACHE_TTL = int(os.getenv("CRAWL_REQ_CACHE_TTL", "900"))

MAX_PARSE_BYTES = 3_000_000
SEC_DEFAULT_DENY_PATHS = {"/admin/delete", "/admin/remove", "/admin/purge", "/upload", "/binary/upload"}
SEC_DEFAULT_DENY_REGEX = [
    r"(?i)/api/.*/(delete|drop|purge)",
    r"(?i)/(bulk|mass)(_)?(delete|remove)",
    r"(?i)/(delete|destroy)\b",
    r"(?i)\b(upload|putObject|put_file)\b",
]
SEC_DANGER_VERBS = {"DELETE", "PATCH"}
SEC_UNAUTH_EXTRA_DELAY_MS = int(os.getenv("CRAWL_UNAUTH_EXTRA_DELAY_MS", "200"))
SEC_403_BASE_MS = int(os.getenv("CRAWL_403_COOLDOWN_MS", "800"))
SEC_429_BASE_MS = int(os.getenv("CRAWL_429_COOLDOWN_MS", "1500"))

# Browser / Dynamic Constants
_WS_PER_BUCKET_MAX = int(os.getenv("WS_PER_BUCKET_MAX", "5"))
_WS_MAX_PAGE_PARAM = int(os.getenv("WS_MAX_PAGE_PARAM", "5"))
_NUMERIC_ID_MINLEN = 5
_EPISODE_KEYS = ("bolum","bölüm","episode","sezon","season","fragman","part","ep")
_DENY_RE = re.compile(r"/(logout|signout|cikis|exit)/?", re.I) # Minimal deny list for aggressive scan

NETWORK_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE"}
BROWSER_MAX_CAPTURE_BYTES = int(os.getenv("BROWSER_MAX_CAPTURE_BYTES", "1048576"))  # 1 MiB
BROWSER_ALLOWED_CT_PREFIXES = [
    "text/",
    "application/json",
    "application/javascript",
    "application/x-javascript",
]

_JS_KEY_PATTERNS = [
    ("AWS", r"AKIA[0-9A-Z]{16}"),
    ("GoogleAPI", r"AIza[0-9A-Za-z\-_]{35}"),
    ("Mapbox", r"sk\.[0-9a-zA-Z]{60,}"),
    ("StripePub", r"pk_(test|live)_[0-9a-zA-Z]{24,}"),
    ("SentryDSN", r"https://[0-9a-zA-Z]+@o\d+\.ingest\.sentry\.io/\d+"),
    ("Algolia", r"[A-Z0-9]{32}"),
]

_JS_URL_RE = re.compile(
    r"""(?ix)
    (?:
        fetch\s*\(\s*['"]([^'"]+)['"]\s*\) |
        ajax\s*\(\s*['"]([^'"]+)['"]\s*\) |
        xhr\.open\s*\(\s*['"]\w+['"]\s*,\s*['"]([^'"]+)['"] |
        url\s*:\s*['"]([^'"]+)['"] |
        new\s+EventSource\s*\(\s*['"]([^'"]+)['"]\s*\) |
        new\s+WebSocket\s*\(\s*['"]([^'"]+)['"]\s*\))
    """
)
_WS_ABS_RE = re.compile(r'(?i)\bwss?://[^\s\'"<>]+')
_CSS_IMPORT_RE = re.compile(r'@import\s+url\(([^)]+)\)', re.I)


# ============================================================================
# UTILITIES
# ============================================================================

def _mask_secret(val: str) -> str:
    return (val[:6] + "…" + val[-4:]) if isinstance(val, str) and len(val) > 12 else val

def _should_skip_by_ext(url: str) -> bool:
    path = (urlsplit(url).path or "").lower()
    return any(path.endswith(ext) for ext in _DISALLOWED_EXTS)

def _normalize_href(base: str, href: str) -> str:
    url = urljoin(base, (href or '').strip())
    url, _ = urldefrag(url)
    return url

def _same_host(a: str, b: str) -> bool:
    an = (urlparse(a).netloc or "").lower()
    bn = (urlparse(b).netloc or "").lower()
    return bool(an) and an == bn

def _strip_fragment(u: str) -> str:
    s = (u or "")
    i = s.find("#")
    return s if i < 0 else s[:i]

# ============================================================================
# LRU CACHE & FETCHER
# ============================================================================

class _LRUCache:
    def __init__(self, max_entries: int = 512, ttl_seconds: int = 900):
        self.template_counts: Dict[str, int] = {}
        self.max = int(max_entries)
        self.ttl = int(ttl_seconds)
        self._data: OrderedDict[str, tuple[float, dict]] = OrderedDict()
        self._lock = threading.RLock()

    def get(self, key: str):
        now = time.time()
        with self._lock:
            ent = self._data.get(key)
            if not ent:
                return None
            ts, val = ent
            if self.ttl > 0 and now - ts > self.ttl:
                if key in self._data:
                    del self._data[key]
                return None
            self._data.move_to_end(key, last=True)
            return val

    def put(self, key: str, value: dict):
        with self._lock:
            self._data[key] = (time.time(), value)
            self._data.move_to_end(key, last=True)
            while len(self._data) > self.max:
                self._data.popitem(last=False)

_fetch_cache = _LRUCache(_CACHE_MAX, _CACHE_TTL)

def _fetch_resp(session, url: str, timeout: int = 10):
    if _should_skip_by_ext(url):
        counters_inc("skipped_by_extension", 1)
        return None

    ckey = f"resp::{url}"
    cached = _fetch_cache.get(ckey)
    if cached is not None:
        counters_inc("cache_hits", 1)
        class _Fake: pass
        fake = _Fake()
        fake.status_code = cached.get("status", 0)
        fake.headers = dict(cached.get("headers", {}))
        fake.text = cached.get("text", "")
        fake.content = cached.get("content", b"")
        fake.url = url
        fake.ok = bool(fake.status_code) and fake.status_code < 400
        return fake

    counters_inc("cache_misses", 1)

    try:
        hr = session.head(url, timeout=min(timeout, 8), allow_redirects=True, verify=getattr(session, "verify", True))
        clen = int(hr.headers.get("Content-Length", "0") or 0)
        if 200 <= getattr(hr, "status_code", 0) < 400 and clen and clen > _MAX_BYTES:
            counters_inc("skipped_by_size", 1)
            add_result("http_skipped", {"url": url, "method": "GET", "reason": "too_large(head)"})
            return None
    except Exception as e:
        add_result("http_skipped", {"url": url, "method": "HEAD", "reason": "head_error", "error": str(e)[:120]})

    try:
        r = session.get(url, timeout=timeout, allow_redirects=True, verify=verify_for_phase(session, 'discovery', url), stream=True)
    except Exception as e:
        add_result("http_skipped", {"url": url, "method": "GET", "reason": "get_error", "error": str(e)[:120]})
        return None

    buf = bytearray()
    limit = _MAX_BYTES
    for chunk in r.iter_content(chunk_size=65536):
        if not chunk: break
        if len(buf) + len(chunk) > limit:
            counters_inc("skipped_by_size", 1)
            add_result("http_skipped", {"url": url, "method": "GET", "reason": "too_large(stream)"})
            r.close()
            return None
        buf.extend(chunk)

    encoding = r.encoding or "utf-8"
    text = bytes(buf).decode(encoding, "ignore")
    _fetch_cache.put(ckey, {
        "status": r.status_code,
        "headers": dict(r.headers or {}),
        "text": text,
        "content": bytes(buf),
    })
    counters_add_bytes(len(buf))
    r._content = bytes(buf)
    if not r.encoding: r.encoding = "utf-8"
    return r

def _fetch_text(session, url: str, timeout=10) -> tuple[int, str, dict]:
    r = _fetch_resp(session, url, timeout)
    if not r:
        return 0, "", {}
    return r.status_code, r.text, r.headers


# ============================================================================
# CRAWLER CONFIG
# ============================================================================

@dataclass
class CrawlerConfig:
    # Basic Limits
    max_depth: int = 4
    max_pages: int = 1000
    timeout_http: int = 12
    fingerprint_head_count: int = 20
    strict_same_origin: bool = True
    ignore_robots: bool = False

    # Hardening
    unauthenticated: bool = False
    guardrails_enabled: bool = True

    # Policy
    allow_paths: Optional[Set[str]] = None
    deny_paths: Optional[Set[str]] = None
    blocklist_urls: Optional[Set[str]] = None
    allow_regex: Optional[List[str]] = None
    deny_regex: Optional[List[str]] = None

    # External Tools
    ffuf_wordlist: Optional[str] = None
    ferox_wordlist: Optional[str] = None

    # Browser / Dynamic
    browser_js_discovery: bool = False
    browser_max_pages: int = 200
    browser_timeout_ms: int = 15000
    browser_record_dir: Optional[str] = None
    browser_prefer: str = "playwright"  # "playwright" | "uc"

    # Persistence
    record_dir: str | None = None
    resume: bool = True
    checkpoint_every_pages: int = 15
    checkpoint_ttl_seconds: int = 86400

    _allow_re_compiled: List[Pattern[str]] = field(default_factory=list, init=False, repr=False)
    _deny_re_compiled: List[Pattern[str]] = field(default_factory=list, init=False, repr=False)

    def compile_regexes(self) -> None:
        self._allow_re_compiled = []
        self._deny_re_compiled = []
        for pat in (self.allow_regex or []):
            if p := (pat or "").strip():
                self._allow_re_compiled.append(re.compile(p, re.IGNORECASE))
        for pat in (self.deny_regex or []):
            if p := (pat or "").strip():
                self._deny_re_compiled.append(re.compile(p, re.IGNORECASE))


# ============================================================================
# WEBCRAWLER CLASS
# ============================================================================

class WebCrawler:
    def __init__(
        self,
        session: requests.Session,
        start_url: str,
        driver=None,
        config: Optional["CrawlerConfig"] = None,
        debug: bool = False,
    ):
        self.sess = session
        self.root = canonicalize_url(start_url)
        self.driver = driver
        self.cfg = config or CrawlerConfig()
        
        # ENV overrides
        if os.getenv("CRAWL_IGNORE_ROBOTS", "0").lower() in {"1", "true", "yes"}:
            self.cfg.ignore_robots = True
        if os.getenv("CRAWL_STRICT_ORIGIN", "1").lower() in {"0", "false", "no"}:
            self.cfg.strict_same_origin = False
        if os.getenv("CRAWL_BROWSER_DISCOVERY", "").lower() in {"1", "true", "yes"}:
            self.cfg.browser_js_discovery = True
        
        self.cfg.compile_regexes()
        self.debug = debug
        
        self.results: Dict[str, Any] = {
            "endpoint_counts": {},
            "crawl_map": {},
            "endpoints": set(),
            "api_endpoints": set(),
            "assets": set(),
            "forms_meta": [],
            "js_endpoints": set(),
            "sse_endpoints": set(),
            "ws_endpoints": set(),
            "endpoint_fingerprints": [],
            "param_candidates": set(),
            "json_keys": set(),
            "graphql_hints": set(),
            "secrets": [],
        }

    def _checkpoint_dir(self) -> Path:
        root_dir = (self.cfg.record_dir or (getattr(self.cfg, "browser_record_dir", None)) or "records")
        p = Path(root_dir) / "crawl_state"
        p.mkdir(parents=True, exist_ok=True)
        return p

    def _checkpoint_file(self) -> Path:
        h = hashlib.sha256(self.root.encode("utf-8")).hexdigest()[:12]
        host = (urlparse(self.root).hostname or "target").replace(":", "_")
        return self._checkpoint_dir() / f"{host}_{h}.json"

    def _save_checkpoint(self, *, queue, seen_set, queued_set, pages_crawled: int) -> None:
        try:
            data = {
                "version": 1,
                "root": self.root,
                "ts": int(time.time()),
                "cfg": {
                    "strict_same_origin": bool(self.cfg.strict_same_origin),
                },
                "queue": list(queue),
                "seen": list(seen_set),
                "queued": list(queued_set),
                "pages_crawled": int(pages_crawled),
            }
            fp = self._checkpoint_file()
            fp.parent.mkdir(parents=True, exist_ok=True)
            fp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        except Exception as e:
            logger.warning(f"Checkpoint save failed: {e}")

    def _load_checkpoint(self):
        try:
            fp = self._checkpoint_file()
            if not fp.exists(): return None
            data = json.loads(fp.read_text(encoding="utf-8"))
            if data.get("root") != self.root: return None
            return {
                "queue": [(u, int(d)) for (u, d) in (data.get("queue") or [])],
                "seen": set(data.get("seen") or []),
                "queued": set(data.get("queued") or []),
                "pages_crawled": int(data.get("pages_crawled") or 0),
            }
        except Exception:
            return None

    def start(self) -> Dict[str, Any]:
        """Main crawl loop."""
        queue: Deque[Tuple[str, int]] = deque()
        queue.append((self.root, 0))
        seen: Set[str] = set()
        queued: Set[str] = {self.root}
        pages_crawled = 0
        
        # Resume?
        if self.cfg.resume:
            cp = self._load_checkpoint()
            if cp:
                queue = deque(cp["queue"])
                seen = cp["seen"]
                queued = cp["queued"]
                pages_crawled = cp["pages_crawled"]
                if self.debug: print(f"[Crawler] Resumed from checkpoint: {pages_crawled} pages.")

        # Robots & Sitemap
        if not self.cfg.ignore_robots:
            seeds, sitemaps = _parse_robots(self.sess, self.root)
            for sm in sitemaps:
                for u in _parse_sitemap_xml(self.sess, sm, self.root):
                    if u not in queued:
                        queued.add(u)
                        queue.append((u, 0))
            for s in seeds:
                if s not in queued:
                    queued.add(s)
                    queue.append((s, 0))
        
        while queue:
            if pages_crawled >= self.cfg.max_pages:
                break
            
            url, depth = queue.popleft()
            if url in seen: continue
            seen.add(url)
            
            # Policy Check
            if not self._allowed_by_policy(url):
                continue

            # Fetch
            try:
                self._process_url(url, depth, queue, queued)
                pages_crawled += 1
                
                # Checkpoint
                if pages_crawled % self.cfg.checkpoint_every_pages == 0:
                    self._save_checkpoint(queue=queue, seen_set=seen, queued_set=queued, pages_crawled=pages_crawled)
                    
            except Exception as e:
                logger.debug(f"Error processing {url}: {e}")

        # Browser Discovery (Optional)
        if self.cfg.browser_js_discovery:
            self._run_browser_discovery()

        self._finalize_results(seen)
        return self.results

    def _allowed_by_policy(self, u: str) -> bool:
        # Simple policy checks: domain, max depth, hardening headers
        if self.cfg.strict_same_origin and not same_origin(u, self.root):
            return False
        
        p = urlparse(u).path or "/"
        if self.cfg.deny_paths and any(p.startswith(d) for d in self.cfg.deny_paths):
            return False
        if self.cfg.unauthenticated and self._is_dangerous_url(u):
            return False
            
        return True

    def _is_dangerous_url(self, u: str) -> bool:
        for rx in SEC_DEFAULT_DENY_REGEX:
            if re.search(rx, u): return True
        return False

    def _process_url(self, url: str, depth: int, queue: Deque, queued: Set[str]):
        resp = _fetch_resp(self.sess, url, timeout=self.cfg.timeout_http)
        if not resp: return
        
        # Harvest content
        self._analyze_content(url, resp)
        
        # Extract links if depth < max
        if depth < self.cfg.max_depth:
            links = self._extract_links(resp.text, url)
            for link in links:
                if link not in queued:
                    queued.add(link)
                    queue.append((link, depth + 1))

    def _extract_links(self, html: str, base_url: str) -> Set[str]:
        out = set()
        if not html: return out
        
        if BeautifulSoup:
            soup = BeautifulSoup(html, "html.parser")
            for a in soup.find_all("a", href=True):
                href = a.get("href")
                if href:
                    full = urljoin(base_url, href)
                    out.add(_strip_fragment(full))
            for f in soup.find_all("form", action=True):
                 act = f.get("action")
                 if act:
                     full = urljoin(base_url, act)
                     out.add(_strip_fragment(full))
        else:
            # Regex fallback
            for m in re.finditer(r'href=["\']([^"\']+)["\']', html, re.I):
                out.add(_strip_fragment(urljoin(base_url, m.group(1))))
        return out

    def _analyze_content(self, url: str, resp):
        # Basic collection
        self.results["endpoints"].add(url)
        content_type = (resp.headers.get("Content-Type") or "").lower()
        
        # JS Keys
        if "javascript" in content_type or url.endswith(".js"):
            keys = harvest_js_keys(self.sess, None, [url])
            if keys:
                self.results["secrets"].extend(keys)
                
        # Forms
        if BeautifulSoup and "html" in content_type:
            soup = BeautifulSoup(resp.text, "html.parser")
            forms = soup.find_all("form")
            if forms:
                self.results["forms_meta"].append({
                    "url": url,
                    "count": len(forms),
                    "forms": [{"action": f.get("action"), "method": f.get("method")} for f in forms]
                })

    def _run_browser_discovery(self):
        if self.debug: print("[Crawler] Starting browser-based discovery...")
        d_eps, d_arts = discover_dynamic_endpoints(
            start_url=self.root, 
            headless=True,
            timeout_ms=self.cfg.browser_timeout_ms,
            max_pages=self.cfg.browser_max_pages,
            prefer=self.cfg.browser_prefer
        )
        for ep in d_eps:
             u = ep.get("url")
             if u: self.results["endpoints"].add(u)
             if ep.get("src") == "ws": self.results["ws_endpoints"].add(u)

    def _finalize_results(self, seen_urls):
        self.results["crawl_map"]["count"] = len(seen_urls)
        self.results["endpoints"] = list(self.results["endpoints"])
        self.results["ws_endpoints"] = list(self.results["ws_endpoints"])
        self.results["secrets"] = list({(s["value"], s["provider"]): s for s in self.results["secrets"]}.values())


# ============================================================================
# HELPER FUNCTIONS (Legacy Support)
# ============================================================================

def _parse_robots(session, base_url: str):
    seeds, sitemaps = [], []
    rob = urljoin(base_url.rstrip("/") + "/", "robots.txt")
    r = _fetch_resp(session, rob)
    if not r or r.status_code >= 500:
        return seeds, sitemaps
    for line in (r.text or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#"): continue
        if line.lower().startswith("sitemap:"):
            sm = line.split(":", 1)[1].strip()
            if sm and same_origin(base_url, sm): sitemaps.append(sm)
        if line.lower().startswith("allow:"):
            path = line.split(":", 1)[1].strip() or "/"
            if path and path != "/":
                seeds.append(urljoin(base_url.rstrip("/") + "/", path.lstrip("/")))
    return list(dict.fromkeys(seeds)), list(dict.fromkeys(sitemaps))

def _parse_sitemap_xml(session, url: str, base_url: str, limit: int = 500):
    r = _fetch_resp(session, url, timeout=12)
    if not r or r.status_code >= 500: return []
    content = r.content or b""
    if not content.lstrip().startswith(b"<"): return []
    
    try:
        root = ET.fromstring(content)
        ns = root.tag.split("}", 1)[0].strip("{") if root.tag.startswith("{") else ""
        loc_tag = f"{{{ns}}}loc" if ns else "loc"
        urls = []
        for loc in root.iter(loc_tag):
            u = (loc.text or "").strip()
            if u and same_origin(u, base_url):
                urls.append(u)
                if len(urls) >= limit: break
        return urls
    except Exception:
        return []

def harvest_js_keys(session, cfg: dict, urls: list[str], source_tag: str | None = None) -> list[dict]:
    out = []
    seen = set()
    for u in (urls or []):
        if not u or u in seen: continue
        seen.add(u)
        sc, txt, _ = _fetch_text(session, u)
        if not sc or sc >= 400 or len(txt) > 1_000_000: continue
        
        for name, pattern in _JS_KEY_PATTERNS:
            for m in re.finditer(pattern, txt):
                val = m.group(0)
                out.append({"provider": name, "value": _mask_secret(val), "source": u})
    return out


# ============================================================================
# BROWSER CRAWLER / DYNAMIC DISCOVERY
# ============================================================================

def _looks_numeric(seg: str) -> bool:
    s = (seg or "").strip().strip("/")
    return s.isdigit() and len(s) >= _NUMERIC_ID_MINLEN

def _exceeds_page_param(u: str) -> bool:
    q = parse_qs(urlparse(u).query or "")
    for k in ("page","sayfa","p"):
        v = q.get(k)
        if v:
            raw = str(v[-1])
            if raw.isdigit() and int(raw) > _WS_MAX_PAGE_PARAM:
                return True
    return False

def _episode_like(u: str) -> bool:
    path = (urlparse(u).path or "").lower()
    return any(k in path for k in _EPISODE_KEYS)

def _bucket_key(u: str) -> str:
    p = urlparse(u)
    parts = [s for s in (p.path or "/").split("/") if s]
    head = "/".join(parts[:2]) if parts else "/"
    return f"{p.hostname or ''}:{head}"

def make_queue_governor(start_url: str):
    buckets: dict[str,int] = {}
    def _allow(u: str) -> bool:
        if not u.startswith(("http://","https://","ws://","wss://")): return False
        comp = u.replace("wss://","https://").replace("ws://","http://")
        if not _same_host(comp, start_url): return False
        pu = urlparse(u)
        if _DENY_RE.search(pu.path or ""): return False
        if _exceeds_page_param(u): return False
        parts = [s for s in (pu.path or "/").split("/") if s]
        leaf = parts[-1] if parts else ""
        if _episode_like(u) or _looks_numeric(leaf):
            key = _bucket_key(u)
            cur = buckets.get(key, 0)
            if cur >= _WS_PER_BUCKET_MAX: return False
            buckets[key] = cur + 1
        return True
    return _allow

class _BrowserDiscoveryStrategy:
    def discover(self, start_url: str, headless: bool, timeout_ms: int, max_pages: int, record_dir: Optional[str] = None, return_artifacts: bool = False):
        raise NotImplementedError

class _PlaywrightStrategy(_BrowserDiscoveryStrategy):
    def discover(self, start_url, headless, timeout_ms, max_pages, record_dir=None, return_artifacts=False):
        endpoints = []
        artifacts = {}
        try:
            from playwright.sync_api import sync_playwright
            visited, queue = set(), []
            allow = make_queue_governor(start_url)
            
            def _enqueue(u):
                u = _strip_fragment(u or "")
                if u and u not in visited and len(visited) < max_pages and allow(u):
                    queue.append(u)

            with sync_playwright() as p:
                logger.info("[Playwright] Launching browser...")
                browser = p.chromium.launch(headless=headless, args=['--disable-webgl', '--disable-extensions'])
                ctx = browser.new_context(ignore_https_errors=True)
                page = ctx.new_page()
                
                # Setup events
                def on_request(req):
                    u = _strip_fragment(req.url)
                    if allow(u):
                        endpoints.append({"url": u, "method": req.method, "src": "xhr"})
                page.on("request", on_request)
                
                _enqueue(start_url)
                while queue and len(visited) < max_pages:
                    target = queue.pop(0)
                    if target in visited: continue
                    visited.add(target)
                    try:
                        page.goto(target, timeout=timeout_ms)
                        page.wait_for_load_state("domcontentloaded", timeout=5000)
                        
                        # Collect links
                        for a in page.query_selector_all("a[href]"):
                            href = a.get_attribute("href")
                            if href:
                                full = urljoin(target, href)
                                _enqueue(full)
                    except Exception as e:
                        logger.debug(f"[Playwright] Page error {target}: {e}")
                        pass
                browser.close()
        except Exception as e:
            logger.error(f"[Playwright] Strategy failed: {e}", exc_info=True)
            
        return endpoints, (artifacts if return_artifacts else None)

class _UCStrategy(_BrowserDiscoveryStrategy):
    def discover(self, start_url, headless, timeout_ms, max_pages, record_dir=None, return_artifacts=False):
        endpoints = []
        if _iu.find_spec("undetected_chromedriver") is None:
            logger.warning("[UC] undetected_chromedriver module not found.")
            return [], None
        
        driver = None
        tmp_profile = None
        try:
            import undetected_chromedriver as uc
            options = uc.ChromeOptions()
            options.add_argument("--headless=new") if headless else None
            options.add_argument("--no-sandbox")
            options.add_argument("--disable-gpu")
            options.add_argument("--disable-dev-shm-usage")
            options.add_argument("--disable-popup-blocking")
            
            # Use temp profile to avoid locking main profile
            tmp_profile = tempfile.mkdtemp(prefix="ws_uc_profile_")
            options.add_argument(f"--user-data-dir={tmp_profile}")

            # Check for local driver
            driver_path = None
            # Prioritize drivers/chromedriver.exe in project root
            local_driver = Path(__file__).parent.parent / "drivers" / "chromedriver.exe"
            if local_driver.exists():
                driver_path = str(local_driver)
                logger.info(f"[UC] Using local driver: {driver_path}")
            
            driver = uc.Chrome(options=options, driver_executable_path=driver_path) if driver_path else uc.Chrome(options=options)
            driver.set_page_load_timeout(timeout_ms/1000)
            
            queue, visited = [start_url], set()
            while queue and len(visited) < max_pages:
                target = queue.pop(0)
                if target in visited: continue
                visited.add(target)
                try:
                    driver.get(target)
                    time.sleep(1)
                    
                    # Capture nav 
                    if _same_host(target, start_url):
                        endpoints.append({"url": target, "method": "GET", "src": "nav"})
                    
                    for a in driver.find_elements("css selector", "a[href]"):
                        href = a.get_attribute("href")
                        if href:
                            full = urljoin(target, href)
                            # Only queue internal links
                            if _same_host(full, start_url): 
                                queue.append(full)
                            # But record all found links if robust
                            endpoints.append({"url": full, "method": "GET", "src": "nav"})
                            
                except Exception as e:
                    logger.debug(f"[UC] Page visit error {target}: {e}")
                    pass
            
        except Exception as e:
             logger.error(f"[UC] Strategy failed: {e}", exc_info=True)
        finally:
            if driver:
                try:
                    driver.quit()
                except Exception:
                    pass
            if tmp_profile and os.path.exists(tmp_profile):
                try:
                    shutil.rmtree(tmp_profile, ignore_errors=True)
                except Exception:
                    pass

        return endpoints, None

def discover_dynamic_endpoints(
    start_url: str,
    trace_id: str | None = None,
    headless: bool = True,
    timeout_ms: int = 15000,
    max_pages: int = 200,
    record_dir: Optional[str] = None,
    prefer: str = "playwright",
    return_artifacts: bool = True,
) -> Tuple[List[Dict[str, Any]], Optional[Dict[str, Any]]]:
    strategies = [_PlaywrightStrategy(), _UCStrategy()] if prefer == "playwright" else [_UCStrategy(), _PlaywrightStrategy()]
    for strat in strategies:
        eps, art = strat.discover(start_url, headless, timeout_ms, max_pages, record_dir, return_artifacts)
        if eps: return eps, art
    return [], {}
