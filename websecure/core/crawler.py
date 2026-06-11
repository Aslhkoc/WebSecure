"""
websecure.core.crawler
-----------------------
Tier-1 HTTP crawler + advanced endpoint discovery toolkit.

Components (SOLID — one responsibility per class):
  EndpointMeta          — discovered endpoint container
  CrawlResult           — unified output from all crawler components
  CrawlerBase           — abstract interface (LSP-safe)
  HTTPCrawler           — fast requests-based BFS crawl with link/form/JS extraction
  OpenAPIImporter       — Swagger / OpenAPI 2.x & 3.x schema -> EndpointMeta list
  GraphQLSchemaImporter — GraphQL introspection -> query / mutation / subscription map
  GRPCProber            — gRPC reflection API -> service / method list
  APIVersionScanner     — /v1/ /v2/ /api/ /rest/ brute-force discovery
  ParameterMiner        — arjun-style hidden GET / POST param differential analysis
  FormMutationFuzzer    — select / checkbox / radio value combination generator
  SitemapGenerator      — structured crawl output (JSON / text / XML)
  CrawlerOrchestrator   — coordinates all components, returns unified CrawlResult
"""
from __future__ import annotations

import itertools
import json
import logging
import re
import socket
import ssl
import xml.etree.ElementTree as ET
from abc import ABC, abstractmethod
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Dict, Generator, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse

_logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Data containers
# ---------------------------------------------------------------------------

@dataclass
class EndpointMeta:
    """Single discovered endpoint with method, params, and source annotation."""
    url: str
    method: str = "GET"
    params: List[str] = field(default_factory=list)
    source: str = ""


@dataclass
class CrawlResult:
    """Unified output from all crawler components."""
    endpoints: List[str] = field(default_factory=list)
    api_endpoints: List[EndpointMeta] = field(default_factory=list)
    forms: List[Dict[str, Any]] = field(default_factory=list)
    js_files: List[str] = field(default_factory=list)
    discovered_params: Dict[str, List[str]] = field(default_factory=dict)
    tech_stack: List[str] = field(default_factory=list)
    sitemap: Dict[str, Any] = field(default_factory=dict)
    grpc_services: List[Dict[str, Any]] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Abstract base
# ---------------------------------------------------------------------------

class CrawlerBase(ABC):
    """Abstract crawler interface — all concrete crawlers implement this."""

    @abstractmethod
    def crawl(self, target: str, session: Any) -> CrawlResult: ...


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

_SKIP_EXT: Set[str] = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
    ".woff", ".woff2", ".ttf", ".eot", ".pdf", ".zip",
    ".tar", ".gz", ".mp4", ".mp3", ".webp", ".avif", ".css",
}

_LINK_RE = re.compile(
    r'''(?:href|src|action|data-url|data-href)\s*=\s*['"]([^'"#?\s]{3,})''', re.I
)
_JS_API_RE = re.compile(
    r'''(?:fetch|axios\.(?:get|post|put|patch|delete)|(?:\$|jQuery)\.(?:get|post|ajax))\s*\(\s*['"`]([^'"`\s]{4,})''',
    re.I,
)
_SCRIPT_SRC_RE = re.compile(r'''<script[^>]+src=['"]([^'"]+\.js[^'"]*)['"]''', re.I)
_FORM_RE = re.compile(r'<form(.*?)>(.*?)</form>', re.I | re.S)
_INPUT_RE = re.compile(
    r'<(?:input|textarea|select)[^>]*name=["\']([^"\']+)["\'][^>]*>', re.I
)

# URL segment classifiers for template deduplication
_SEG_ID_RE = re.compile(r'^\d+$')
_SEG_UUID_RE = re.compile(
    r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', re.I
)
_SEG_HEX_RE = re.compile(r'^[0-9a-f]{16,}$', re.I)
_SEG_SLUG_RE = re.compile(r'^[a-z0-9][a-z0-9\-]{3,}[a-z0-9]$', re.I)
# Kullanıcı adı / kanal / profil tarzı tek-kelime segment (Kick/Twitch/IG vb.):
# küçük harf + rakam + alt çizgi/nokta, 3-30 karakter, tire YOK (slug değil).
_SEG_HANDLE_RE = re.compile(r'^[a-z0-9][a-z0-9_.]{2,29}$', re.I)

# Bunlar GERÇEK uygulama route'larıdır — {handle}'a indirgenmemeli (yoksa
# /login ve /about aynı template'e düşüp biri atlanır). Statik route allowlist'i.
_STATIC_ROUTES = frozenset({
    "login", "logout", "signin", "signup", "register", "kaydol", "giris",
    "auth", "oauth", "account", "accounts", "settings", "profile", "user",
    "users", "home", "about", "help", "support", "faq", "contact", "terms",
    "privacy", "legal", "careers", "jobs", "press", "blog", "news", "search",
    "ara", "explore", "browse", "gozat", "discover", "category", "categories",
    "tag", "tags", "api", "graphql", "admin", "dashboard", "cart", "checkout",
    "payment", "billing", "orders", "wishlist", "favorites", "following",
    "followers", "notifications", "messages", "inbox", "feed", "trending",
    "popular", "live", "videos", "clips", "vods", "streams", "channels",
    "directory", "store", "shop", "market", "products", "product", "download",
    "downloads", "docs", "documentation", "status", "health", "static",
    "assets", "img", "images", "css", "js", "media", "uploads", "files",
    "en", "tr", "de", "fr", "es", "index", "main", "app", "web", "www",
})


def _url_template(url: str) -> str:
    """Normalize dynamic URL path segments to a canonical template string.

    Amaç: Kick/Twitch/e-ticaret gibi sitelerde her kullanıcı/ürün ayrı URL
    olduğundan crawler her birine giriyordu. Dinamik segmentleri ({id}/{uuid}/
    {hex}/{slug}/{handle}) tek template'e indirger → max_samples_per_template ile
    "her yayıncıya/ürüne girme" sorununu kökten çözer. Statik route'lar korunur.
    """
    from urllib.parse import parse_qs
    parsed = urlparse(url)
    parts = [p for p in parsed.path.split("/") if p]
    norm: List[str] = []
    for part in parts:
        low = part.lower()
        if low in _STATIC_ROUTES:
            norm.append(low)  # gerçek route — ASLA templateleme (sıra: önce bu)
        elif _SEG_UUID_RE.match(part):
            norm.append("{uuid}")
        elif _SEG_ID_RE.match(part):
            norm.append("{id}")
        elif _SEG_HEX_RE.match(part):
            norm.append("{hex}")
        elif _SEG_SLUG_RE.match(part) and "-" in part:
            # tireli çok-kelimeli segment = ürün/makale/başlık slug'ı (dinamik)
            norm.append("{slug}")
        elif _SEG_HANDLE_RE.match(part):
            # kullanıcı adı / kanal / profil tarzı tek-kelime dinamik segment
            norm.append("{handle}")
        else:
            norm.append(part)
    if parsed.query:
        try:
            keys = sorted(parse_qs(parsed.query, keep_blank_values=True).keys())
            return f"{parsed.netloc}/{'/'.join(norm)}?{'&'.join(keys)}"
        except Exception as _fix_e:
            _logger.debug(f"[core.crawler] {type(_fix_e).__name__}: {_fix_e!r}")
    return f"{parsed.netloc}/{'/'.join(norm)}"


def _chunks(lst: List[Any], n: int) -> Generator[List[Any], None, None]:
    for i in range(0, len(lst), n):
        yield lst[i:i + n]


# ---------------------------------------------------------------------------
# HTTPCrawler — Tier-1, no browser
# ---------------------------------------------------------------------------

class HTTPCrawler(CrawlerBase):
    """
    Fast requests-based BFS crawler.
    Extracts links, forms, JS API call hints, and script file URLs.
    No JavaScript rendering — use BrowserCrawler for SPAs.
    """

    def __init__(
        self,
        max_pages: int = 200,
        timeout: int = 10,
        max_samples_per_template: int = 3,
        max_unique_templates: int = 50,
    ):
        self.max_pages = max_pages
        self.timeout = timeout
        self.max_samples_per_template = max_samples_per_template
        self.max_unique_templates = max_unique_templates

    def crawl(self, target: str, session: Any) -> CrawlResult:
        result = CrawlResult()
        base_netloc = urlparse(target).netloc
        queue: deque[str] = deque([target])
        visited: Set[str] = set()
        queued: Set[str] = {target}
        template_counts: Dict[str, int] = {}

        while queue and len(visited) < self.max_pages:
            url = queue.popleft()
            queued.discard(url)
            if url in visited:
                continue

            # Skip if this URL's template is already saturated
            tmpl = _url_template(url)
            count = template_counts.get(tmpl, 0)
            if count >= self.max_samples_per_template:
                continue
            if len(template_counts) >= self.max_unique_templates and tmpl not in template_counts:
                continue

            visited.add(url)
            template_counts[tmpl] = count + 1

            try:
                resp = session.get(url, timeout=self.timeout, allow_redirects=True)
            except Exception as exc:
                _logger.debug(f"[HTTPCrawler] {url}: {exc}")
                continue

            # Only include reachable, non-error pages in the result
            if resp.status_code >= 400:
                continue

            ct = resp.headers.get("Content-Type", "")
            if not any(t in ct for t in ("html", "text", "javascript")):
                continue

            if url not in result.endpoints:
                result.endpoints.append(url)

            html = resp.text
            self._extract_links(html, url, base_netloc, queue, queued, visited, template_counts, result)
            self._extract_api_calls(html, url, base_netloc, result)
            self._extract_js_files(html, url, result)
            self._extract_forms(html, url, result)

        result.endpoints = list(dict.fromkeys(result.endpoints))
        _logger.info(
            f"[HTTPCrawler] {len(result.endpoints)} pages, "
            f"{len(result.api_endpoints)} API hints, "
            f"{len(result.forms)} forms, "
            f"{len(template_counts)} unique URL templates"
        )
        return result

    def _extract_links(
        self, html: str, base_url: str, netloc: str,
        queue: deque, queued: Set[str], visited: Set[str],
        template_counts: Dict[str, int], result: CrawlResult,
    ) -> None:
        for m in _LINK_RE.finditer(html):
            href = m.group(1)
            full = urljoin(base_url, href)
            parsed = urlparse(full)
            if parsed.netloc != netloc:
                continue
            raw_path = parsed.path
            ext = ("." + raw_path.rsplit(".", 1)[-1].lower()
                   if "." in raw_path.rsplit("/", 1)[-1] else "")
            if ext in _SKIP_EXT:
                continue
            if full in visited or full in queued:
                continue
            # Pre-check template saturation before enqueuing
            tmpl = _url_template(full)
            if template_counts.get(tmpl, 0) >= self.max_samples_per_template:
                continue
            if len(template_counts) >= self.max_unique_templates and tmpl not in template_counts:
                continue
            queue.append(full)
            queued.add(full)

    def _extract_api_calls(
        self, html: str, base_url: str, netloc: str, result: CrawlResult
    ) -> None:
        for m in _JS_API_RE.finditer(html):
            path = m.group(1)
            full = urljoin(base_url, path) if not path.startswith("http") else path
            if urlparse(full).netloc == netloc:
                meta = EndpointMeta(url=full, method="GET", source="html_js_api")
                result.api_endpoints.append(meta)

    def _extract_js_files(self, html: str, base_url: str, result: CrawlResult) -> None:
        for m in _SCRIPT_SRC_RE.finditer(html):
            js_url = urljoin(base_url, m.group(1))
            if js_url not in result.js_files:
                result.js_files.append(js_url)

    def _extract_forms(self, html: str, base_url: str, result: CrawlResult) -> None:
        for fm in _FORM_RE.finditer(html):
            attrs, body = fm.group(1), fm.group(2)
            action_m = re.search(r'action=["\']([^"\']*)["\']', attrs, re.I)
            method_m = re.search(r'method=["\']([^"\']*)["\']', attrs, re.I)
            action = urljoin(base_url, action_m.group(1)) if action_m else base_url
            method = method_m.group(1).upper() if method_m else "GET"
            inputs = [{"name": inp.group(1), "type": "text"}
                      for inp in _INPUT_RE.finditer(body)]
            if inputs:
                try:
                    from websecure.core.analysis import infer_form_method as _ifm
                    method = _ifm(action, inputs, method)
                except Exception:
                    pass
                result.forms.append({
                    "action": action,
                    "method": method,
                    "inputs": inputs,
                    "source_url": base_url,
                })


# ---------------------------------------------------------------------------
# OpenAPIImporter
# ---------------------------------------------------------------------------

class OpenAPIImporter:
    """
    Discovers OpenAPI 2.x (Swagger) and 3.x specifications at common paths.
    Converts all path + method combinations to EndpointMeta objects.
    """

    _PATHS: List[str] = [
        "/openapi.json", "/openapi.yaml",
        "/swagger.json", "/swagger.yaml",
        "/api-docs", "/api-docs/swagger.json",
        "/api/openapi.json", "/api/swagger.json",
        "/swagger/v1/swagger.json", "/swagger/v2/swagger.json",
        "/v1/openapi.json", "/v2/openapi.json", "/v3/openapi.json",
        "/docs/openapi.json", "/.well-known/openapi.json",
        "/api/v1/openapi.json", "/api/v2/openapi.json",
        "/api/v1/swagger.json", "/api/v2/swagger.json",
    ]
    _HTTP_METHODS: Set[str] = {"get", "post", "put", "patch", "delete", "options", "head"}

    def discover(self, base_url: str, session: Any) -> Optional[Dict[str, Any]]:
        """Probe common paths to find an OpenAPI / Swagger spec. Returns parsed dict or None."""
        base = base_url.rstrip("/")
        for path in self._PATHS:
            try:
                r = session.get(base + path, timeout=8)
                if r.status_code != 200:
                    continue
                ct = r.headers.get("Content-Type", "")
                if "yaml" in ct or path.endswith(".yaml"):
                    try:
                        import yaml
                        data = yaml.safe_load(r.text)
                    except Exception:
                        continue
                else:
                    try:
                        data = r.json()
                    except Exception:
                        continue
                if isinstance(data, dict) and "paths" in data:
                    _logger.info(f"[OpenAPIImporter] Spec found at {base + path}")
                    return data
            except Exception:
                continue
        return None

    def extract_endpoints(self, spec: Dict[str, Any], base_url: str) -> List[EndpointMeta]:
        """Parse OpenAPI spec into a flat list of EndpointMeta objects."""
        paths = spec.get("paths") or {}
        server_url = self._resolve_server(spec, base_url)
        out: List[EndpointMeta] = []

        for path, path_item in paths.items():
            if not isinstance(path_item, dict):
                continue
            full_url = server_url.rstrip("/") + path
            global_params = [
                p["name"] for p in path_item.get("parameters", [])
                if isinstance(p, dict) and "name" in p
            ]
            for method, op in path_item.items():
                if method.lower() not in self._HTTP_METHODS:
                    continue
                if not isinstance(op, dict):
                    continue
                op_params = [
                    p["name"] for p in op.get("parameters", [])
                    if isinstance(p, dict) and "name" in p
                ]
                params = list(dict.fromkeys(global_params + op_params))
                out.append(EndpointMeta(
                    url=full_url,
                    method=method.upper(),
                    params=params,
                    source="openapi",
                ))

        _logger.info(f"[OpenAPIImporter] {len(out)} endpoints extracted from spec")
        return out

    def run(self, base_url: str, session: Any) -> List[EndpointMeta]:
        spec = self.discover(base_url, session)
        return self.extract_endpoints(spec, base_url) if spec else []

    def _resolve_server(self, spec: Dict[str, Any], base_url: str) -> str:
        if "openapi" in spec:
            servers = spec.get("servers") or []
            if servers:
                url = servers[0].get("url", base_url)
                return url if url.startswith("http") else base_url.rstrip("/") + url
            return base_url
        host = spec.get("host", urlparse(base_url).netloc)
        base_path = spec.get("basePath", "/")
        schemes = spec.get("schemes") or ["https"]
        scheme = "https" if "https" in base_url else schemes[0]
        return f"{scheme}://{host}{base_path}"


# ---------------------------------------------------------------------------
# GraphQLSchemaImporter
# ---------------------------------------------------------------------------

class GraphQLSchemaImporter:
    """
    Runs GraphQL introspection and maps all query / mutation / subscription
    fields to virtual EndpointMeta objects for downstream scanning.
    """

    _INTROSPECTION: Dict[str, str] = {
        "query": (
            "{ __schema { "
            "  queryType { name fields { name args { name } } } "
            "  mutationType { name fields { name args { name } } } "
            "  subscriptionType { name fields { name args { name } } } "
            "} }"
        )
    }
    _PATHS: List[str] = ["/graphql", "/api/graphql", "/gql", "/v1/graphql", "/graph"]

    def run(self, base_url: str, session: Any) -> List[EndpointMeta]:
        for path in self._PATHS:
            url = base_url.rstrip("/") + path
            try:
                r = session.post(
                    url,
                    json=self._INTROSPECTION,
                    timeout=10,
                    headers={"Content-Type": "application/json"},
                )
                if r.status_code != 200:
                    continue
                schema = (r.json().get("data") or {}).get("__schema") or {}
                if not schema:
                    continue
                return self._parse_schema(schema, url)
            except Exception as exc:
                _logger.debug(f"[GraphQLSchemaImporter] {url}: {exc}")
        return []

    def _parse_schema(self, schema: Dict[str, Any], endpoint_url: str) -> List[EndpointMeta]:
        out: List[EndpointMeta] = []
        for root_key in ("queryType", "mutationType", "subscriptionType"):
            root = schema.get(root_key) or {}
            for f in root.get("fields") or []:
                name = f.get("name", "")
                args = [a.get("name", "") for a in (f.get("args") or [])]
                out.append(EndpointMeta(
                    url=endpoint_url,
                    method="POST",
                    params=args,
                    source=f"graphql_{root_key}:{name}",
                ))
        _logger.info(f"[GraphQLSchemaImporter] {len(out)} fields from {endpoint_url}")
        return out


# ---------------------------------------------------------------------------
# GRPCProber
# ---------------------------------------------------------------------------

class GRPCProber:
    """
    Probes gRPC reflection API to enumerate services and methods.
    Falls back to HTTP/2 ALPN detection when grpcio is unavailable.
    """

    _PORTS: List[int] = [50051, 9090, 8080, 443, 8443]

    def probe(self, host: str, ports: Optional[List[int]] = None) -> List[Dict[str, Any]]:
        for port in (ports or self._PORTS):
            result = self._try_reflection(host, port)
            if result:
                _logger.info(f"[GRPCProber] {len(result)} services at {host}:{port}")
                return result
        return []

    def _try_reflection(self, host: str, port: int) -> List[Dict[str, Any]]:
        try:
            import grpc
            from grpc_reflection.v1alpha import reflection_pb2, reflection_pb2_grpc

            creds = grpc.ssl_channel_credentials() if port in (443, 8443) else None
            channel = (
                grpc.secure_channel(f"{host}:{port}", creds)
                if creds else grpc.insecure_channel(f"{host}:{port}")
            )
            stub = reflection_pb2_grpc.ServerReflectionStub(channel)
            req = reflection_pb2.ServerReflectionRequest(list_services="")
            services: List[Dict[str, Any]] = []
            for resp in stub.ServerReflectionInfo(iter([req])):
                lr = getattr(resp, "list_services_response", None)
                for svc in (getattr(lr, "service", None) or []):
                    services.append({
                        "service": svc.name,
                        "port": port,
                        "methods": [],
                        "source": "grpc_reflection",
                    })
            channel.close()
            return services
        except ImportError:
            return self._alpn_detect(host, port)
        except Exception as exc:
            _logger.debug(f"[GRPCProber] {host}:{port}: {exc}")
            return []

    def _alpn_detect(self, host: str, port: int) -> List[Dict[str, Any]]:
        if port not in (443, 8443):
            return []
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.set_alpn_protocols(["h2", "http/1.1"])
            with socket.create_connection((host, port), timeout=3) as s:
                with ctx.wrap_socket(s, server_hostname=host) as tls:
                    proto = tls.selected_alpn_protocol()
            if proto == "h2":
                return [{"service": "unknown_grpc", "port": port,
                         "methods": [], "source": "h2_alpn_detected"}]
        except Exception as _fix_e:
            _logger.debug(f"[core.crawler] {type(_fix_e).__name__}: {_fix_e!r}")
        return []


# ---------------------------------------------------------------------------
# APIVersionScanner
# ---------------------------------------------------------------------------

class APIVersionScanner:
    """
    Brute-forces common API version prefixes combined with common endpoint names
    to discover versioned REST surfaces without prior schema knowledge.
    """

    _PREFIXES: List[str] = [
        "/api", "/api/v1", "/api/v2", "/api/v3", "/api/v4",
        "/v1", "/v2", "/v3", "/v4",
        "/rest", "/rest/v1", "/rest/v2",
        "/service", "/services", "/rpc",
    ]
    _ENDPOINTS: List[str] = [
        "/users", "/user", "/admin", "/health", "/status", "/ping",
        "/me", "/profile", "/account", "/accounts",
        "/login", "/logout", "/register", "/auth", "/token", "/refresh",
        "/search", "/products", "/product", "/items", "/item",
        "/orders", "/order", "/config", "/settings",
        "/info", "/version", "/docs", "/metrics", "/debug",
    ]

    def scan(self, base_url: str, session: Any, timeout: int = 5) -> List[EndpointMeta]:
        base = base_url.rstrip("/")
        found: List[EndpointMeta] = []

        for prefix in self._PREFIXES:
            for ep in self._ENDPOINTS:
                url = base + prefix + ep
                try:
                    r = session.get(url, timeout=timeout, allow_redirects=False)
                    if r.status_code not in (404, 410):
                        found.append(EndpointMeta(
                            url=url,
                            method="GET",
                            source=f"version_scan:{r.status_code}",
                        ))
                        _logger.debug(f"[APIVersionScanner] {url} -> {r.status_code}")
                except Exception:
                    continue

        _logger.info(f"[APIVersionScanner] {len(found)} endpoints discovered")
        return found


# ---------------------------------------------------------------------------
# ParameterMiner
# ---------------------------------------------------------------------------

class ParameterMiner:
    """
    Discovers hidden GET / POST parameters via differential analysis.

    Algorithm:
      1. Baseline request -> (status_code, body_length)
      2. Chunk-probe: send N params with canary values, compare to baseline
      3. If chunk causes difference -> narrow down one-by-one
      4. Active params = those that individually shift status or body size
    """

    _WORDLIST: List[str] = [
        "id", "user", "username", "email", "password", "token", "key", "api_key",
        "search", "q", "query", "page", "limit", "offset", "sort", "order",
        "filter", "category", "type", "status", "action", "redirect", "url",
        "next", "return", "callback", "data", "file", "path", "name", "code",
        "ref", "source", "target", "format", "lang", "locale", "debug", "test",
        "admin", "mode", "view", "tab", "section", "auth", "session", "csrf",
        "nonce", "hash", "sig", "signature", "start", "end", "from", "to",
        "date", "time", "fields", "include", "exclude", "expand", "depth",
        "version", "v", "pretty", "output", "scope", "client_id", "state",
        "grant_type", "response_type", "access_token", "refresh_token",
        # P8 fix: "username" was duplicated (also appears at the start of the list).
        "pass", "pwd", "secret", "apikey", "appid", "app_id",
    ]

    _WL_CACHE: Optional[List[str]] = None

    def __init__(self, chunk_size: int = 15, threshold_bytes: int = 25):
        self.chunk_size = chunk_size
        self.threshold_bytes = threshold_bytes

    @classmethod
    def _resolve_wordlist(cls) -> List[str]:
        """
        Paketli wordlists/params.txt (769 ad) — eskiden ORPHAN'dı: ParameterMiner yalnız
        yukarıdaki ~90 hardcoded adı kullanıyordu. params.txt'yi yükle, hardcoded çekirdeği
        ÖNDE tutarak (yüksek-sinyal adlar önce) dedup'lı ekle, makul bir tavanda kes
        (Tor'da istek patlamasını önle). Sonuç cache'lenir.
        """
        if cls._WL_CACHE is not None:
            return cls._WL_CACHE
        names = list(cls._WORDLIST)
        seen = {n.lower() for n in names}
        try:
            from websecure.core.payloads import load_external_payloads
            for w in load_external_payloads("params") or []:
                wl = (w or "").strip()
                if not wl or wl.startswith("#") or wl.lower() in seen:
                    continue
                seen.add(wl.lower())
                names.append(wl)
                if len(names) >= 300:   # tavan: çekirdek + ~210 ek ad
                    break
        except Exception:
            pass
        cls._WL_CACHE = names
        return names

    def mine(
        self,
        url: str,
        session: Any,
        wordlist: Optional[List[str]] = None,
        methods: Optional[List[str]] = None,
    ) -> Dict[str, List[str]]:
        """Returns {url: [active_param_names]} for GET and POST."""
        wl = wordlist or self._resolve_wordlist()
        active: List[str] = []
        for method in (methods or ["GET", "POST"]):
            for param in self._mine_method(url, session, method, wl):
                if param not in active:
                    active.append(param)
        return {url: active}

    def _mine_method(
        self, url: str, session: Any, method: str, wordlist: List[str]
    ) -> List[str]:
        baseline = self._request(session, method, url, {})
        if baseline is None:
            return []
        base_len, base_code = baseline
        found: List[str] = []

        for chunk in _chunks(wordlist, self.chunk_size):
            probe = {p: f"ws{i:04d}" for i, p in enumerate(chunk)}
            result = self._request(session, method, url, probe)
            if result is None:
                continue
            r_len, r_code = result
            if abs(r_len - base_len) <= self.threshold_bytes and r_code == base_code:
                continue
            for param in chunk:
                single = self._request(session, method, url, {param: "ws0000"})
                if single is None:
                    continue
                s_len, s_code = single
                if abs(s_len - base_len) > self.threshold_bytes or s_code != base_code:
                    found.append(param)
                    _logger.debug(f"[ParameterMiner] [{method}] {url} -> active: {param}")
        return found

    def _request(
        self, session: Any, method: str, url: str, params: Dict[str, str]
    ) -> Optional[Tuple[int, int]]:
        try:
            if method.upper() == "GET":
                r = session.get(url, params=params, timeout=8, allow_redirects=False)
            else:
                r = session.post(url, data=params, timeout=8, allow_redirects=False)
            return len(r.content), r.status_code
        except Exception:
            return None


# ---------------------------------------------------------------------------
# FormMutationFuzzer
# ---------------------------------------------------------------------------

class FormMutationFuzzer:
    """
    Generates all value combinations for enumerable form fields.
    Handles select options, radio buttons, and checkbox on/off states.
    Returns one data dict per test case — ready for scanner consumption.
    """

    def mutate(self, form: Dict[str, Any]) -> List[Dict[str, str]]:
        inputs = form.get("inputs") or []
        enum_fields: Dict[str, List[str]] = {}
        fixed: Dict[str, str] = {}

        for inp in inputs:
            name = inp.get("name", "")
            itype = inp.get("type", "text").lower()
            value = inp.get("value") or ""
            if not name:
                continue

            if itype == "select":
                opts = inp.get("options") or [value or "1", "2", "0"]
                enum_fields[name] = [str(o) for o in opts]
            elif itype == "radio":
                opts = inp.get("options") or [value or "on", "off"]
                enum_fields[name] = [str(o) for o in opts]
            elif itype == "checkbox":
                enum_fields[name] = ["on", ""]
            else:
                fixed[name] = value

        if not enum_fields:
            return [fixed] if fixed else []

        names = list(enum_fields.keys())
        combos: List[Dict[str, str]] = []
        for values in itertools.product(*[enum_fields[n] for n in names]):
            data = dict(fixed)
            for name, val in zip(names, values):
                if val:
                    data[name] = val
            combos.append(data)
        return combos


# ---------------------------------------------------------------------------
# SitemapGenerator
# ---------------------------------------------------------------------------

class SitemapGenerator:
    """
    Converts CrawlResult into structured sitemap output.
    Formats: "json" (default), "text" (tree), "xml" (sitemap.org).
    """

    def generate(self, result: CrawlResult, base_url: str, fmt: str = "json") -> str:
        if fmt == "xml":
            return self._as_xml(result)
        if fmt == "text":
            return self._as_text(result, base_url)
        return self._as_json(result, base_url)

    def _as_json(self, result: CrawlResult, base_url: str) -> str:
        return json.dumps(
            {
                "base_url": base_url,
                "stats": {
                    "pages": len(result.endpoints),
                    "api_endpoints": len(result.api_endpoints),
                    "forms": len(result.forms),
                    "js_files": len(result.js_files),
                    "tech_stack": result.tech_stack,
                    "grpc_services": len(result.grpc_services),
                },
                "pages": sorted(result.endpoints),
                "api_endpoints": [
                    {
                        "url": e.url,
                        "method": e.method,
                        "params": e.params,
                        "source": e.source,
                    }
                    for e in result.api_endpoints
                ],
                "forms": [
                    {
                        "action": f["action"],
                        "method": f["method"],
                        "inputs": [i.get("name", "") for i in f.get("inputs", [])],
                    }
                    for f in result.forms
                ],
                "js_files": result.js_files,
                "discovered_params": result.discovered_params,
                "grpc_services": result.grpc_services,
            },
            indent=2,
            ensure_ascii=False,
        )

    def _as_text(self, result: CrawlResult, base_url: str) -> str:
        lines = [f"Sitemap — {base_url}", f"\nPages ({len(result.endpoints)}):"]
        lines += [f"  {ep}" for ep in sorted(result.endpoints)]
        lines += [f"\nAPI Endpoints ({len(result.api_endpoints)}):"]
        lines += [
            f"  [{e.method}] {e.url}  params={e.params}  src={e.source}"
            for e in result.api_endpoints
        ]
        lines += [f"\nForms ({len(result.forms)}):"]
        lines += [
            f"  [{f['method']}] {f['action']}  "
            f"inputs={[i.get('name', '') for i in f.get('inputs', [])]}"
            for f in result.forms
        ]
        if result.grpc_services:
            lines += [f"\ngRPC Services ({len(result.grpc_services)}):"]
            lines += [f"  {s['service']} :{s['port']}" for s in result.grpc_services]
        return "\n".join(lines)

    def _as_xml(self, result: CrawlResult) -> str:
        root = ET.Element("urlset", xmlns="http://www.sitemaps.org/schemas/sitemap/0.9")
        for ep in sorted(set(result.endpoints)):
            url_el = ET.SubElement(root, "url")
            ET.SubElement(url_el, "loc").text = ep
        return ET.tostring(root, encoding="unicode")


# ---------------------------------------------------------------------------
# CrawlerOrchestrator
# ---------------------------------------------------------------------------

class CrawlerOrchestrator:
    """
    Coordinates all crawler components in a single pipeline:
      HTTPCrawler -> OpenAPIImporter -> GraphQLSchemaImporter ->
      GRPCProber -> APIVersionScanner -> ParameterMiner -> SitemapGenerator
    """

    def __init__(
        self,
        max_pages: int = 200,
        enable_openapi: bool = True,
        enable_graphql: bool = True,
        enable_grpc: bool = False,
        enable_version_scan: bool = True,
        enable_param_mining: bool = True,
        param_mine_limit: int = 20,
    ):
        self._http = HTTPCrawler(max_pages=max_pages)
        self._openapi = OpenAPIImporter() if enable_openapi else None
        self._graphql = GraphQLSchemaImporter() if enable_graphql else None
        self._grpc = GRPCProber() if enable_grpc else None
        self._version = APIVersionScanner() if enable_version_scan else None
        self._param = ParameterMiner() if enable_param_mining else None
        self._param_mine_limit = param_mine_limit
        self._sitemap = SitemapGenerator()

    def run(self, target: str, session: Any) -> CrawlResult:
        result = self._http.crawl(target, session)

        if self._openapi:
            result.api_endpoints.extend(self._openapi.run(target, session))

        if self._graphql:
            result.api_endpoints.extend(self._graphql.run(target, session))

        if self._grpc:
            host = urlparse(target).hostname or target
            result.grpc_services.extend(self._grpc.probe(host))

        if self._version:
            result.api_endpoints.extend(self._version.scan(target, session))

        if self._param:
            for url in result.endpoints[: self._param_mine_limit]:
                result.discovered_params.update(self._param.mine(url, session))

        result.sitemap = json.loads(self._sitemap.generate(result, target, "json"))
        _logger.info(
            f"[CrawlerOrchestrator] Complete: {len(result.endpoints)} pages, "
            f"{len(result.api_endpoints)} API endpoints, "
            f"{len(result.grpc_services)} gRPC services, "
            f"{sum(len(v) for v in result.discovered_params.values())} active params found"
        )
        return result


__all__ = [
    "EndpointMeta",
    "CrawlResult",
    "CrawlerBase",
    "HTTPCrawler",
    "OpenAPIImporter",
    "GraphQLSchemaImporter",
    "GRPCProber",
    "APIVersionScanner",
    "ParameterMiner",
    "FormMutationFuzzer",
    "SitemapGenerator",
    "CrawlerOrchestrator",
]
