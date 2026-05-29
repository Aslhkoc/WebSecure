"""
websecure.api.server
~~~~~~~~~~~~~~~~~~~~~
Stdlib tabanlı REST API sunucusu — Flask/FastAPI bağımlılığı yok.

Endpoint'ler
------------
GET  /api/v1/health                        — Sunucu sağlık kontrolü
GET  /api/v1/scans                         — Tarama listesi (limit, tenant_id)
POST /api/v1/scans                         — Yeni tarama başlat
GET  /api/v1/scans/{id}                    — Tek tarama detayı
GET  /api/v1/scans/{id}/findings           — Tarama bulguları
GET  /api/v1/scans/{id}/score              — Tarama skoru
GET  /api/v1/findings                      — Bulgu arama (keyword, severity)
POST /api/v1/findings/{id}/false_positive  — FP işaretleme
GET  /api/v1/score/trend                   — Skor trendi (target, project_id)
GET  /api/v1/fp/rules                      — FP kuralları listesi
GET  /api/v1/plugins                       — Plugin listesi
POST /api/v1/plugins/{name}/run            — Plugin çalıştır
GET  /api/v1/correlate                     — İki tarama korelasyonu (s1, s2)

Auth
----
X-API-Key header veya ?api_key= query param
Tenant izolasyonu API key ile sağlanır.

SOLID
-----
- SRP  : APIHandler sadece HTTP işler; iş mantığı servis katmanında.
- OCP  : Yeni endpoint eklemek mevcut kodu değiştirmez (_routes dict).
- DIP  : Handler, servisler üzerinden çalışır.
"""
from __future__ import annotations

import json
import logging
import re
import threading
import traceback
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, urlparse

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Tip alias
# ---------------------------------------------------------------------------

_HandlerFn = Callable[["APIHandler", Dict[str, str], Dict[str, Any]], Tuple[int, Any]]

# ---------------------------------------------------------------------------
# APIResponse yardımcısı
# ---------------------------------------------------------------------------

def _ok(data: Any, message: str = "ok") -> Tuple[int, Dict]:
    return 200, {"status": "ok", "message": message, "data": data}


def _created(data: Any) -> Tuple[int, Dict]:
    return 201, {"status": "created", "data": data}


def _err(code: int, message: str) -> Tuple[int, Dict]:
    return code, {"status": "error", "message": message}


# ---------------------------------------------------------------------------
# APIHandler
# ---------------------------------------------------------------------------

class APIHandler(BaseHTTPRequestHandler):
    """HTTP istek yöneticisi."""

    # Sunucu tarafından enjekte edilir
    api_server: "APIServer" = None  # type: ignore[assignment]

    def log_message(self, fmt: str, *args: Any) -> None:
        logger.debug(f"[API] {self.address_string()} {fmt % args}")

    # ------------------------------------------------------------------
    # Ortak yardımcılar
    # ------------------------------------------------------------------

    def _parse_url(self) -> Tuple[str, Dict[str, str]]:
        parsed = urlparse(self.path)
        qs = parse_qs(parsed.query)
        params = {k: v[0] for k, v in qs.items()}
        return parsed.path.rstrip("/"), params

    def _read_body(self) -> Dict[str, Any]:
        length = int(self.headers.get("Content-Length", 0))
        if length <= 0:
            return {}
        try:
            return json.loads(self.rfile.read(length).decode("utf-8"))
        except Exception:
            return {}

    def _auth(self, params: Optional[Dict[str, str]] = None) -> Optional[str]:
        """API key -> tenant_id. None -> auth başarısız."""
        key = (
            self.headers.get("X-API-Key", "")
            or (params or self._parse_url()[1]).get("api_key", "")
        )
        if not key:
            return None
        return self.api_server.resolve_tenant(key)

    def _send_json(self, code: int, data: Any) -> None:
        body = json.dumps(data, ensure_ascii=False, default=str).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def _dispatch(self, method: str) -> None:
        path, params = self._parse_url()
        body = self._read_body() if method == "POST" else {}

        # OPTIONS preflight
        if method == "OPTIONS":
            self.send_response(204)
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "X-API-Key, Content-Type")
            self.end_headers()
            return

        # Public endpoint (auth gereksiz)
        if path == "/api/v1/health":
            self._send_json(200, {"status": "ok", "version": "20.0.0"})
            return

        # Auth gerekli — params zaten parse edildi, tekrar parse etme
        tenant_id = self._auth(params)
        if tenant_id is None and not self.api_server.no_auth:
            self._send_json(*_err(401, "API key gerekli (X-API-Key header)"))
            return

        # Rota eşleştirme
        try:
            code, data = self.api_server.dispatch(method, path, params, body, tenant_id)
        except Exception:
            logger.error(f"[API] İşleme hatası:\n{traceback.format_exc()}")
            code, data = _err(500, "Sunucu hatası")

        self._send_json(code, data)

    def do_GET(self) -> None:
        self._dispatch("GET")

    def do_POST(self) -> None:
        self._dispatch("POST")

    def do_OPTIONS(self) -> None:
        self._dispatch("OPTIONS")


# ---------------------------------------------------------------------------
# Route tablosu
# ---------------------------------------------------------------------------

class RouteTable:
    """
    Pattern -> handler eşleştirme tablosu.

    Pattern formatı: ``/api/v1/scans/{id}/findings``
    {id} -> named capture group
    """

    def __init__(self) -> None:
        self._routes: List[Tuple[str, str, re.Pattern, _HandlerFn]] = []

    def add(self, method: str, pattern: str, handler: _HandlerFn) -> None:
        # {name} -> (?P<name>[^/]+)
        regex = re.sub(r"\{(\w+)\}", r"(?P<\1>[^/]+)", pattern)
        self._routes.append((method.upper(), pattern, re.compile(f"^{regex}$"), handler))

    def match(
        self,
        method: str,
        path: str,
    ) -> Tuple[Optional[_HandlerFn], Dict[str, str]]:
        for m, _, pat, handler in self._routes:
            if m != method.upper():
                continue
            match = pat.match(path)
            if match:
                return handler, match.groupdict()
        return None, {}


# ---------------------------------------------------------------------------
# APIServer
# ---------------------------------------------------------------------------

class APIServer:
    """
    WebSecure REST API sunucusu.

    Kullanım
    --------
    ```python
    server = APIServer(port=8080, no_auth=True)
    server.start()   # daemon thread
    # ...
    server.stop()
    ```
    """

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 8888,
        no_auth: bool = False,
        db=None,
    ) -> None:
        self.host = host
        self.port = port
        self.no_auth = no_auth
        self._db = db
        self._server: Optional[HTTPServer] = None
        self._thread: Optional[threading.Thread] = None
        self._routes = RouteTable()
        self._setup_routes()

    # ------------------------------------------------------------------
    # Rota kurulumu
    # ------------------------------------------------------------------

    def _setup_routes(self) -> None:
        r = self._routes
        # Health
        r.add("GET",  "/api/v1/health",                          self._health)
        # Scans
        r.add("GET",  "/api/v1/scans",                           self._list_scans)
        r.add("POST", "/api/v1/scans",                           self._create_scan)
        r.add("GET",  "/api/v1/scans/{scan_id}",                 self._get_scan)
        r.add("GET",  "/api/v1/scans/{scan_id}/findings",        self._scan_findings)
        r.add("GET",  "/api/v1/scans/{scan_id}/score",           self._scan_score)
        # Findings
        r.add("GET",  "/api/v1/findings",                        self._search_findings)
        r.add("POST", "/api/v1/findings/{finding_id}/false_positive", self._mark_fp)
        # Score
        r.add("GET",  "/api/v1/score/trend",                     self._score_trend)
        # FP
        r.add("GET",  "/api/v1/fp/rules",                        self._fp_rules)
        # Plugins
        r.add("GET",  "/api/v1/plugins",                         self._list_plugins)
        r.add("POST", "/api/v1/plugins/{plugin_name}/run",       self._run_plugin)
        # Correlate
        r.add("GET",  "/api/v1/correlate",                       self._correlate)

    # ------------------------------------------------------------------
    # Dispatch
    # ------------------------------------------------------------------

    def dispatch(
        self,
        method: str,
        path: str,
        params: Dict[str, str],
        body: Dict[str, Any],
        tenant_id: Optional[str],
    ) -> Tuple[int, Any]:
        handler, path_params = self._routes.match(method, path)
        if handler is None:
            return _err(404, f"Endpoint bulunamadı: {method} {path}")

        ctx = {
            "tenant_id": tenant_id,
            "params": params,
            "body": body,
            "path_params": path_params,
        }
        return handler(ctx)

    def resolve_tenant(self, api_key: str) -> Optional[str]:
        """API key -> tenant_id. no_auth modda default döner."""
        if self.no_auth:
            return "default"
        try:
            from websecure.db.repository import TenantRepository
            repo = TenantRepository(self._db)
            tenant = repo.get_by_api_key(api_key)
            return tenant.id if tenant else None
        except Exception:
            # DB yoksa key'i tenant_id olarak kullan
            return api_key if api_key else None

    # ------------------------------------------------------------------
    # Endpoint handler'ları
    # ------------------------------------------------------------------

    def _health(self, ctx: Dict) -> Tuple[int, Any]:
        return _ok({
            "version": "20.0.0",
            "db": self._db is not None,
            "no_auth": self.no_auth,
        })

    def _list_scans(self, ctx: Dict) -> Tuple[int, Any]:
        params = ctx["params"]
        tenant_id = ctx["tenant_id"]
        try:
            from websecure.db.repository import ScanRepository
            repo = ScanRepository(self._db)
            scans = repo.list_recent(
                tenant_id=tenant_id,
                project_id=params.get("project_id"),
                limit=int(params.get("limit", 50)),
            )
            return _ok([self._scan_to_dict(s) for s in scans])
        except Exception as exc:
            return _err(503, f"DB hatası: {exc}")

    def _create_scan(self, ctx: Dict) -> Tuple[int, Any]:
        body = ctx["body"]
        tenant_id = ctx["tenant_id"]
        target = body.get("target", "")
        if not target:
            return _err(400, "target gerekli")
        try:
            from websecure.db.repository import ScanRepository, Scan
            scan = Scan(
                tenant_id=tenant_id,
                target=target,
                profile=body.get("profile", "default"),
                config_json=body.get("options", {}),
            )
            ScanRepository(self._db).create(scan)
            return _created(self._scan_to_dict(scan))
        except Exception as exc:
            return _err(503, f"DB hatası: {exc}")

    def _get_scan(self, ctx: Dict) -> Tuple[int, Any]:
        scan_id = ctx["path_params"].get("scan_id", "")
        try:
            from websecure.db.repository import ScanRepository
            scan = ScanRepository(self._db).get(scan_id)
            if not scan:
                return _err(404, f"Tarama bulunamadı: {scan_id}")
            return _ok(self._scan_to_dict(scan))
        except Exception as exc:
            return _err(503, f"DB hatası: {exc}")

    def _scan_findings(self, ctx: Dict) -> Tuple[int, Any]:
        scan_id = ctx["path_params"].get("scan_id", "")
        include_fp = ctx["params"].get("include_fp", "false").lower() == "true"
        try:
            from websecure.db.repository import FindingRepository
            findings = FindingRepository(self._db).list_by_scan(scan_id, include_fp)
            return _ok([self._finding_to_dict(f) for f in findings])
        except Exception as exc:
            return _err(503, f"DB hatası: {exc}")

    def _scan_score(self, ctx: Dict) -> Tuple[int, Any]:
        scan_id = ctx["path_params"].get("scan_id", "")
        try:
            from websecure.db.repository import FindingRepository
            from websecure.core.score_tracker import ScoreCalculator
            findings = FindingRepository(self._db).list_by_scan(scan_id)
            scan = None
            try:
                from websecure.db.repository import ScanRepository
                scan = ScanRepository(self._db).get(scan_id)
            except Exception as _fix_e:
                logger.debug(f"[api.server] {type(_fix_e).__name__}: {_fix_e!r}")
            target = scan.target if scan else "unknown"
            calc = ScoreCalculator()
            snap = calc.calculate(scan_id, target, [self._finding_to_dict(f) for f in findings])
            return _ok(snap.to_dict())
        except Exception as exc:
            return _err(503, f"Skor hatası: {exc}")

    def _search_findings(self, ctx: Dict) -> Tuple[int, Any]:
        params = ctx["params"]
        tenant_id = ctx["tenant_id"]
        keyword = params.get("q", "")
        severity = params.get("severity")
        limit = int(params.get("limit", 100))
        try:
            from websecure.db.repository import FindingRepository
            findings = FindingRepository(self._db).search(
                keyword=keyword,
                tenant_id=tenant_id,
                severity=severity,
                limit=limit,
            )
            return _ok([self._finding_to_dict(f) for f in findings])
        except Exception as exc:
            return _err(503, f"DB hatası: {exc}")

    def _mark_fp(self, ctx: Dict) -> Tuple[int, Any]:
        finding_id = ctx["path_params"].get("finding_id", "")
        is_fp = ctx["body"].get("false_positive", True)
        try:
            from websecure.db.repository import FindingRepository
            ok = FindingRepository(self._db).mark_false_positive(finding_id, is_fp)
            if not ok:
                return _err(404, f"Bulgu bulunamadı: {finding_id}")
            return _ok({"finding_id": finding_id, "false_positive": is_fp})
        except Exception as exc:
            return _err(503, f"DB hatası: {exc}")

    def _score_trend(self, ctx: Dict) -> Tuple[int, Any]:
        params = ctx["params"]
        target = params.get("target")
        project_id = params.get("project_id")
        limit = int(params.get("limit", 20))
        try:
            from websecure.core.score_tracker import get_score_tracker
            tracker = get_score_tracker(self._db)
            if project_id:
                trend = tracker.project_trend(project_id, limit)
            elif target:
                trend = tracker.trend(target, limit)
            else:
                return _err(400, "target veya project_id gerekli")
            return _ok(trend.to_dict())
        except Exception as exc:
            return _err(503, f"Trend hatası: {exc}")

    def _fp_rules(self, ctx: Dict) -> Tuple[int, Any]:
        tenant_id = ctx["tenant_id"]
        try:
            from websecure.core.fp_learner import get_fp_learner
            learner = get_fp_learner()
            rules = learner.list_rules(tenant_id=tenant_id)
            return _ok([r.to_dict() for r in rules])
        except Exception as exc:
            return _err(503, f"FP hatası: {exc}")

    def _list_plugins(self, ctx: Dict) -> Tuple[int, Any]:
        try:
            from websecure.core.plugin_marketplace import get_marketplace
            plugins = get_marketplace().list_plugins()
            return _ok([
                {
                    "name": p.name,
                    "version": p.version,
                    "description": p.description,
                    "enabled": p.enabled,
                    "source": p.source,
                    "tags": p.tags,
                }
                for p in plugins
            ])
        except Exception as exc:
            return _err(503, f"Plugin hatası: {exc}")

    def _run_plugin(self, ctx: Dict) -> Tuple[int, Any]:
        plugin_name = ctx["path_params"].get("plugin_name", "")
        target = ctx["body"].get("target", "")
        options = ctx["body"].get("options", {})
        if not target:
            return _err(400, "target gerekli")
        try:
            from websecure.core.plugin_marketplace import get_marketplace
            findings = get_marketplace().run(plugin_name, target, options)
            return _ok({"plugin": plugin_name, "target": target, "findings": findings})
        except Exception as exc:
            return _err(503, f"Plugin çalıştırma hatası: {exc}")

    def _correlate(self, ctx: Dict) -> Tuple[int, Any]:
        params = ctx["params"]
        s1 = params.get("s1", "")
        s2 = params.get("s2", "")
        if not s1 or not s2:
            return _err(400, "s1 ve s2 tarama ID gerekli")
        try:
            from websecure.core.correlation_engine import get_correlation_engine
            engine = get_correlation_engine(self._db)
            matches = engine.correlate_from_db(s1, s2)
            report = engine.report(matches)
            return _ok(report)
        except Exception as exc:
            return _err(503, f"Korelasyon hatası: {exc}")

    # ------------------------------------------------------------------
    # Serileştirme yardımcıları
    # ------------------------------------------------------------------

    @staticmethod
    def _scan_to_dict(scan) -> Dict[str, Any]:
        from dataclasses import asdict
        try:
            return asdict(scan)
        except Exception:
            return vars(scan)

    @staticmethod
    def _finding_to_dict(finding) -> Dict[str, Any]:
        from dataclasses import asdict
        try:
            return asdict(finding)
        except Exception:
            return vars(finding)

    # ------------------------------------------------------------------
    # Sunucu yaşam döngüsü
    # ------------------------------------------------------------------

    def start(self, daemon: bool = True) -> None:
        """Sunucuyu daemon thread olarak başlat."""
        if self._thread and self._thread.is_alive():
            logger.warning("[API] Sunucu zaten çalışıyor.")
            return

        APIHandler.api_server = self

        self._server = HTTPServer((self.host, self.port), APIHandler)
        self._thread = threading.Thread(
            target=self._server.serve_forever,
            name="websecure-api",
            daemon=daemon,
        )
        self._thread.start()
        logger.info(f"[API] REST API başlatıldı: http://{self.host}:{self.port}/api/v1/")

    def stop(self) -> None:
        """Sunucuyu durdur."""
        if self._server:
            self._server.shutdown()
            self._server = None
        if self._thread:
            self._thread.join(timeout=5)
            self._thread = None
        logger.info("[API] REST API durduruldu.")

    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def base_url(self) -> str:
        return f"http://{self.host}:{self.port}/api/v1"


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------

_server_instance: Optional[APIServer] = None


def get_api_server(
    host: str = "127.0.0.1",
    port: int = 8888,
    no_auth: bool = False,
    db=None,
) -> APIServer:
    """Global APIServer singleton'ını döndür."""
    global _server_instance
    if _server_instance is None:
        _server_instance = APIServer(host=host, port=port, no_auth=no_auth, db=db)
    return _server_instance


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

__all__ = [
    "APIServer",
    "get_api_server",
]
