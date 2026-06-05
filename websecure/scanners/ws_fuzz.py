"""
websecure.scanners.ws_fuzz
--------------------------
Full WebSocket Fuzzing Scanner.

Techniques:
- WS endpoint discovery (page source + common path probing)
- Raw WebSocket connection via socket (no external library required)
- Payload injection: XSS, SQLi, NoSQLi, SSTI, CMDI, path traversal, null-byte
- Origin manipulation bypass (null origin, arbitrary cross-origin)
- Unauthenticated data access detection
- Subprotocol fuzzing
- Response anomaly / sensitive data detection
- Parallel payload testing via ThreadPoolExecutor
"""
from __future__ import annotations

import base64
import logging
import os
import re
import socket
import ssl
import struct
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from .base import BaseScanner
from websecure.core.reporting import add_result

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Payload catalog  (payload, category, short description)
# ---------------------------------------------------------------------------
_WS_PAYLOADS: List[Tuple[str, str, str]] = [
    # XSS
    ("<script>alert(1)</script>",           "xss",           "HTML script injection"),
    ("<img src=x onerror=alert(1)>",        "xss",           "onerror handler"),
    ("javascript:alert(1)",                 "xss",           "JS protocol"),
    # SQLi
    ("' OR '1'='1",                         "sqli",          "SQL tautology (single)"),
    ("\" OR 1=1--",                         "sqli",          "SQL tautology (double)"),
    ("' UNION SELECT 1,2,3--",              "sqli",          "UNION probe"),
    # Command injection
    ("; echo WSTEST_$(id)",                 "cmdi",          "Unix id via echo"),
    ("| echo WSTEST_$(id)",                 "cmdi",          "Pipe Unix id"),
    ("`echo WSTEST_$(whoami)`",             "cmdi",          "Backtick whoami"),
    ("& echo WSTEST_%USERNAME%",            "cmdi",          "Windows USERNAME"),
    # NoSQLi
    ('{"$ne": null}',                       "nosqli",        "MongoDB $ne:null"),
    ('{"$gt": ""}',                         "nosqli",        "MongoDB $gt empty"),
    ('{"$where": "1==1"}',                  "nosqli",        "MongoDB $where"),
    # SSTI
    ("{{7*7}}",                             "ssti",          "Jinja2/Twig math"),
    ("${7*7}",                              "ssti",          "FreeMarker/Mako math"),
    ("#{7*7}",                              "ssti",          "Ruby ERB math"),
    # Path traversal
    ("../../../etc/passwd",                 "path_traversal","Unix path traversal"),
    ("..\\..\\..\\windows\\win.ini",        "path_traversal","Windows path traversal"),
    # Null byte
    ("test\x00admin",                       "null_byte",     "Null byte injection"),
    # JSON polyglot
    ('{"action":"admin","role":"admin"}',   "mass_assign",   "Role escalation"),
    # Format string
    ("%s%s%s%s%s%n",                        "format_str",    "Format string probe"),
]

# Patterns that indicate a successful injection in WS response
_SUCCESS_PATTERNS: List[Tuple[str, str, str]] = [
    # (regex, vuln_type, description)
    (r"<script>alert\(1\)</script>",                    "xss",           "XSS payload reflected"),
    (r"uid=\d+\(.*?\)\s+gid=\d+",                      "cmdi",          "Unix id command executed"),
    (r"root:.*:0:0:",                                   "cmdi",          "/etc/passwd read"),
    (r"WSTEST_",                                        "cmdi",          "Echo marker reflected"),
    (r"\[extensions\].*for 16-bit app",                 "cmdi",          "Windows win.ini read"),
    (r"(?i)\bSQL syntax\b|ORA-\d{4}|PSQLException",    "sqli",          "SQL error in response"),
    (r"MongoError|CastError",                           "nosqli",        "MongoDB error"),
    (r"^49$|[>\s]49[<\s]",                              "ssti",          "SSTI math result (7*7=49)"),
    (r"(?i)(exception|traceback|stack.?trace)",         "info_leak",     "Server error leak"),
    (r"(?i)(password|secret|api_key|private_key)",      "info_leak",     "Sensitive keyword in response"),
]

# Common WebSocket paths to probe
_WS_PATHS = [
    "/ws", "/websocket", "/socket", "/socket.io/",
    "/ws/v1", "/api/ws", "/api/websocket",
    "/realtime", "/live", "/stream",
    "/chat", "/events", "/feed",
    "/notify", "/push", "/hub",
]

# Origin values for bypass testing
_ORIGIN_BYPASSES: List[Optional[str]] = [
    None,                    # no Origin header at all
    "null",                  # null origin (sandboxed iframe trick)
    "https://evil.com",      # arbitrary cross-origin
    "https://attacker.com",  # another attacker domain
]

_SENSITIVE_RESPONSE_PATTERNS = re.compile(
    r'"(email|user|username|name|role|admin|token|id|balance|phone|address)"\s*:',
    re.I,
)


# ---------------------------------------------------------------------------
# Raw WebSocket implementation (no external dependency)
# ---------------------------------------------------------------------------

def _make_ws_key() -> str:
    return base64.b64encode(os.urandom(16)).decode()


def _make_frame(payload: str, opcode: int = 0x1) -> bytes:
    """Build a masked client WebSocket text frame (RFC 6455)."""
    data = payload.encode("utf-8", errors="replace")
    length = len(data)
    mask = os.urandom(4)
    masked = bytes(b ^ mask[i % 4] for i, b in enumerate(data))

    frame = bytearray()
    frame.append(0x80 | opcode)          # FIN + opcode
    if length <= 125:
        frame.append(0x80 | length)
    elif length <= 65535:
        frame.append(0x80 | 126)
        frame.extend(struct.pack("!H", length))
    else:
        frame.append(0x80 | 127)
        frame.extend(struct.pack("!Q", length))
    frame.extend(mask)
    frame.extend(masked)
    return bytes(frame)


def _read_frame(sock: socket.socket, timeout: float = 3.0) -> Optional[str]:
    """Read a single WebSocket frame from server, return decoded text."""
    sock.settimeout(timeout)
    try:
        header = b""
        while len(header) < 2:
            chunk = sock.recv(2 - len(header))
            if not chunk:
                return None
            header += chunk

        opcode = header[0] & 0x0F
        if opcode == 0x8:   # connection close frame
            return None

        payload_len = header[1] & 0x7F
        if payload_len == 126:
            ext = sock.recv(2)
            payload_len = struct.unpack("!H", ext)[0]
        elif payload_len == 127:
            ext = sock.recv(8)
            payload_len = struct.unpack("!Q", ext)[0]

        if payload_len > 131072:  # cap at 128 KB
            return None

        data = b""
        while len(data) < payload_len:
            chunk = sock.recv(payload_len - len(data))
            if not chunk:
                break
            data += chunk

        return data.decode("utf-8", errors="replace")
    except (OSError, ssl.SSLError, struct.error) as exc:
        logger.debug(f"[WSFuzz] Frame read error: {exc!r}")
        return None


class _RawWSConn:
    """Minimal raw WebSocket connection (plain or TLS)."""

    def __init__(self, url: str, extra_headers: Dict[str, str] = None, timeout: float = 5.0):
        self._url = url
        self._headers = extra_headers or {}
        self._timeout = timeout
        self._sock: Optional[socket.socket] = None
        self.connected = False

    def connect(self) -> bool:
        parsed = urlparse(self._url)
        host = parsed.hostname or ""
        port = parsed.port or (443 if parsed.scheme == "wss" else 80)
        path = (parsed.path or "/") + (f"?{parsed.query}" if parsed.query else "")

        key = _make_ws_key()
        raw = socket.create_connection((host, port), timeout=self._timeout)

        if parsed.scheme == "wss":
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            raw = ctx.wrap_socket(raw, server_hostname=host)

        self._sock = raw

        lines = [
            f"GET {path} HTTP/1.1",
            f"Host: {host}",
            "Upgrade: websocket",
            "Connection: Upgrade",
            f"Sec-WebSocket-Key: {key}",
            "Sec-WebSocket-Version: 13",
        ]
        for k, v in self._headers.items():
            lines.append(f"{k}: {v}")
        lines += ["", ""]
        raw.sendall("\r\n".join(lines).encode())

        resp = b""
        while b"\r\n\r\n" not in resp:
            chunk = raw.recv(4096)
            if not chunk:
                break
            resp += chunk

        resp_str = resp.decode("utf-8", errors="replace")
        if "101" in resp_str and "websocket" in resp_str.lower():
            self.connected = True
        return self.connected

    def send(self, text: str) -> bool:
        if not self._sock or not self.connected:
            return False
        try:
            self._sock.sendall(_make_frame(text))
            return True
        except OSError as exc:
            logger.debug(f"[WSFuzz] Send error: {exc!r}")
            return False

    def recv(self, timeout: float = 3.0) -> Optional[str]:
        return _read_frame(self._sock, timeout) if self._sock else None

    def close(self):
        if self._sock:
            try:
                self._sock.sendall(_make_frame("", opcode=0x8))
                self._sock.close()
            except OSError as exc:
                logger.debug(f"[WSFuzz] Close error: {exc!r}")
            self._sock = None
        self.connected = False


# ---------------------------------------------------------------------------
# WebSocketFuzzer
# ---------------------------------------------------------------------------

class WebSocketFuzzer(BaseScanner):
    """Full WebSocket security scanner with injection, origin bypass, and auth testing."""

    name = "ws_fuzz"
    MAX_WORKERS = 4

    def run(self, target: str, **kwargs) -> Any:
        bucket = self.name
        self.results.setdefault(bucket, [])

        ws_endpoints = self._discover_endpoints(target)
        if not ws_endpoints:
            logger.info(f"[WSFuzz] No WebSocket endpoints found on {target}")
            return self.results

        logger.info(f"[WSFuzz] Scanning {len(ws_endpoints)} WebSocket endpoint(s)")
        for ws_url in ws_endpoints:
            self._fuzz_endpoint(ws_url, bucket)
            self._test_cswsh(ws_url, bucket)

        return self.results

    def _test_cswsh(self, ws_url: str, bucket: str) -> None:
        """
        Cross-Site WebSocket Hijacking (CSWSH) — Origin doğrulaması yapılmıyor mu?
        Farklı Origin header'ları ile bağlantı kurup kabul edilip edilmediğini test eder.
        Kabul edilirse saldırgan sayfasından kurbanın kimliğiyle WS açılabilir.
        """
        evil_origins = [
            "https://evil.websecure.internal",
            "null",
            "http://localhost",
            "https://attacker.example.com",
        ]

        for evil_origin in evil_origins:
            conn = _RawWSConn(ws_url, extra_headers={"Origin": evil_origin}, timeout=5.0)
            try:
                connected = conn.connect()
                if connected:
                    conn.send('{"type":"ping","data":"cswsh-probe"}')
                    resp = conn.recv(timeout=2.0)
                    conn.close()

                    self.add(bucket, {
                        "type": "Cross-Site WebSocket Hijacking (CSWSH)",
                        "severity": "High",
                        "url": ws_url,
                        "payload": f"Origin: {evil_origin}",
                        "evidence": (
                            f"WebSocket handshake accepted from evil Origin '{evil_origin}'. "
                            f"Response snippet: {(resp or '')[:150]}"
                        ),
                        "description": (
                            "Server accepted WS connection from cross-origin domain. "
                            "Attacker can hijack authenticated WebSocket sessions."
                        ),
                    })
                    return
            except Exception as exc:
                logger.debug("[CSWSH] Origin probe failed (%s): %s", evil_origin, exc)
            finally:
                try:
                    conn.close()
                except Exception:
                    pass

    # -------------------------------------------------------------------------
    # Endpoint discovery
    # -------------------------------------------------------------------------

    def _discover_endpoints(self, http_url: str) -> List[str]:
        found: List[str] = []
        parsed = urlparse(http_url)
        scheme_ws = "wss" if parsed.scheme == "https" else "ws"
        base_ws = f"{scheme_ws}://{parsed.netloc}"

        # 1. Extract WS URLs from page source
        try:
            resp = self.session.get(http_url, timeout=8)
            for m in re.finditer(r"""wss?://[^\s'"<>)]+""", resp.text):
                url = m.group(0).rstrip(",'\"")
                if url not in found:
                    found.append(url)
            # Relative paths containing WS keywords
            for m in re.finditer(r"""['"](/[^\s'"<>]+)['"]""", resp.text):
                path = m.group(1)
                if any(k in path.lower() for k in ("ws", "socket", "realtime", "live", "stream", "chat")):
                    candidate = base_ws + path
                    if candidate not in found:
                        found.append(candidate)
        except Exception as e:
            logger.debug(f"[WSFuzz] Page fetch failed: {e}")

        # 2. Probe common WS paths
        for path in _WS_PATHS:
            candidate = base_ws + path
            if candidate not in found and self._probe_endpoint(candidate):
                found.append(candidate)

        # 3. Convert the HTTP URL itself
        direct = http_url.replace("https://", "wss://").replace("http://", "ws://")
        if direct not in found and self._probe_endpoint(direct):
            found.append(direct)

        return found

    def _probe_endpoint(self, ws_url: str) -> bool:
        conn = _RawWSConn(ws_url, timeout=4.0)
        try:
            return conn.connect()
        except (OSError, ssl.SSLError) as exc:
            logger.debug(f"[WSFuzz] Endpoint probe failed for {ws_url!r}: {exc!r}")
            return False
        finally:
            conn.close()

    # -------------------------------------------------------------------------
    # Per-endpoint fuzzing
    # -------------------------------------------------------------------------

    def _fuzz_endpoint(self, ws_url: str, bucket: str):
        self.add(bucket, self.create_finding(
            type="WebSocket Endpoint Discovered",
            url=ws_url,
            severity="Info",
            details="WebSocket upgrade handshake succeeded",
        ))

        self._test_origin_bypass(ws_url, bucket)
        self._test_payloads(ws_url, bucket)
        self._test_unauth_access(ws_url, bucket)

    def _test_origin_bypass(self, ws_url: str, bucket: str):
        """Check if server enforces origin restrictions."""
        for origin in _ORIGIN_BYPASSES:
            headers: Dict[str, str] = {}
            if origin is not None:
                headers["Origin"] = origin
            conn = _RawWSConn(ws_url, extra_headers=headers, timeout=4.0)
            try:
                if not conn.connect():
                    continue
                conn.send('{"test":"origin"}')
                resp = conn.recv(2.0)

                # Flag suspicious origins that still connect
                # origin is None = no Origin header sent — not a bypass, skip
                if origin is not None and origin in ("null", "https://evil.com", "https://attacker.com"):
                    sev = "High" if origin and "evil" in origin else "Medium"
                    finding = self.create_finding(
                        type="WebSocket — Origin Policy Not Enforced",
                        url=ws_url,
                        severity=sev,
                        details=f"Connection accepted with Origin: {origin!r} — CSRF over WebSocket possible",
                        evidence={"origin": str(origin), "response_snippet": (resp or "")[:200]},
                    )
                    self.add(bucket, finding)
                    add_result("offensive", finding)
            except (OSError, ssl.SSLError) as exc:
                logger.debug(f"[WSFuzz] Origin bypass test error for origin={origin!r}: {exc!r}")
            finally:
                conn.close()

    def _test_payloads(self, ws_url: str, bucket: str):
        """Inject attack payloads and check responses for anomalies."""
        baseline = self._send_recv(ws_url, '{"action":"ping","id":1}')

        def test_one(payload: str, category: str, desc: str) -> Optional[Dict]:
            # Try as raw string and as JSON-wrapped
            for msg in [payload, f'{{"message":"{payload}","action":"test"}}'.replace('"', '\\"').replace("\\\"", '"')]:
                try:
                    resp = self._send_recv(ws_url, msg)
                    if resp is None:
                        continue
                    for pattern, vuln_type, vuln_desc in _SUCCESS_PATTERNS:
                        if re.search(pattern, resp, re.I | re.S):
                            if baseline is None or not re.search(pattern, baseline, re.I | re.S):
                                sev = "Critical" if vuln_type in ("cmdi", "ssti", "path_traversal") else "High"
                                return self.create_finding(
                                    type=f"WebSocket Injection — {vuln_type.upper()}",
                                    url=ws_url,
                                    severity=sev,
                                    details=f"{desc}: {vuln_desc}",
                                    evidence={"payload": payload[:120], "response": resp[:300]},
                                )
                except (OSError, ssl.SSLError) as exc:
                    logger.debug(f"[WSFuzz] Payload test error for payload={payload[:40]!r}: {exc!r}")
            return None

        with ThreadPoolExecutor(max_workers=self.MAX_WORKERS) as pool:
            futures = {
                pool.submit(test_one, p, cat, desc): (p, cat)
                for p, cat, desc in _WS_PAYLOADS
                if cat != "dos"
            }
            for f in as_completed(futures):
                result = f.result()
                if result:
                    self.add(bucket, result)
                    add_result("offensive", result)

    def _test_unauth_access(self, ws_url: str, bucket: str):
        """Check if WS returns sensitive data without authentication."""
        conn = _RawWSConn(ws_url, timeout=4.0)
        try:
            if not conn.connect():
                return
            for probe in ['{"action":"get_profile"}', '{"action":"list_users"}',
                          '{"type":"subscribe","channel":"user"}']:
                conn.send(probe)
                resp = conn.recv(2.0)
                if resp and len(resp) > 30:
                    if _SENSITIVE_RESPONSE_PATTERNS.search(resp):
                        finding = self.create_finding(
                            type="WebSocket — Unauthenticated Data Exposure",
                            url=ws_url,
                            severity="High",
                            details="WebSocket returns user/sensitive data fields without authentication",
                            evidence={"probe": probe, "response": resp[:300]},
                        )
                        self.add(bucket, finding)
                        add_result("offensive", finding)
                        break
        except (OSError, ssl.SSLError) as exc:
            logger.debug(f"[WSFuzz] Unauthenticated access test error for {ws_url!r}: {exc!r}")
        finally:
            conn.close()

    # -------------------------------------------------------------------------
    # Helpers
    # -------------------------------------------------------------------------

    def _send_recv(self, ws_url: str, message: str, timeout: float = 3.0) -> Optional[str]:
        conn = _RawWSConn(ws_url, timeout=5.0)
        try:
            if not conn.connect():
                return None
            conn.send(message)
            return conn.recv(timeout)
        except (OSError, ssl.SSLError) as exc:
            logger.debug(f"[WSFuzz] send/recv error for {ws_url!r}: {exc!r}")
            return None
        finally:
            conn.close()


# ---------------------------------------------------------------------------
# Module-level adapter
# ---------------------------------------------------------------------------

def run(url: str, session=None, results: Dict = None, debug: bool = False, **kwargs) -> Dict:
    scanner = WebSocketFuzzer(session=session, results=results or {}, debug=debug)
    return scanner.run(url, **kwargs)
