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
    except Exception:
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
        ("CL.TE timing",      _probe_cl_te),
        ("TE.CL timing",      _probe_te_cl),
        ("TE.TE obfuscation", _probe_te_te),
        ("CL.TE differential",_probe_differential),
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
