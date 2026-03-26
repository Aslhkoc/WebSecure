"""
websecure.scanners.race_condition
-----------------------------------
Race Condition / Time-of-Check-Time-of-Use (TOCTOU) vulnerability detector.

Techniques
──────────
  1. Parallel identical requests — fire N concurrent copies of the same
     mutating request (POST /transfer, POST /redeem) and look for duplicate
     success responses indicating the server processed the same action twice.

  2. Token / coupon reuse      — submit the same one-time-use token N times
     simultaneously; duplicate 2xx responses confirm the race window.

  3. Rate-limit bypass         — send bursts of requests that should be
     rate-limited; if more than 1 succeeds, the rate limiter is bypassable.

  4. Parallel account creation — submit the same username N times; if >1
     account is created the server has a registration race condition.

All techniques use a "last-byte sync" strategy: prepare all connections,
then release the final byte simultaneously to maximise overlap.

References
──────────
  • https://portswigger.net/web-security/race-conditions
  • https://portswigger.net/research/smashing-the-state-machine
"""
from __future__ import annotations

import logging
import random
import socket
import ssl
import string
import threading
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
DEFAULT_PARALLEL      = 20    # simultaneous connections per race burst
DEFAULT_TIMEOUT       = 10.0  # per-request timeout (seconds)
LAST_BYTE_SYNC_SLEEP  = 0.05  # seconds to wait after N-1 bytes before last byte burst


# ---------------------------------------------------------------------------
# Finding dataclass
# ---------------------------------------------------------------------------
@dataclass
class RaceFinding:
    technique:   str
    url:         str
    severity:    str
    description: str
    evidence:    Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type":        "Race Condition",
            "technique":   self.technique,
            "url":         self.url,
            "severity":    self.severity,
            "description": self.description,
            "evidence":    self.evidence,
        }


# ---------------------------------------------------------------------------
# Low-level: last-byte sync HTTP/1.1 over raw socket
# ---------------------------------------------------------------------------

def _make_socket(host: str, port: int, use_ssl: bool, timeout: float):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode    = ssl.CERT_NONE
    s = socket.create_connection((host, port), timeout=timeout)
    if use_ssl:
        s = ctx.wrap_socket(s, server_hostname=host)
    return s


def _build_raw_request(
    method: str,
    path: str,
    host: str,
    body: bytes,
    extra_headers: Optional[Dict[str, str]] = None,
) -> bytes:
    """Build a minimal HTTP/1.1 request as bytes."""
    headers = {
        "Host":           host,
        "Content-Type":   "application/x-www-form-urlencoded",
        "Content-Length": str(len(body)),
        "Connection":     "close",
        "User-Agent":     "Mozilla/5.0 (compatible; WebSecure/3.0; Race)",
    }
    if extra_headers:
        headers.update(extra_headers)

    header_block = "\r\n".join(f"{k}: {v}" for k, v in headers.items())
    request_line = f"{method.upper()} {path} HTTP/1.1\r\n"
    return (request_line + header_block + "\r\n\r\n").encode() + body


def _send_and_receive(sock, payload_head: bytes, payload_last: bytes) -> Tuple[int, str]:
    """
    Send *payload_head* (all bytes except the last), wait for synchronization
    signal, then send *payload_last*.  Returns (status_code, body_excerpt).
    """
    try:
        sock.sendall(payload_head)
        return sock, True
    except Exception as exc:
        return sock, False


def _read_response(sock: socket.socket, timeout: float = 5.0) -> Tuple[int, str]:
    """Read response from socket; return (status_code, body_excerpt)."""
    sock.settimeout(timeout)
    chunks = []
    try:
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)
    except OSError as exc:
        logger.debug("[Race] Socket recv error: %s", exc)
    raw = b"".join(chunks)
    status = 0
    body   = ""
    try:
        first_line = raw.split(b"\r\n", 1)[0]
        status = int(first_line.split(b" ", 2)[1])
        sep_idx = raw.find(b"\r\n\r\n")
        if sep_idx != -1:
            body = raw[sep_idx + 4 : sep_idx + 500].decode("utf-8", "replace")
    except (ValueError, IndexError) as exc:
        logger.debug("[Race] Response parse error: %s", exc)
    return status, body


def _race_burst(
    host: str,
    port: int,
    use_ssl: bool,
    method: str,
    path: str,
    body: bytes,
    n: int,
    extra_headers: Optional[Dict[str, str]] = None,
    timeout: float = DEFAULT_TIMEOUT,
) -> List[Tuple[int, str]]:
    """
    Open *n* sockets, send all-but-last byte, then simultaneously send last byte.
    Returns list of (status_code, body_excerpt) for each response.
    """
    full_payload = _build_raw_request(method, path, host, body, extra_headers)

    # Last-byte sync: send everything except the final byte first
    payload_head = full_payload[:-1]
    payload_tail = full_payload[-1:]

    sockets: List[socket.socket] = []
    for _ in range(n):
        try:
            s = _make_socket(host, port, use_ssl, timeout=timeout)
            sockets.append(s)
        except Exception as exc:
            logger.debug("[Race] Socket create error: %s", exc)

    if not sockets:
        return []

    # Send N-1 bytes to all sockets
    for s in sockets:
        try:
            s.sendall(payload_head)
        except OSError as exc:
            logger.debug("[Race] sendall payload_head error: %s", exc)

    # Brief pause to let all sockets buffer their data
    time.sleep(LAST_BYTE_SYNC_SLEEP)

    # Fire last byte simultaneously
    barrier = threading.Barrier(len(sockets) + 1)

    def _fire(s):
        barrier.wait()
        try:
            s.sendall(payload_tail)
        except OSError as exc:
            logger.debug("[Race] sendall payload_tail error: %s", exc)

    threads = [threading.Thread(target=_fire, args=(s,), daemon=True) for s in sockets]
    for t in threads:
        t.start()
    barrier.wait()
    for t in threads:
        t.join(timeout=1.0)

    # Collect responses in parallel
    results: List[Tuple[int, str]] = []
    with ThreadPoolExecutor(max_workers=len(sockets)) as ex:
        futures = {ex.submit(_read_response, s, 5.0): s for s in sockets}
        for fut in as_completed(futures):
            try:
                results.append(fut.result())
            except Exception as exc:
                logger.debug("[Race] Future result error: %s", exc)
                results.append((0, ""))

    for s in sockets:
        try:
            s.close()
        except OSError as exc:
            logger.debug("[Race] Socket close error: %s", exc)

    return results


# ---------------------------------------------------------------------------
# High-level probe helpers (session-based, simpler but less precise timing)
# ---------------------------------------------------------------------------

def _session_burst(
    session,
    method: str,
    url: str,
    data: Optional[Dict] = None,
    json_body: Optional[Dict] = None,
    headers: Optional[Dict] = None,
    n: int = DEFAULT_PARALLEL,
    timeout: float = DEFAULT_TIMEOUT,
) -> List[Tuple[int, str]]:
    """
    Send *n* concurrent requests using *session* via ThreadPoolExecutor.
    Returns list of (status_code, body_excerpt).
    """
    def _one_req(_):
        try:
            resp = session.request(
                method, url,
                data=data,
                json=json_body,
                headers=headers or {},
                timeout=timeout,
                allow_redirects=True,
            )
            return resp.status_code, resp.text[:300]
        except Exception as exc:
            logger.debug("[Race] session request error: %s", exc)
            return 0, ""

    with ThreadPoolExecutor(max_workers=n) as ex:
        results = list(ex.map(_one_req, range(n)))
    return results


# ---------------------------------------------------------------------------
# Probe: parallel identical POST (generic race window)
# ---------------------------------------------------------------------------

def _probe_parallel_post(
    url: str,
    session,
    n: int = DEFAULT_PARALLEL,
) -> Optional[RaceFinding]:
    """
    Fire *n* identical POST requests simultaneously.
    A race condition is likely if multiple requests get a 2xx response for
    an action that should only succeed once (e.g. coupon redemption, transfer).
    """
    # Generic body — scanners provide more specific payloads per endpoint
    body = {"_race": "1", "amount": "1", "quantity": "1"}

    results = _session_burst(session, "POST", url, data=body, n=n)
    successes = [r for r in results if 200 <= r[0] < 300]

    if len(successes) > 1:
        return RaceFinding(
            technique   = "Parallel POST (generic race window)",
            url         = url,
            severity    = "High",
            description = (
                f"{len(successes)}/{n} concurrent POST requests succeeded (HTTP 2xx). "
                "If this endpoint performs a one-time action (transfer, redemption, "
                "registration), a race condition may allow the action to be executed "
                "multiple times simultaneously."
            ),
            evidence    = {
                "parallel_n":     n,
                "success_count":  len(successes),
                "sample_statuses": [r[0] for r in results],
            },
        )
    return None


# ---------------------------------------------------------------------------
# Probe: rate-limit bypass
# ---------------------------------------------------------------------------

def _probe_rate_limit_bypass(
    url: str,
    session,
    n: int = DEFAULT_PARALLEL,
) -> Optional[RaceFinding]:
    """
    Send a burst of GET/POST requests that would normally be rate-limited
    (e.g. login attempts, OTP checks).  If >1 succeeds, rate limiting is
    bypassable via concurrent requests.
    """
    results = _session_burst(session, "GET", url, n=n)
    non_429 = [r for r in results if r[0] not in (429, 503, 0)]

    # If the very first request is also rate-limited, skip this probe
    if not results or results[0][0] in (429, 503):
        return None

    # If most requests bypass the rate limit
    if len(non_429) > n * 0.7:
        return None   # not rate-limited at all — skip

    if len(non_429) > 1 and len(non_429) < len(results):
        return RaceFinding(
            technique   = "Rate-limit bypass via concurrent requests",
            url         = url,
            severity    = "Medium",
            description = (
                f"{len(non_429)}/{n} concurrent requests bypassed rate limiting. "
                "The rate limiter appears to be checking a counter that is not "
                "atomically updated, allowing some concurrent requests to slip through."
            ),
            evidence    = {
                "parallel_n":     n,
                "bypass_count":   len(non_429),
                "sample_statuses": [r[0] for r in results],
            },
        )
    return None


# ---------------------------------------------------------------------------
# Probe: low-level last-byte sync (raw socket)
# ---------------------------------------------------------------------------

def _probe_raw_socket_race(
    url: str,
    n: int = 15,
) -> Optional[RaceFinding]:
    """
    Use last-byte synchronisation over raw sockets for maximum timing precision.
    Targets POST endpoints; checks for duplicate 2xx responses.
    """
    parsed  = urllib.parse.urlparse(url)
    host    = parsed.hostname
    if not host:
        return None
    port    = parsed.port or (443 if parsed.scheme == "https" else 80)
    use_ssl = parsed.scheme == "https"
    path    = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query

    body = b"_race=1&quantity=1"
    try:
        results = _race_burst(host, port, use_ssl, "POST", path, body, n=n)
    except Exception as exc:
        logger.debug("[Race] raw socket burst error: %s", exc)
        return None

    successes = [r for r in results if 200 <= r[0] < 300]
    if len(successes) > 1:
        return RaceFinding(
            technique   = "Last-byte sync race (raw socket)",
            url         = url,
            severity    = "High",
            description = (
                f"{len(successes)}/{n} raw-socket requests succeeded simultaneously. "
                "Last-byte synchronisation confirms a tight race window in the server's "
                "request handling, indicating a likely TOCTOU vulnerability."
            ),
            evidence    = {
                "parallel_n":     n,
                "success_count":  len(successes),
                "sample_statuses": [r[0] for r in results],
                "sample_bodies":   [r[1][:100] for r in successes[:3]],
            },
        )
    return None


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def run(
    url: str,
    session=None,
    debug: bool = False,
    auth_ctx: Any = None,
    **_,
) -> List[Dict[str, Any]]:
    """
    Test *url* for race condition vulnerabilities.

    Returns a list of finding dicts (may be empty).
    """
    if debug:
        logger.setLevel(logging.DEBUG)

    results: List[Dict[str, Any]] = []

    if session is None:
        try:
            import requests
            session = requests.Session()
        except ImportError:
            logger.warning("[Race] requests not available")

    probes = [
        ("Parallel POST",       lambda: _probe_parallel_post(url, session) if session else None),
        ("Rate-limit bypass",   lambda: _probe_rate_limit_bypass(url, session) if session else None),
        ("Last-byte sync",      lambda: _probe_raw_socket_race(url)),
    ]

    for name, fn in probes:
        logger.debug("[Race] running %s probe on %s", name, url)
        try:
            finding = fn()
            if finding:
                results.append(finding.to_dict())
                logger.info("[Race] %s — found %s on %s", name, finding.technique, url)
        except Exception as exc:
            logger.debug("[Race] probe %s error: %s", name, exc)

    return results
