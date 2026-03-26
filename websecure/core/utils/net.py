import os
import re
import socket
import ssl
import time
import json
import logging
from urllib.parse import urlparse, urlunparse, urljoin, parse_qsl, urlencode, urlsplit
from typing import Dict, Any, List, Optional, Union, Tuple, Mapping

_logger = logging.getLogger(__name__)

try:
    import requests
except ImportError:
    requests = None

# ========================== Constants ==========================
# hardened_session kaldırıldı — websecure.core.http:hardened_session() kullanılır

def silence_insecure_request_warnings() -> None:
    try:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    except (ImportError, AttributeError):
        pass

# ========================== URL & Scheme ==========================
def _host_of_url(url: str) -> str:
    return urlsplit(url).hostname or ""

def _port_of_url(url: str) -> int:
    s = urlsplit(url)
    if s.port:
        return s.port
    return 443 if s.scheme == "https" else 80

def _tcp_open(host: str, port: int, timeout: int) -> bool:
    try:
        fam = socket.AF_INET6 if ":" in host else socket.AF_INET
        sock = socket.socket(fam, socket.SOCK_STREAM)
        sock.settimeout(max(1, int(timeout)))
        code = sock.connect_ex((host, port))
        sock.close()
        return code == 0
    except Exception as exc:
        return False

class SchemeDetectionResult:
    def __init__(self, scheme: str, final_url: str, reason: str):
        self.scheme = scheme
        self.final_url = final_url
        self.reason = reason

def detect_canonical_scheme(u: str, timeout: int = 6) -> SchemeDetectionResult:
    # Simplified logic extracted from original
    # Note: Full IDN normalization logic should be imported from text.py if needed, 
    # but for basic net operations we use standard urlparse
    if "://" not in u:
        u = "http://" + u # temporary for parsing
        
    p = urlparse(u)
    host = p.hostname or p.path
    path = p.path if p.hostname else "/"
    
    # Try HTTPS (Head)
    try:
        if requests:
            target = f"https://{host}{path}"
            r = requests.head(target, timeout=timeout, verify=False, allow_redirects=True)
            if r.status_code < 400:
                return SchemeDetectionResult("https", r.url, "HTTPS Accessible")
    except Exception as exc:
        pass

    # Try HTTP (Head)
    try:
        if requests:
            target = f"http://{host}{path}"
            r = requests.head(target, timeout=timeout, allow_redirects=True)
            if r.status_code < 400:
                if urlparse(r.url).scheme == "https":
                    return SchemeDetectionResult("https", r.url, "HTTP Redirects to HTTPS")
                return SchemeDetectionResult("http", r.url, "HTTP Accessible")
    except Exception as exc:
        pass
        
    return SchemeDetectionResult("http", f"http://{host}{path}", "Fallback")

def apply_detected_scheme(u: str, timeout: int = 6) -> str:
    res = detect_canonical_scheme(u, timeout=timeout)
    return res.final_url

def http_to_ws(url: str) -> str:
    if not url: return url
    if url.startswith("https://"): return "wss://" + url[len("https://"):]
    if url.startswith("http://"): return "ws://" + url[len("http://"):]
    return url

# ========================== POC Generators ==========================
def make_curl_poc(method: str, url: str, headers: Mapping[str, Any] = None, body: Any = None) -> str:
    m = (method or "GET").upper()
    cmds = [f"curl -i -sS -X {m}"]
    if headers:
        for k, v in headers.items():
            cmds.append(f"-H '{k}: {v}'")
    if body:
        cmds.append(f"--data '{body}'")
    cmds.append(f"'{url}'")
    return " ".join(cmds)

def allowed_http_methods() -> List[str]:
    return ["GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD", "PATCH", "TRACE", "CONNECT"]

def build_raw_http_request(method: str, url: str, headers: Dict[str, str], body: Optional[str] = None) -> str:
    parsed = urlparse(url)
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
        
    req = [f"{method} {path} HTTP/1.1"]
    req.append(f"Host: {parsed.netloc}")
    
    for k, v in headers.items():
        req.append(f"{k}: {v}")
        
    req.append("")
    if body:
        req.append(body)
        
    return "\r\n".join(req)

def build_response_head(status_code: int, reason: str, headers: Dict[str, str], protocol: str = "HTTP/1.1") -> str:
    res = [f"{protocol} {status_code} {reason}"]
    for k, v in headers.items():
        res.append(f"{k}: {v}")
    return "\r\n".join(res) + "\r\n"

def normalize_url(url: str) -> str:
    from urllib.parse import urlparse, urlunparse
    p = urlparse(url)
    return urlunparse(p)

def resolve_canonical_base(url: str) -> str:
    return normalize_url(url)

# ========================== Missing Helpers for Crawler ==========================
def canonicalize_url(url: str) -> str:
    return normalize_url(url)

def same_origin(url_a: str, url_b: str) -> bool:
    try:
        from urllib.parse import urlparse
        if not url_a or not url_b: return False
        pa = urlparse(url_a)
        pb = urlparse(url_b)
        # Port handling: if None, infer from scheme
        pa_port = pa.port or (443 if pa.scheme == "https" else 80)
        pb_port = pb.port or (443 if pb.scheme == "https" else 80)
        return (pa.scheme, pa.hostname, pa_port) == (pb.scheme, pb.hostname, pb_port)
    except Exception as exc:
        return False

def is_static_asset(url: str) -> bool:
    from urllib.parse import urlparse
    path = (urlparse(url).path or "").lower()
    # Common static extensions
    exts = (
        ".css", ".js", ".jpg", ".jpeg", ".png", ".gif", ".svg", ".ico", ".webp",
        ".woff", ".woff2", ".ttf", ".eot", ".otf",
        ".mp4", ".webm", ".mp3", ".wav",
        ".pdf", ".zip", ".tar", ".gz"
    )
    return path.endswith(exts)

def run_content_discovery(url, cfg, results, timeout=900, debug=False, call_timeout=900.0):
    """
    Legacy wrapper for main.py compatibility.
    Redirects to flow_runner.run_discovery_extended with a context object.
    """
    try:
        from websecure.core.phases import run_discovery_extended
        from websecure.core.http import hardened_session # Need session
        
        # Emulate context
        class Ctx: pass
        ctx = Ctx()
        ctx.url = url
        ctx.target = url
        ctx.config = cfg
        ctx.results = results
        ctx.debug = debug
        # Create a temporary session if needed, although discovery usually needs a pre-configured one.
        # But here we just create a fresh one to avoid errors.
        ctx.session = hardened_session()
        
        run_discovery_extended(ctx)
    except Exception as e:
        # Log error but don't crash main
        if debug:
            print(f"[run_content_discovery] Wrapper error: {e}")
        pass

def validate_url(url: str) -> Tuple[bool, Optional[str], Optional[str]]:
    try:
        from urllib.parse import urlparse
        p = urlparse(url)
        if p.scheme and p.netloc:
            return True, url, p.scheme
        return False, None, None
    except Exception as exc:
        return False, None, None
