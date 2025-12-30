import os
import re
import socket
import ssl
import time
import json
import logging
from urllib.parse import urlparse, urlunparse, urljoin, parse_qsl, urlencode, urlsplit
from typing import Dict, Any, List, Optional, Union, Tuple, Mapping

try:
    import requests
    from requests.adapters import HTTPAdapter
    from requests.packages.urllib3.util.retry import Retry
except ImportError:
    requests = None
    HTTPAdapter = object
    Retry = object

# ========================== Constants ==========================
_BROWSER_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/119 Safari/537.36"
)

# ========================== HTTP Session ==========================
class _TimeoutHTTPAdapter(HTTPAdapter):
    def __init__(self, *args, **kwargs):
        self.timeout = kwargs.pop("timeout", 20)
        super().__init__(*args, **kwargs)

    def send(self, request, **kwargs):
        timeout = kwargs.get("timeout")
        if timeout is None:
            kwargs["timeout"] = self.timeout
        return super().send(request, **kwargs)

def hardened_session(
    proxies: Dict[str, str] = None,
    verify: bool = False,
    timeout: int = 20,
    retries: int = 2,
    backoff_factor: float = 0.5,
    pool_connections: int = 10,
    pool_maxsize: int = 10,
    user_agent: str = None
) -> "requests.Session":
    if requests is None:
        raise ImportError("requests library is required for hardened_session")

    s = requests.Session()
    
    # Retry strategy
    retry_strategy = Retry(
        total=retries,
        backoff_factor=backoff_factor,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["HEAD", "GET", "OPTIONS", "POST", "PUT", "DELETE"]
    )
    
    adapter = _TimeoutHTTPAdapter(
        timeout=timeout,
        max_retries=retry_strategy,
        pool_connections=pool_connections,
        pool_maxsize=pool_maxsize
    )
    
    s.mount("https://", adapter)
    s.mount("http://", adapter)
    
    s.verify = verify
    if proxies:
        s.proxies.update(proxies)
        
    s.headers.update({
        "User-Agent": user_agent or _BROWSER_UA,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1"
    })
    
    return s

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
    except Exception:
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
    except Exception:
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
    except Exception:
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
