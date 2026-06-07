import logging
from urllib.parse import urlparse, urlunparse
from typing import Dict, Any, List, Optional, Tuple, Mapping

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
    except (ImportError, AttributeError) as _fix_e:
        _logger.debug(f"[core.utils.net] {type(_fix_e).__name__}: {_fix_e!r}")

# ========================== URL & Scheme ==========================
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
        _logger.debug(f"[core.utils.net] {type(exc).__name__}: {exc!r}")

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
        _logger.debug(f"[core.utils.net] {type(exc).__name__}: {exc!r}")
        
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
    p = urlparse(url)
    return urlunparse(p)

def resolve_canonical_base(url: str) -> str:
    return normalize_url(url)

# ========================== Missing Helpers for Crawler ==========================
def canonicalize_url(url: str) -> str:
    return normalize_url(url)

def same_origin(url_a: str, url_b: str) -> bool:
    try:
        if not url_a or not url_b: return False
        pa = urlparse(url_a)
        pb = urlparse(url_b)
        # Port handling: if None, infer from scheme
        pa_port = pa.port or (443 if pa.scheme == "https" else 80)
        pb_port = pb.port or (443 if pb.scheme == "https" else 80)
        return (pa.scheme, pa.hostname, pa_port) == (pb.scheme, pb.hostname, pb_port)
    except Exception:
        return False

# Bilinen çok-parçalı second-level domain'ler (eTLD+1 sezgiseli için).
# PSL'in tam kopyası değil; analytics/ads gibi third-party gürültüsünü
# elemeye ve meşru alt-domain'leri (api.site.co.il) korumaya yeter.
_MULTI_PART_SLD = frozenset({
    "co", "com", "org", "net", "gov", "edu", "ac", "mil", "gob",
    "or", "ne", "go", "in", "biz", "info",
})


def registrable_domain(host: str) -> str:
    """
    Bir host adından kayıt-edilebilir alan adını (eTLD+1) sezgisel olarak çıkarır.
    'www.ynet.co.il' -> 'ynet.co.il', 'analytics.google.com' -> 'google.com'.
    PSL kullanmaz; çok-parçalı ccTLD'ler için _MULTI_PART_SLD sezgisini kullanır.
    """
    host = (host or "").lower().strip().strip(".")
    if not host:
        return ""
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    # 'example.co.il' / 'example.com.tr' gibi: son etiket 2 harf (ccTLD) ve
    # ondan önceki etiket bilinen bir SLD ise son 3 etiketi al.
    if len(labels[-1]) == 2 and labels[-2] in _MULTI_PART_SLD:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def same_site(url_a: str, url_b: str) -> bool:
    """
    İki URL'in aynı kayıt-edilebilir alan adına (site) ait olup olmadığını döner.
    Crawl/fuzz kapsamını hedef siteye sınırlamak için kullanılır; üçüncü-parti
    analytics/ads/tracking host'larını (analytics.google.com, doubleclick vb.)
    keşif havuzunun dışında tutar. same_origin'den daha gevşektir: alt-domain'lere
    (api.site.com) izin verir.
    """
    try:
        ha = urlparse(url_a).hostname or ""
        hb = urlparse(url_b).hostname or ""
        if not ha or not hb:
            return False
        rd_a = registrable_domain(ha)
        return bool(rd_a) and rd_a == registrable_domain(hb)
    except Exception:
        return False


def is_static_asset(url: str) -> bool:
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
        _logger.warning(f"[run_content_discovery] Wrapper error: {e!r}")

def validate_url(url: str) -> Tuple[bool, Optional[str], Optional[str]]:
    try:
        p = urlparse(url)
        if p.scheme and p.netloc:
            return True, url, p.scheme
        return False, None, None
    except Exception:
        return False, None, None
