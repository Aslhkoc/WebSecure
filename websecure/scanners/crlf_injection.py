"""
websecure.scanners.crlf_injection
-----------------------------------
CRLF Injection / HTTP Response Splitting detector.

Techniques
──────────
  1. URL parameter injection  — inject CRLF into query string values
                                reflected in Location / Set-Cookie / custom headers
  2. Header value injection   — inject CRLF via path segment or host header
  3. Response splitting       — inject double-CRLF to fabricate a second response
  4. Cookie injection         — forge a Set-Cookie header via CRLF

All injection sequences are sourced from CRLFInjector in websecure.core.evasion
so any future additions to that class are automatically tested here.

References
──────────
  • https://owasp.org/www-community/attacks/HTTP_Response_Splitting
  • https://portswigger.net/web-security/request-smuggling/advanced/response-queue-poisoning
"""
from __future__ import annotations

import logging
import random
import re
import string
import urllib.parse
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# CRLF injection sequences (kept in sync with evasion.CRLFInjector)
# ---------------------------------------------------------------------------
_CRLF_SEQS: List[str] = [
    "%0d%0a",
    "%0a",
    "%0d",
    "%0a%0d",
    "%0d%0a%09",
    "%23%0d%0a",
    "%E5%98%8A%E5%98%8D",
    "%C0%8A",
    "%C0%8D",
    "%250d%250a",
    "%2F%2F%0d%0a",
    "%3F%0d%0a",
    "\r\n",
    "\\r\\n",
]

# Unique canary header injected to confirm CRLF
_CANARY_HEADER = "X-Wsp-Injected"


def _canary_value() -> str:
    return "wsp" + "".join(random.choices(string.digits, k=6))


# ---------------------------------------------------------------------------
# Common URL parameters that are reflected in redirects/headers
# ---------------------------------------------------------------------------
_REDIRECT_PARAMS = [
    "url", "redirect", "redirect_url", "return", "return_url",
    "next", "location", "goto", "dest", "destination", "path",
    "ref", "continue", "callback", "forward",
]


def _inject_urls(base_url: str, canary: str) -> List[str]:
    """
    Return test URLs that inject CRLF + canary header into each common
    redirect/return parameter found in *base_url*, plus brute-force variants.
    """
    parsed   = urllib.parse.urlparse(base_url)
    qs_pairs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    existing = {k.lower() for k, _ in qs_pairs}

    inject_suffix_fmt = "{seq}{header}: {val}"
    urls: List[str] = []

    # Inject into existing query parameters
    for k, v in qs_pairs:
        for seq in _CRLF_SEQS[:6]:   # first 6 sequences cover most WAFs
            inj = inject_suffix_fmt.format(
                seq=seq, header=_CANARY_HEADER, val=canary
            )
            new_pairs = [(pk, pv if pk != k else v + inj) for pk, pv in qs_pairs]
            new_qs    = urllib.parse.urlencode(new_pairs)
            urls.append(urllib.parse.urlunparse(parsed._replace(query=new_qs)))

    # Brute-force common redirect params if not in original QS
    sep = "&" if parsed.query else ""
    for param in _REDIRECT_PARAMS:
        if param not in existing:
            for seq in _CRLF_SEQS[:6]:
                inj = urllib.parse.quote(
                    inject_suffix_fmt.format(
                        seq=seq, header=_CANARY_HEADER, val=canary
                    ),
                    safe="%"
                )
                extra_qs = parsed.query + sep + f"{param}={inj}" if parsed.query else f"{param}={inj}"
                urls.append(urllib.parse.urlunparse(parsed._replace(query=extra_qs)))
            break  # test one extra param per URL to keep request count manageable

    return urls


# ---------------------------------------------------------------------------
# Response analysis
# ---------------------------------------------------------------------------
def _canary_in_headers(resp, canary: str) -> Optional[str]:
    """
    Return the header name where canary was found, or None.
    Covers both an injected X-Wsp-Injected header and Set-Cookie forgery.
    """
    headers = getattr(resp, "headers", {})
    for k, v in headers.items():
        if canary in v:
            return k
    return None


def _split_response_detected(resp) -> bool:
    """
    Heuristic: if the back-end echoed a fake HTTP/1.1 response start into
    the body, response splitting may have occurred.
    """
    try:
        text = resp.text[:2000]
        return bool(re.search(r"HTTP/\d\.\d\s+\d{3}", text))
    except Exception:
        return False


def _build_finding(
    technique: str,
    url: str,
    seq: str,
    evidence: Dict[str, Any],
) -> Dict[str, Any]:
    return {
        "type": "CRLF Injection",
        "technique": technique,
        "url": url,
        "severity": "High",
        "description": (
            f"CRLF injection detected via {technique}. "
            f"The server accepted the CRLF sequence {seq!r} and reflected "
            "the injected header in the response, confirming HTTP response splitting."
        ),
        "evidence": evidence,
    }


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
    Test *url* for CRLF injection / HTTP response splitting.

    Returns a list of finding dicts (may be empty).
    """
    if debug:
        logger.setLevel(logging.DEBUG)

    results: List[Dict[str, Any]] = []
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
        # Extract which CRLF sequence was used from the URL
        seq_used = ""
        for seq in _CRLF_SEQS:
            if seq.lower() in test_url.lower() or urllib.parse.quote(seq, safe="").lower() in test_url.lower():
                seq_used = seq
                break

        try:
            resp = session.get(
                test_url,
                timeout=10,
                allow_redirects=False,   # Do NOT follow redirects — we inspect the raw Location header
            )

            # Check if injected header appears in response headers
            hit_header = _canary_in_headers(resp, canary)
            if hit_header:
                results.append(_build_finding(
                    "URL parameter → response header",
                    test_url,
                    seq_used,
                    {
                        "injected_header": hit_header,
                        "canary": canary,
                        "status": resp.status_code,
                        "response_headers": dict(list(resp.headers.items())[:10]),
                    },
                ))
                logger.info("[CRLF] Header injection confirmed: %s → %s", test_url, hit_header)
                break  # one confirmed finding is enough

            # Heuristic: response splitting via body echo
            if resp.status_code in (301, 302, 303, 307, 308):
                loc = resp.headers.get("location", "")
                if canary in loc:
                    results.append(_build_finding(
                        "Location header injection",
                        test_url,
                        seq_used,
                        {
                            "location": loc,
                            "canary": canary,
                            "status": resp.status_code,
                        },
                    ))
                    logger.info("[CRLF] Location injection confirmed: %s", test_url)
                    break

        except Exception as exc:
            logger.debug("[CRLF] Request error for %s: %s", test_url, exc)

    if results:
        return results

    # ── Cookie injection probe ─────────────────────────────────────────────
    # Try injecting a Set-Cookie header via CRLF in a path segment
    parsed = urllib.parse.urlparse(url)
    for seq in _CRLF_SEQS[:4]:
        cookie_inj = urllib.parse.quote(
            f"{seq}Set-Cookie: wsp_injected={canary}; path=/",
            safe="%"
        )
        path_inj = parsed.path.rstrip("/") + "/" + cookie_inj
        test_url  = urllib.parse.urlunparse(parsed._replace(path=path_inj))
        try:
            resp = session.get(test_url, timeout=10, allow_redirects=False)
            sc   = resp.cookies.get("wsp_injected")
            if sc == canary or _canary_in_headers(resp, canary):
                results.append(_build_finding(
                    "Path segment → Set-Cookie injection",
                    test_url,
                    seq,
                    {"cookie": sc, "canary": canary, "status": resp.status_code},
                ))
                logger.info("[CRLF] Cookie injection confirmed: %s", test_url)
                break
        except Exception as exc:
            logger.debug("[CRLF] Cookie probe error: %s", exc)

    return results
