"""
websecure.scanners.prototype_pollution
----------------------------------------
JavaScript Prototype Pollution vulnerability detector.

Techniques
----------
  1. JSON body injection  — POST/PUT with __proto__, constructor.prototype keys
  2. Query-string pollution — ?__proto__[x]=1, ?constructor[prototype][x]=1
  3. Deep-merge sink probe  — nested JSON objects that trigger polluted keys
  4. Reflected-property check — response body searched for canary value

References
----------
  • https://portswigger.net/web-security/prototype-pollution
  • https://github.com/nicehash/node-prototype-pollution-test
"""
from __future__ import annotations

import json
import logging
import random
import string
import urllib.parse
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Canary value — unique per scan run
# ---------------------------------------------------------------------------
def _canary() -> str:
    return "wsp_" + "".join(random.choices(string.ascii_lowercase, k=8))


# ---------------------------------------------------------------------------
# JSON body payloads
# ---------------------------------------------------------------------------
def _json_payloads(canary: str) -> List[Dict[str, Any]]:
    """Return a list of JSON bodies that attempt prototype pollution."""
    return [
        # Direct __proto__ key
        {"__proto__": {"polluted": canary}},

        # constructor.prototype path
        {"constructor": {"prototype": {"polluted": canary}}},

        # Nested merge target
        {"a": {"__proto__": {"polluted": canary}}},

        # Array-like deep merge
        {"__proto__": {"polluted": canary, "toString": canary}},

        # Lodash-style deep clone target
        {"level1": {"level2": {"__proto__": {"polluted": canary}}}},

        # Unicode key variant (__proto__ with zero-width space)
        {"\u200b__proto__\u200b": {"polluted": canary}},

        # Numeric prototype pollution
        {"__proto__": {"0": canary, "length": 1}},

        # constructor chain
        {"constructor": {"prototype": {"constructor": {"prototype": {"polluted": canary}}}}},
    ]


# ---------------------------------------------------------------------------
# Query-string payloads
# ---------------------------------------------------------------------------
_QS_TEMPLATES: List[str] = [
    "__proto__[polluted]={c}",
    "__proto__.polluted={c}",
    "constructor[prototype][polluted]={c}",
    "constructor.prototype.polluted={c}",
    "__proto__[toString]={c}",
    "a[__proto__][polluted]={c}",
    "a.__proto__.polluted={c}",
    "obj[__proto__][polluted]={c}",
    # URL-encoded variants
    "%5B__proto__%5D%5Bpolluted%5D={c}",
    "constructor%5Bprototype%5D%5Bpolluted%5D={c}",
]


def _qs_payloads(base_url: str, canary: str) -> List[str]:
    """Return URLs with prototype-pollution query strings appended."""
    sep = "&" if "?" in base_url else "?"
    urls = []
    for tmpl in _QS_TEMPLATES:
        param = tmpl.format(c=urllib.parse.quote(canary, safe=""))
        urls.append(base_url + sep + param)
    return urls


# ---------------------------------------------------------------------------
# Response analysis
# ---------------------------------------------------------------------------
def _canary_in_response(resp, canary: str) -> bool:
    """Return True if the canary appears in the response text."""
    try:
        text = resp.text if hasattr(resp, "text") else resp.content.decode("utf-8", "replace")
        return canary in text
    except Exception as exc:
        return False


def _build_finding(technique: str, url: str, payload: Any, canary: str) -> Dict[str, Any]:
    return {
        "type": "Prototype Pollution",
        "technique": technique,
        "url": url,
        "severity": "High",
        "description": (
            f"Prototype pollution candidate detected via {technique}. "
            f"Canary value '{canary}' was reflected in the response, indicating "
            "the injected __proto__ property may have been merged into a shared object."
        ),
        "evidence": {
            "payload": str(payload)[:300],
            "canary": canary,
        },
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
    Test *url* for prototype pollution vulnerabilities.

    Returns a list of finding dicts (may be empty).
    """
    if debug:
        logger.setLevel(logging.DEBUG)

    results: List[Dict[str, Any]] = []
    canary = _canary()

    if session is None:
        try:
            import requests
            session = requests.Session()
        except ImportError:
            logger.warning("[ProtoPollution] requests not available")
            return results

    # -- 1. JSON body injection ----------------------------------------------
    for payload in _json_payloads(canary):
        for method in ("POST", "PUT", "PATCH"):
            try:
                resp = session.request(
                    method,
                    url,
                    json=payload,
                    headers={"Content-Type": "application/json"},
                    timeout=10,
                    allow_redirects=True,
                )
                if _canary_in_response(resp, canary):
                    results.append(_build_finding(
                        f"JSON body ({method})", url, payload, canary
                    ))
                    logger.info("[ProtoPollution] JSON body hit on %s (%s)", url, method)
                    break  # One finding per technique is enough
            except Exception as exc:
                logger.debug("[ProtoPollution] JSON %s error: %s", method, exc)
        if results:
            break  # Stop after first confirmed finding

    if results:
        return results

    # -- 2. Query-string injection -------------------------------------------
    for test_url in _qs_payloads(url, canary):
        try:
            resp = session.get(test_url, timeout=10, allow_redirects=True)
            if _canary_in_response(resp, canary):
                results.append(_build_finding(
                    "Query-string parameter", test_url, test_url, canary
                ))
                logger.info("[ProtoPollution] QS hit: %s", test_url)
                break
        except Exception as exc:
            logger.debug("[ProtoPollution] QS error: %s", exc)

    if results:
        return results

    # -- 3. Deep-merge probe (JSON PATCH) -----------------------------------
    deep_payload = {
        "data": {
            "__proto__": {"polluted": canary},
            "constructor": {"prototype": {"polluted": canary}},
        }
    }
    try:
        resp = session.patch(
            url,
            json=deep_payload,
            headers={"Content-Type": "application/merge-patch+json"},
            timeout=10,
            allow_redirects=True,
        )
        if _canary_in_response(resp, canary):
            results.append(_build_finding(
                "JSON PATCH deep-merge", url, deep_payload, canary
            ))
    except Exception as exc:
        logger.debug("[ProtoPollution] PATCH probe error: %s", exc)

    return results
