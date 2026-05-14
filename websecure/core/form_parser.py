from __future__ import annotations
import json
import re
import urllib.parse
from urllib.parse import urljoin
from typing import Any, Dict, List, Optional, Set

# [WS3] Integration of AdvancedFormFuzzer logic
def extract_all_forms(html_content: str, base_url: str) -> List[Dict[str, Any]]:
    """
    Extracts all forms and dynamic inputs using robust regex logic.
    Integrates user's AdvancedFormFuzzer logic (script extraction).
    """
    forms = []
    
    # 1. Standard HTML Forms
    # <form ...> ... </form>
    # Using regex as requested (BeautifulSoup optional but regex handles broken HTML well for fuzzing)
    form_tags = re.finditer(r"<form(.*?)>(.*?)</form>", html_content, re.IGNORECASE | re.DOTALL)
    
    for match in form_tags:
        attrs_str = match.group(1)
        inner_html = match.group(2)
        
        # Extract action
        action_match = re.search(r'action=["\']([^"\']+)["\']', attrs_str, re.IGNORECASE)
        raw_action = action_match.group(1) if action_match else ""
        action = urljoin(base_url, raw_action)
        
        # Extract method
        method_match = re.search(r'method=["\']([^"\']+)["\']', attrs_str, re.IGNORECASE)
        method = (method_match.group(1) if method_match else "GET").upper()
        
        # Extract inputs
        inputs = []
        # <input ...>
        for im in re.finditer(r"<input(.*?)>", inner_html, re.IGNORECASE):
            i_attrs = im.group(1)
            name_m = re.search(r'name=["\']([^"\']+)["\']', i_attrs, re.IGNORECASE)
            type_m = re.search(r'type=["\']([^"\']+)["\']', i_attrs, re.IGNORECASE)
            val_m = re.search(r'value=["\']([^"\']+)["\']', i_attrs, re.IGNORECASE)
            
            if name_m:
                inputs.append({
                    "name": name_m.group(1),
                    "type": (type_m.group(1) if type_m else "text").lower(),
                    "value": val_m.group(1) if val_m else ""
                })
        
        # <textarea ...>
        for tm in re.finditer(r"<textarea(.*?)name=[\"']([^\"']+)[\"']", inner_html, re.IGNORECASE):
            inputs.append({"name": tm.group(2), "type": "textarea"})
            
        # <select ...>
        for sm in re.finditer(r"<select(.*?)name=[\"']([^\"']+)[\"']", inner_html, re.IGNORECASE):
            inputs.append({"name": sm.group(2), "type": "select"})

        if inputs:
            forms.append({
                "action": action,
                "method": method,
                "inputs": inputs
            })

    # 2. Dynamic/Script Inputs (User's Logic)
    # Javascript patterns often reveal hidden API params or client-side logic inputs
    scripts = re.findall(r"<script[^>]*>(.*?)</script>", html_content, re.DOTALL | re.IGNORECASE)
    for script_content in scripts:
        if not script_content: continue
        
        # Common patterns: name="foo", data: { foo: bar }
        # The user's specific regex: name=["']([^"']+)["']
        patterns = re.findall(r'name=["\']([^"\']+)["\']', script_content)
        
        # Also look for simplified JSON keys? Maybe too noisy. Stick to user request.
        
        known_names = set()
        for f in forms:
            for i in f["inputs"]:
                known_names.add(i["name"])
        
        new_inputs = []
        for p in patterns:
            # Filter out common false positives (meta tags, charset, etc usually not in script but be careful)
            if p not in known_names and len(p) < 30 and " " not in p:
                new_inputs.append({"name": p, "type": "text", "value": "1"})
        
        if new_inputs:
            # Group these into a "virtual" form targeting base_url
            forms.append({
                "action": base_url, # Assume current page
                "method": "GET", # Assume GET or generic probe
                "inputs": new_inputs,
                "is_virtual": True
            })

    return forms


# ---------------------------------------------------------------------------
# Numeric / price / quantity field classifier
# ---------------------------------------------------------------------------
_PRICE_NAMES = re.compile(
    r"(price|cost|amount|total|fee|charge|rate|value|qty|quantity|"
    r"count|num|number|limit|discount|tax|sum|balance|credit|debit|"
    r"fiyat|miktar|tutar|adet)",
    re.I,
)

def _classify_input(inp: Dict[str, Any]) -> Dict[str, Any]:
    """Annotate an input dict with extra metadata used by fuzzers."""
    name = inp.get("name", "")
    itype = inp.get("type", "text").lower()

    inp = dict(inp)  # shallow copy
    inp.setdefault("injectable", True)

    # Price / quantity — flag for integer overflow, negative value, float tricks
    if itype in ("number", "range") or _PRICE_NAMES.search(name):
        inp["field_class"] = "numeric"
        inp["fuzz_hints"]  = ["negative", "zero", "overflow", "float_trick", "sql"]

    elif itype == "password":
        inp["field_class"] = "password"
        inp["fuzz_hints"]  = ["sql", "xss", "ssti", "long_string"]

    elif itype == "email":
        inp["field_class"] = "email"
        inp["fuzz_hints"]  = ["sql", "xss", "ssrf_email"]

    elif itype == "file":
        inp["field_class"] = "file_upload"
        inp["fuzz_hints"]  = ["malicious_ext", "webshell", "xxe_xml", "svg_xss"]
        inp["injectable"]  = False  # handled separately

    elif itype == "hidden":
        inp["field_class"] = "hidden"
        inp["fuzz_hints"]  = ["sql", "xss", "idor", "csrf_token_test"]

    else:
        inp["field_class"] = "text"
        inp["fuzz_hints"]  = ["sql", "xss", "ssti", "crlf", "path_traversal"]

    return inp


# ---------------------------------------------------------------------------
# URL parameter extraction
# ---------------------------------------------------------------------------

def extract_url_params(url: str) -> List[Dict[str, Any]]:
    """
    Parse the query string of *url* and return each key=value pair as a
    fuzzable input descriptor.

    Returns a list of dicts:
        [{"name": "id", "type": "url_param", "value": "1", ...}, ...]
    """
    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    inputs = []
    for name, value in params:
        inp = {
            "name":   name,
            "type":   "url_param",
            "value":  value,
            "source": "url_query",
        }
        inputs.append(_classify_input(inp))
    return inputs


# ---------------------------------------------------------------------------
# JSON body field extraction
# ---------------------------------------------------------------------------

def extract_json_fields(
    body: str,
    *,
    parent_key: str = "",
    depth: int = 0,
    max_depth: int = 5,
) -> List[Dict[str, Any]]:
    """
    Recursively extract all leaf key-value pairs from a JSON body string.

    Returns a flat list of input descriptors for fuzzing:
        [{"name": "user.email", "type": "json_field", "value": "a@b.com", ...}]
    """
    if depth > max_depth:
        return []
    try:
        obj = json.loads(body)
    except (json.JSONDecodeError, TypeError):
        return []

    def _flatten(node: Any, prefix: str) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []
        if isinstance(node, dict):
            for k, v in node.items():
                full_key = f"{prefix}.{k}" if prefix else k
                if isinstance(v, (dict, list)):
                    results.extend(_flatten(v, full_key))
                else:
                    inp = {
                        "name":   full_key,
                        "type":   "json_field",
                        "value":  str(v) if v is not None else "",
                        "source": "json_body",
                        "json_type": type(v).__name__,
                    }
                    results.append(_classify_input(inp))
        elif isinstance(node, list):
            for i, item in enumerate(node[:10]):  # cap to first 10 items
                results.extend(_flatten(item, f"{prefix}[{i}]"))
        return results

    return _flatten(obj, parent_key)


# ---------------------------------------------------------------------------
# Cookie extraction
# ---------------------------------------------------------------------------

def extract_cookie_params(cookie_header: str) -> List[Dict[str, Any]]:
    """
    Parse a Cookie header string and return each name=value pair as a
    fuzzable input descriptor.

        extract_cookie_params("session=abc123; lang=en; cart_id=99")
        -> [{"name": "session", "type": "cookie", ...}, ...]
    """
    inputs = []
    for part in cookie_header.split(";"):
        part = part.strip()
        if "=" in part:
            name, _, value = part.partition("=")
            inp = {
                "name":   name.strip(),
                "type":   "cookie",
                "value":  value.strip(),
                "source": "cookie_header",
            }
            inputs.append(_classify_input(inp))
    return inputs


# ---------------------------------------------------------------------------
# Injectable HTTP header detection
# ---------------------------------------------------------------------------

# Headers commonly used in auth, routing, and origin checks — prime injection targets
_INJECTABLE_HEADERS: List[Dict[str, Any]] = [
    {"name": "Authorization",       "type": "header", "value": "Bearer test",    "fuzz_hints": ["jwt_forge", "sql", "ssti"]},
    {"name": "X-Forwarded-For",     "type": "header", "value": "127.0.0.1",      "fuzz_hints": ["ssrf", "sql", "ip_spoof"]},
    {"name": "X-Real-IP",           "type": "header", "value": "127.0.0.1",      "fuzz_hints": ["ip_spoof", "sql"]},
    {"name": "X-Original-URL",      "type": "header", "value": "/admin",         "fuzz_hints": ["path_traversal", "auth_bypass"]},
    {"name": "X-Rewrite-URL",       "type": "header", "value": "/admin",         "fuzz_hints": ["path_traversal", "auth_bypass"]},
    {"name": "Host",                "type": "header", "value": "evil.internal",   "fuzz_hints": ["ssrf", "host_header_injection"]},
    {"name": "Referer",             "type": "header", "value": "https://evil.com","fuzz_hints": ["sql", "xss", "open_redirect"]},
    {"name": "User-Agent",          "type": "header", "value": "pentest",         "fuzz_hints": ["sql", "xss", "ssti"]},
    {"name": "Content-Type",        "type": "header", "value": "application/json","fuzz_hints": ["content_type_confusion"]},
    {"name": "X-Api-Key",           "type": "header", "value": "test",            "fuzz_hints": ["sql", "auth_bypass"]},
    {"name": "X-Custom-IP-Authorization", "type": "header", "value": "127.0.0.1","fuzz_hints": ["ip_spoof", "auth_bypass"]},
    {"name": "X-HTTP-Method-Override", "type": "header", "value": "DELETE",      "fuzz_hints": ["method_override"]},
]

def get_injectable_headers() -> List[Dict[str, Any]]:
    """Return the standard list of injection-worthy HTTP headers."""
    return [dict(h) for h in _INJECTABLE_HEADERS]


# ---------------------------------------------------------------------------
# Unified input extractor — THE main entry point for scanners
# ---------------------------------------------------------------------------

def extract_all_inputs(
    html_content: str,
    base_url: str,
    *,
    response_body: str = "",
    cookie_header: str = "",
    include_headers: bool = True,
) -> Dict[str, List[Dict[str, Any]]]:
    """
    Extract ALL fuzzable input vectors from a page.

    Returns a dict with keys:
        "forms"    — list of HTML form dicts (action, method, inputs[])
        "url_params" — URL query-string parameters
        "json_fields" — fields extracted from JSON body (API responses)
        "cookies"  — cookie name=value pairs
        "headers"  — injectable HTTP headers (always returned if include_headers)

    Each input in "url_params", "json_fields", "cookies" is annotated with
    field_class and fuzz_hints by _classify_input().
    Each form input is also annotated.
    """
    # HTML forms (existing logic + classification)
    raw_forms = extract_all_forms(html_content, base_url)
    for form in raw_forms:
        form["inputs"] = [_classify_input(inp) for inp in form.get("inputs", [])]

    # URL parameters from base_url
    url_params = extract_url_params(base_url)

    # JSON fields (try both response body and page content)
    json_fields: List[Dict[str, Any]] = []
    for candidate in (response_body, html_content):
        if candidate and candidate.lstrip().startswith(("{", "[")):
            json_fields = extract_json_fields(candidate)
            if json_fields:
                break

    # Cookies
    cookies = extract_cookie_params(cookie_header) if cookie_header else []

    # Injectable headers
    headers = get_injectable_headers() if include_headers else []

    return {
        "forms":       raw_forms,
        "url_params":  url_params,
        "json_fields": json_fields,
        "cookies":     cookies,
        "headers":     headers,
    }
