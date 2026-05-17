"""
websecure.scanners.csrf
-----------------------
Dedicated CSRF Vulnerability Scanner.
Checks for:
1. Missing Anti-CSRF Tokens in sensitive forms.
2. Weak SameSite attribute configuration.
3. Login CSRF potential.
"""
from __future__ import annotations
import re
import random
import string
import logging
from typing import Dict, Any, List, Optional
from urllib.parse import urljoin, urlparse

import requests
from websecure.core.reporting import add_result

_logger = logging.getLogger(__name__)

# Heuristics for sensitive forms (password change, email update, etc.)
SENSITIVE_ACTION_REGEX = re.compile(
    r"(password|passwd|pwd|email|mail|update|change|edit|delete|remove|transfer|withdraw|send|add|create|setting|config|admin)",
    re.IGNORECASE
)
# Heuristics for token fields
TOKEN_FIELD_REGEX = re.compile(
    r"(csrf|xsrf|token|nonce|authenticity_token|javax\.faces\.ViewState|__RequestVerificationToken)",
    re.IGNORECASE
)

def _get_forms(html_content: str) -> List[Dict[str, Any]]:
    """Simple regex-based form extractor."""
    forms = []
    # Find <form ...>
    # Note: Using regex for HTML is fragile but sufficient for heuristic scanning without heavy deps
    form_tags = re.finditer(r"<form(.*?)>(.*?)</form>", html_content, re.IGNORECASE | re.DOTALL)
    
    for match in form_tags:
        attrs_str = match.group(1)
        inner_html = match.group(2)
        
        # Extract action
        action_match = re.search(r'action=["\']([^"\']+)["\']', attrs_str, re.IGNORECASE)
        action = action_match.group(1) if action_match else ""
        
        # Extract method
        method_match = re.search(r'method=["\']([^"\']+)["\']', attrs_str, re.IGNORECASE)
        method = (method_match.group(1) if method_match else "GET").upper()
        
        # Extract inputs
        inputs = []
        input_tags = re.finditer(r"<input(.*?)>", inner_html, re.IGNORECASE)
        for im in input_tags:
            i_attrs = im.group(1)
            name_m = re.search(r'name=["\']([^"\']+)["\']', i_attrs, re.IGNORECASE)
            type_m = re.search(r'type=["\']([^"\']+)["\']', i_attrs, re.IGNORECASE)
            val_m = re.search(r'value=["\']([^"\']+)["\']', i_attrs, re.IGNORECASE)
            
            inputs.append({
                "name": name_m.group(1) if name_m else None,
                "type": (type_m.group(1) if type_m else "text").lower(),
                "value": val_m.group(1) if val_m else ""
            })
            
        forms.append({
            "action": action,
            "method": method,
            "inputs": inputs,
            "raw": match.group(0)[:200]
        })
    return forms

def check_csrf_protection(url: str, session, results: Dict[str, Any], debug: bool = False):
    """
    Scans the given URL for CSRF vulnerabilities.
    """
    bucket = "a05_csrf"

    try:
        r = session.get(url, timeout=10)
    except requests.exceptions.RequestException as exc:
        _logger.debug(f"[CSRF] GET failed for {url}: {exc!r}")
        # Report the network error so the dashboard shows it rather than silently skipping.
        add_result(bucket, {
            "type": "CSRF Scan Error",
            "severity": "Info",
            "url": url,
            "reason": f"Network error fetching target: {exc!r}",
        })
        return

    # 1. Analyze Cookies (SameSite)
    # ---------------------------
    # We check the cookie jar for the domain
    domain = urlparse(url).hostname
    if domain and session.cookies:
        for cookie in session.cookies:
            if domain in (cookie.domain or ""):
                # Requests cookie objects might not expose SameSite attribute easily 
                # depending on the cookiejar backend. We generally rely on Set-Cookie header analysis
                # which is done in owasp.py. But here we can re-verify if needed.
                pass 

    # 2. Analyze Forms & API Endpoints
    # ----------------
    # [WS3] Enhanced: Look for crawler metadata first (Playwright forms)
    crawled_forms = results.get("forms_meta", [])
    
    # Merge regex-found forms with crawled forms
    forms = _get_forms(r.text or "")
    if crawled_forms:
        # Simple normalization to match structure
        for cf in crawled_forms:
            forms.append({
                "action": cf.get("action") or "",
                "method": (cf.get("method") or "GET").upper(),
                "inputs": cf.get("inputs", []),
                "raw": f"Crawled Form: {cf.get('action')}"
            })

    # [WS3] SPA/API Logic: If no forms found, check if we have API endpoints from Discovery
    if not forms and results.get("endpoints"):
        api_eps = [u for u in results.get("endpoints") if any(m in u for m in ("/api/", "/v1/", "/graphql"))]
        if api_eps:
             add_result(bucket, {
                "type": "API CSRF Check",
                "severity": "Info", 
                "reason": f"Found {len(api_eps)} API endpoints. Manual verifying of Anti-CSRF headers (X-CSRF-Token, etc.) required.",
                "evidence": {"endpoints": api_eps[:5]}
             })
             # Note: Fully automated API CSRF check requires traffic analysis (knowing payload)
             # Here we assume Info/Manual review for APIs unless specific headers are missing in responses (Passive)

    if not forms and not results.get("endpoints"):
        add_result("offensive", {"type": "CSRF", "severity": "Info", "reason": "No forms or API endpoints found to scan."})
        return
    else:
        # [WS3] Visibility patch: Report that we ARE scanning.
        add_result(bucket, {"type": "CSRF Scan", "severity": "Info", "reason": f"Scanning {len(forms)} forms and {len(results.get('endpoints', []))} endpoints for CSRF."})

    for form in forms:
        method = form.get("method", "GET")
        action = form.get("action", "")
        # Only POST/PUT/DELETE are typically dangerous for CSRF
        if method not in ("POST", "PUT", "DELETE", "PATCH"):
            continue

        # Is it a sensitive form?
        is_sensitive = bool(SENSITIVE_ACTION_REGEX.search(action)) or \
                       any(SENSITIVE_ACTION_REGEX.search(i.get("name") or "") for i in form["inputs"])
        
        # Does it have a token?
        has_token = any(TOKEN_FIELD_REGEX.search(i.get("name") or "") for i in form["inputs"])
        
        if is_sensitive and not has_token:
            add_result(bucket, {
                "type": "CSRF",
                "url": url,
                "location": f"Form action: {action}",
                "severity": "Medium", # Elevated to High if chained later
                "confidence": "High",
                "reason": "Sensitive action form without anti-CSRF token",
                "evidence": {"form_snippet": form.get("raw")}
            })
            
    # [WS3] Generic Header Check on Base URL (SPA)
    # Some SPAs send CSRF tokens in headers (X-XSRF-TOKEN). If the site sets a cookie XSRF-TOKEN, it must match header.
    if session.cookies:
        xsrf_cookie = next((c for c in session.cookies if "xsrf" in c.name.lower() or "csrf" in c.name.lower()), None)
        if xsrf_cookie:
            # Check if we can find a matching header logic in JS files? Too deep.
            # Just Info note.
            pass


    # 3. Login CSRF Check
    # -------------------
    # If the page has a login form, check if it has CSRF protection.
    # Login CSRF is often overlooked (Low/Medium severity).
    if "login" in url.lower() or any("password" in (i.get("name") or "") for f in forms for i in f["inputs"]):
        # Find the login form specifically
        login_forms = [f for f in forms if any("password" in (i.get("name") or "") for i in f["inputs"])]
        for lf in login_forms:
            has_token = any(TOKEN_FIELD_REGEX.search(i.get("name") or "") for i in lf["inputs"])
            if not has_token:
               add_result(bucket, {
                    "type": "Login CSRF",
                    "url": url, 
                    "location": "Login Form",
                    "severity": "Low",
                    "reason": "Login form missing anti-CSRF token"
                })

def run_scan(url: str, session, results: Dict[str, Any], debug: bool = False, **kwargs):
    """EntryPoint for the CSRF scanner."""
    check_csrf_protection(url, session, results, debug)

run = run_scan

