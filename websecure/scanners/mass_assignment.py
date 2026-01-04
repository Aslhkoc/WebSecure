from typing import Any, Dict, List, Optional
import requests
import json
import logging
from urllib.parse import urlparse

# Module-level logger
logger = logging.getLogger(__name__)

# Common sensitive fields to probe for Mass Assignment / Auto-Binding
SENSITIVE_KEYS = [
    "is_admin", "isAdmin", "admin", "role", "roles", 
    "account_type", "type", "is_superuser", "superuser",
    "permissions", "perms", "group", "groups",
    "balance", "credit", "is_verified", "verified"
]

SENSITIVE_VALUES = [
    True, "admin", "administrator", "superuser", "root", 999999
]

def run(url: str, session=None, debug: bool = False, auth_ctx=None) -> List[Dict[str, Any]]:
    """
    Scans for Mass Assignment vulnerabilities by attempting to inject sensitive 
    parameters into POST/PUT requests and observing reflections or state changes.
    """
    results = []
    
    if not session:
        session = requests.Session()

    # Pre-flight: Identify if this looks like an API/Form endpoint
    # Note: In a real flow, 'run' might be called with a specific context (like a previously discovered form).
    # Since we are just given a URL, we will try to probe it effectively if it supports POST/PUT.

    # 1. Probe for POST behavior with a dummy payload to see baseline
    try:
        # Check specific HTTP methods that are state-changing
        methods_to_test = ["POST", "PUT", "PATCH"]
        
        for method in methods_to_test:
            _scan_method(url, session, method, results, debug)

    except Exception as e:
        logger.debug(f"Mass assignment scan error on {url}: {e}")
        if debug:
            logger.exception("Mass assignment detailed error")

    return results

def _scan_method(url: str, session, method: str, results: list, debug: bool):
    """
    Helper to execute mass assignment checks for a specific HTTP method.
    """
    # Baseline request (empty or valid-looking small payload)
    baseline_payload = {"user": "test", "name": "test"}
    
    try:
        if method == "POST":
            resp_base = session.post(url, json=baseline_payload, timeout=5)
        elif method == "PUT":
            resp_base = session.put(url, json=baseline_payload, timeout=5)
        elif method == "PATCH":
            resp_base = session.patch(url, json=baseline_payload, timeout=5)
        else:
            return

        # If 404 Not Found or 405 Method Not Allowed, skip
        if resp_base.status_code in (404, 405):
            return

    except requests.RequestException:
        # Connection failed or so, skip
        return

    # 2. Injection Phase
    # We will try to send a payload that includes SENSITIVE_KEYS and see if the response
    # differs significantly or reflects the key.
    
    for key in SENSITIVE_KEYS:
        for val in SENSITIVE_VALUES:
            attack_payload = baseline_payload.copy()
            attack_payload[key] = val
            
            try:
                if method == "POST":
                    resp_attack = session.post(url, json=attack_payload, timeout=5)
                elif method == "PUT":
                    resp_attack = session.put(url, json=attack_payload, timeout=5)
                elif method == "PATCH":
                    resp_attack = session.patch(url, json=attack_payload, timeout=5)
                else:
                    continue

                # Analysis Phase
                analyze_response(url, method, key, val, resp_base, resp_attack, results)

            except requests.RequestException:
                continue

def analyze_response(url: str, method: str, key: str, val: Any, base_resp, attack_resp, results: list):
    """
    Compares baseline response vs attack response to decide if Mass Assignment happened.
    """
    # 1. Reflection Check (Fastest)
    # If the response is JSON, and it contains our injected key AND value, 
    # and the baseline did NOT contain that key (or contained a default), it's a strong lead.
    
    if attack_resp.status_code >= 500:
        # Skip server errors generally, unless we want to flag fragility
        return

    try:
        base_json = base_resp.json()
    except:
        base_json = {}

    try:
        attack_json = attack_resp.json()
    except:
        # If not JSON, maybe just grep text
        attack_json = None

    if isinstance(attack_json, dict):
        # Structured check
        if key in attack_json:
            reflected_val = attack_json[key]
            # Normalization for strict checking
            if str(reflected_val).lower() == str(val).lower():
                # We found the value! Was it in baseline?
                if key not in base_json or str(base_json[key]).lower() != str(val).lower():
                    # It was NOT in baseline (or different), so we successfully injected it into the response.
                    # This implies Mass Assignment / Auto-Binding success.
                    results.append({
                        "type": "mass_assignment",
                        "severity": "high",
                        "url": url,
                        "method": method,
                        "message": f"Possible Mass Assignment: Parameter '{key}' was successfully reflected with value '{val}'.",
                        "details": f"Injected '{key}': '{val}' and server returned it in JSON response. Verify if this persists."
                    })
    else:
        # Text check fallback
        if str(val) in attack_resp.text and key in attack_resp.text:
            # Weaker signal, but worth noting if baseline didn't have it
            if str(val) not in base_resp.text:
                results.append({
                    "type": "mass_assignment",
                    "severity": "medium",
                    "url": url,
                    "method": method,
                    "message": f"Potential Mass Assignment (Text Reflection): '{key}' appeared in response.",
                    "details": f"Response text contained injected value '{val}' for key '{key}'."
                })
