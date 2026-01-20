from typing import Dict, Any, List, Optional
import time
import logging
from ..core.http import hardened_session
from ..core.reporting import add_result, redact_sensitive
from ..core.payloads import get_payloads
from ..core.input_analyzer import InputContext


class BaseScanner:
    """
    Standard base class for all WebSecure scanners.
    replaces legacy BaseCheck and standardizes result reporting.
    """
    name: str = "base"

    def __init__(self, session=None, results: Dict = None, debug: bool = False):
        self.session = session or hardened_session()
        self.results = results if results is not None else {}
        self.debug = debug
        self.logger = logging.getLogger(f"websecure.scanners.{self.name}")
        if debug:
            self.logger.setLevel(logging.DEBUG)

    def add(self, bucket: str, entry: Dict[str, Any]) -> None:
        """
        Add a finding to the results bucket.
        Handles redaction, enrichment (timestamp), and centralized logging.
        """
        # 1. Enrich
        if "timestamp" not in entry:
            entry["timestamp"] = time.time()
            
        # 2. Redact
        safe_entry = redact_sensitive(entry)
        
        # 3. Store
        if bucket not in self.results:
            self.results[bucket] = []
        self.results[bucket].append(safe_entry)
        
        # 4. Central Report & Alert (The Hook)
        from ..core.reporting import add_result
        add_result(bucket, safe_entry)

        # 5. Log
        sev = safe_entry.get("severity", "Info")
        msg = safe_entry.get("status") or safe_entry.get("issue")
        self.logger.debug(f"[{sev.upper()}] {bucket}: {msg}")

    def set_summary(self, bucket: str, count: int) -> None:
        self.results[f"{bucket}_summary"] = {"vulnerabilities": count}

    def get_smart_payloads(self, category: str, param_name: str, tech_stack: Optional[set] = None) -> List[str]:
        """
        Smart Payload Retriever:
        1. Checks if we have context for this parameter (from Crawler).
        2. Adjusts payload list based on context (e.g. Email -> less aggressive, Search -> XSS, ID -> SQLi).
        3. Uses technology stack if provided.
        """
        # 1. Try to get context
        contexts = self.results.get("param_contexts", {})
        ctx_result = contexts.get(param_name)
        
        # 2. Determine Tech Stack (merged from results or arg)
        if tech_stack is None:
            tech_stack = set(self.results.get("tech_stack", []))
            
        # 3. Fetch Payloads
        # If we have a specific context, we might want to prioritize certain payloads
        # For now, we rely on filter_by_technology inside get_payloads, 
        # but we can also use context-specific logic here.
        
        # Phase 2: Use input_analyzer's knowledge
        # If context says "NUMERIC_ID", maybe we append specific numeric SQLi payloads
        # If context says "EMAIL", maybe we avoid whitespace-heavy payloads
        
        # Basic: Just fetch standard payloads filtered by tech
        payloads = get_payloads(category, tech_tags=tech_stack)
        
        if ctx_result and self.debug:
            self.logger.debug(f"[SmartPayload] {param_name} ({ctx_result.context.name}) fetching {category} payloads.")
            
        return payloads

    def run(self, target: str, **kwargs) -> Any:
        raise NotImplementedError("Scanners must implement run()")

    def prepare_injection(self, url: str, param: str, payload: str, method: str = "GET", 
                          data: Optional[Dict] = None, json_body: Optional[Dict] = None) -> Dict[str, Any]:
        """
        Constructs request arguments (params, data, json) with the payload injected.
        Returns a kwarg dict suitable for session.request(method, url, **kwargs).
        """
        from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse
        
        req_kwargs = {}
        
        # 1. URL Query Injection (always checked for GET, or mixed)
        if method == "GET" or (param in (dict(parse_qsl(urlparse(url).query)).keys())):
            parsed = urlparse(url)
            curr_params = dict(parse_qsl(parsed.query))
            if param in curr_params:
                curr_params[param] = payload
                new_query = urlencode(curr_params)
                req_kwargs["url"] = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))
            else:
                # Param not in URL, maybe it was intended for body but passed as GET?
                # Just return original url
                req_kwargs["url"] = url

        else:
            req_kwargs["url"] = url

        # 2. POST Form Data Injection
        if method in ("POST", "PUT", "PATCH") and data:
            new_data = data.copy()
            if param in new_data:
                new_data[param] = payload
            req_kwargs["data"] = new_data
            
        # 3. JSON Injection
        if method in ("POST", "PUT", "PATCH") and json_body:
            new_json = json_body.copy()
            # Simple flat key check for now; recursive support can be added if needed
            if param in new_json:
                new_json[param] = payload
            req_kwargs["json"] = new_json

        return req_kwargs

