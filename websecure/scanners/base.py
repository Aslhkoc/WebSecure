from typing import Dict, Any, List, Optional
import time
import logging
from ..core.utils import hardened_session, redact_sensitive, setup_logging

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
        
        # 4. Log
        sev = safe_entry.get("severity", "Info")
        msg = safe_entry.get("status") or safe_entry.get("issue")
        self.logger.info(f"[{sev.upper()}] {bucket}: {msg}")

    def set_summary(self, bucket: str, count: int) -> None:
        self.results[f"{bucket}_summary"] = {"vulnerabilities": count}

    def run(self, target: str, **kwargs) -> Any:
        raise NotImplementedError("Scanners must implement run()")
