import requests
import time
import json
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

class SQLMapClient:
    """
    Client for interacting with the SQLMap REST-JSON API.
    """
    def __init__(self, api_url: str = "http://127.0.0.1:8775"):
        self.api_url = api_url.rstrip("/")
        self.task_id: Optional[str] = None
        self.admin_id: Optional[str] = None

    def _req(self, method: str, path: str, json_data: Dict = None) -> Dict:
        """Internal helper for Making API requests."""
        url = f"{self.api_url}{path}"
        try:
            resp = requests.request(method, url, json=json_data, timeout=5)
            resp.raise_for_status()
            return resp.json()
        except Exception as e:
            logger.debug(f"SQLMap API error ({path}): {e}")
            return {}

    def new_task(self) -> Optional[str]:
        """Creates a new task ID."""
        r = self._req("GET", "/task/new")
        if r.get("success"):
            self.task_id = r.get("taskid")
            return self.task_id
        return None

    def start_scan(self, url: str, options: Dict[str, Any] = None) -> bool:
        """Starts a scan on the current task ID."""
        if not self.task_id:
            return False
            
        opts = options or {}
        opts["url"] = url
        
        # Start scan
        r = self._req("POST", f"/scan/{self.task_id}/start", opts)
        return bool(r.get("success"))

    def get_status(self) -> str:
        """Returns scan status: 'running', 'terminated', 'not running'."""
        if not self.task_id:
            return "unknown"
        r = self._req("GET", f"/scan/{self.task_id}/status")
        return r.get("status", "unknown")

    def get_data(self) -> list:
        """Retrieves findings data."""
        if not self.task_id:
            return []
        r = self._req("GET", f"/scan/{self.task_id}/data")
        return r.get("data", [])

    def get_log(self) -> list:
        """Retrieves scan logs."""
        if not self.task_id:
            return []
        r = self._req("GET", f"/scan/{self.task_id}/log")
        return r.get("log", [])

    def delete_task(self) -> bool:
        """Clean up."""
        if not self.task_id:
            return True
        r = self._req("GET", f"/task/{self.task_id}/delete")
        self.task_id = None
        return bool(r.get("success"))

    @staticmethod
    def is_alive(api_url="http://127.0.0.1:8775") -> bool:
        """Fast check if API server is up."""
        try:
            requests.get(f"{api_url}/admin/list", timeout=3)
            return True
        except Exception:
            return False
