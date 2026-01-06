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

class SQLMapWrapper:
    """
    Wrapper for SQLMap binary (direct execution).
    """
    def __init__(self, binary_path: str = "sqlmap"):
        self.binary = binary_path

    def is_available(self) -> bool:
        return shutil.which(self.binary) is not None

    def scan(self, target: str, batch: bool = True, risk: int = 1, level: int = 1, extra_args: List[str] = None) -> List[Dict[str, Any]]:
        """
        Runs sqlmap on the target.
        Note: Parsing sqlmap textual output is hard. 
        We often use --batch and look for output folder or use known findings format.
        For integration purposes, we verify it runs. 
        Parsing results from stdout/csv is implemented basically.
        """
        if not self.is_available():
            logger.warning("SQLMap binary not found.")
            return []

        import tempfile
        import csv

        # Use CSV output for easier parsing
        fd, temp_output = tempfile.mkstemp(suffix="") # just a dir prefix? sqlmap creates files
        os.close(fd)
        # Actually sqlmap output directory logic is complex. 
        # Easier: capture stdout for "vulnerability found"? 
        # Or use --output-dir.
        
        out_dir = tempfile.mkdtemp()
        
        try:
            cmd = [
                self.binary, 
                "-u", target, 
                "--batch", 
                "--risk", str(risk), 
                "--level", str(level),
                "--output-dir", out_dir,
                "--disable-coloring"
            ]
            if extra_args:
                cmd.extend(extra_args)
            
            logger.info(f"Starting SQLMap binary scan on {target}...")
            # We want to wait for it.
            subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
            
            # Check results.csv in output directory/target_hostname
            # Structure: out_dir/hostname/log
            # log file contains findings.
            
            results = []
            
            # Find the log file
            for root, dirs, files in os.walk(out_dir):
                if "log" in files:
                    log_path = os.path.join(root, "log")
                    # 'log' file format:
                    # [time] [INFO] ...
                    # CSV format inside log? No, it's text usually unless --parse-errors.
                    # Wait, sqlmap has a 'results.csv' if configured? 
                    # Actually parsing 'log' file for key phrases is standard usage.
                    with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
                        for line in f:
                            # Simple heuristic: look for "Parameter: ... ("
                            # Or "Type: " 
                            if "Type: " in line or "Title: " in line:
                                results.append({"raw_finding": line.strip()})
            return results

        except Exception as e:
            logger.error(f"SQLMap binary execution error: {e}")
            return []
        finally:
            try:
                shutil.rmtree(out_dir)
            except: pass
