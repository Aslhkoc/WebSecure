import json
import logging
import shutil
import subprocess
import tempfile
import os
from typing import List, Dict, Optional, Any

logger = logging.getLogger(__name__)

class FFUFWrapper:
    """
    Wrapper for FFUF (Fuzz Faster U Fool).
    Requires 'ffuf' binary to be in PATH.
    """
    
    def __init__(self, binary_path: str = "ffuf"):
        self.binary = binary_path
        self._check_binary()

    def _check_binary(self):
        if not shutil.which(self.binary):
            logger.warning(f"FFUF binary not found at '{self.binary}'. Fuzzing will be disabled.")

    def is_available(self) -> bool:
        return shutil.which(self.binary) is not None

    def run_scan(self, 
                 url: str, 
                 wordlist: str, 
                 extensions: Optional[str] = None,
                 threads: int = 40,
                 custom_args: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """
        Runs FFUF against the target URL.
        :param url: Target URL with 'FUZZ' keyword (e.g., http://target/FUZZ)
        :param wordlist: Path to wordlist file
        :param extensions: Comma separated extensions (e.g., .php,.html)
        :return: List of findings
        """
        if not self.is_available():
            return []

        if "FUZZ" not in url:
            if not url.endswith("/"):
                url += "/"
            url += "FUZZ"

        findings = []
        
        # Temp file for JSON output
        fd, temp_output = tempfile.mkstemp(suffix=".json")
        os.close(fd) # Close handle immediately

        try:
            cmd = [
                self.binary,
                "-u", url,
                "-w", wordlist,
                "-o", temp_output,
                "-of", "json",
                "-t", str(threads),
                "-mc", "200,204,301,302,307,401,403" # Interesting codes
            ]
            
            if extensions:
                cmd.extend(["-e", extensions])
                
            if custom_args:
                cmd.extend(custom_args)

            logger.info(f"Starting FFUF scan on {url}")
            process = subprocess.run(
                cmd, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE,
                text=True,
                check=False
            )

            if process.returncode != 0 and process.stderr:
                # FFUF found nothing or error? FFUF doesn't always exit 0
                logger.debug(f"FFUF stderr: {process.stderr}")

            # Parse Output
            findings = self._parse_json_output(temp_output)
            
        except Exception as e:
            logger.error(f"FFUF execution failed: {e}")
        finally:
            if os.path.exists(temp_output):
                try:
                    os.remove(temp_output)
                except:
                    pass

        return findings

    def _parse_json_output(self, file_path: str) -> List[Dict]:
        results = []
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                
            # FFUF JSON structure: { "results": [ ... ] }
            for item in data.get("results", []):
                results.append({
                    "input": item.get("input", {}).get("FUZZ", ""),
                    "url": item.get("url"),
                    "status": item.get("status"),
                    "length": item.get("length"),
                    "words": item.get("words"),
                    "lines": item.get("lines"),
                    "content_type": item.get("content_type"),
                    "redirect_location": item.get("redirectlocation")
                })
        except json.JSONDecodeError:
            logger.warning("FFUF output was not valid JSON.")
        except Exception as e:
            logger.error(f"FFUF result parsing error: {e}")
            
        return results
