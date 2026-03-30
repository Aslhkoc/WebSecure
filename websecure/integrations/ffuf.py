"""
websecure.integrations.ffuf
----------------------------
Fuzzing tool wrappers.
(Merged from ffuf.py + feroxbuster.py)
"""
import json
import logging
import random
import shutil
import string
import subprocess
import tempfile
import os
from typing import List, Dict, Optional, Any

try:
    import requests as _requests
except ImportError:
    _requests = None

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
        if shutil.which(self.binary):
            return

        from pathlib import Path
        root = Path(__file__).resolve().parent.parent.parent
        possible = [
            str(root / "tools" / "ffuf" / "ffuf.exe"),
            str(root / "tools" / "ffuf.exe")
        ]
        for p in possible:
            if os.path.exists(p):
                self.binary = p
                return

        logger.warning(f"FFUF binary not found at '{self.binary}'. Fuzzing will be disabled.")

    def is_available(self) -> bool:
        if self.binary.endswith(".py"):
            import sys
            return shutil.which(sys.executable) is not None and os.path.exists(self.binary)
        return shutil.which(self.binary) is not None or os.path.exists(self.binary)

    def _get_baseline_size(self, base_url: str) -> Optional[str]:
        """
        Probe a guaranteed-nonexistent path to get the 404 response size.
        Returns the size as a string for ffuf -fs, or None on failure.
        This prevents false positives caused by soft-404 pages.
        """
        if _requests is None:
            return None
        try:
            rand_path = "".join(random.choices(string.ascii_lowercase + string.digits, k=16))
            probe_url = base_url.rstrip("/") + "/" + rand_path
            resp = _requests.get(probe_url, timeout=10, allow_redirects=True,
                                 headers={"User-Agent": "WebSecure/1.0"})
            size = len(resp.content)
            logger.debug(f"[FFUF] Baseline 404 size for {base_url}: {size} bytes")
            return str(size)
        except Exception as e:
            logger.debug(f"[FFUF] Baseline probe failed: {e}")
            return None

    def run_scan(self,
                 url: str,
                 wordlist: str,
                 extensions: Optional[str] = None,
                 threads: int = 40,
                 match_codes: str = "200,204,301,302,307,401,403,405,500",
                 filter_size: Optional[str] = None,
                 custom_args: Optional[List[str]] = None,
                 proxy: str = None) -> List[Dict[str, Any]]:
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

        # Auto-baseline: if no explicit filter_size, probe a 404 to suppress soft-404 FPs
        if not filter_size:
            base = url.split("FUZZ")[0]
            filter_size = self._get_baseline_size(base)

        findings = []
        fd, temp_output = tempfile.mkstemp(suffix=".json")
        os.close(fd)

        try:
            cmd = []
            if self.binary.endswith(".py"):
                import sys
                cmd = [sys.executable, self.binary]
            else:
                cmd = [self.binary]

            cmd.extend([
                "-u", url,
                "-w", wordlist,
                "-o", temp_output,
                "-of", "json",
                "-t", str(threads),
                "-mc", match_codes,
            ])

            if filter_size:
                cmd.extend(["-fs", filter_size])

            if extensions:
                cmd.extend(["-e", extensions])

            if custom_args:
                cmd.extend(custom_args)

            if proxy:
                cmd.extend(["-x", proxy.replace("socks5h://", "socks5://")])

            logger.info(f"Starting FFUF scan on {url}")
            process = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False
            )

            if process.returncode != 0 and process.stderr:
                logger.debug(f"FFUF stderr: {process.stderr}")

            findings = self._parse_json_output(temp_output)

        except Exception as e:
            logger.error(f"FFUF execution failed: {e}")
        finally:
            if os.path.exists(temp_output):
                try:
                    os.remove(temp_output)
                except OSError:
                    pass

        return findings

    def _parse_json_output(self, file_path: str) -> List[Dict]:
        results = []
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
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


# ============================================================================
# SECTION 2: Feroxbuster (merged from feroxbuster.py)
# ============================================================================

class FeroxbusterWrapper:
    """Wrapper for Feroxbuster binary."""

    def __init__(self):
        self.binary = "feroxbuster"
        self._find_binary()

    def _find_binary(self):
        if shutil.which(self.binary):
            return
        from pathlib import Path
        root = Path(__file__).resolve().parent.parent.parent
        possible = [
            str(root / "tools" / "feroxbuster" / "feroxbuster.exe"),
            str(root / "tools" / "feroxbuster.exe"),
        ]
        for p in possible:
            if os.path.exists(p):
                self.binary = p
                return

    def is_available(self) -> bool:
        return shutil.which(self.binary) is not None or os.path.exists(self.binary)

    def scan(self, target: str, wordlist: str = None, threads: int = 50,
             depth: int = 1, extra_args: List[str] = None) -> List[Dict[str, Any]]:
        if not self.is_available():
            logger.warning("Feroxbuster binary not found.")
            return []

        fd, temp_output = tempfile.mkstemp(suffix=".json")
        os.close(fd)

        try:
            cmd = [self.binary, "--url", target, "--threads", str(threads),
                   "--depth", str(depth), "--json", "--output", temp_output]

            if wordlist:
                cmd.extend(["--wordlist", wordlist])

            if extra_args:
                cmd.extend(extra_args)

            logger.info(f"Starting Feroxbuster on {target}...")
            subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)

            results = []
            if os.path.exists(temp_output):
                with open(temp_output, "r", encoding="utf-8") as f:
                    for line in f:
                        if not line.strip():
                            continue
                        try:
                            data = json.loads(line)
                            if data.get("type") == "response":
                                results.append({
                                    "url": data.get("url"),
                                    "status": data.get("status"),
                                    "length": data.get("content_length"),
                                    "words": data.get("word_count"),
                                    "lines": data.get("line_count"),
                                    "title": data.get("title", "")
                                })
                        except json.JSONDecodeError:
                            pass
            return results

        except Exception as e:
            logger.error(f"Feroxbuster execution error: {e}")
            return []
        finally:
            if os.path.exists(temp_output):
                try:
                    os.remove(temp_output)
                except OSError:
                    pass
