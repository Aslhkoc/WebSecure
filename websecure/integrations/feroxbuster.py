import logging
import subprocess
import shutil
import json
import os
import tempfile
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)

class FeroxbusterWrapper:
    """
    Wrapper for Feroxbuster binary.
    """
    def __init__(self):
        self.binary = "feroxbuster"

    def is_available(self) -> bool:
        return shutil.which(self.binary) is not None

    def scan(self, target: str, wordlist: str = None, threads: int = 50, depth: int = 1, extra_args: List[str] = None) -> List[Dict[str, Any]]:
        if not self.is_available():
            logger.warning("Feroxbuster binary not found.")
            return []

        # Output file
        fd, temp_output = tempfile.mkstemp(suffix=".json")
        os.close(fd)

        try:
            # Construct command
            # feroxbuster -u <url> -w <wordlist> -t <threads> -d <depth> --json -o <output>
            cmd = [self.binary, "--url", target, "--threads", str(threads), "--depth", str(depth), "--json", "--output", temp_output]
            
            if wordlist:
                cmd.extend(["--wordlist", wordlist])
                
            if extra_args:
                cmd.extend(extra_args)
                
            # Run
            logger.info(f"Starting Feroxbuster on {target}...")
            # Feroxbuster writes updates to stderr, we might want to capture or silence
            subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
            
            # Parse Results (JSON Lines)
            results = []
            if os.path.exists(temp_output):
                with open(temp_output, 'r', encoding='utf-8') as f:
                    for line in f:
                        if not line.strip(): continue
                        try:
                            data = json.loads(line)
                            # Feroxbuster JSON format: {type, url, path, status, content_length, line_count, word_count, method...}
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
                except: pass
