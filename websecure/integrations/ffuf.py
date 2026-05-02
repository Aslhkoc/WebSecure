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
                 proxy: str = None,
                 profile_cfg: dict = None) -> List[Dict[str, Any]]:
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

            # Profil ayarları
            _p = profile_cfg or {}
            _threads = _p.get("threads", threads)
            _prof_extra = list(_p.get("extra_args", []))

            cmd.extend([
                "-u", url,
                "-w", wordlist,
                "-o", temp_output,
                "-of", "json",
                "-t", str(_threads),
                "-mc", match_codes,
            ])

            if filter_size:
                cmd.extend(["-fs", filter_size])

            if extensions:
                cmd.extend(["-e", extensions])

            if _prof_extra:
                cmd.extend(_prof_extra)

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

    # ─────────────────────────────────────────────────────────────────────────
    # Header fuzzing mode
    # ─────────────────────────────────────────────────────────────────────────

    # Common security-relevant headers to fuzz for auth bypass / WAF bypass
    _SECURITY_HEADERS = [
        "X-Forwarded-For",
        "X-Forwarded-Host",
        "X-Forwarded-Proto",
        "X-Real-IP",
        "X-Remote-IP",
        "X-Remote-Addr",
        "X-Originating-IP",
        "X-Host",
        "X-Custom-IP-Authorization",
        "X-Original-URL",
        "X-Override-URL",
        "X-Rewrite-URL",
        "X-Original-Host",
        "X-Forwarded-Server",
        "X-HTTP-Host-Override",
        "Forwarded",
        "Via",
        "True-Client-IP",
        "CF-Connecting-IP",
        "Fastly-Client-IP",
        "X-Client-IP",
        "Client-IP",
        "X-ProxyUser-Ip",
        "X-Requested-With",
        "Authorization",
        "X-Api-Key",
        "X-Auth-Token",
        "X-Access-Token",
        "X-User-Id",
        "X-Admin",
        "X-Internal",
        "X-Backend-Server",
        "X-Cluster-Client-IP",
    ]

    # Values to try when fuzzing IP-spoofing headers
    _IP_BYPASS_VALUES = [
        "127.0.0.1",
        "127.0.0.1:80",
        "localhost",
        "0.0.0.0",
        "::1",
        "10.0.0.1",
        "172.16.0.1",
        "192.168.0.1",
        "169.254.169.254",
        "2130706433",   # 127.0.0.1 decimal
        "0x7f000001",   # 127.0.0.1 hex
    ]

    def fuzz_headers(
        self,
        url: str,
        wordlist: Optional[str] = None,
        headers_to_fuzz: Optional[List[str]] = None,
        baseline_codes: str = "200,204,301,302",
        threads: int = 20,
        proxy: Optional[str] = None,
        profile_cfg: dict = None,
    ) -> List[Dict[str, Any]]:
        """
        Fuzz HTTP request headers for auth bypass, IP spoofing, and WAF bypass.

        Two modes:
          1. header_name mode — inject FUZZ as header name, wordlist = header names
          2. header_value mode — inject FUZZ as value for each security header,
             wordlist = IP/bypass values (default: built-in IP bypass list)

        Args:
            url: Target URL
            wordlist: Path to wordlist. If None, uses built-in IP bypass values.
            headers_to_fuzz: List of specific headers to fuzz. Default: all security headers.
            baseline_codes: HTTP status codes to match as interesting.
            threads: Concurrent FFUF threads.
            proxy: HTTP proxy URL.
            profile_cfg: Profile configuration dict.

        Returns:
            List of interesting findings.
        """
        if not self.is_available():
            logger.warning("[FFUF] Header fuzzing skipped — binary not available")
            return []

        # If no external wordlist, build a temporary one from built-in IP values
        _temp_wl = None
        if not wordlist or not os.path.isfile(wordlist):
            fd, _temp_wl = tempfile.mkstemp(suffix=".txt", prefix="ws_hdr_")
            with os.fdopen(fd, "w") as fh:
                fh.write("\n".join(self._IP_BYPASS_VALUES))
            wordlist = _temp_wl

        target_headers = headers_to_fuzz or self._SECURITY_HEADERS
        all_results: List[Dict[str, Any]] = []

        try:
            for header in target_headers:
                findings = self._fuzz_single_header(
                    url=url,
                    header_name=header,
                    wordlist=wordlist,
                    baseline_codes=baseline_codes,
                    threads=threads,
                    proxy=proxy,
                    profile_cfg=profile_cfg,
                )
                all_results.extend(findings)
        finally:
            if _temp_wl and os.path.exists(_temp_wl):
                try:
                    os.remove(_temp_wl)
                except OSError:
                    pass

        return all_results

    def _fuzz_single_header(
        self,
        url: str,
        header_name: str,
        wordlist: str,
        baseline_codes: str,
        threads: int,
        proxy: Optional[str],
        profile_cfg: dict,
    ) -> List[Dict[str, Any]]:
        """
        Run FFUF with FUZZ injected as the value of a specific header.
        Uses -H "HeaderName: FUZZ" syntax.
        """
        fd, temp_output = tempfile.mkstemp(suffix=".json")
        os.close(fd)

        try:
            _p = profile_cfg or {}
            _threads = _p.get("threads", threads)

            cmd = [self.binary,
                   "-u", url,
                   "-w", wordlist,
                   "-H", f"{header_name}: FUZZ",
                   "-o", temp_output,
                   "-of", "json",
                   "-t", str(_threads),
                   "-mc", baseline_codes,
                   "-s"]

            if proxy:
                cmd.extend(["-x", proxy.replace("socks5h://", "socks5://")])

            logger.debug(f"[FFUF] Header fuzzing: {header_name} on {url}")
            subprocess.run(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
                timeout=120,
            )

            raw = self._parse_json_output(temp_output)
            results = []
            for item in raw:
                item["fuzzed_header"] = header_name
                item["fuzz_mode"] = "header_value"
                results.append(item)
            return results

        except subprocess.TimeoutExpired:
            logger.warning(f"[FFUF] Header fuzz timed out for header={header_name}")
            return []
        except Exception as exc:
            logger.error(f"[FFUF] Header fuzz error for header={header_name}: {exc!r}")
            return []
        finally:
            if os.path.exists(temp_output):
                try:
                    os.remove(temp_output)
                except OSError:
                    pass

    def fuzz_header_names(
        self,
        url: str,
        wordlist: Optional[str] = None,
        threads: int = 20,
        match_codes: str = "200,204,301,302,401,403",
        proxy: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Fuzz header names — inject FUZZ as the header name with a fixed value of '1'.
        Useful for discovering hidden/undocumented headers that change behavior.
        """
        if not self.is_available():
            return []

        _temp_wl = None
        if not wordlist or not os.path.isfile(wordlist):
            fd, _temp_wl = tempfile.mkstemp(suffix=".txt", prefix="ws_hdrname_")
            with os.fdopen(fd, "w") as fh:
                fh.write("\n".join(self._SECURITY_HEADERS))
            wordlist = _temp_wl

        fd2, temp_output = tempfile.mkstemp(suffix=".json")
        os.close(fd2)

        try:
            cmd = [self.binary,
                   "-u", url,
                   "-w", wordlist,
                   "-H", "FUZZ: 1",
                   "-o", temp_output,
                   "-of", "json",
                   "-t", str(threads),
                   "-mc", match_codes,
                   "-s"]

            if proxy:
                cmd.extend(["-x", proxy.replace("socks5h://", "socks5://")])

            logger.debug(f"[FFUF] Header name fuzzing on {url}")
            subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           check=False, timeout=120)

            raw = self._parse_json_output(temp_output)
            for item in raw:
                item["fuzz_mode"] = "header_name"
            return raw

        except Exception as exc:
            logger.error(f"[FFUF] Header name fuzz error: {exc!r}")
            return []
        finally:
            if _temp_wl and os.path.exists(_temp_wl):
                try:
                    os.remove(_temp_wl)
                except OSError:
                    pass
            if os.path.exists(temp_output):
                try:
                    os.remove(temp_output)
                except OSError:
                    pass


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
