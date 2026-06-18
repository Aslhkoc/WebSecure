"""
websecure.integrations.ffuf
----------------------------
Fuzzing tool wrappers.
(Merged from ffuf.py + feroxbuster.py)
"""
import json
import logging
import os
import random
import shutil
import string
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

try:
    import requests as _requests
except ImportError:
    _requests = None

try:
    from websecure.core.http import hardened_session as _hardened_session
except ImportError:
    def _hardened_session(*_a, **_kw):  # type: ignore[misc]
        return _requests.Session() if _requests is not None else None

from websecure.integrations.base import (
    ToolFinding,
    ToolIntegration,
    ToolResult,
    ToolSeverity,
    ToolStatus,
    content_discovery_timeout,
    effective_timeout,
)

logger = logging.getLogger(__name__)


def _run_proc_tracked(
    cmd: List[str], **kw
) -> Tuple[subprocess.Popen, Optional[Callable]]:
    """Popen + scan-cancellation registration. Returns (proc, unregister_fn|None)."""
    proc = subprocess.Popen(cmd, **kw)
    try:
        from websecure.core.phases import register_child_proc, unregister_child_proc
        register_child_proc(proc)
        return proc, unregister_child_proc
    except Exception:
        return proc, None


class FFUFWrapper(ToolIntegration):
    """
    Wrapper for FFUF (Fuzz Faster U Fool).
    Requires 'ffuf' binary to be in PATH.
    """

    @property
    def tool_name(self) -> str:
        return "ffuf"

    def __init__(self, binary_path: str = "ffuf", session=None):
        super().__init__(binary_path)
        self._session = session
        self._check_binary()

    def _check_binary(self):
        if shutil.which(self.binary):
            return

        from websecure.core.platform_compat import binary_candidates as _bc
        from websecure.core.paths import writable_root as _ws_root
        root = _ws_root()
        for _cand in _bc(root, "ffuf"):
            if _cand.exists():
                self._binary_path = str(_cand)
                return

        logger.warning(f"FFUF binary not found at '{self.binary}'. Fuzzing will be disabled.")

    def is_available(self) -> bool:
        if self.binary.endswith(".py"):
            return shutil.which(sys.executable) is not None and os.path.exists(self.binary)
        return shutil.which(self.binary) is not None or (
            self._binary_path is not None and Path(self._binary_path).exists()
        )

    def run(self, target: str, **kwargs) -> ToolResult:
        """ToolIntegration interface — directory/endpoint discovery on target."""
        wordlist = kwargs.get("wordlist", "")
        if not wordlist:
            return ToolResult(tool=self.tool_name, target=target, status=ToolStatus.SKIPPED,
                              stderr="No wordlist provided")
        start = time.monotonic()
        raw = self.run_scan(target, wordlist=wordlist,
                            threads=kwargs.get("threads", 40),
                            proxy=kwargs.get("proxy"),
                            profile_cfg=kwargs.get("profile_cfg"))
        findings = self._results_to_tool_findings(raw, target)
        return ToolResult(
            tool=self.tool_name, target=target, status=ToolStatus.SUCCESS,
            findings=findings, duration_s=time.monotonic() - start,
            extra={"discovered": raw},
        )

    def _results_to_tool_findings(self, results: List[Dict], target: str) -> List[ToolFinding]:
        findings: List[ToolFinding] = []
        for r in results:
            status = r.get("status", 0)
            url = r.get("url", target)
            sev = ToolSeverity.MEDIUM if status in {401, 403, 500} else ToolSeverity.INFO
            findings.append(ToolFinding(
                title=f"Discovered: {r.get('input', url)}  [{status}]",
                severity=sev,
                url=url,
                tool=self.tool_name,
                description=f"HTTP {status}  Size: {r.get('length', 0)}  Words: {r.get('words', 0)}",
                evidence=json.dumps(r)[:300],
                confidence="high",
                verified=True,
                tags=["discovery", "ffuf", f"http-{status}"],
                raw=r,
            ))
        return findings

    def _get_baseline_size(self, base_url: str) -> Optional[str]:
        """
        Probe a guaranteed-nonexistent path to get the 404 response size.
        Returns the size as a string for ffuf -fs, or None on failure.
        This prevents false positives caused by soft-404 pages.
        Uses self._session (SmartSession) when available; falls back to bare requests.
        """
        # Prefer SmartSession so circuit-breaker / identity-rotation applies
        _getter = None
        if self._session is not None:
            _getter = self._session.get
        else:
            _hs = _hardened_session({})
            if _hs is not None:
                _getter = _hs.get
        if _getter is None:
            return None
        try:
            rand_path = "".join(random.choices(string.ascii_lowercase + string.digits, k=16))
            probe_url = base_url.rstrip("/") + "/" + rand_path
            resp = _getter(probe_url, timeout=10, allow_redirects=True,
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
                 profile_cfg: dict = None,
                 maxtime: Optional[int] = None) -> List[Dict[str, Any]]:
        """
        Runs FFUF against the target URL.
        :param url: Target URL with 'FUZZ' keyword (e.g., http://target/FUZZ)
        :param wordlist: Path to wordlist file
        :param extensions: Comma separated extensions (e.g., .php,.html)
        :return: List of findings
        """
        if not self.is_available():
            logger.warning("[Ffuf] run_scan: binary bulunamadı, atlanıyor.")
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
            if self.binary.endswith(".py"):
                cmd = [sys.executable, self.binary]
            else:
                cmd = [self.binary]

            # Profil ayarları
            _p = profile_cfg or {}
            _threads = _p.get("threads", threads)
            _prof_extra = list(_p.get("extra_args", []))

            # Tor/proxy üzerinden çok thread + rate'siz çalışmak Tor devresini boğar
            # (bağlantılar zaman aşımına uğrar → ffuf yavaşlar, güvenilmez/eksik sonuç).
            # Az thread + global rate limit ile Tor üzerinde sağlıklı çalışır.
            if proxy:
                _threads = min(int(_threads), 10)

            cmd.extend([
                "-u", url,
                "-w", wordlist,
                "-o", temp_output,
                "-of", "json",
                "-t", str(_threads),
                "-mc", match_codes,
            ])

            # ffuf'u SÜRE TAVANIYLA çalıştır: -maxtime dolunca ffuf KENDİ durur ve o
            # ana kadar bulduklarını '-o' JSON'una YAZAR. Eskiden yalnız Python tarafı
            # proc.kill() ediyordu → ffuf JSON dizisini ASLA yazamadan ölüyordu →
            # "FFUF output was not valid JSON", 0 sonuç (kullanıcının "ffuf farklı
            # yerlerde timeout yiyor" şikâyetinin asıl kaynağı). -maxtime ile kısmi
            # sonuç bile kurtulur. Tavan = subprocess kill-bütçesinin biraz altı
            # (ffuf önce kendi durup yazsın; Python kill yalnızca son-kalkan).
            # Tor-farkında bütçe: Tor aktifken ×4 no_timeout şişirmesi UYGULANMAZ
            # (effective_timeout 2400→-maxtime 34dk = Tor'da çoğu boşa bekleme +
            # sıralı boruyu kilitler). content_discovery_timeout Tor'da ~7dk tavanına
            # sabitler; direkt bağlantıda tam güç (effective_timeout) aynen kalır.
            _eff_to = content_discovery_timeout(600)
            if maxtime is None:
                maxtime = max(60, int(_eff_to * 0.85))
            cmd.extend(["-maxtime", str(int(maxtime))])

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
                # Tor: global istek hızını sınırla (devreyi boğmamak için)
                if not any(str(a) == "-rate" for a in (custom_args or [])):
                    cmd.extend(["-rate", "20"])

            logger.info(f"Starting FFUF scan on {url}")
            process, _unreg = _run_proc_tracked(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            # _eff_to yukarıda (-maxtime ile birlikte) hesaplandı. Python kill'i
            # ffuf'un kendi -maxtime'ından SONRA devreye girer (son-kalkan).
            try:
                _, stderr_b = process.communicate(timeout=_eff_to)
            except subprocess.TimeoutExpired:
                process.kill()
                process.communicate()
                logger.warning(f"[FFUF] Zaman aşımı ({_eff_to}s) — kısmi sonuçlar ayrıştırılıyor")
            else:
                if process.returncode != 0 and stderr_b:
                    logger.debug(f"FFUF stderr: {stderr_b.decode('utf-8', 'ignore')[:300]}")
            finally:
                if _unreg:
                    _unreg(process)

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

    # -------------------------------------------------------------------------
    # Header fuzzing mode
    # -------------------------------------------------------------------------

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
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
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
            proc, _unreg = _run_proc_tracked(
                cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            try:
                proc.communicate(timeout=effective_timeout(120))
            except subprocess.TimeoutExpired:
                proc.kill()
                try:
                    proc.communicate(timeout=10)
                except subprocess.TimeoutExpired:
                    pass
                logger.warning(f"[FFUF] Header fuzz timed out for header={header_name}")
            finally:
                if _unreg:
                    _unreg(proc)

            raw = self._parse_json_output(temp_output)
            results = []
            for item in raw:
                item["fuzzed_header"] = header_name
                item["fuzz_mode"] = "header_value"
                results.append(item)
            return results
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
            logger.warning("[Ffuf] fuzz_headers: binary bulunamadı, atlanıyor.")
            return []

        _temp_wl = None
        if not wordlist or not os.path.isfile(wordlist):
            fd, _temp_wl = tempfile.mkstemp(suffix=".txt", prefix="ws_hdrname_")
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
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
            proc, _unreg = _run_proc_tracked(
                cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            try:
                proc.communicate(timeout=effective_timeout(120))
            except subprocess.TimeoutExpired:
                proc.kill()
                try:
                    proc.communicate(timeout=10)
                except subprocess.TimeoutExpired:
                    pass
                logger.warning("[FFUF] Header name fuzz timed out (120s)")
            finally:
                if _unreg:
                    _unreg(proc)

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

class FeroxbusterWrapper(ToolIntegration):
    """Wrapper for Feroxbuster binary."""

    @property
    def tool_name(self) -> str:
        return "feroxbuster"

    def __init__(self):
        super().__init__("feroxbuster")
        self._find_binary()

    def _find_binary(self):
        if shutil.which(self.binary):
            return
        from websecure.core.platform_compat import binary_candidates as _bc
        from websecure.core.paths import writable_root as _ws_root
        root = _ws_root()
        for _cand in _bc(root, "feroxbuster"):
            if _cand.exists():
                self._binary_path = str(_cand)
                return

    # is_available → ToolIntegration ortak varsayılanı (binary tools/'da veya PATH'te).

    def run(self, target: str, **kwargs) -> ToolResult:
        """ToolIntegration interface — recursive directory brute-force."""
        start = time.monotonic()
        raw = self.scan(
            target,
            wordlist=kwargs.get("wordlist"),
            threads=kwargs.get("threads", 50),
            depth=kwargs.get("depth", 2),
        )
        findings = self._results_to_tool_findings(raw, target)
        return ToolResult(
            tool=self.tool_name, target=target, status=ToolStatus.SUCCESS,
            findings=findings, duration_s=time.monotonic() - start,
            extra={"discovered": raw},
        )

    def _results_to_tool_findings(self, results: List[Dict], target: str) -> List[ToolFinding]:
        findings: List[ToolFinding] = []
        for r in results:
            status = r.get("status", 0)
            url = r.get("url", target)
            sev = ToolSeverity.MEDIUM if status in {401, 403, 500} else ToolSeverity.INFO
            findings.append(ToolFinding(
                title=f"Discovered: {url}  [{status}]",
                severity=sev,
                url=url,
                tool=self.tool_name,
                description=f"HTTP {status}  Size: {r.get('length', 0)}  Words: {r.get('words', 0)}",
                evidence=json.dumps(r)[:300],
                confidence="high",
                verified=True,
                tags=["discovery", "feroxbuster", f"http-{status}"],
                raw=r,
            ))
        return findings

    @staticmethod
    def _default_wordlist() -> Optional[str]:
        p = Path(__file__).resolve().parent.parent / "wordlists" / "dirs.txt"
        return str(p) if p.exists() else None

    def scan(self, target: str, wordlist: str = None, threads: int = 50,
             depth: int = 1, extra_args: List[str] = None) -> List[Dict[str, Any]]:
        if not self.is_available():
            logger.warning("Feroxbuster binary not found.")
            return []

        # On Windows feroxbuster has no built-in default wordlist path — require one.
        effective_wordlist = wordlist or self._default_wordlist()
        if not effective_wordlist:
            logger.warning("[Feroxbuster] Wordlist bulunamadı — tarama atlandı.")
            return []

        fd, temp_output = tempfile.mkstemp(suffix=".json")
        os.close(fd)

        try:
            cmd = [self.binary, "--url", target, "--threads", str(threads),
                   "--depth", str(depth), "--json", "--output", temp_output,
                   "--wordlist", effective_wordlist, "--no-state"]

            # Graceful süre tavanı: feroxbuster kill-bütçesinden ÖNCE kendi durur.
            # (JSONL çıktısı kill'de kısmi sonuç verir ama --time-limit ile özyineleme
            # sonsuza gitmez ve temiz kapanır.) Kullanıcı talebi: faz atlanmasın, ama
            # araç bütçesi içinde bitsin.
            # Tor-farkında bütçe (ffuf ile aynı): Tor'da ×4 şişirme yok → ~7dk tavan,
            # direkt bağlantıda tam güç. --time-limit ile feroxbuster kendi durur.
            _ferox_budget = content_discovery_timeout(600)
            if not any(str(a) == "--time-limit" for a in (extra_args or [])):
                _ferox_to = int(_ferox_budget * 0.9)
                cmd.extend(["--time-limit", f"{max(60, _ferox_to)}s"])

            if extra_args:
                cmd.extend(extra_args)

            logger.info(f"[Feroxbuster] Başlatılıyor → {target} (wordlist={effective_wordlist})")
            proc, _unreg = _run_proc_tracked(
                cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE
            )
            try:
                _, stderr_b = proc.communicate(timeout=_ferox_budget)
                if proc.returncode not in (0, 1) and stderr_b:
                    logger.warning(f"[Feroxbuster] rc={proc.returncode} stderr={stderr_b.decode('utf-8','ignore')[:300]}")
            except subprocess.TimeoutExpired:
                proc.kill()
                try:
                    proc.communicate(timeout=10)
                except subprocess.TimeoutExpired:
                    pass
                logger.warning(f"[Feroxbuster] Zaman aşımı ({int(_ferox_budget)}s) — kısmi sonuçlar ayrıştırılıyor")
            finally:
                if _unreg:
                    _unreg(proc)

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
                        except json.JSONDecodeError as _fix_e:
                            logger.debug(f"[integrations.ffuf] {type(_fix_e).__name__}: {_fix_e!r}")
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


# ============================================================================
# SECTION 3: Parametre Keşif Pipeline (Step 17 — Arjun tarzı)
# ============================================================================

# Yaygın GET/POST parametre isimleri (built-in)
_COMMON_PARAMS = [
    "id", "user", "username", "name", "email", "password", "pass", "token",
    "key", "api_key", "apikey", "api-key", "auth", "session", "sid", "uid",
    "page", "limit", "offset", "start", "size", "count", "order", "sort",
    "search", "query", "q", "term", "keyword", "filter", "type", "category",
    "file", "path", "url", "uri", "redirect", "return", "callback", "next",
    "prev", "lang", "locale", "format", "view", "mode", "action", "method",
    "data", "payload", "content", "body", "message", "text", "value", "val",
    "param", "field", "input", "output", "response", "result", "status",
    "code", "ref", "source", "dest", "target", "host", "port", "protocol",
    "version", "v", "debug", "test", "dev", "admin", "config", "setting",
    "from", "to", "date", "time", "start_date", "end_date", "timestamp",
    "access_token", "refresh_token", "bearer", "jwt", "csrf", "nonce",
    "phone", "mobile", "address", "city", "country", "zip", "state",
    "first_name", "last_name", "full_name", "display_name", "nickname",
    "role", "permission", "scope", "group", "org", "company", "account",
    "product", "item", "cart", "order_id", "transaction_id", "invoice",
    "amount", "price", "quantity", "currency", "discount", "coupon",
    "latitude", "longitude", "location", "coords", "geo",
    "cmd", "exec", "command", "shell", "template",
]

_HIGH_VALUE_PARAMS = {
    "redirect", "url", "uri", "return", "next", "callback",
    "file", "path", "include", "page",
    "id", "user_id", "uid", "account",
    "debug", "test", "admin", "dev",
    "token", "key", "api_key", "auth", "password", "pass",
    "cmd", "exec", "command", "shell",
    "query", "search", "q",
    "template", "lang", "locale",
}


class ParamDiscoveryResult:
    """Parametre keşif sonucu."""

    def __init__(
        self,
        url: str,
        method: str = "GET",
        params: Optional[List[str]] = None,
        interesting_params: Optional[List[str]] = None,
        raw_results: Optional[List[Dict]] = None,
    ) -> None:
        self.url = url
        self.method = method
        self.params: List[str] = params or []
        self.interesting_params: List[str] = interesting_params or []
        self.raw_results: List[Dict] = raw_results or []

    def to_websecure_feed(self) -> List[Dict[str, Any]]:
        """
        Keşfedilen parametreleri WebSecure scanner için URL listesine dönüştür.

        Döndürür
        --------
        List[Dict] — {url, param, method} formatı
        """
        feed: List[Dict[str, Any]] = []
        separator = "&" if "?" in self.url else "?"
        for param in self.params:
            if self.method.upper() == "GET":
                feed.append({
                    "url": f"{self.url}{separator}{param}=",
                    "param": param,
                    "method": "GET",
                })
            else:
                feed.append({
                    "url": self.url,
                    "param": param,
                    "method": "POST",
                    "data": f"{param}=",
                })
        return feed

    def __repr__(self) -> str:
        return (
            f"<ParamDiscoveryResult url={self.url!r}  "
            f"params={len(self.params)}  interesting={len(self.interesting_params)}>"
        )


class ParamDiscoveryPipeline:
    """
    FFUF tabanlı parametre keşif pipeline'ı (Arjun tarzı).

    URL'deki gizli GET/POST parametrelerini keşfeder ve
    bu parametreleri WebSecure scanner'larına besler.

    Kullanım
    --------
    ```python
    pipeline = ParamDiscoveryPipeline()
    result = pipeline.discover("https://example.com/api/user", method="GET")
    # result.params -> ["id", "token", "debug", ...]
    # result.to_websecure_feed() -> WebSecure scanner feed
    ```
    """

    def __init__(
        self,
        ffuf_wrapper: Optional[FFUFWrapper] = None,
        threads: int = 50,
        proxy: Optional[str] = None,
    ) -> None:
        self._ffuf = ffuf_wrapper or FFUFWrapper()
        self.threads = threads
        self.proxy = proxy

    def is_available(self) -> bool:
        return self._ffuf.is_available()

    def discover(
        self,
        url: str,
        method: str = "GET",
        wordlist: Optional[str] = None,
        cookie: str = "",
        headers: Optional[Dict[str, str]] = None,
    ) -> ParamDiscoveryResult:
        """
        Parametre keşfi yap.

        Parametreler
        ------------
        url       : Hedef URL
        method    : "GET" veya "POST"
        wordlist  : Param wordlist dosyası (None -> built-in)
        cookie    : Oturum cookie'si
        headers   : Ek HTTP başlıkları

        Döndürür
        --------
        ParamDiscoveryResult
        """
        if not self.is_available():
            logger.warning("[ParamDiscovery] FFUF binary bulunamadı.")
            return ParamDiscoveryResult(url=url, method=method)

        _temp_wl = None
        if not wordlist or not os.path.isfile(wordlist):
            fd, _temp_wl = tempfile.mkstemp(suffix=".txt", prefix="ws_params_")
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write("\n".join(_COMMON_PARAMS))
            wordlist = _temp_wl

        try:
            if method.upper() == "GET":
                raw = self._discover_get(url, wordlist, cookie, headers or {})
            else:
                raw = self._discover_post(url, wordlist, cookie, headers or {})

            params = [item["input"] for item in raw if item.get("input")]
            interesting = [p for p in params if p.lower() in _HIGH_VALUE_PARAMS]

            logger.info(
                f"[ParamDiscovery] {url}: {len(params)} parametre  "
                f"{len(interesting)} yüksek değerli"
            )
            return ParamDiscoveryResult(
                url=url, method=method,
                params=params,
                interesting_params=interesting,
                raw_results=raw,
            )
        finally:
            if _temp_wl and os.path.exists(_temp_wl):
                try:
                    os.remove(_temp_wl)
                except OSError:
                    pass

    def _discover_get(
        self, url: str, wordlist: str, cookie: str, headers: Dict[str, str]
    ) -> List[Dict]:
        separator = "&" if "?" in url else "?"
        fuzz_url = f"{url}{separator}FUZZ=ws_probe_value"
        custom_args = ["-mr", "ws_probe_value"]
        if cookie:
            custom_args.extend(["-H", f"Cookie: {cookie}"])
        for h, v in headers.items():
            custom_args.extend(["-H", f"{h}: {v}"])
        if self.proxy:
            custom_args.extend(["-x", self.proxy])
        return self._ffuf.run_scan(
            url=fuzz_url, wordlist=wordlist, threads=self.threads,
            match_codes="200,201,204,301,302,400,401,403,422",
            custom_args=custom_args,
        )

    def _discover_post(
        self, url: str, wordlist: str, cookie: str, headers: Dict[str, str]
    ) -> List[Dict]:
        custom_args = [
            "-X", "POST",
            "-d", "FUZZ=ws_probe_value",
            "-H", "Content-Type: application/x-www-form-urlencoded",
            "-mr", "ws_probe_value",
        ]
        if cookie:
            custom_args.extend(["-H", f"Cookie: {cookie}"])
        for h, v in headers.items():
            custom_args.extend(["-H", f"{h}: {v}"])
        if self.proxy:
            custom_args.extend(["-x", self.proxy])
        return self._ffuf.run_scan(
            url=url, wordlist=wordlist, threads=self.threads,
            match_codes="200,201,204,301,302,400,401,403,422",
            custom_args=custom_args,
        )
