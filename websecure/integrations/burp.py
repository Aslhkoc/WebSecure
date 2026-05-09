"""
websecure.integrations.burp
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Burp Suite Professional REST API entegrasyonu.

Özellikler
----------
* Burp Suite Pro REST API v0.1 (Burp 2020.9+)
* Aktif tarama başlatma ve sonuç alma
* Tarama sonuçlarını WebSecure finding'e dönüştürme
* Issue deduplication (WebSecure ile çakışmaları önleme)
* Proxy üzerinden Burp geçişi (pasif log alma)
* ToolIntegration arayüzü (SOLID OCP/DIP)

KURULUM
-------
Burp Suite Pro -> User Options -> REST API -> Enable REST API
Varsayılan: http://127.0.0.1:1337
API Key: User Options -> REST API -> API Key
"""
from __future__ import annotations

import hashlib
import logging
import re
import time
import uuid
from typing import Any, Dict, Iterator, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse

from websecure.integrations.base import (
    ToolFinding,
    ToolIntegration,
    ToolResult,
    ToolSeverity,
    ToolStatus,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Sabitler
# ---------------------------------------------------------------------------

_BURP_DEFAULT_HOST = "http://127.0.0.1:1337"
_BURP_API_PREFIX   = "/v0.1"

# Burp severity -> ToolSeverity
_BURP_SEV_MAP: Dict[str, ToolSeverity] = {
    "high":            ToolSeverity.HIGH,
    "medium":          ToolSeverity.MEDIUM,
    "low":             ToolSeverity.LOW,
    "information":     ToolSeverity.INFO,
    "false_positive":  ToolSeverity.INFO,
}

# Burp confidence -> WebSecure confidence
_BURP_CONF_MAP: Dict[str, str] = {
    "certain":   "high",
    "firm":      "medium",
    "tentative": "low",
}

# Burp issue type -> CWE eşleme (yaygın tipler)
_BURP_TYPE_TO_CWE: Dict[int, str] = {
    1048832:  "CWE-89",   # SQL injection
    2097920:  "CWE-79",   # XSS reflected
    2097921:  "CWE-79",   # XSS stored
    2097929:  "CWE-79",   # DOM XSS
    2359297:  "CWE-22",   # Path traversal
    4194433:  "CWE-918",  # SSRF
    5243392:  "CWE-611",  # XXE
    4195328:  "CWE-77",   # OS command injection
    1049601:  "CWE-94",   # SSTI
}


# ---------------------------------------------------------------------------
# BurpSuiteAPIClient
# ---------------------------------------------------------------------------

class BurpSuiteAPIClient:
    """
    Burp Suite Pro REST API istemcisi.

    Tüm HTTP iletişimini requests üzerinden yapar.
    API anahtarı Bearer token olarak gönderilir.
    """

    def __init__(
        self,
        api_url: str = _BURP_DEFAULT_HOST,
        api_key: str = "",
        timeout: int = 30,
        verify_ssl: bool = False,
    ) -> None:
        self.api_url = api_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self._session = None

    def _get_session(self):
        """requests Session lazy init."""
        if self._session is not None:
            return self._session
        try:
            import requests
            from requests.packages.urllib3.exceptions import InsecureRequestWarning  # noqa
            requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
            self._session = requests.Session()
            self._session.verify = self.verify_ssl
            if self.api_key:
                self._session.headers["Authorization"] = f"Bearer {self.api_key}"
            self._session.headers["Content-Type"] = "application/json"
            return self._session
        except ImportError:
            logger.warning("[Burp] 'requests' kütüphanesi yüklü değil.")
            return None

    def _url(self, path: str) -> str:
        return f"{self.api_url}{_BURP_API_PREFIX}{path}"

    def _get(self, path: str) -> Optional[Any]:
        sess = self._get_session()
        if sess is None:
            return None
        try:
            resp = sess.get(self._url(path), timeout=self.timeout)
            resp.raise_for_status()
            return resp.json()
        except Exception as exc:
            logger.debug(f"[Burp] GET {path} hatası: {exc!r}")
            return None

    def _post(self, path: str, data: Dict[str, Any]) -> Optional[Any]:
        sess = self._get_session()
        if sess is None:
            return None
        try:
            resp = sess.post(self._url(path), json=data, timeout=self.timeout)
            resp.raise_for_status()
            return resp.json() if resp.content else {}
        except Exception as exc:
            logger.debug(f"[Burp] POST {path} hatası: {exc!r}")
            return None

    def is_alive(self) -> bool:
        """Burp Suite API erişilebilir mi?"""
        result = self._get("/")
        return result is not None

    # ------------------------------------------------------------------ #
    # Tarama işlemleri
    # ------------------------------------------------------------------ #

    def start_scan(
        self,
        target_url: str,
        config: Optional[Dict[str, Any]] = None,
    ) -> Optional[str]:
        """
        Aktif tarama başlat.

        Döndürür
        --------
        str veya None — Tarama ID'si.
        """
        payload: Dict[str, Any] = {
            "urls": [target_url],
            "scope": {
                "include": [{"rule": target_url}],
            },
        }
        if config:
            payload["scan_configurations"] = [config]

        result = self._post("/scan", payload)
        if result is None:
            return None

        scan_id = (
            result.get("scan_id")
            or result.get("id")
            or result.get("task_id")
        )
        if scan_id:
            logger.info(f"[Burp] Tarama başlatıldı: {scan_id}  ->  {target_url}")
        return str(scan_id) if scan_id else None

    def get_scan_status(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """Tarama durumu ve ilerleme bilgisi."""
        return self._get(f"/scan/{scan_id}")

    def wait_for_scan(
        self,
        scan_id: str,
        poll_interval: int = 10,
        max_wait_s: int = 1800,
    ) -> bool:
        """
        Tarama tamamlanana kadar bekle.

        Döndürür
        --------
        bool — True: tamamlandı, False: zaman aşımı.
        """
        deadline = time.monotonic() + max_wait_s
        while time.monotonic() < deadline:
            status = self.get_scan_status(scan_id)
            if status is None:
                time.sleep(poll_interval)
                continue

            scan_status = (
                status.get("scan_status")
                or status.get("status")
                or ""
            ).lower()
            pct = status.get("scan_metrics", {}).get("total_percentage_complete", 0)

            logger.debug(f"[Burp] Tarama {scan_id}: {scan_status}  %{pct}")

            if scan_status in ("succeeded", "completed", "done", "finished"):
                logger.info(f"[Burp] Tarama tamamlandı: {scan_id}")
                return True

            if scan_status in ("failed", "cancelled", "error"):
                logger.warning(f"[Burp] Tarama başarısız: {scan_id}  status={scan_status}")
                return False

            time.sleep(poll_interval)

        logger.warning(f"[Burp] Zaman aşımı — tarama {scan_id}")
        return False

    def get_issues(self, scan_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Tarama bulgularını al.

        Parametreler
        ------------
        scan_id : None -> tüm geçmiş bulgular; str -> belirli tarama

        Döndürür
        --------
        List[Dict] — Ham Burp bulgu dict'leri.
        """
        path = f"/scan/{scan_id}/issues" if scan_id else "/issue-activity"
        result = self._get(path)
        if result is None:
            return []
        if isinstance(result, list):
            return result
        return result.get("issues") or result.get("data") or []

    def get_proxy_history(
        self,
        filter_url: str = "",
        count: int = 100,
    ) -> List[Dict[str, Any]]:
        """Burp Proxy geçmişini al."""
        path = f"/proxy/history?count={count}"
        if filter_url:
            path += f"&url={filter_url}"
        result = self._get(path)
        if result is None:
            return []
        return result if isinstance(result, list) else result.get("messages", [])

    def start_active_scan(
        self,
        url: str,
        config: Optional[Dict[str, Any]] = None,
    ) -> Optional[str]:
        """
        Start an active scan via the Burp Suite Pro API.

        Parameters
        ----------
        url    : str — target URL.
        config : Dict — optional named scan configuration object.

        Returns
        -------
        str or None — scan_id on success.
        """
        payload: Dict[str, Any] = {
            "urls": [url],
            "scope": {"include": [{"rule": url}]},
        }
        if config:
            payload["scan_configurations"] = [config]

        result = self._post("/scan", payload)
        if result is None:
            return None

        scan_id = (
            result.get("scan_id") or
            result.get("id") or
            result.get("task_id")
        )
        if scan_id:
            logger.info(f"[Burp] Active scan started: id={scan_id}  url={url}")
        return str(scan_id) if scan_id else None

    def get_scan_issues(self, scan_id: str) -> List[Dict[str, Any]]:
        """
        Fetch all issues found by a completed scan.

        Parameters
        ----------
        scan_id : str — scan identifier.

        Returns
        -------
        List[Dict] — raw Burp issue dicts.
        """
        result = self._get(f"/scan/{scan_id}/issues")
        if result is None:
            return []
        if isinstance(result, list):
            return result
        return result.get("issues") or result.get("data") or []

    def stop_scan(self, scan_id: str) -> bool:
        """
        Cancel an in-progress scan.

        Parameters
        ----------
        scan_id : str

        Returns
        -------
        bool — True if stop was acknowledged.
        """
        try:
            result = self._post(f"/scan/{scan_id}/stop", {})
            return result is not None
        except Exception as exc:
            logger.debug(f"[Burp] stop_scan error: {exc!r}")
            return False

    def list_scans(self) -> List[Dict[str, Any]]:
        """
        List all scans (current and historical).

        Returns
        -------
        List[Dict] — scan summary objects.
        """
        result = self._get("/scan")
        if result is None:
            return []
        if isinstance(result, list):
            return result
        return result.get("scans") or result.get("data") or []

    def get_scope(self) -> List[str]:
        """
        Return the current Burp target scope as a list of URL patterns.

        Returns
        -------
        List[str]
        """
        result = self._get("/target/scope")
        if result is None:
            return []
        include = result.get("include") or []
        return [
            item.get("rule") or item.get("url") or ""
            for item in include
            if isinstance(item, dict)
        ]

    def add_to_scope(self, url: str) -> bool:
        """
        Add a URL to the Burp target scope.

        Parameters
        ----------
        url : str — URL or pattern to include.

        Returns
        -------
        bool — True if acknowledged.
        """
        try:
            result = self._post("/target/scope", {
                "include": [{"rule": url}],
            })
            return result is not None
        except Exception as exc:
            logger.debug(f"[Burp] add_to_scope error: {exc!r}")
            return False

    def send_to_intruder(self, request_id: str, positions: List[int]) -> bool:
        """
        Send a captured request to Burp Intruder with payload positions.

        Parameters
        ----------
        request_id : str     — proxy history item ID.
        positions  : List[int] — byte offsets of payload injection points.

        Returns
        -------
        bool — True if acknowledged.
        """
        try:
            result = self._post("/intruder/send_to", {
                "request_id": request_id,
                "positions":  positions,
            })
            return result is not None
        except Exception as exc:
            logger.debug(f"[Burp] send_to_intruder error: {exc!r}")
            return False

    def send_to_repeater(self, request_id: str) -> bool:
        """
        Send a captured request to Burp Repeater.

        Parameters
        ----------
        request_id : str — proxy history item ID.

        Returns
        -------
        bool — True if acknowledged.
        """
        try:
            result = self._post("/repeater/send_to", {"request_id": request_id})
            return result is not None
        except Exception as exc:
            logger.debug(f"[Burp] send_to_repeater error: {exc!r}")
            return False


# ---------------------------------------------------------------------------
# BurpIntegration — ToolIntegration
# ---------------------------------------------------------------------------

class BurpIntegration(ToolIntegration):
    """
    Burp Suite Professional REST API tabanlı tarama entegrasyonu.

    İki çalışma modu:
    1. **Active Scan**: Burp'ü aktif tarama başlatır, bekler, sonuçları alır.
    2. **Import**: Mevcut Burp bulgularını WebSecure'a import eder.
    """

    def __init__(
        self,
        api_url: str = _BURP_DEFAULT_HOST,
        api_key: str = "",
        timeout: int = 30,
    ) -> None:
        super().__init__("")
        self._client = BurpSuiteAPIClient(
            api_url=api_url, api_key=api_key, timeout=timeout
        )
        self._available: Optional[bool] = None

    # ------------------------------------------------------------------ #
    # ToolIntegration arayüzü
    # ------------------------------------------------------------------ #

    @property
    def tool_name(self) -> str:
        return "burp"

    def is_available(self) -> bool:
        if self._available is not None:
            return self._available
        self._available = self._client.is_alive()
        return self._available

    def version(self) -> Optional[str]:
        if not self.is_available():
            return None
        info = self._client._get("/")
        if info and isinstance(info, dict):
            return info.get("version") or info.get("burp_version")
        return None

    def run(self, target: str, **kwargs) -> ToolResult:
        """
        Burp Suite aktif tarama çalıştır.

        Anahtar argümanlar
        ------------------
        mode         : "active" | "import" (varsayılan: "import")
        scan_config  : Dict — Burp scan configuration
        wait_s       : int — Tarama için maksimum bekleme süresi
        """
        mode = kwargs.get("mode", "import")

        if not self.is_available():
            logger.warning("[Burp] API erişilemiyor, atlanıyor.")
            return ToolResult(tool=self.tool_name, target=target, status=ToolStatus.NOT_FOUND)

        if mode == "active":
            return self._run_active_scan(target, **kwargs)
        else:
            return self._import_existing(target, **kwargs)

    def import_findings(self, scan_id: Optional[str] = None) -> ToolResult:
        """
        Mevcut Burp bulgularını import et.
        scan_id = None -> tüm geçmiş bulgular.
        """
        return self._import_existing("", scan_id=scan_id)

    # ------------------------------------------------------------------ #
    # Çalışma modları
    # ------------------------------------------------------------------ #

    def _run_active_scan(self, target: str, **kwargs) -> ToolResult:
        """Aktif tarama başlat, bekle, sonuçları al."""
        start = time.monotonic()
        scan_config = kwargs.get("scan_config")
        wait_s = kwargs.get("wait_s", 1800)

        scan_id = self._client.start_scan(target, config=scan_config)
        if scan_id is None:
            return ToolResult(
                tool=self.tool_name, target=target,
                status=ToolStatus.ERROR,
                stderr="Burp taraması başlatılamadı.",
            )

        completed = self._client.wait_for_scan(scan_id, max_wait_s=wait_s)
        status = ToolStatus.SUCCESS if completed else ToolStatus.TIMEOUT

        issues = self._client.get_issues(scan_id)
        findings = self._normalize_issues(issues)

        duration = time.monotonic() - start
        logger.info(
            f"[Burp] Aktif tarama tamamlandı: {target}  "
            f"{len(findings)} bulgu  {duration:.1f}s"
        )

        return ToolResult(
            tool=self.tool_name, target=target,
            status=status, findings=findings,
            duration_s=duration,
            extra={"scan_id": scan_id, "raw_issues": issues},
        )

    def _import_existing(self, target: str, scan_id: Optional[str] = None, **_) -> ToolResult:
        """Mevcut Burp bulgularını import et."""
        start = time.monotonic()
        issues = self._client.get_issues(scan_id)

        if not issues:
            logger.info("[Burp] Import edilecek bulgu yok.")
            return ToolResult(
                tool=self.tool_name, target=target,
                status=ToolStatus.SUCCESS, duration_s=time.monotonic() - start,
            )

        findings = self._normalize_issues(issues)
        logger.info(f"[Burp] {len(findings)} bulgu import edildi.")

        return ToolResult(
            tool=self.tool_name, target=target,
            status=ToolStatus.SUCCESS, findings=findings,
            duration_s=time.monotonic() - start,
        )

    # ------------------------------------------------------------------ #
    # Normalize etme
    # ------------------------------------------------------------------ #

    def _normalize_issues(
        self, issues: List[Dict[str, Any]]
    ) -> List[ToolFinding]:
        findings: List[ToolFinding] = []
        for issue in issues:
            f = self._parse_issue(issue)
            if f:
                findings.append(f)
        return findings

    def _parse_issue(self, issue: Dict[str, Any]) -> Optional[ToolFinding]:
        try:
            # Farklı Burp API sürümlerini destekle
            name = (
                issue.get("issue_name")
                or issue.get("name")
                or issue.get("type_name")
                or "Bilinmeyen Bulgu"
            )
            sev_raw = (
                issue.get("severity")
                or issue.get("issue_severity")
                or "information"
            ).lower()
            conf_raw = (
                issue.get("confidence")
                or issue.get("issue_confidence")
                or "tentative"
            ).lower()

            url = (
                issue.get("url")
                or issue.get("origin")
                or issue.get("host")
                or ""
            )

            description = self._extract_text(
                issue.get("issue_detail")
                or issue.get("description")
                or ""
            )
            remediation = self._extract_text(
                issue.get("remediation_detail")
                or issue.get("remediation")
                or ""
            )

            # Evidence
            req_resp = issue.get("request_response") or issue.get("evidence") or []
            evidence_parts = []
            if isinstance(req_resp, list):
                for rr in req_resp[:2]:
                    if isinstance(rr, dict):
                        req = rr.get("request", {})
                        if isinstance(req, dict):
                            evidence_parts.append(f"Request: {req.get('body', '')[:200]}")
            evidence = "\n".join(evidence_parts) or description[:200]

            # CWE
            issue_type = issue.get("issue_type") or issue.get("type", 0)
            cwe = _BURP_TYPE_TO_CWE.get(int(issue_type), "") if issue_type else ""

            return ToolFinding(
                title=name,
                severity=_BURP_SEV_MAP.get(sev_raw, ToolSeverity.INFO),
                url=url,
                tool=self.tool_name,
                description=description,
                evidence=evidence,
                remediation=remediation,
                cwe_ids=[cwe] if cwe else [],
                confidence=_BURP_CONF_MAP.get(conf_raw, "low"),
                verified=conf_raw == "certain",
                tags=["burp", f"burp-{sev_raw}"],
                raw=issue,
            )
        except Exception as exc:
            logger.debug(f"[Burp] Issue parse hatası: {exc!r}")
            return None

    @staticmethod
    def _extract_text(html_or_text: str) -> str:
        """HTML etiketlerini temizle."""
        if not html_or_text:
            return ""
        clean = re.sub(r"<[^>]+>", " ", html_or_text)
        clean = re.sub(r"\s+", " ", clean).strip()
        return clean[:1000]

    # ------------------------------------------------------------------ #
    # Enhanced public API
    # ------------------------------------------------------------------ #

    @property
    def collaborator(self) -> "BurpCollaboratorClient":
        """
        Lazy-initialised BurpCollaboratorClient instance.

        Uses the integration's api_key for Collaborator authentication.
        """
        if not hasattr(self, "_collaborator"):
            object.__setattr__(
                self,
                "_collaborator",
                BurpCollaboratorClient(api_key=self._client.api_key),
            )
        return self._collaborator  # type: ignore[attr-defined]

    @property
    def active_scanner(self) -> "BurpActiveScanOrchestrator":
        """
        Lazy-initialised BurpActiveScanOrchestrator instance.
        """
        if not hasattr(self, "_active_scanner"):
            object.__setattr__(
                self,
                "_active_scanner",
                BurpActiveScanOrchestrator(self._client),
            )
        return self._active_scanner  # type: ignore[attr-defined]

    def full_scan(
        self,
        target: str,
        include_passive: bool = True,
        include_active: bool = True,
    ) -> ToolResult:
        """
        Run a comprehensive scan combining passive import and active scanning.

        Parameters
        ----------
        target          : str  — target URL.
        include_passive : bool — import existing proxy/passive findings.
        include_active  : bool — launch a new active scan.

        Returns
        -------
        ToolResult — combined findings from both modes.
        """
        if not self.is_available():
            logger.warning("[Burp] API unavailable for full_scan.")
            return ToolResult(
                tool=self.tool_name, target=target, status=ToolStatus.NOT_FOUND
            )

        start = time.monotonic()
        all_findings: List[ToolFinding] = []

        if include_passive:
            passive_result = self._import_existing(target)
            all_findings.extend(passive_result.findings)

        if include_active:
            active_result = self._run_active_scan(target)
            all_findings.extend(active_result.findings)

        # Deduplicate by fingerprint
        seen: Set[str] = set()
        unique_findings: List[ToolFinding] = []
        for finding in all_findings:
            fp = finding.fingerprint()
            if fp not in seen:
                seen.add(fp)
                unique_findings.append(finding)

        duration = time.monotonic() - start
        logger.info(
            f"[Burp] full_scan: {target}  "
            f"{len(unique_findings)} unique findings ({len(all_findings)} total)  "
            f"{duration:.1f}s"
        )

        return ToolResult(
            tool=self.tool_name, target=target,
            status=ToolStatus.SUCCESS,
            findings=unique_findings,
            duration_s=duration,
        )

    def import_and_correlate(
        self,
        existing_findings: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """
        Import all Burp findings and remove duplicates against existing findings.

        Parameters
        ----------
        existing_findings : List[Dict] — WebSecure native findings already known.

        Returns
        -------
        List[Dict] — only net-new findings not already present.
        """
        # Build fingerprint set from existing findings
        existing_fps: Set[str] = set()
        for f in existing_findings:
            key = f"{f.get('source','burp')}:{f.get('type','')}:{f.get('url','')}:{f.get('severity','')}"
            existing_fps.add(hashlib.sha256(key.encode()).hexdigest()[:16])

        result = self.import_findings()
        new_findings: List[Dict[str, Any]] = []
        for finding in result.findings:
            if finding.fingerprint() not in existing_fps:
                new_findings.append(finding.to_dict())

        logger.info(
            f"[Burp] import_and_correlate: {len(new_findings)} new findings "
            f"(deduped {len(result.findings) - len(new_findings)})"
        )
        return new_findings


# ---------------------------------------------------------------------------
# BurpCollaboratorClient
# ---------------------------------------------------------------------------

class BurpCollaboratorClient:
    """
    Burp Suite Collaborator client — OOB callback detection.

    Polls the Collaborator server for DNS/HTTP/SMTP interactions
    triggered by payloads injected by WebSecure scanners.

    Compatible with Burp Suite Pro Collaborator and PortSwigger's
    public Collaborator (burpcollaborator.net).

    SRP: solely responsible for payload generation and interaction polling.
    DIP: depends on requests abstraction, not a specific HTTP library version.
    """

    def __init__(
        self,
        api_key: str,
        poll_url: str = "https://api.burpcollaborator.net",
    ) -> None:
        """
        Parameters
        ----------
        api_key  : str — Burp Collaborator API key.
        poll_url : str — Collaborator server poll endpoint base URL.
        """
        self.api_key = api_key
        self.poll_url = poll_url.rstrip("/")
        self._generated_ids: Dict[str, str] = {}  # payload_id -> full payload

    def _get_session(self):
        """Lazy-init requests session."""
        try:
            import requests
            sess = requests.Session()
            if self.api_key:
                sess.headers["Authorization"] = f"Bearer {self.api_key}"
            sess.headers["Content-Type"] = "application/json"
            return sess
        except ImportError:
            logger.warning("[BurpCollaborator] 'requests' not installed.")
            return None

    def generate_payload(self) -> str:
        """
        Generate a unique Collaborator subdomain payload.

        Returns
        -------
        str — full Collaborator payload (e.g. "abc123.burpcollaborator.net").
        """
        try:
            sess = self._get_session()
            if sess is None:
                raise RuntimeError("requests not available")

            resp = sess.post(
                f"{self.poll_url}/generate",
                json={"count": 1},
                timeout=15,
                verify=False,
            )
            if resp.status_code == 200:
                data = resp.json()
                payloads = data.get("payloads") or []
                if payloads:
                    payload = payloads[0]
                    payload_id = payload.split(".")[0] if "." in payload else payload
                    self._generated_ids[payload_id] = payload
                    logger.debug(f"[BurpCollaborator] Generated payload: {payload}")
                    return payload

            # Fallback: generate a deterministic local subdomain
            payload_id = uuid.uuid4().hex[:12]
            domain = self.poll_url.replace("https://api.", "").replace("https://", "")
            payload = f"{payload_id}.{domain}"
            self._generated_ids[payload_id] = payload
            return payload

        except Exception as exc:
            logger.debug(f"[BurpCollaborator] generate_payload error: {exc!r}")
            payload_id = uuid.uuid4().hex[:12]
            payload = f"{payload_id}.burpcollaborator.net"
            self._generated_ids[payload_id] = payload
            return payload

    def poll_interactions(
        self,
        payload_id: str,
        timeout: int = 30,
    ) -> List[Dict[str, Any]]:
        """
        Poll the Collaborator server for interactions triggered by the payload.

        Parameters
        ----------
        payload_id : str — the unique subdomain prefix returned by generate_payload().
        timeout    : int — max seconds to wait for interactions.

        Returns
        -------
        List[Dict] — interaction records with keys: type, time, client_ip, data.
        """
        sess = self._get_session()
        if sess is None:
            return []

        deadline = time.monotonic() + timeout
        all_interactions: List[Dict[str, Any]] = []

        while time.monotonic() < deadline:
            try:
                resp = sess.get(
                    f"{self.poll_url}/poll",
                    params={"biid": payload_id, "secret": self.api_key},
                    timeout=15,
                    verify=False,
                )
                if resp.status_code == 200:
                    data = resp.json()
                    interactions = data.get("responses") or data.get("interactions") or []
                    if interactions:
                        all_interactions.extend(interactions)
                        break  # stop polling once we have results
            except Exception as exc:
                logger.debug(f"[BurpCollaborator] poll error: {exc!r}")

            time.sleep(3)

        return all_interactions

    def check_interaction(self, payload_id: str) -> bool:
        """
        Check whether any OOB interaction has occurred for the payload.

        Parameters
        ----------
        payload_id : str

        Returns
        -------
        bool — True if at least one interaction recorded.
        """
        interactions = self.poll_interactions(payload_id, timeout=5)
        return len(interactions) > 0

    def get_dns_interactions(self, payload_id: str) -> List[Dict[str, Any]]:
        """
        Return only DNS interactions for the given payload.

        Parameters
        ----------
        payload_id : str

        Returns
        -------
        List[Dict] — DNS interaction records.
        """
        all_interactions = self.poll_interactions(payload_id, timeout=10)
        return [
            i for i in all_interactions
            if str(i.get("type", "")).upper() in ("DNS", "DNS_A", "DNS_AAAA", "DNS_MX")
        ]

    def get_http_interactions(self, payload_id: str) -> List[Dict[str, Any]]:
        """
        Return only HTTP/HTTPS interactions for the given payload.

        Parameters
        ----------
        payload_id : str

        Returns
        -------
        List[Dict] — HTTP interaction records.
        """
        all_interactions = self.poll_interactions(payload_id, timeout=10)
        return [
            i for i in all_interactions
            if str(i.get("type", "")).upper() in ("HTTP", "HTTPS")
        ]

    def bulk_check(
        self,
        payload_ids: List[str],
    ) -> Dict[str, List[Dict[str, Any]]]:
        """
        Check multiple payload IDs for interactions in one pass.

        Parameters
        ----------
        payload_ids : List[str] — list of payload IDs to poll.

        Returns
        -------
        Dict[str, List[Dict]] — {payload_id: [interactions]}.
        """
        results: Dict[str, List[Dict[str, Any]]] = {}
        for pid in payload_ids:
            results[pid] = self.poll_interactions(pid, timeout=5)
        return results


# ---------------------------------------------------------------------------
# BurpActiveScanOrchestrator
# ---------------------------------------------------------------------------

class BurpActiveScanOrchestrator:
    """
    Orchestrates Burp Suite Pro's active scanner for given endpoints.

    Workflow:
    1. Start active scan via API for each target URL
    2. Poll scan status until complete (with progress reporting)
    3. Fetch all issues found by Burp
    4. Convert to WebSecure findings format
    5. Deduplicate against existing WebSecure findings

    SRP: only responsible for scan lifecycle management.
    OCP: map/severity conversion extensible without modifying scan logic.
    """

    # Burp severity -> ToolSeverity (repeated here for encapsulation)
    _SEV_MAP: Dict[str, ToolSeverity] = {
        "high":           ToolSeverity.HIGH,
        "medium":         ToolSeverity.MEDIUM,
        "low":            ToolSeverity.LOW,
        "information":    ToolSeverity.INFO,
        "false_positive": ToolSeverity.INFO,
    }
    _CONF_MAP: Dict[str, str] = {
        "certain":   "high",
        "firm":      "medium",
        "tentative": "low",
    }

    def __init__(self, api_client: BurpSuiteAPIClient) -> None:
        """
        Parameters
        ----------
        api_client : BurpSuiteAPIClient — authenticated API client.
        """
        self._client = api_client
        self._scan_registry: Dict[str, str] = {}  # url -> scan_id

    def scan_url(
        self,
        url: str,
        config_name: str = "Default",
    ) -> str:
        """
        Start an active scan for a single URL.

        Parameters
        ----------
        url         : str — target URL to scan.
        config_name : str — named scan configuration in Burp Pro.

        Returns
        -------
        str — scan_id (empty string on failure).
        """
        config: Optional[Dict[str, Any]] = None
        if config_name and config_name != "Default":
            config = {"name": config_name}

        scan_id = self._client.start_active_scan(url, config=config)
        if scan_id:
            self._scan_registry[url] = scan_id
            logger.info(f"[BurpActiveScanOrchestrator] Scan started: url={url} id={scan_id}")
            return scan_id

        logger.warning(f"[BurpActiveScanOrchestrator] Failed to start scan for {url}")
        return ""

    def scan_urls_batch(
        self,
        urls: List[str],
    ) -> Dict[str, str]:
        """
        Start active scans for multiple URLs.

        Parameters
        ----------
        urls : List[str] — target URLs.

        Returns
        -------
        Dict[str, str] — {url: scan_id} mapping. Failed scans have empty string IDs.
        """
        results: Dict[str, str] = {}
        for url in urls:
            results[url] = self.scan_url(url)
        return results

    def wait_for_scan(
        self,
        scan_id: str,
        timeout: int = 3600,
        poll_interval: int = 30,
    ) -> str:
        """
        Block until the scan reaches a terminal state.

        Parameters
        ----------
        scan_id       : str — identifier of the running scan.
        timeout       : int — max wait time in seconds (default 1 hour).
        poll_interval : int — polling interval in seconds.

        Returns
        -------
        str — final scan status ("succeeded", "failed", "timeout", etc.).
        """
        deadline = time.monotonic() + timeout

        while time.monotonic() < deadline:
            status_data = self._client.get_scan_status(scan_id)
            if status_data is None:
                time.sleep(poll_interval)
                continue

            status = (
                status_data.get("scan_status") or
                status_data.get("status") or
                ""
            ).lower()

            pct = status_data.get("scan_metrics", {}).get("total_percentage_complete", 0)
            logger.debug(f"[BurpActiveScanOrchestrator] Scan {scan_id}: {status} {pct}%")

            terminal_ok  = {"succeeded", "completed", "done", "finished"}
            terminal_bad = {"failed", "cancelled", "error"}

            if status in terminal_ok:
                logger.info(f"[BurpActiveScanOrchestrator] Scan {scan_id} completed: {status}")
                return status
            if status in terminal_bad:
                logger.warning(f"[BurpActiveScanOrchestrator] Scan {scan_id} failed: {status}")
                return status

            time.sleep(poll_interval)

        logger.warning(f"[BurpActiveScanOrchestrator] Scan {scan_id} timed out after {timeout}s")
        return "timeout"

    def get_scan_issues(self, scan_id: str) -> List[Dict[str, Any]]:
        """
        Fetch all issues from a completed scan.

        Parameters
        ----------
        scan_id : str

        Returns
        -------
        List[Dict] — raw Burp issue objects.
        """
        return self._client.get_scan_issues(scan_id)

    def get_all_issues(self) -> List[Dict[str, Any]]:
        """
        Aggregate issues from all scans initiated by this orchestrator.

        Returns
        -------
        List[Dict] — deduplicated raw Burp issue objects.
        """
        all_issues: List[Dict[str, Any]] = []
        seen_issue_ids: Set[str] = set()

        for url, scan_id in self._scan_registry.items():
            if not scan_id:
                continue
            issues = self.get_scan_issues(scan_id)
            for issue in issues:
                issue_id = str(
                    issue.get("serial_number") or
                    issue.get("id") or
                    issue.get("issue_type") or
                    id(issue)
                )
                if issue_id not in seen_issue_ids:
                    seen_issue_ids.add(issue_id)
                    all_issues.append(issue)

        return all_issues

    def to_websecure_findings(
        self,
        burp_issues: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """
        Convert raw Burp issue objects to WebSecure native finding format.

        Parameters
        ----------
        burp_issues : List[Dict] — raw Burp issue dicts.

        Returns
        -------
        List[Dict] — WebSecure native finding dicts.
        """
        findings: List[Dict[str, Any]] = []
        for issue in burp_issues:
            sev_raw  = str(issue.get("severity") or issue.get("issue_severity") or "information").lower()
            conf_raw = str(issue.get("confidence") or issue.get("issue_confidence") or "tentative").lower()
            name = (
                issue.get("issue_name") or
                issue.get("name") or
                issue.get("type_name") or
                "Burp Issue"
            )
            url = (
                issue.get("url") or
                issue.get("origin") or
                issue.get("host") or
                ""
            )
            detail = re.sub(
                r"<[^>]+>", " ",
                str(issue.get("issue_detail") or issue.get("description") or "")
            ).strip()
            remediation = re.sub(
                r"<[^>]+>", " ",
                str(issue.get("remediation_detail") or issue.get("remediation") or "")
            ).strip()

            # Evidence extraction
            evidence_parts: List[str] = []
            req_resp = issue.get("request_response") or issue.get("evidence") or []
            if isinstance(req_resp, list):
                for rr in req_resp[:3]:
                    if isinstance(rr, dict):
                        req = rr.get("request", {})
                        if isinstance(req, dict):
                            body = req.get("body") or req.get("raw") or ""
                            if body:
                                evidence_parts.append(f"Request: {body[:300]}")
                        resp_obj = rr.get("response", {})
                        if isinstance(resp_obj, dict):
                            rbody = resp_obj.get("body") or resp_obj.get("raw") or ""
                            if rbody:
                                evidence_parts.append(f"Response: {rbody[:200]}")
            evidence = "\n".join(evidence_parts) or detail[:300]

            # CWE mapping
            issue_type = issue.get("issue_type") or issue.get("type", 0)
            cwe = _BURP_TYPE_TO_CWE.get(int(issue_type) if issue_type else 0, "")

            # CVSS score from Burp severity
            cvss_map = {
                "high": 7.5, "medium": 5.0, "low": 3.0, "information": 0.0
            }
            cvss = cvss_map.get(sev_raw, 0.0)

            findings.append({
                "type":       name,
                "severity":   self._map_severity(sev_raw).value,
                "url":        url,
                "detail":     detail[:1000],
                "evidence":   {
                    "text":  evidence,
                    "cwe":   [cwe] if cwe else [],
                    "cvss":  cvss,
                    "refs":  [],
                    "raw":   issue,
                },
                "confidence": self._map_confidence(conf_raw),
                "verified":   conf_raw == "certain",
                "source":     "burp",
                "remediation": remediation[:500],
                "tags":       ["burp", f"burp-{sev_raw}"],
            })

        return findings

    def _map_severity(self, burp_severity: str) -> ToolSeverity:
        """
        Map a Burp severity string to a ToolSeverity enum value.

        Parameters
        ----------
        burp_severity : str — e.g. "high", "medium", "low", "information".

        Returns
        -------
        ToolSeverity
        """
        return self._SEV_MAP.get(burp_severity.lower(), ToolSeverity.INFO)

    def _map_confidence(self, burp_confidence: str) -> str:
        """
        Map a Burp confidence string to a WebSecure confidence string.

        Parameters
        ----------
        burp_confidence : str — "certain", "firm", "tentative".

        Returns
        -------
        str — "high", "medium", or "low".
        """
        return self._CONF_MAP.get(burp_confidence.lower(), "low")


# ---------------------------------------------------------------------------
# BurpScanConfiguration
# ---------------------------------------------------------------------------

class BurpScanConfiguration:
    """
    Manages Burp scan configurations (named scan configs in Pro).

    Provides pre-built configs optimised for different scan types.

    SRP: solely responsible for configuration management.
    OCP: new predefined configs added as class-level constants without
         modifying create/list logic.
    """

    # Pre-defined configuration templates
    _PREDEFINED: Dict[str, Dict[str, Any]] = {
        "aggressive_crawl_and_audit": {
            "name": "aggressive_crawl_and_audit",
            "crawl_configuration": {
                "maximum_crawl_time": 60,
                "crawl_strategy": "fastest",
                "maximum_unique_locations": 10000,
            },
            "audit_configuration": {
                "audit_insertion_point_types": [
                    "url_path_parameters",
                    "url_query_parameters",
                    "body_parameters",
                    "http_headers",
                    "cookie_parameters",
                ],
                "audit_optimization": "thorough",
            },
        },
        "api_only": {
            "name": "api_only",
            "crawl_configuration": {
                "crawl_strategy": "fastest",
                "maximum_crawl_time": 15,
            },
            "audit_configuration": {
                "audit_insertion_point_types": [
                    "url_query_parameters",
                    "body_parameters",
                    "http_headers",
                ],
                "issues_to_audit": ["SQL_INJECTION", "XSS", "COMMAND_INJECTION", "SSRF", "XXE"],
            },
        },
        "sqli_focused": {
            "name": "sqli_focused",
            "audit_configuration": {
                "issues_to_audit": ["SQL_INJECTION"],
                "audit_optimization": "thorough",
                "audit_insertion_point_types": [
                    "url_query_parameters",
                    "body_parameters",
                    "cookie_parameters",
                ],
            },
        },
        "xss_focused": {
            "name": "xss_focused",
            "audit_configuration": {
                "issues_to_audit": ["REFLECTED_XSS", "STORED_XSS", "DOM_BASED_XSS"],
                "audit_optimization": "thorough",
            },
        },
        "light_passive": {
            "name": "light_passive",
            "crawl_configuration": {
                "crawl_strategy": "fastest",
                "maximum_crawl_time": 5,
            },
            "audit_configuration": {
                "audit_optimization": "minimise_false_positives",
                "issues_to_audit": ["INFORMATION_DISCLOSURE", "WEAK_TLS", "CLICKJACKING"],
            },
        },
    }

    def __init__(self, api_client: BurpSuiteAPIClient) -> None:
        """
        Parameters
        ----------
        api_client : BurpSuiteAPIClient — for pushing configs to Burp Pro.
        """
        self._client = api_client
        self._local_configs: Dict[str, Dict[str, Any]] = {}

    def create_config(self, name: str, options: Dict[str, Any]) -> str:
        """
        Create a named scan configuration in Burp Pro.

        The configuration is stored locally and pushed to Burp via the API.

        Parameters
        ----------
        name    : str  — unique configuration name.
        options : Dict — Burp scan configuration object.

        Returns
        -------
        str — config_id (the name is used as ID if API does not return one).
        """
        payload = dict(options)
        payload["name"] = name

        try:
            result = self._client._post("/scan-configurations", payload)
            if result and isinstance(result, dict):
                config_id = result.get("id") or result.get("config_id") or name
                self._local_configs[str(config_id)] = payload
                logger.info(f"[BurpScanConfiguration] Config created: {name} -> id={config_id}")
                return str(config_id)
        except Exception as exc:
            logger.debug(f"[BurpScanConfiguration] create_config API error: {exc!r}")

        # Store locally even if API failed (useful for testing)
        self._local_configs[name] = payload
        return name

    def get_predefined_config(self, scan_type: str) -> Dict[str, Any]:
        """
        Return a pre-built configuration dict for the given scan type.

        Parameters
        ----------
        scan_type : str — one of "aggressive_crawl_and_audit", "api_only",
                         "sqli_focused", "xss_focused", "light_passive".

        Returns
        -------
        Dict — configuration object (empty dict if type not found).
        """
        config = self._PREDEFINED.get(scan_type.lower())
        if config is None:
            logger.warning(
                f"[BurpScanConfiguration] Unknown scan type: {scan_type!r}. "
                f"Available: {list(self._PREDEFINED)}"
            )
            return {}
        return dict(config)

    def list_configs(self) -> List[Dict[str, Any]]:
        """
        List all scan configurations (pre-defined + locally created).

        Attempts to fetch live configs from Burp Pro; falls back to local store.

        Returns
        -------
        List[Dict] — configuration summary objects.
        """
        # Try live API first
        try:
            result = self._client._get("/scan-configurations")
            if result is not None:
                if isinstance(result, list):
                    return result
                return result.get("configurations") or result.get("data") or []
        except Exception as exc:
            logger.debug(f"[BurpScanConfiguration] list_configs API error: {exc!r}")

        # Merge predefined + locally created configs
        all_configs: List[Dict[str, Any]] = [
            {"id": k, "name": v.get("name", k)} for k, v in self._PREDEFINED.items()
        ]
        for cid, cfg in self._local_configs.items():
            all_configs.append({"id": cid, "name": cfg.get("name", cid)})
        return all_configs


# ---------------------------------------------------------------------------
# BurpExtensionBridge
# ---------------------------------------------------------------------------

class BurpExtensionBridge:
    """
    Bridge to Burp Suite extensions via the REST API.

    Supported extensions:
    - Param Miner (hidden parameter discovery)
    - Backslash Powered Scanner
    - Active Scan++ (additional checks)
    - JWT Editor
    - GraphQL Raider
    - Turbo Intruder

    SRP: bridges Burp extension results into WebSecure's data model.
    ISP: each method targets a specific extension — callers use only what they need.
    """

    _EXTENSION_ENDPOINTS: Dict[str, str] = {
        "param_miner":          "/extensions/param-miner/scan",
        "backslash_scanner":    "/extensions/backslash-powered-scanner/scan",
        "active_scan_plus":     "/extensions/active-scan-plus/scan",
        "jwt_editor":           "/extensions/jwt-editor/analyze",
        "graphql_raider":       "/extensions/graphql-raider/scan",
        "turbo_intruder":       "/extensions/turbo-intruder/attack",
    }

    def __init__(self, api_client: BurpSuiteAPIClient) -> None:
        """
        Parameters
        ----------
        api_client : BurpSuiteAPIClient — authenticated API client.
        """
        self._client = api_client

    def trigger_param_miner(self, url: str) -> List[str]:
        """
        Invoke the Param Miner extension to discover hidden parameters.

        Parameters
        ----------
        url : str — target URL.

        Returns
        -------
        List[str] — discovered hidden parameter names.
        """
        try:
            result = self._client._post(
                self._EXTENSION_ENDPOINTS["param_miner"],
                {"url": url, "wordlist": "default"},
            )
            if result is None:
                return []
            params = result.get("discovered_parameters") or result.get("params") or []
            logger.info(f"[BurpExtensionBridge] Param Miner: {len(params)} hidden params found for {url}")
            return [str(p) for p in params]
        except Exception as exc:
            logger.debug(f"[BurpExtensionBridge] trigger_param_miner error: {exc!r}")
            return []

    def trigger_backslash_scanner(self, url: str) -> List[Dict[str, Any]]:
        """
        Invoke the Backslash Powered Scanner extension.

        Parameters
        ----------
        url : str — target URL.

        Returns
        -------
        List[Dict] — findings with keys: parameter, payload, evidence.
        """
        try:
            result = self._client._post(
                self._EXTENSION_ENDPOINTS["backslash_scanner"],
                {"url": url},
            )
            if result is None:
                return []
            findings = result.get("issues") or result.get("findings") or []
            logger.info(f"[BurpExtensionBridge] Backslash Scanner: {len(findings)} findings for {url}")
            return findings if isinstance(findings, list) else []
        except Exception as exc:
            logger.debug(f"[BurpExtensionBridge] trigger_backslash_scanner error: {exc!r}")
            return []

    def get_extension_results(self, extension_name: str) -> List[Dict[str, Any]]:
        """
        Fetch pending results from any installed extension by name.

        Parameters
        ----------
        extension_name : str — logical extension name (e.g. "param_miner",
                               "jwt_editor").

        Returns
        -------
        List[Dict] — extension-specific result objects.
        """
        endpoint = self._EXTENSION_ENDPOINTS.get(extension_name.lower().replace(" ", "_"))
        if endpoint is None:
            logger.warning(f"[BurpExtensionBridge] Unknown extension: {extension_name!r}")
            return []
        try:
            result = self._client._get(f"{endpoint}/results")
            if result is None:
                return []
            if isinstance(result, list):
                return result
            return result.get("results") or result.get("issues") or []
        except Exception as exc:
            logger.debug(f"[BurpExtensionBridge] get_extension_results({extension_name}) error: {exc!r}")
            return []

    def list_installed_extensions(self) -> List[str]:
        """
        List extension names currently loaded in Burp Suite.

        Returns
        -------
        List[str] — extension names.
        """
        try:
            result = self._client._get("/extensions")
            if result is None:
                return []
            if isinstance(result, list):
                return [
                    e.get("name") or e.get("id") or str(e)
                    for e in result
                    if isinstance(e, dict)
                ]
            exts = result.get("extensions") or result.get("data") or []
            return [
                e.get("name") or e.get("id") or str(e)
                for e in exts
                if isinstance(e, dict)
            ]
        except Exception as exc:
            logger.debug(f"[BurpExtensionBridge] list_installed_extensions error: {exc!r}")
            return []


# ---------------------------------------------------------------------------
# BurpIntercept
# ---------------------------------------------------------------------------

class BurpIntercept:
    """
    Manages Burp's proxy intercept and traffic analysis.

    Allows WebSecure to:
    - Configure Burp as upstream proxy
    - Read intercepted traffic
    - Replay modified requests
    - Extract authentication tokens from traffic

    SRP: responsible only for proxy/intercept operations.
    DIP: depends on BurpSuiteAPIClient abstraction for all network access.
    """

    def __init__(self, api_client: BurpSuiteAPIClient) -> None:
        """
        Parameters
        ----------
        api_client : BurpSuiteAPIClient — authenticated API client.
        """
        self._client = api_client

    def configure_as_proxy(
        self,
        host: str = "127.0.0.1",
        port: int = 8080,
    ) -> bool:
        """
        Set Burp to listen as a proxy on the given host/port.

        Also configures the requests library to route through Burp
        when called from this WebSecure process.

        Parameters
        ----------
        host : str — bind address (default localhost).
        port : int — proxy port (default 8080).

        Returns
        -------
        bool — True if Burp acknowledged the configuration.
        """
        try:
            result = self._client._post("/proxy/listeners", {
                "listener_port": port,
                "listener_interface": host,
                "running": True,
            })
            if result is not None:
                logger.info(f"[BurpIntercept] Proxy configured at {host}:{port}")
                return True
        except Exception as exc:
            logger.debug(f"[BurpIntercept] configure_as_proxy error: {exc!r}")
        return False

    def get_proxy_history(self, filter_url: str = "") -> List[Dict[str, Any]]:
        """
        Retrieve entries from Burp's proxy history.

        Parameters
        ----------
        filter_url : str — optional URL substring filter.

        Returns
        -------
        List[Dict] — proxy history item dicts.
        """
        return self._client.get_proxy_history(filter_url=filter_url)

    def replay_request(
        self,
        request_id: str,
        modifications: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Replay a proxy history request with optional modifications.

        Parameters
        ----------
        request_id    : str  — proxy history item ID.
        modifications : Dict — keys: "headers", "body", "method" overrides.

        Returns
        -------
        Dict — response object with keys: status_code, headers, body.
        """
        try:
            payload: Dict[str, Any] = {
                "request_id": request_id,
            }
            payload.update(modifications)

            result = self._client._post("/repeater/replay", payload)
            if result and isinstance(result, dict):
                return result

            # Fallback: send_to_repeater + manual re-send is not fully automated
            # Return a structured error response
            return {
                "status_code": 0,
                "headers": {},
                "body": "",
                "error": "replay not supported by this Burp version",
            }
        except Exception as exc:
            logger.debug(f"[BurpIntercept] replay_request error: {exc!r}")
            return {"status_code": 0, "headers": {}, "body": "", "error": str(exc)}

    def extract_auth_tokens(
        self,
        history: List[Dict[str, Any]],
    ) -> Dict[str, str]:
        """
        Scan proxy history for authentication tokens.

        Extracts Bearer tokens, session cookies, CSRF tokens, and API keys
        from request headers and response Set-Cookie headers.

        Parameters
        ----------
        history : List[Dict] — proxy history items (from get_proxy_history()).

        Returns
        -------
        Dict[str, str] — {token_type: token_value} mapping.
        """
        tokens: Dict[str, str] = {}

        bearer_re  = re.compile(r"Bearer\s+([A-Za-z0-9\-._~+/]+=*)", re.I)
        basic_re   = re.compile(r"Basic\s+([A-Za-z0-9+/]+=*)", re.I)
        cookie_re  = re.compile(r"([a-zA-Z_][a-zA-Z0-9_]*)=([^;]+)")
        csrf_names = {"csrf_token", "csrfmiddlewaretoken", "_token", "xsrf-token", "__requestverificationtoken"}
        session_names = {"session", "sessionid", "phpsessid", "jsessionid", "sid", "auth"}

        for item in history:
            request = item.get("request") or {}
            response = item.get("response") or {}

            # Extract from request headers
            req_headers: Dict[str, str] = {}
            if isinstance(request, dict):
                raw_headers = request.get("headers") or request.get("header_string") or {}
                if isinstance(raw_headers, dict):
                    req_headers = raw_headers
                elif isinstance(raw_headers, str):
                    for line in raw_headers.splitlines():
                        if ":" in line:
                            k, _, v = line.partition(":")
                            req_headers[k.strip().lower()] = v.strip()

            auth_header = req_headers.get("authorization") or req_headers.get("x-api-key") or ""
            if auth_header:
                bearer_match = bearer_re.search(auth_header)
                if bearer_match:
                    tokens["bearer_token"] = bearer_match.group(1)

                basic_match = basic_re.search(auth_header)
                if basic_match:
                    tokens["basic_auth"] = basic_match.group(1)

                if req_headers.get("x-api-key"):
                    tokens["api_key"] = req_headers["x-api-key"]

            # Extract cookies from Cookie header
            cookie_header = req_headers.get("cookie") or ""
            for name, value in cookie_re.findall(cookie_header):
                name_lower = name.lower()
                if name_lower in session_names:
                    tokens[f"session_cookie:{name}"] = value.strip()
                if name_lower in csrf_names:
                    tokens[f"csrf_token:{name}"] = value.strip()

            # Extract from response Set-Cookie
            resp_headers: Dict[str, str] = {}
            if isinstance(response, dict):
                raw_resp_h = response.get("headers") or response.get("header_string") or {}
                if isinstance(raw_resp_h, dict):
                    resp_headers = {k.lower(): v for k, v in raw_resp_h.items()}
                elif isinstance(raw_resp_h, str):
                    for line in raw_resp_h.splitlines():
                        if ":" in line:
                            k, _, v = line.partition(":")
                            resp_headers[k.strip().lower()] = v.strip()

            set_cookie = resp_headers.get("set-cookie") or ""
            for name, value in cookie_re.findall(set_cookie):
                name_lower = name.lower()
                if name_lower in session_names:
                    tokens[f"session_cookie:{name}"] = value.strip()

        return tokens


# ---------------------------------------------------------------------------
# Updated import_burp_findings with dedup and CVSS
# ---------------------------------------------------------------------------

def import_burp_findings(
    api_url: str = _BURP_DEFAULT_HOST,
    api_key: str = "",
    scan_id: Optional[str] = None,
    existing_findings: Optional[List[Dict[str, Any]]] = None,
) -> List[Dict[str, Any]]:
    """
    Import Burp Suite findings and return in WebSecure native format.

    Performs deduplication against existing_findings if provided,
    adds CVSS scores based on severity, and extracts full evidence.

    Parameters
    ----------
    api_url          : str       — Burp REST API base URL.
    api_key          : str       — Burp API key.
    scan_id          : str|None  — specific scan ID; None = all historical.
    existing_findings: List[Dict] — already-known findings for dedup.

    Returns
    -------
    List[Dict] — net-new WebSecure native findings.
    """
    integration = BurpIntegration(api_url=api_url, api_key=api_key)
    if not integration.is_available():
        return []

    result = integration.import_findings(scan_id=scan_id)

    if not existing_findings:
        return [f.to_dict() for f in result.findings]

    return integration.import_and_correlate(existing_findings)


__all__ = [
    "BurpSuiteAPIClient",
    "BurpIntegration",
    "BurpCollaboratorClient",
    "BurpActiveScanOrchestrator",
    "BurpScanConfiguration",
    "BurpExtensionBridge",
    "BurpIntercept",
    "import_burp_findings",
]
