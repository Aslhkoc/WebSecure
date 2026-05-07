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
Burp Suite Pro → User Options → REST API → Enable REST API
Varsayılan: http://127.0.0.1:1337
API Key: User Options → REST API → API Key
"""
from __future__ import annotations

import logging
import time
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin

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

# Burp severity → ToolSeverity
_BURP_SEV_MAP: Dict[str, ToolSeverity] = {
    "high":            ToolSeverity.HIGH,
    "medium":          ToolSeverity.MEDIUM,
    "low":             ToolSeverity.LOW,
    "information":     ToolSeverity.INFO,
    "false_positive":  ToolSeverity.INFO,
}

# Burp confidence → WebSecure confidence
_BURP_CONF_MAP: Dict[str, str] = {
    "certain":   "high",
    "firm":      "medium",
    "tentative": "low",
}

# Burp issue type → CWE eşleme (yaygın tipler)
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
            logger.info(f"[Burp] Tarama başlatıldı: {scan_id}  →  {target_url}")
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
        scan_id : None → tüm geçmiş bulgular; str → belirli tarama

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
    ) -> List[Dict[str, Any]]:
        """Burp Proxy geçmişini al."""
        path = "/proxy/history"
        if filter_url:
            path += f"?url={filter_url}"
        result = self._get(path)
        if result is None:
            return []
        return result if isinstance(result, list) else result.get("messages", [])


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
        scan_id = None → tüm geçmiş bulgular.
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
        import re
        clean = re.sub(r"<[^>]+>", " ", html_or_text)
        clean = re.sub(r"\s+", " ", clean).strip()
        return clean[:1000]


# ---------------------------------------------------------------------------
# Kısayol fonksiyonlar
# ---------------------------------------------------------------------------

def import_burp_findings(
    api_url: str = _BURP_DEFAULT_HOST,
    api_key: str = "",
    scan_id: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """
    Burp Suite bulgularını import et, WebSecure native formatında döndür.

    Döndürür
    --------
    List[Dict] — WebSecure native finding formatı.
    """
    integration = BurpIntegration(api_url=api_url, api_key=api_key)
    if not integration.is_available():
        return []
    result = integration.import_findings(scan_id=scan_id)
    return [f.to_dict() for f in result.findings]


__all__ = [
    "BurpSuiteAPIClient",
    "BurpIntegration",
    "import_burp_findings",
]
