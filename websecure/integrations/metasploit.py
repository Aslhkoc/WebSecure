"""
websecure.integrations.metasploit
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Metasploit RPC (MSGRPC) entegrasyonu — kritik CVE exploit doğrulama.

Özellikler
----------
* MSGRPC üzerinden Metasploit'e bağlanma (msgpack veya JSON-RPC)
* CVE ID → Metasploit modül eşleme
* Exploit sonucu → WebSecure finding dönüşümü
* Oturum yönetimi (meterpreter / shell)
* Güvenli sandbox mod (check only — gerçek exploit yok)
* ToolIntegration arayüzü (SOLID OCP/DIP)

UYARI
-----
Bu modül yalnızca yetkili hedeflerde kullanılmalıdır.
WebSecure, `check` komutunu çalıştırır — gerçek exploit yürütmez.
Gerçek exploit için kullanıcı manuel onay vermelidir.
"""
from __future__ import annotations

import hashlib
import json
import logging
import time
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from websecure.integrations.base import (
    ToolFinding,
    ToolIntegration,
    ToolResult,
    ToolSeverity,
    ToolStatus,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# CVE → Metasploit modül eşleme (yaygın web CVE'leri)
# ---------------------------------------------------------------------------

_CVE_TO_MODULE: Dict[str, str] = {
    # Apache
    "CVE-2021-41773": "exploit/multi/http/apache_normalize_path_rce",
    "CVE-2021-42013": "exploit/multi/http/apache_normalize_path_rce",
    "CVE-2017-7679":  "exploit/multi/http/apache_mod_cgi_bash_env_exec",
    # Apache Log4j
    "CVE-2021-44228": "exploit/multi/http/log4shell_header_injection",
    "CVE-2021-45046": "exploit/multi/http/log4shell_header_injection",
    # Confluence
    "CVE-2022-26134": "exploit/multi/http/atlassian_confluence_namespace_ognl_injection",
    "CVE-2023-22515": "exploit/multi/http/atlassian_confluence_rce",
    # Exchange
    "CVE-2021-34473": "exploit/windows/http/exchange_proxyshell_rce",
    "CVE-2022-41040": "exploit/windows/http/exchange_proxynotshell_rce",
    # Spring
    "CVE-2022-22965": "exploit/multi/http/spring4shell",
    "CVE-2022-22963": "exploit/multi/http/spring_cloud_function_spel_injection",
    # Drupal
    "CVE-2018-7600":  "exploit/unix/webapp/drupal_drupalgeddon2",
    "CVE-2019-6340":  "exploit/unix/webapp/drupal_restws_unserialize",
    # WordPress
    "CVE-2020-25213": "exploit/multi/http/wp_file_manager_rce",
    # Jenkins
    "CVE-2019-1003000": "exploit/multi/http/jenkins_script_console",
    # GitLab
    "CVE-2021-22205": "exploit/multi/http/gitlab_exiftool_rce",
    # Weblogic
    "CVE-2020-14882": "exploit/multi/http/oracle_weblogic_wls_wsat",
    # Generic
    "CVE-2014-6271":  "exploit/multi/http/apache_mod_cgi_bash_env_exec",  # Shellshock
}

# Modül → check komutu desteği (False → sadece info alınır)
_MODULE_SUPPORTS_CHECK: Dict[str, bool] = {
    "exploit/multi/http/apache_normalize_path_rce": True,
    "exploit/multi/http/log4shell_header_injection": True,
    "exploit/multi/http/spring4shell": True,
    "exploit/multi/http/atlassian_confluence_namespace_ognl_injection": True,
    "exploit/unix/webapp/drupal_drupalgeddon2": True,
}


# ---------------------------------------------------------------------------
# MetasploitRPCClient
# ---------------------------------------------------------------------------

class MetasploitRPCClient:
    """
    Metasploit MSGRPC istemcisi.

    Metasploit Pro veya Community sürümünde `load msgrpc` ile
    başlatılan RPC servisine bağlanır.

    Bağlantı Kurma
    --------------
    ```
    msfconsole -q -x "load msgrpc Pass=yourpassword ServerPort=55553"
    ```
    """

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 55553,
        username: str = "msf",
        password: str = "msf",
        ssl: bool = False,
        timeout: int = 30,
    ) -> None:
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.ssl = ssl
        self.timeout = timeout
        self._token: Optional[str] = None
        self._session = None

    @property
    def base_url(self) -> str:
        scheme = "https" if self.ssl else "http"
        return f"{scheme}://{self.host}:{self.port}/api/v1"

    def _get_requests(self):
        """requests modülünü lazy import et."""
        try:
            import requests
            return requests
        except ImportError:
            logger.warning("[Metasploit] 'requests' kütüphanesi yüklü değil.")
            return None

    def authenticate(self) -> bool:
        """MSGRPC ile kimlik doğrula, token al."""
        req = self._get_requests()
        if req is None:
            return False

        try:
            resp = req.post(
                f"{self.base_url}/auth/login",
                json={"username": self.username, "password": self.password},
                timeout=self.timeout,
                verify=False,
            )
            if resp.status_code == 200:
                data = resp.json()
                self._token = data.get("token") or data.get("result", {}).get("token")
                if self._token:
                    logger.info("[Metasploit] Kimlik doğrulama başarılı")
                    return True
            logger.warning(f"[Metasploit] Kimlik doğrulama başarısız: HTTP {resp.status_code}")
            return False
        except Exception as exc:
            logger.debug(f"[Metasploit] Bağlantı hatası: {exc!r}")
            return False

    def is_connected(self) -> bool:
        return self._token is not None

    def _api(self, path: str, data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """API çağrısı yap."""
        req = self._get_requests()
        if req is None or not self._token:
            return None
        try:
            resp = req.post(
                f"{self.base_url}/{path}",
                json=data,
                headers={"Authorization": f"Bearer {self._token}"},
                timeout=self.timeout,
                verify=False,
            )
            return resp.json() if resp.status_code == 200 else None
        except Exception as exc:
            logger.debug(f"[Metasploit] API hatası ({path}): {exc!r}")
            return None

    def module_check(
        self,
        module_name: str,
        options: Dict[str, Any],
    ) -> Optional[str]:
        """
        Exploit modülünü `check` komutuyla çalıştır (hedefi exploit etmez).

        Döndürür
        --------
        str veya None:
          "safe"       — güvenli (zafiyet yok)
          "vulnerable" — zafiyet tespit edildi
          "unknown"    — sonuç belirsiz
        """
        result = self._api("modules/check", {
            "module": module_name,
            "options": options,
        })
        if result is None:
            return None

        status = (result.get("status") or result.get("result") or "").lower()
        if "vulnerable" in status or "appears vulnerable" in status:
            return "vulnerable"
        if "safe" in status or "not vulnerable" in status:
            return "safe"
        return "unknown"

    def module_info(self, module_name: str) -> Dict[str, Any]:
        """Modül meta bilgisini al."""
        result = self._api(f"modules/info/{module_name}", {})
        return result or {}

    def list_sessions(self) -> List[Dict[str, Any]]:
        """Aktif Meterpreter/shell oturumlarını listele."""
        result = self._api("sessions/list", {})
        if not result:
            return []
        sessions = result.get("sessions") or result
        if isinstance(sessions, dict):
            return list(sessions.values())
        return sessions if isinstance(sessions, list) else []


# ---------------------------------------------------------------------------
# MetasploitIntegration — ToolIntegration
# ---------------------------------------------------------------------------

class MetasploitIntegration(ToolIntegration):
    """
    Metasploit RPC tabanlı CVE doğrulama entegrasyonu.

    Sadece `check` komutu çalıştırır — hedef exploit edilmez.
    """

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 55553,
        username: str = "msf",
        password: str = "msf",
        ssl: bool = False,
    ) -> None:
        super().__init__("")
        self._client = MetasploitRPCClient(
            host=host, port=port,
            username=username, password=password,
            ssl=ssl,
        )
        self._connected: Optional[bool] = None

    # ------------------------------------------------------------------ #
    # ToolIntegration arayüzü
    # ------------------------------------------------------------------ #

    @property
    def tool_name(self) -> str:
        return "metasploit"

    def is_available(self) -> bool:
        """Metasploit RPC servisine bağlanılabilir mi?"""
        if self._connected is not None:
            return self._connected
        self._connected = self._client.authenticate()
        return self._connected

    def run(self, target: str, **kwargs) -> ToolResult:
        """
        Hedef URL için bilinen CVE'leri Metasploit ile kontrol et.

        Anahtar argümanlar
        ------------------
        cve_ids     : List[str] — test edilecek CVE ID'leri
        check_only  : bool — True → sadece check, False → tam exploit izni sor
        """
        cve_ids: List[str] = kwargs.get("cve_ids", [])
        if not cve_ids:
            return ToolResult(
                tool=self.tool_name, target=target,
                status=ToolStatus.SKIPPED,
                stderr="CVE ID listesi boş.",
            )

        if not self.is_available():
            logger.warning("[Metasploit] RPC servisine bağlanılamıyor, atlanıyor.")
            return ToolResult(tool=self.tool_name, target=target, status=ToolStatus.NOT_FOUND)

        start = time.monotonic()
        findings: List[ToolFinding] = []
        target_host = _extract_host(target)

        for cve_id in cve_ids:
            module = _CVE_TO_MODULE.get(cve_id.upper())
            if module is None:
                logger.debug(f"[Metasploit] {cve_id} için modül bulunamadı, atlanıyor.")
                continue

            finding = self._check_cve(cve_id, module, target, target_host)
            if finding:
                findings.append(finding)

        duration = time.monotonic() - start
        logger.info(
            f"[Metasploit] {target}: {len(cve_ids)} CVE kontrol edildi  "
            f"{len(findings)} doğrulandı  {duration:.1f}s"
        )

        return ToolResult(
            tool=self.tool_name, target=target,
            status=ToolStatus.SUCCESS,
            findings=findings, duration_s=duration,
        )

    # ------------------------------------------------------------------ #
    # CVE kontrolü
    # ------------------------------------------------------------------ #

    def _check_cve(
        self,
        cve_id: str,
        module: str,
        target_url: str,
        target_host: str,
    ) -> Optional[ToolFinding]:
        """Tekil CVE için Metasploit check çalıştır."""
        supports_check = _MODULE_SUPPORTS_CHECK.get(module, False)

        options: Dict[str, Any] = {
            "RHOSTS": target_host,
            "RPORT": _extract_port(target_url),
            "SSL": target_url.startswith("https://"),
            "TARGETURI": _extract_path(target_url),
        }

        if supports_check:
            status = self._client.module_check(module, options)
        else:
            # check desteklemiyorsa sadece modül bilgisi al
            info = self._client.module_info(module)
            status = "info_only" if info else None

        if status is None:
            logger.debug(f"[Metasploit] {cve_id} → {module}: check sonuç yok")
            return None

        if status == "vulnerable":
            mod_info = self._client.module_info(module)
            return ToolFinding(
                title=f"{cve_id} — Exploit Doğrulandı",
                severity=ToolSeverity.CRITICAL,
                url=target_url,
                tool=self.tool_name,
                description=(
                    f"Metasploit check: hedef {cve_id}'e karşı savunmasız. "
                    f"Modül: {module}"
                ),
                evidence=(
                    f"Module: {module}\n"
                    f"Check result: vulnerable\n"
                    f"Description: {mod_info.get('description', '')[:200]}"
                ),
                cve_ids=[cve_id],
                cvss_score=mod_info.get("cvss_score"),
                confidence="high",
                verified=True,
                tags=["exploit", "cve", "metasploit-verified", cve_id.lower()],
                references=mod_info.get("references", []),
                raw={"module": module, "options": options, "check_status": status},
            )
        elif status == "safe":
            logger.info(f"[Metasploit] {cve_id}: hedef güvenli (not vulnerable)")
        else:
            logger.debug(f"[Metasploit] {cve_id}: check sonucu belirsiz ({status})")

        return None


# ---------------------------------------------------------------------------
# Yardımcı fonksiyonlar
# ---------------------------------------------------------------------------

def _extract_host(url: str) -> str:
    try:
        return urlparse(url).hostname or url
    except Exception:
        return url


def _extract_port(url: str) -> int:
    try:
        parsed = urlparse(url)
        if parsed.port:
            return parsed.port
        return 443 if parsed.scheme == "https" else 80
    except Exception:
        return 80


def _extract_path(url: str) -> str:
    try:
        p = urlparse(url).path
        return p or "/"
    except Exception:
        return "/"


def check_cves_with_metasploit(
    target: str,
    cve_ids: List[str],
    msf_host: str = "127.0.0.1",
    msf_port: int = 55553,
    msf_pass: str = "msf",
) -> List[Dict[str, Any]]:
    """
    CVE listesini Metasploit ile kontrol et, doğrulanmış bulguları döndür.

    Döndürür
    --------
    List[Dict] — WebSecure native finding formatında doğrulanmış bulgular.
    """
    integration = MetasploitIntegration(
        host=msf_host, port=msf_port, password=msf_pass
    )
    if not integration.is_available():
        return []
    result = integration.run(target, cve_ids=cve_ids)
    return [f.to_dict() for f in result.findings]


__all__ = [
    "MetasploitRPCClient",
    "MetasploitIntegration",
    "check_cves_with_metasploit",
    "_CVE_TO_MODULE",
]
