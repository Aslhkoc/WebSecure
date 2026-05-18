"""
WebSecure — Nmap Entegrasyonu (Maksimum Kapsam)

Tarama Stratejisi (2 Faz):
  Faz 1 — Port Keşfi : -p- --open -T4  -> tüm 65535 TCP portunu hızlıca tara, açıkları bul
  Faz 2 — Derin Analiz: bulunan portlarda -sV --version-intensity 9 + kapsamlı NSE scriptler

Stealth profilde:
  Faz 1 — -sT --top-ports 1000 -T2 (root gerektirmez, sessiz)
  Faz 2 — aynı derinlikte analiz ama -T2

UDP (root varsa):
  Kritik UDP portlarında -sU taraması: DNS, SNMP, NTP, TFTP, Syslog, DHCP...

NSE Script Kategorileri (aggressive):
  default, auth, discovery, version, vuln, exploit, malware, safe, brute
  + servis-spesifik: http-*, ssl-*, ssh-*, ftp-*, smtp-*, mysql-*, dns-*...
"""

from __future__ import annotations

import logging
import os
import platform
import re
import shutil
import subprocess
import tempfile
import threading
import time
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional, Tuple

from websecure.integrations.base import (
    ToolFinding,
    ToolIntegration,
    ToolResult,
    ToolSeverity,
    ToolStatus,
)

logger = logging.getLogger(__name__)

# Kritik UDP portları — root ile taranır
_UDP_PORTS = "53,67,68,69,111,123,137,138,161,162,500,514,520,1900,4500,5353,11211"

# Windows'ta raw socket desteklenmiyor — bu returncode assertion failure'ı gösterir
_WINDOWS_CRASH_CODES = {3221226505, 3221225477, 3221225725, 0xC0000005, 0xC000013A}

def _is_windows() -> bool:
    return platform.system() == "Windows"


def _has_npcap() -> bool:
    """Windows'ta Npcap kurulu ve servis çalışıyor mu kontrol eder.
    Npcap + Administrator = SYN scan, UDP scan, OS detection çalışır.
    """
    if not _is_windows():
        return False
    # Npcap DLL varlığı — en güvenilir gösterge
    npcap_dll = r"C:\Windows\System32\Npcap\wpcap.dll"
    if not os.path.exists(npcap_dll):
        return False
    # Npcap veya WinPcap servisi çalışıyor mu
    for svc in ("npcap", "npf"):
        try:
            r = subprocess.run(
                ["sc", "query", svc],
                capture_output=True, text=True, timeout=5
            )
            if "RUNNING" in r.stdout:
                return True
        except Exception:
            pass
    # DLL var ama servis sorgulanamadı — yine de True say
    return True

# Servis adına göre ek NSE scriptler
_SERVICE_SCRIPTS: Dict[str, str] = {
    "http":    "http-title,http-headers,http-methods,http-auth-finder,http-robots.txt,"
               "http-server-header,http-open-proxy,http-shellshock,http-put,http-git,"
               "http-phpmyadmin-dir-traversal,http-vuln-cve2017-5638,http-vuln-cve2015-1635,"
               "http-wordpress-users,http-backup-finder,http-config-backup,"
               "http-default-accounts,http-unsafe-output-escaping,http-csrf",
    "https":   "ssl-cert,ssl-enum-ciphers,ssl-heartbleed,ssl-dh-params,ssl-poodle,"
               "ssl-ccs-injection,ssl-date,ssl-known-key,sslv2,sslv2-drown,"
               "http-title,http-headers,http-methods,http-auth-finder,"
               "http-shellshock,http-git,http-vuln-cve2017-5638",
    "ssh":     "ssh-auth-methods,ssh-hostkey,ssh-brute,ssh-run,ssh2-enum-algos",
    "ftp":     "ftp-anon,ftp-bounce,ftp-brute,ftp-libopie,ftp-proftpd-backdoor,"
               "ftp-syst,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221",
    "smtp":    "smtp-commands,smtp-enum-users,smtp-ntlm-info,smtp-open-relay,"
               "smtp-strangeport,smtp-vuln-cve2010-4344",
    "smb":     "smb-enum-shares,smb-enum-users,smb-brute,smb-os-discovery,"
               "smb-security-mode,smb-vuln-ms08-067,smb-vuln-ms17-010,"
               "smb-vuln-regsvc-dos,smb2-security-mode,smb2-vuln-uptime,"
               "msrpc-enum",
    "mysql":   "mysql-info,mysql-auth-bypass-hashdump,mysql-brute,mysql-databases,"
               "mysql-empty-password,mysql-enum,mysql-query,mysql-users,mysql-vuln-cve2012-2122",
    "mssql":   "ms-sql-config,ms-sql-dump-hashes,ms-sql-empty-password,ms-sql-info,"
               "ms-sql-ntlm-info,ms-sql-query,ms-sql-tables,ms-sql-xp-cmdshell",
    "rdp":     "rdp-enum-encryption,rdp-vuln-ms12-020,rdp-brute",
    "vnc":     "vnc-info,vnc-brute,vnc-title",
    "dns":     "dns-brute,dns-cache-snoop,dns-nsid,dns-recursion,dns-service-discovery,"
               "dns-zone-transfer,dns-update",
    "snmp":    "snmp-brute,snmp-hh3c-logins,snmp-info,snmp-interfaces,snmp-ios-config,"
               "snmp-netstat,snmp-processes,snmp-sysdescr,snmp-win32-services",
    "ldap":    "ldap-brute,ldap-novell-getpass,ldap-rootdse,ldap-search",
    "pop3":    "pop3-brute,pop3-capabilities,pop3-ntlm-info",
    "imap":    "imap-brute,imap-capabilities,imap-ntlm-info",
    "mongodb": "mongodb-brute,mongodb-databases,mongodb-info",
    "redis":   "redis-brute,redis-info",
    "elasticsearch": "http-title,http-headers",
    "telnet":  "telnet-brute,telnet-encryption,telnet-ntlm-info",
}

# Tüm servisler için her zaman çalışan base scriptler
_BASE_SCRIPTS = (
    "banner,version,default,auth,"
    "vuln,exploit,malware"
)


def _is_root() -> bool:
    """Linux'ta root, Windows'ta Administrator kontrolü."""
    try:
        return os.geteuid() == 0          # Linux / macOS / Kali
    except AttributeError:
        pass
    # Windows — ctypes ile admin kontrolü
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _run_nmap(binary: str, args: List[str], target: str,
              timeout: int = 900) -> Tuple[int, str, str, str]:
    """
    Nmap çalıştırır, XML çıktısını döner.
    Returns: (returncode, xml_file_path, stdout, stderr)
    """
    fd, xml_out = tempfile.mkstemp(suffix=".xml")
    os.close(fd)

    cmd = [binary] + args + ["-oX", xml_out, target]
    cmd_str = " ".join(cmd)
    print(f"\n\033[36m[Nmap]\033[0m {cmd_str}\n")
    logger.info(f"[Nmap] {cmd_str}")

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        # Ctrl+C gelince öldürülebilmesi için kaydet
        try:
            from websecure.core.phases import register_child_proc, unregister_child_proc
            register_child_proc(proc)
        except Exception:
            pass

        try:
            stdout_b, stderr_b = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.communicate()
            msg = f"[Nmap] Zaman aşımı ({timeout}s) — {cmd_str}"
            logger.warning(msg)
            print(f"\033[31m{msg}\033[0m")
            return -1, xml_out, "", "timeout"
        finally:
            try:
                from websecure.core.phases import unregister_child_proc
                unregister_child_proc(proc)
            except Exception:
                pass

        stdout = stdout_b.decode("utf-8", errors="replace")
        stderr = stderr_b.decode("utf-8", errors="replace")

        if proc.returncode != 0:
            logger.warning(f"[Nmap] returncode={proc.returncode}\nstderr: {stderr.strip()}")
            print(f"\033[33m[Nmap] Uyarı (kod {proc.returncode}):\033[0m {stderr.strip()[:300]}")

        return proc.returncode, xml_out, stdout, stderr

    except Exception as e:
        logger.error(f"[Nmap] Hata: {e}")
        print(f"\033[31m[Nmap] Hata: {e}\033[0m")
        return -2, xml_out, "", str(e)


class NmapWrapper(ToolIntegration):
    """
    İki fazlı, servis-farkındalıklı, UDP destekli maksimum Nmap tarayıcısı.

    Faz 1 — Hızlı keşif  : tüm TCP portlarını hızla tara -> açık portlar tespit
    Faz 2 — Derin analiz : tespit edilen portlara -sV + servis özelinde NSE scriptler
    UDP   — (root) kritik UDP servisleri
    """

    _HIGH_RISK_PORTS = {21, 22, 23, 25, 110, 143, 3306, 5432, 5900, 6379, 27017, 1433, 3389}

    def __init__(self, binary_path: str = "nmap"):
        super().__init__(binary_path)  # pass binary_path so self.binary resolves correctly
        self._binary_name = binary_path
        self._find_binary()

    @property
    def tool_name(self) -> str:
        return "nmap"

    def _find_binary(self):
        found = shutil.which(self.binary)
        if found:
            self._binary_path = found
            return
        from pathlib import Path
        candidates = [
            r"C:\Program Files (x86)\Nmap\nmap.exe",
            r"C:\Program Files\Nmap\nmap.exe",
            str(Path(__file__).resolve().parent.parent.parent / "tools" / "Nmap" / "nmap.exe"),
        ]
        for c in candidates:
            if os.path.exists(c):
                self._binary_path = c
                logger.info(f"[Nmap] Binary: {c}")
                return
        logger.warning("[Nmap] Nmap bulunamadı. Kali: sudo apt install nmap")
        print("\033[31m[Nmap] Binary bulunamadı! Kali Linux: sudo apt install nmap\033[0m")

    def is_available(self) -> bool:
        return bool(shutil.which(self.binary)) or os.path.exists(self.binary)

    def run(self, target: str, **kwargs) -> ToolResult:
        """ToolIntegration interface — scan target and return ToolResult."""
        start = time.monotonic()
        raw = self.scan(
            target,
            mode=kwargs.get("mode", "aggressive"),
            timeout=kwargs.get("timeout", 900),
            proxy=kwargs.get("proxy"),
        )
        findings = self._results_to_tool_findings(raw, target)
        return ToolResult(
            tool=self.tool_name,
            target=target,
            status=ToolStatus.SUCCESS,
            findings=findings,
            duration_s=time.monotonic() - start,
            extra={"ports": raw},
        )

    def _results_to_tool_findings(self, results: List[Dict[str, Any]], target: str) -> List[ToolFinding]:
        findings: List[ToolFinding] = []
        for r in results:
            port = r.get("port", 0)
            service = r.get("service", "unknown")
            product = r.get("product", "")
            version = r.get("version", "")
            scripts = r.get("scripts", {})
            title = f"Open Port {port}/{r.get('protocol','tcp')} — {product} {version}".strip(" —")
            desc = f"Service: {service}  Product: {product}  Version: {version}  Host: {r.get('host', target)}"
            evidence = "\n".join(f"{k}: {str(v)[:200]}" for k, v in list(scripts.items())[:5])
            sev = ToolSeverity.MEDIUM if port in self._HIGH_RISK_PORTS else ToolSeverity.INFO
            findings.append(ToolFinding(
                title=title,
                severity=sev,
                url=f"{r.get('host', target)}:{port}",
                tool=self.tool_name,
                description=desc,
                evidence=evidence,
                confidence="high",
                verified=True,
                tags=["port-scan", service, r.get("protocol", "tcp")],
                raw=r,
            ))
        return findings

    # ------------------------------------------------------------------
    # Ana tarama metodu
    # ------------------------------------------------------------------

    def scan(self,
             target: str,
             ports: Optional[str] = None,
             mode: str = "aggressive",
             extra_args: Optional[List[str]] = None,
             timeout: int = 900,
             proxy: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Akıllı iki fazlı tarama.
        mode="aggressive" -> 2-faz + UDP (root varsa)
        mode="stealth"    -> TCP connect, yavaş, gizli
        mode="fast"       -> tek faz, hızlı
        """
        if not self.is_available():
            print("\033[31m[Nmap] Bulunamadı. sudo apt install nmap\033[0m")
            return []

        root = _is_root()
        mode = (mode or "aggressive").lower()

        if mode in ("aggressive", "deep", "standard", "normal"):
            return self._scan_two_phase(target, root=root, proxy=proxy, timeout=timeout)
        elif mode == "stealth":
            return self._scan_stealth(target, proxy=proxy, timeout=timeout)
        elif mode == "full":
            return self._scan_two_phase(target, root=root, proxy=proxy,
                                        timeout=timeout, all_ports=True)
        elif mode == "fast":
            return self._scan_single(target,
                                     ["-sT", "-F", "-T4", "--open", "--host-timeout", "60s"],
                                     proxy=proxy, timeout=180)
        else:
            return self._scan_two_phase(target, root=root, proxy=proxy, timeout=timeout)

    # ------------------------------------------------------------------
    # İki Fazlı Tarama (Ana Strateji)
    # ------------------------------------------------------------------

    def _scan_two_phase(self, target: str, root: bool = False,
                        proxy: Optional[str] = None, timeout: int = 900,
                        all_ports: bool = False) -> List[Dict[str, Any]]:
        """
        Faz 1: Tüm TCP portlarını hızlıca tara -> açık portları bul
        Faz 2: Bulunan portlarda derin servis + NSE script analizi
        UDP:   Root varsa kritik UDP portları
        """

        # ----- FAZ 1: Port Keşfi -----
        print(f"\033[36m[Nmap Faz-1]\033[0m Port keşfi başlıyor ({target})...")
        on_windows = _is_windows()

        # Raw socket erişimi: Linux/Mac root, VEYA Windows Admin+Npcap
        _npcap_ok = on_windows and root and _has_npcap()
        _raw_socket = (root and not on_windows) or _npcap_ok

        if _raw_socket:
            # SYN scan — Linux/Mac root veya Windows Admin+Npcap
            if _npcap_ok:
                print("\033[36m[Nmap]\033[0m Windows Admin + Npcap tespit edildi — SYN scan aktif!")
            if all_ports:
                phase1_args = ["-sS", "-p-", "-T4", "--open",
                               "--min-rate", "1000", "--max-retries", "2",
                               "--host-timeout", "300s"]
            else:
                phase1_args = ["-sS", "--top-ports", "65535", "-T4", "--open",
                               "--min-rate", "1000", "--max-retries", "2",
                               "--host-timeout", "300s"]
        else:
            # TCP connect scan — raw socket yok (normal kullanıcı veya Npcap yok)
            top = "10000" if not on_windows else "5000"
            phase1_args = [
                "-sT", "--top-ports", top, "-T4", "--open",
                "--min-rate", "500", "--max-retries", "2",
                "--host-timeout", "180s",
            ]
            if on_windows and not _npcap_ok:
                # raw socket erişimi yok — nmap'e söyle
                phase1_args += ["--unprivileged"]

        self._inject_proxy(phase1_args, proxy)
        rc1, xml1, _, _ = _run_nmap(self.binary, phase1_args, target, timeout=max(timeout // 2, 240))

        # Açık portları ayıkla (nmap crash etse bile kısmi XML'den kurtarmayı dene)
        open_ports = NmapParser.extract_open_ports_safe(xml1) if xml1 else []
        try:
            if xml1:
                os.remove(xml1)
        except Exception:
            pass

        if rc1 not in (0, 1) and not open_ports:
            code_note = " (Windows raw socket kısıtlaması)" if rc1 in _WINDOWS_CRASH_CODES else ""
            print(f"\033[33m[Nmap Faz-1]\033[0m Nmap hata kodu {rc1}{code_note} — çıktı yok.")
            return []

        if not open_ports:
            print(f"\033[33m[Nmap Faz-1]\033[0m {target} üzerinde açık port bulunamadı.")
            return []

        print(f"\033[32m[Nmap Faz-1]\033[0m {len(open_ports)} açık port bulundu: "
              f"{','.join(map(str, sorted(open_ports)[:30]))}{'...' if len(open_ports) > 30 else ''}")

        # ----- FAZ 2: Derin Analiz -----
        print(f"\033[36m[Nmap Faz-2]\033[0m Derin servis + script analizi ({len(open_ports)} port)...")

        ports_str = ",".join(map(str, sorted(open_ports)))

        if _raw_socket:
            # Linux/Mac root veya Windows Admin+Npcap: tam güç
            phase2_args = [
                "-sS",
                "-sV", "--version-intensity", "9", "--version-all",
                "-sC",
                "-O" if not on_windows else "",          # OS detect sadece Linux/Mac
                "--osscan-guess" if not on_windows else "",
                "-A" if not on_windows else "",
                "--script", self._build_script_list(windows_safe=on_windows),
                "--script-args",
                "http.useragent=Mozilla/5.0,brute.firstonly=true,"
                "vulns.showall=true" + ("" if on_windows else ",unsafe=1"),
                "--script-timeout", "60s",
                "--host-timeout", "180s",
                "-p", ports_str,
                "-T4",
            ]
        else:
            # TCP connect — raw socket yok (normal kullanıcı)
            phase2_args = [
                "-sT", "--unprivileged",
                "-sV", "--version-intensity", "7",
                "-sC",
                "--script", self._build_script_list(windows_safe=True),
                "--script-args",
                "http.useragent=Mozilla/5.0,brute.firstonly=true,vulns.showall=true",
                "--script-timeout", "30s",
                "--host-timeout", "120s",
                "-p", ports_str,
                "-T4",
            ]

        phase2_args = [a for a in phase2_args if a]  # boşları temizle
        self._inject_proxy(phase2_args, proxy)

        rc2, xml2, _, _ = _run_nmap(self.binary, phase2_args, target, timeout=timeout)
        if rc2 not in (0, 1):
            code_note = " (Windows raw socket kısıtlaması)" if rc2 in _WINDOWS_CRASH_CODES else ""
            print(f"\033[33m[Nmap Faz-2]\033[0m Nmap hata kodu {rc2}{code_note} — XML ayrıştırılmıyor.")
            results = []  # Don't parse on error — XML may be incomplete or missing
        else:
            results = NmapParser.parse_xml(xml2) if xml2 else []
        try:
            os.remove(xml2)
        except Exception:
            pass

        # ----- UDP Taraması (root + raw socket gerektirir) -----
        if _raw_socket:
            print(f"\033[36m[Nmap UDP]\033[0m Kritik UDP portları taranıyor...")
            udp_args = [
                "-sU",
                "--version-intensity", "5",
                "--script", "snmp-info,snmp-sysdescr,snmp-brute,dns-recursion,"
                            "dns-service-discovery,ntp-info,tftp-enum,dhcp-discover,"
                            "sip-methods",
                "-p", _UDP_PORTS,
                "-T4", "--max-retries", "1",
            ]
            self._inject_proxy(udp_args, proxy)
            _, xml_udp, _, _ = _run_nmap(self.binary, udp_args, target, timeout=300)
            udp_results = NmapParser.parse_xml(xml_udp)
            try:
                os.remove(xml_udp)
            except Exception:
                pass
            results.extend(udp_results)
            if udp_results:
                print(f"\033[32m[Nmap UDP]\033[0m {len(udp_results)} UDP servis bulundu.")

        if results:
            print(f"\n\033[32m[Nmap]\033[0m Tarama tamamlandı — {len(results)} açık port/servis.\n")
        return results

    # ------------------------------------------------------------------
    # Stealth Tarama
    # ------------------------------------------------------------------

    def _scan_stealth(self, target: str, proxy: Optional[str] = None,
                      timeout: int = 900) -> List[Dict[str, Any]]:
        """
        TCP connect scan — root gerektirmez, Windows uyumlu.
        "Stealth" = raw socket yok, SYN yok. Timing T4 — T2 değil.
        T2 ile 1000 port = 2500+ saniye; T4 ile = 30 saniye.
        """
        print(f"\033[36m[Nmap Stealth Faz-1]\033[0m Port keşfi ({target})...")
        on_windows = _is_windows()

        # T4 kullan — T2 1000 portu 2500+ saniyede tamamlar, kesinlikle timeout
        phase1_args = [
            "-sT", "--top-ports", "2000", "-T4", "--open",
            "--max-retries", "2", "--min-rate", "300",
            "--host-timeout", "120s",
        ]
        self._inject_proxy(phase1_args, proxy)
        _, xml1, _, _ = _run_nmap(self.binary, phase1_args, target, timeout=max(timeout // 2, 120))
        open_ports = NmapParser.extract_open_ports_safe(xml1)
        try:
            os.remove(xml1)
        except Exception:
            pass

        if not open_ports:
            print("[Nmap Stealth] Açık port bulunamadı.")
            return []

        print(f"[Nmap Stealth Faz-2] {len(open_ports)} porta derin analiz...")
        ports_str = ",".join(map(str, sorted(open_ports)))
        phase2_args = [
            "-sT", "-sV", "--version-intensity", "7",
            "--script", self._build_script_list(safe_only=True, windows_safe=on_windows),
            "--script-timeout", "30s",
            "--host-timeout", "120s",
            "-p", ports_str, "-T4",
        ]
        self._inject_proxy(phase2_args, proxy)
        _, xml2, _, _ = _run_nmap(self.binary, phase2_args, target, timeout=timeout)
        results = NmapParser.parse_xml(xml2)
        try:
            os.remove(xml2)
        except Exception:
            pass

        if results:
            print(f"\033[32m[Nmap Stealth]\033[0m Tamamlandı — {len(results)} açık port/servis.")
        return results

    # ------------------------------------------------------------------
    # Tek Faz (hızlı fallback)
    # ------------------------------------------------------------------

    def _scan_single(self, target: str, args: List[str],
                     proxy: Optional[str] = None, timeout: int = 300) -> List[Dict[str, Any]]:
        self._inject_proxy(args, proxy)
        _, xml, _, _ = _run_nmap(self.binary, args, target, timeout=timeout)
        results = NmapParser.parse_xml(xml)
        try:
            os.remove(xml)
        except Exception:
            pass
        return results

    # ------------------------------------------------------------------
    # Yardımcılar
    # ------------------------------------------------------------------

    @staticmethod
    def _inject_proxy(args: List[str], proxy: Optional[str]):
        if not proxy:
            return
        # Nmap --proxies ONLY accepts HTTP proxies (http://).
        # socks4://, socks5://, socks5h:// all trigger:
        #   "libnsock proxy_node_new(): Invalid protocol … QUITTING!"
        # When a SOCKS proxy (Tor on 9150, etc.) is configured, skip --proxies
        # entirely so nmap can reach the target directly.
        if proxy.startswith(("socks5://", "socks5h://", "socks4://", "socks4a://")):
            logger.info(f"[Nmap] SOCKS proxy atlandı — nmap yalnızca HTTP proxy destekler: {proxy}")
            return
        args.extend(["--proxies", proxy])
        if "-n" not in args:
            args.append("-n")

    @staticmethod
    def _build_script_list(safe_only: bool = False, windows_safe: bool = False) -> str:
        """
        NSE script listesi oluşturur.
        windows_safe=True → raw socket gerektiren scriptleri (lltd-discovery dahil) hariç tutar.
        safe_only=True    → sadece bilgi toplama scriptleri (brute/vuln yok).
        """
        if windows_safe or safe_only:
            # Windows veya stealth: discovery kategorisini (lltd-discovery dahil) dışla,
            # raw socket gerektiren scriptleri dışla, explicit liste kullan.
            return (
                "default,auth,version,safe,"
                "banner,ssl-cert,ssl-enum-ciphers,ssl-date,"
                "http-title,http-headers,http-methods,http-auth-finder,"
                "http-server-header,http-robots.txt,http-git,"
                "http-backup-finder,http-default-accounts,"
                "ssh-auth-methods,ssh-hostkey,ssh2-enum-algos,"
                "ftp-anon,ftp-syst,"
                "smtp-commands,smtp-open-relay,"
                "smb-security-mode,smb-enum-shares,"
                "mysql-info,mysql-empty-password,"
                "ms-sql-info,ms-sql-empty-password,"
                "rdp-enum-encryption,"
                "dns-recursion,"
                "mongodb-info,redis-info"
            )
        # Linux/Mac full scan: discovery kategorisi dahil ama lltd-discovery explicit değil
        # (lltd-discovery sadece Windows hedefler için, Linux'ta safe)
        return (
            "default,auth,discovery,version,vuln,exploit,malware,safe,"
            "banner,ssl-cert,ssl-enum-ciphers,ssl-heartbleed,ssl-dh-params,"
            "ssl-poodle,ssl-ccs-injection,ssl-date,sslv2,"
            "http-title,http-headers,http-methods,http-auth-finder,"
            "http-server-header,http-robots.txt,http-git,http-shellshock,"
            "http-open-proxy,http-vuln-cve2017-5638,http-vuln-cve2015-1635,"
            "http-backup-finder,http-default-accounts,"
            "ssh-auth-methods,ssh-hostkey,ssh2-enum-algos,"
            "ftp-anon,ftp-bounce,ftp-vsftpd-backdoor,ftp-proftpd-backdoor,"
            "smtp-commands,smtp-open-relay,smtp-enum-users,"
            "smb-os-discovery,smb-security-mode,smb-enum-shares,"
            "smb-vuln-ms17-010,smb-vuln-ms08-067,"
            "mysql-info,mysql-empty-password,mysql-databases,"
            "ms-sql-info,ms-sql-empty-password,"
            "rdp-enum-encryption,rdp-vuln-ms12-020,"
            "dns-recursion,dns-zone-transfer,dns-brute,"
            "snmp-info,snmp-sysdescr,"
            "mongodb-info,redis-info"
        )

    @staticmethod
    def _extract_open_ports(xml_file: str) -> List[int]:
        """XML dosyasından sadece açık port numaralarını çıkarır (eski compat)."""
        return NmapParser.extract_open_ports_safe(xml_file)

    def quick_web_scan(self, target: str) -> List[Dict[str, Any]]:
        """Web odaklı hızlı tarama."""
        return self._scan_single(
            target,
            ["-sT", "-sV", "--version-intensity", "7", "-sC",
             "--script", "http-title,http-headers,http-methods,ssl-cert,banner",
             "-p", "80,443,8080,8443,8000,8888,9090,3000,4000,5000",
             "-T4", "--open"],
            timeout=120,
        )


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

class NmapParser:
    """Nmap XML (-oX) çıktısını parse eder — tüm NSE script çıktıları dahil."""

    @staticmethod
    def extract_open_ports_safe(xml_file: str) -> List[int]:
        """
        Açık portları kısmi/bozuk XML'den de kurtarır.
        Önce düzgün parse, başarısız olursa regex fallback.
        """
        if not xml_file or not os.path.exists(xml_file):
            return []

        ports: List[int] = []

        # Yöntem 1: Normal XML parse
        try:
            tree = ET.parse(xml_file)
            for port in tree.getroot().findall(".//port"):
                state = port.find("state")
                if state is not None and state.get("state") == "open":
                    try:
                        ports.append(int(port.get("portid", 0)))
                    except (ValueError, TypeError):
                        pass
            return ports
        except ET.ParseError:
            pass  # Bozuk XML → fallback
        except Exception as e:
            logger.debug(f"[Nmap] Port çıkarma hatası: {e}")
            return []

        # Yöntem 2: Regex fallback — bozuk/kısmi XML'den port bilgisini çek
        try:
            content = open(xml_file, encoding="utf-8", errors="replace").read()
            # <port protocol="tcp" portid="80"> ... <state state="open"
            for m in re.finditer(
                r'<port\s[^>]*portid="(\d+)"[^>]*>.*?<state\s[^>]*state="open"',
                content, re.DOTALL
            ):
                try:
                    ports.append(int(m.group(1)))
                except (ValueError, TypeError):
                    pass
            if ports:
                logger.debug(f"[Nmap] Regex fallback ile {len(ports)} port kurtarıldı.")
        except Exception as e:
            logger.debug(f"[Nmap] Regex port kurtarma hatası: {e}")

        return ports

    @staticmethod
    def parse_xml(file_path: str) -> List[Dict[str, Any]]:
        results = []
        try:
            if not os.path.exists(file_path):
                logger.error(f"[Nmap] XML yok: {file_path}")
                return []

            tree = ET.parse(file_path)
            root = tree.getroot()

            for host in root.findall("host"):
                status = host.find("status")
                if status is not None and status.get("state") != "up":
                    continue

                # IP ve hostname
                ip = "unknown"
                for addr in host.findall("address"):
                    if addr.get("addrtype") in ("ipv4", "ipv6"):
                        ip = addr.get("addr", "unknown")
                        break

                hostname = ""
                hostnames = host.find("hostnames")
                if hostnames is not None:
                    hn = hostnames.find("hostname")
                    if hn is not None:
                        hostname = hn.get("name", "")

                # OS Tespiti (birden fazla osmatch, en yüksek accuracy)
                os_guess = ""
                os_accuracy = 0
                os_family = ""
                os_gen = ""
                for osmatch in host.findall(".//osmatch"):
                    acc = int(osmatch.get("accuracy", 0))
                    if acc > os_accuracy:
                        os_accuracy = acc
                        os_guess = osmatch.get("name", "")
                        osclass = osmatch.find("osclass")
                        if osclass is not None:
                            os_family = osclass.get("osfamily", "")
                            os_gen = osclass.get("osgen", "")

                # Host-level scriptler (OS fingerprint vs.)
                host_scripts: Dict[str, str] = {}
                hostscript_el = host.find("hostscript")
                if hostscript_el is not None:
                    for s in hostscript_el.findall("script"):
                        sid = s.get("id", "")
                        if sid:
                            host_scripts[sid] = s.get("output", "")

                # Portlar
                ports_el = host.find("ports")
                if ports_el is None:
                    continue

                for port in ports_el.findall("port"):
                    state = port.find("state")
                    if state is None or state.get("state") != "open":
                        continue

                    port_id   = int(port.get("portid", 0))
                    protocol  = port.get("protocol", "tcp")
                    reason    = state.get("reason", "")

                    service_el   = port.find("service")
                    service_name = "unknown"
                    product = version = extra_info = tunnel = ""
                    cpe_list: List[str] = []
                    service_conf = 0

                    if service_el is not None:
                        service_name = service_el.get("name", "unknown")
                        product      = service_el.get("product", "")
                        version      = service_el.get("version", "")
                        extra_info   = service_el.get("extrainfo", "")
                        tunnel       = service_el.get("tunnel", "")
                        service_conf = int(service_el.get("conf", 0))
                        for cpe in service_el.findall("cpe"):
                            if cpe.text:
                                cpe_list.append(cpe.text)

                    # NSE script çıktıları — tam metin
                    scripts: Dict[str, str] = {}
                    for script in port.findall("script"):
                        sid = script.get("id", "")
                        if not sid:
                            continue
                        # Hem output attribute hem de elem içindeki tablo/satırları al
                        out = script.get("output", "").strip()
                        # Alt elementleri de stringify et
                        for elem in script:
                            key_attr = elem.get("key", "")
                            val_attr = elem.get("value", "")
                            text = elem.text or ""
                            line = f"{key_attr}: {val_attr or text}".strip(": ")
                            if line:
                                out += f"\n  {line}"
                        scripts[sid] = out

                    # Host-level scriptleri de port kaydına ekle
                    for k, v in host_scripts.items():
                        if k not in scripts:
                            scripts[k] = v

                    results.append({
                        "ip":           ip,
                        "hostname":     hostname,
                        "host":         hostname or ip,
                        "port":         port_id,
                        "protocol":     protocol,
                        "proto":        protocol,
                        "reason":       reason,
                        "service":      service_name,
                        "product":      product,
                        "version":      version,
                        "extra_info":   extra_info,
                        "tunnel":       tunnel,
                        "service_conf": service_conf,
                        "cpe":          cpe_list,
                        "os_guess":     os_guess,
                        "os_accuracy":  os_accuracy,
                        "os_family":    os_family,
                        "os_gen":       os_gen,
                        "scripts":      scripts,
                        "state":        "open",
                    })

        except ET.ParseError as e:
            logger.warning(f"[Nmap] XML parse hatası (kısmi kurtarma deneniyor): {e}")
            # Kısmi XML kurtarma: son geçerli </port> tag'ine kadar kes ve kapat
            results = NmapParser._recover_partial_xml(file_path)
        except FileNotFoundError:
            logger.error(f"[Nmap] Dosya yok: {file_path}")
        except Exception as e:
            logger.error(f"[Nmap] Parse hatası: {e}")

        logger.info(f"[Nmap] {len(results)} servis parse edildi.")
        return results

    @staticmethod
    def _recover_partial_xml(file_path: str) -> List[Dict[str, Any]]:
        """
        Nmap crash sonrası yarım kalan XML dosyasından port kayıtlarını kurtarır.
        Son geçerli </port> tag'inden sonrasını keser, kapanış tag'lerini ekler.
        """
        results: List[Dict[str, Any]] = []
        try:
            content = open(file_path, encoding="utf-8", errors="replace").read()
            # Son </port> tag pozisyonunu bul
            last_port_close = content.rfind("</port>")
            if last_port_close == -1:
                logger.debug("[Nmap] Kurtarılacak <port> kaydı bulunamadı.")
                return []

            truncated = content[:last_port_close + len("</port>")] + \
                        "\n</ports></host></nmaprun>"

            root = ET.fromstring(truncated)
            # Normal parse_xml logic'ini yeniden çalıştır
            for host in root.findall("host"):
                status = host.find("status")
                if status is not None and status.get("state") != "up":
                    continue
                ip = "unknown"
                for addr in host.findall("address"):
                    if addr.get("addrtype") in ("ipv4", "ipv6"):
                        ip = addr.get("addr", "unknown")
                        break
                hostname = ""
                hn_el = host.find(".//hostname")
                if hn_el is not None:
                    hostname = hn_el.get("name", "")
                ports_el = host.find("ports")
                if ports_el is None:
                    continue
                for port in ports_el.findall("port"):
                    state = port.find("state")
                    if state is None or state.get("state") != "open":
                        continue
                    port_id = int(port.get("portid", 0))
                    protocol = port.get("protocol", "tcp")
                    svc = port.find("service")
                    service_name = svc.get("name", "unknown") if svc is not None else "unknown"
                    product = svc.get("product", "") if svc is not None else ""
                    version = svc.get("version", "") if svc is not None else ""
                    results.append({
                        "ip": ip, "hostname": hostname, "host": hostname or ip,
                        "port": port_id, "protocol": protocol, "proto": protocol,
                        "reason": "recovered", "service": service_name,
                        "product": product, "version": version,
                        "extra_info": "", "tunnel": "", "service_conf": 0,
                        "cpe": [], "os_guess": "", "os_accuracy": 0,
                        "os_family": "", "os_gen": "", "scripts": {}, "state": "open",
                    })
            logger.info(f"[Nmap] Kısmi XML kurtarma: {len(results)} kayıt elde edildi.")
        except Exception as exc:
            logger.debug(f"[Nmap] Kısmi kurtarma başarısız: {exc!r}")
        return results
