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


def _rm_xml(path: Optional[str]) -> None:
    """Geçici nmap XML dosyasını sessizce siler."""
    if not path:
        return
    try:
        os.remove(path)
    except Exception:
        pass


def _run_nmap(binary: str, args: List[str], target: str,
              timeout: int = 900) -> Tuple[int, str, str, str]:
    """
    Nmap çalıştırır, XML çıktısını döner.
    Stdout gerçek zamanlı yazdırılır — kullanıcı tarama ilerlemesini görebilir.
    Returns: (returncode, xml_file_path, stdout, stderr)
    """
    fd, xml_out = tempfile.mkstemp(suffix=".xml")
    os.close(fd)

    cmd = [binary] + args + ["-oX", xml_out, target]
    cmd_str = " ".join(str(a) for a in cmd)
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

        # Gerçek zamanlı stdout okuma — kullanıcı tarama ilerlemesini görür
        stdout_lines: List[str] = []
        stderr_lines: List[str] = []

        def _drain_stderr():
            for raw in proc.stderr:
                line = raw.decode("utf-8", errors="replace").rstrip()
                stderr_lines.append(line)

        stderr_thread = threading.Thread(target=_drain_stderr, daemon=True)
        stderr_thread.start()

        deadline = time.monotonic() + timeout
        try:
            for raw in proc.stdout:
                line = raw.decode("utf-8", errors="replace").rstrip()
                stdout_lines.append(line)
                print(f"  {line}")          # gerçek zamanlı ekrana yaz
                if time.monotonic() > deadline:
                    proc.kill()
                    msg = f"[Nmap] Zaman aşımı ({timeout}s)"
                    logger.warning(msg)
                    print(f"\033[31m{msg}\033[0m")
                    break
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
        finally:
            stderr_thread.join(timeout=5)
            try:
                from websecure.core.phases import unregister_child_proc
                unregister_child_proc(proc)
            except Exception:
                pass

        stdout = "\n".join(stdout_lines)
        stderr = "\n".join(stderr_lines)

        if proc.returncode not in (0, 1, None):
            logger.warning(f"[Nmap] returncode={proc.returncode}\nstderr: {stderr.strip()[:300]}")
            print(f"\033[33m[Nmap] Uyarı (kod {proc.returncode}):\033[0m {stderr.strip()[:300]}")

        return proc.returncode or 0, xml_out, stdout, stderr

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
        # 1. PATH üzerinden ara
        found = shutil.which(self.binary)
        if found:
            self._binary_path = found
            return

        # 2. Yaygın kurulum konumları (Windows + Linux + macOS)
        from pathlib import Path
        candidates = [
            r"C:\Program Files (x86)\Nmap\nmap.exe",
            r"C:\Program Files\Nmap\nmap.exe",
            r"C:\Nmap\nmap.exe",
            r"C:\tools\nmap\nmap.exe",
            "/usr/bin/nmap",
            "/usr/local/bin/nmap",
            "/opt/homebrew/bin/nmap",
            str(Path(__file__).resolve().parent.parent.parent / "tools" / "Nmap" / "nmap.exe"),
        ]

        # 3. Windows PATH kayıt defterinden de dene
        try:
            import winreg
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                 r"SOFTWARE\Nmap")
            install_dir, _ = winreg.QueryValueEx(key, "")
            winreg.CloseKey(key)
            candidates.insert(0, os.path.join(install_dir, "nmap.exe"))
        except Exception:
            pass

        # 4. Sistem PATH'i doğrudan os.environ'dan yeniden oku (process başlatıldıktan sonra güncellenmiş olabilir)
        try:
            import subprocess as _sp
            if platform.system() == "Windows":
                result = _sp.run(["where", "nmap"], capture_output=True, text=True, timeout=5)
            else:
                result = _sp.run(["which", "nmap"], capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                found = result.stdout.strip().splitlines()[0]
                if found and os.path.exists(found):
                    self._binary_path = found
                    logger.info(f"[Nmap] Binary (shell lookup): {found}")
                    return
        except Exception:
            pass

        for c in candidates:
            if os.path.exists(c):
                self._binary_path = c
                logger.info(f"[Nmap] Binary (fallback): {c}")
                return

        logger.warning("[Nmap] Nmap bulunamadı — nmap.org'dan indir veya PATH'e ekle.")

    def is_available(self) -> bool:
        if hasattr(self, "_binary_path") and self._binary_path and os.path.exists(self._binary_path):
            return True
        self._find_binary()
        return hasattr(self, "_binary_path") and bool(self._binary_path) and os.path.exists(self._binary_path)

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
    # Ana tarama metodu — mod yönlendirici
    # ------------------------------------------------------------------

    def scan(self,
             target: str,
             ports: Optional[str] = None,
             mode: str = "aggressive",
             extra_args: Optional[List[str]] = None,
             timeout: int = 900,
             proxy: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Mod tabanlı nmap taraması.

        aggressive  — T4, SYN+UDP, -A, tüm NSE kategorileri (vuln/exploit/brute)
        stealth     — T2, SYN half-open, paket fragmentasyon, decoy, minimal script
        normal      — T3, SYN, default+vuln scriptler, dengeli
        deep        — aggressive + tüm 65535 port
        full        — deep ile aynı
        fast        — T4, top-100 port, script yok, hızlı keşif
        """
        if not self.is_available():
            print("\033[31m[Nmap] Bulunamadı. sudo apt install nmap\033[0m")
            return []

        on_windows = _is_windows()
        root = _is_root()
        _npcap_ok = on_windows and root and _has_npcap()
        _raw = (root and not on_windows) or _npcap_ok   # SYN / raw socket erişimi var mı

        if _raw and _npcap_ok:
            print("\033[36m[Nmap]\033[0m Windows Admin + Npcap — SYN scan aktif")
        elif _raw:
            print("\033[36m[Nmap]\033[0m Root — SYN scan aktif")
        else:
            print("\033[36m[Nmap]\033[0m Raw socket yok — TCP connect modunda")

        mode = (mode or "aggressive").lower()

        if mode == "aggressive":
            return self._scan_aggressive(target, raw=_raw, on_windows=on_windows,
                                         all_ports=False, ports=ports,
                                         extra_args=extra_args, proxy=proxy, timeout=timeout)
        elif mode == "stealth":
            return self._scan_stealth(target, raw=_raw, on_windows=on_windows,
                                      ports=ports, extra_args=extra_args,
                                      proxy=proxy, timeout=timeout)
        elif mode in ("normal", "standard"):
            return self._scan_normal(target, raw=_raw, on_windows=on_windows,
                                     ports=ports, extra_args=extra_args,
                                     proxy=proxy, timeout=timeout)
        elif mode in ("deep", "full"):
            return self._scan_aggressive(target, raw=_raw, on_windows=on_windows,
                                         all_ports=True, ports=ports,
                                         extra_args=extra_args, proxy=proxy, timeout=timeout)
        elif mode == "fast":
            return self._scan_fast(target, raw=_raw, on_windows=on_windows,
                                   ports=ports, proxy=proxy, timeout=min(timeout, 300))
        else:
            return self._scan_aggressive(target, raw=_raw, on_windows=on_windows,
                                         ports=ports, extra_args=extra_args,
                                         proxy=proxy, timeout=timeout)

    # ------------------------------------------------------------------
    # AGRESİF — T4, SYN+UDP, -A, tüm NSE kategorileri
    # ------------------------------------------------------------------

    def _scan_aggressive(self, target: str, raw: bool, on_windows: bool,
                         all_ports: bool = False, ports: Optional[str] = None,
                         extra_args: Optional[List[str]] = None,
                         proxy: Optional[str] = None, timeout: int = 900) -> List[Dict[str, Any]]:
        """
        AGRESİF TARAMA:
          Faz-1: SYN (veya TCP connect) + -Pn + T4 + top-1000 port keşfi
          Faz-2: -sS -sV -A -O + tüm NSE kategorileri + vuln/exploit/brute
          UDP:   raw socket varsa kritik UDP portları
        """
        print(f"\n\033[36;1m[Nmap AGRESİF]\033[0m Faz-1 — Port keşfi ({target})...")

        # --- FAZ 1: Hızlı port keşfi ---
        scan1 = "-sS" if raw else "-sT"
        if ports:
            port_args1 = ["-p", ports]
        elif all_ports:
            port_args1 = ["-p-"]
        else:
            port_args1 = ["--top-ports", "1000"]

        phase1 = (
            [scan1, "-Pn", "--open"] + port_args1 +
            ["-T4", "--min-rate", "1000" if raw else "500",
             "--max-retries", "2", "--host-timeout", "600s"]
        )
        if on_windows and not raw:
            phase1 += ["--unprivileged"]

        self._inject_proxy(phase1, proxy)
        t1 = max(timeout // 2, 300)
        rc1, xml1, _, _ = _run_nmap(self.binary, phase1, target, timeout=t1)
        open_ports = NmapParser.extract_open_ports_safe(xml1)
        _rm_xml(xml1)

        if rc1 not in (0, 1) and not open_ports:
            print(f"\033[33m[Nmap AGRESİF Faz-1]\033[0m rc={rc1} — açık port bulunamadı, tarama durdu.")
            return []
        if not open_ports:
            print(f"\033[33m[Nmap AGRESİF]\033[0m {target} üzerinde açık port yok.")
            return []

        print(f"\033[32m[Nmap AGRESİF Faz-1]\033[0m {len(open_ports)} port → "
              f"{','.join(map(str, sorted(open_ports)[:30]))}{'...' if len(open_ports) > 30 else ''}")

        # --- FAZ 2: Derin servis + script analizi ---
        print(f"\033[36;1m[Nmap AGRESİF]\033[0m Faz-2 — Derin analiz ({len(open_ports)} port)...")
        ports_str = ",".join(map(str, sorted(open_ports)))

        if raw:
            # Tam güç: SYN + sürüm 9 + OS + -A + tüm NSE
            phase2 = [
                "-sS", "-Pn", "-T4",
                "-sV", "--version-intensity", "9", "--version-all",
                "-O", "--osscan-guess",
                "-A",
                "--script", (
                    "default,auth,discovery,vuln,exploit,malware,safe,brute,"
                    "banner,ssl-cert,ssl-enum-ciphers,ssl-heartbleed,ssl-dh-params,"
                    "ssl-poodle,ssl-ccs-injection,http-title,http-headers,http-methods,"
                    "http-auth-finder,http-server-header,http-robots.txt,http-git,"
                    "http-shellshock,http-vuln-cve2017-5638,http-vuln-cve2015-1635,"
                    "http-backup-finder,http-default-accounts,"
                    "ssh-auth-methods,ssh-hostkey,ssh2-enum-algos,"
                    "ftp-anon,ftp-bounce,ftp-vsftpd-backdoor,"
                    "smtp-commands,smtp-open-relay,smtp-enum-users,"
                    "smb-os-discovery,smb-security-mode,smb-enum-shares,"
                    "smb-vuln-ms17-010,smb-vuln-ms08-067,"
                    "mysql-info,mysql-empty-password,mysql-databases,"
                    "ms-sql-info,ms-sql-empty-password,"
                    "rdp-enum-encryption,rdp-vuln-ms12-020,"
                    "dns-recursion,dns-zone-transfer,"
                    "snmp-info,snmp-sysdescr,"
                    "mongodb-info,redis-info"
                ),
                "--script-args",
                "http.useragent=Mozilla/5.0,brute.firstonly=true,"
                "vulns.showall=true,unsafe=1",
                "--script-timeout", "90s",
                "--host-timeout", "600s",
                "-p", ports_str,
            ]
            if on_windows:
                # Windows'ta OS detection kısıtlı — kaldır
                phase2 = [a for a in phase2
                          if a not in ("-O", "--osscan-guess", "-A")]
        else:
            # TCP connect — raw socket yok
            phase2 = [
                "-sT", "-Pn", "-T4",
                "-sV", "--version-intensity", "7",
                "-sC",
                "--script", (
                    "default,auth,safe,vuln,"
                    "banner,ssl-cert,ssl-enum-ciphers,http-title,http-headers,"
                    "http-methods,http-auth-finder,http-server-header,http-robots.txt,"
                    "http-git,http-backup-finder,http-default-accounts,"
                    "ssh-auth-methods,ssh-hostkey,ssh2-enum-algos,"
                    "ftp-anon,ftp-syst,smtp-commands,smtp-open-relay,"
                    "smb-security-mode,smb-enum-shares,"
                    "mysql-info,mysql-empty-password,"
                    "ms-sql-info,ms-sql-empty-password,"
                    "rdp-enum-encryption,dns-recursion,"
                    "mongodb-info,redis-info"
                ),
                "--script-args",
                "http.useragent=Mozilla/5.0,brute.firstonly=true,vulns.showall=true",
                "--script-timeout", "60s",
                "--host-timeout", "600s",
                "-p", ports_str,
            ]
            if on_windows:
                phase2 += ["--unprivileged"]

        if extra_args:
            phase2.extend(extra_args)

        self._inject_proxy(phase2, proxy)
        rc2, xml2, _, _ = _run_nmap(self.binary, phase2, target, timeout=timeout)
        if rc2 not in (0, 1):
            print(f"\033[33m[Nmap AGRESİF Faz-2]\033[0m rc={rc2} — kısmi XML kurtarılıyor...")
        results = NmapParser.parse_xml(xml2) if xml2 else []
        _rm_xml(xml2)

        # --- UDP: raw socket varsa kritik portlar ---
        if raw:
            print(f"\033[36m[Nmap UDP]\033[0m Kritik UDP portları taranıyor...")
            udp_args = [
                "-sU", "-Pn", "-T4",
                "--version-intensity", "5",
                "--script", (
                    "snmp-info,snmp-sysdescr,snmp-brute,"
                    "dns-recursion,dns-service-discovery,"
                    "ntp-info,tftp-enum,dhcp-discover,"
                    "sip-methods,upnp-info"
                ),
                "-p", _UDP_PORTS,
                "--max-retries", "1",
                "--host-timeout", "300s",
            ]
            self._inject_proxy(udp_args, proxy)
            _, xml_udp, _, _ = _run_nmap(self.binary, udp_args, target, timeout=300)
            udp_res = NmapParser.parse_xml(xml_udp)
            _rm_xml(xml_udp)
            if udp_res:
                results.extend(udp_res)
                print(f"\033[32m[Nmap UDP]\033[0m {len(udp_res)} UDP servis bulundu.")

        if results:
            print(f"\n\033[32;1m[Nmap AGRESİF]\033[0m Tamamlandı — {len(results)} port/servis.\n")
        return results

    # ------------------------------------------------------------------
    # STEALTH — T2, SYN half-open, fragmentasyon, decoy, minimal script
    # ------------------------------------------------------------------

    def _scan_stealth(self, target: str, raw: bool, on_windows: bool,
                      ports: Optional[str] = None, extra_args: Optional[List[str]] = None,
                      proxy: Optional[str] = None, timeout: int = 900) -> List[Dict[str, Any]]:
        """
        STEALTH TARAMA:
          - T2 timing: çok yavaş → IDS alarm eşiğinin altında kalır
          - SYN half-open: bağlantı tamamlanmaz → log bırakmaz (raw socket gerektirir)
          - -f: paket fragmentasyon → DPI atlatır
          - -D RND:3: decoy IP'ler → kaynak tespitini zorlaştırır
          - Minimal script: sadece safe → gürültü üretmez
          - Düşük version intensity → az prob → az iz
        """
        print(f"\n\033[35;1m[Nmap STEALTH]\033[0m Faz-1 — Sessiz port keşfi ({target})...")

        port_args = ["-p", ports] if ports else ["--top-ports", "1000"]

        if raw:
            # SYN half-open + fragmentasyon + decoy = maksimum gizlilik
            phase1 = (
                ["-sS", "-Pn", "--open"] + port_args +
                ["-T2", "--max-retries", "1", "--scan-delay", "500ms",
                 "-f", "--data-length", "25", "-D", "RND:3",
                 "--host-timeout", "900s"]
            )
        else:
            # TCP connect — raw socket yok, en azından T2 yavaşlık sağlar
            phase1 = (
                ["-sT", "-Pn", "--open"] + port_args +
                ["-T2", "--max-retries", "1",
                 "--host-timeout", "900s"]
            )
            if on_windows:
                phase1 += ["--unprivileged"]

        self._inject_proxy(phase1, proxy)
        t1 = max(timeout // 2, 300)
        _, xml1, _, _ = _run_nmap(self.binary, phase1, target, timeout=t1)
        open_ports = NmapParser.extract_open_ports_safe(xml1)
        _rm_xml(xml1)

        if not open_ports:
            print(f"\033[33m[Nmap STEALTH]\033[0m {target} üzerinde açık port yok.")
            return []

        print(f"\033[35m[Nmap STEALTH Faz-1]\033[0m {len(open_ports)} port → "
              f"{','.join(map(str, sorted(open_ports)[:30]))}")

        # --- FAZ 2: Sessiz servis analizi ---
        print(f"\033[35;1m[Nmap STEALTH]\033[0m Faz-2 — Sessiz servis analizi ({len(open_ports)} port)...")
        ports_str = ",".join(map(str, sorted(open_ports)))

        if raw:
            phase2 = [
                "-sS", "-Pn", "-T2",
                "-sV", "--version-intensity", "2",     # Düşük yoğunluk = az gürültü
                "--script", "default,safe",             # Sadece safe = IDS radarı altında
                "--script-args", "http.useragent=Mozilla/5.0",
                "--script-timeout", "30s",
                "--host-timeout", "600s",
                "-p", ports_str,
                "-f", "--data-length", "25",            # Fragmentasyon korunuyor
            ]
        else:
            phase2 = [
                "-sT", "-Pn", "-T2",
                "-sV", "--version-intensity", "2",
                "--script", "default,safe",
                "--script-args", "http.useragent=Mozilla/5.0",
                "--script-timeout", "30s",
                "--host-timeout", "600s",
                "-p", ports_str,
            ]
            if on_windows:
                phase2 += ["--unprivileged"]

        if extra_args:
            phase2.extend(extra_args)

        self._inject_proxy(phase2, proxy)
        _, xml2, _, _ = _run_nmap(self.binary, phase2, target, timeout=timeout)
        results = NmapParser.parse_xml(xml2)
        _rm_xml(xml2)

        if results:
            print(f"\033[35m[Nmap STEALTH]\033[0m Tamamlandı — {len(results)} açık port/servis.")
        return results

    # ------------------------------------------------------------------
    # NORMAL — T3, dengeli, default+vuln scriptler
    # ------------------------------------------------------------------

    def _scan_normal(self, target: str, raw: bool, on_windows: bool,
                     ports: Optional[str] = None, extra_args: Optional[List[str]] = None,
                     proxy: Optional[str] = None, timeout: int = 900) -> List[Dict[str, Any]]:
        """
        NORMAL TARAMA:
          - T3: dengeli hız (IDS riski ve keşif arasında denge)
          - SYN veya TCP connect
          - version intensity 5: orta derinlik
          - default + safe + vuln scriptler
        """
        print(f"\n\033[36m[Nmap NORMAL]\033[0m Faz-1 — Port keşfi ({target})...")

        scan_t = "-sS" if raw else "-sT"
        port_args = ["-p", ports] if ports else ["--top-ports", "1000"]

        phase1 = (
            [scan_t, "-Pn", "--open"] + port_args +
            ["-T3", "--max-retries", "2", "--host-timeout", "600s"]
        )
        if on_windows and not raw:
            phase1 += ["--unprivileged"]

        self._inject_proxy(phase1, proxy)
        t1 = max(timeout // 2, 240)
        _, xml1, _, _ = _run_nmap(self.binary, phase1, target, timeout=t1)
        open_ports = NmapParser.extract_open_ports_safe(xml1)
        _rm_xml(xml1)

        if not open_ports:
            print(f"\033[33m[Nmap NORMAL]\033[0m {target} üzerinde açık port yok.")
            return []

        print(f"\033[32m[Nmap NORMAL Faz-1]\033[0m {len(open_ports)} port → "
              f"{','.join(map(str, sorted(open_ports)[:30]))}")

        print(f"\033[36m[Nmap NORMAL]\033[0m Faz-2 — Servis analizi ({len(open_ports)} port)...")
        ports_str = ",".join(map(str, sorted(open_ports)))

        phase2 = [
            scan_t, "-Pn", "-T3",
            "-sV", "--version-intensity", "5",
            "-sC",
            "--script", "default,safe,vuln",
            "--script-args", "http.useragent=Mozilla/5.0,vulns.showall=true",
            "--script-timeout", "60s",
            "--host-timeout", "600s",
            "-p", ports_str,
        ]
        if on_windows and not raw:
            phase2 += ["--unprivileged"]
        if extra_args:
            phase2.extend(extra_args)

        self._inject_proxy(phase2, proxy)
        _, xml2, _, _ = _run_nmap(self.binary, phase2, target, timeout=timeout)
        results = NmapParser.parse_xml(xml2)
        _rm_xml(xml2)

        if results:
            print(f"\033[32m[Nmap NORMAL]\033[0m Tamamlandı — {len(results)} açık port/servis.")
        return results

    # ------------------------------------------------------------------
    # FAST — T4, top-100, script yok, hızlı keşif
    # ------------------------------------------------------------------

    def _scan_fast(self, target: str, raw: bool, on_windows: bool,
                   ports: Optional[str] = None, proxy: Optional[str] = None,
                   timeout: int = 180) -> List[Dict[str, Any]]:
        """
        FAST: T4, top-100 port (veya -F), versiyon yok, script yok.
        Saniyeler içinde açık portları listeler.
        """
        print(f"\n\033[36m[Nmap FAST]\033[0m Hızlı port keşfi ({target})...")

        scan_t = "-sS" if raw else "-sT"
        port_args = ["-p", ports] if ports else ["-F"]   # -F = nmap'in top-100 portu

        args = (
            [scan_t, "-Pn", "--open"] + port_args +
            ["-T4", "--host-timeout", "60s"]
        )
        if on_windows and not raw:
            args += ["--unprivileged"]

        self._inject_proxy(args, proxy)
        _, xml, _, _ = _run_nmap(self.binary, args, target, timeout=timeout)
        results = NmapParser.parse_xml(xml)
        _rm_xml(xml)

        if results:
            print(f"\033[32m[Nmap FAST]\033[0m {len(results)} açık port bulundu.")
        return results

    # ------------------------------------------------------------------
    # Yardımcı: temp XML temizle
    # ------------------------------------------------------------------

    @staticmethod
    def _rm_temp(path: Optional[str]) -> None:
        _rm_xml(path)

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
        """Web odaklı hızlı tarama — sadece web portları, T4, web scriptleri."""
        on_windows = _is_windows()
        root = _is_root()
        _npcap_ok = on_windows and root and _has_npcap()
        raw = (root and not on_windows) or _npcap_ok

        scan_t = "-sS" if raw else "-sT"
        args = [
            scan_t, "-Pn", "--open",
            "-p", "80,443,8080,8443,8000,8888,9090,3000,4000,5000",
            "-T4",
            "-sV", "--version-intensity", "7",
            "-sC",
            "--script",
            "http-title,http-headers,http-methods,http-auth-finder,"
            "http-server-header,http-robots.txt,http-git,http-backup-finder,"
            "ssl-cert,ssl-enum-ciphers,banner",
            "--script-args", "http.useragent=Mozilla/5.0",
            "--script-timeout", "30s",
            "--host-timeout", "120s",
        ]
        if on_windows and not raw:
            args += ["--unprivileged"]

        self._inject_proxy(args, None)
        _, xml, _, _ = _run_nmap(self.binary, args, target, timeout=120)
        results = NmapParser.parse_xml(xml)
        _rm_xml(xml)

        if results:
            print(f"\033[32m[Nmap quick_web_scan]\033[0m {len(results)} web portu bulundu.")
        return results


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
