"""
WebSecure — Nmap Entegrasyonu (Maksimum Kapsam)

Tarama Stratejisi (2 Faz):
  Faz 1 — Port Keşfi : -p- --open -T4  → tüm 65535 TCP portunu hızlıca tara, açıkları bul
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
import re
import shutil
import subprocess
import tempfile
import threading
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# Kritik UDP portları — root ile taranır
_UDP_PORTS = "53,67,68,69,111,123,137,138,161,162,500,514,520,1900,4500,5353,11211"

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
        res = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
        )
        stdout = res.stdout.decode("utf-8", errors="replace")
        stderr = res.stderr.decode("utf-8", errors="replace")

        if res.returncode != 0:
            logger.warning(f"[Nmap] returncode={res.returncode}\nstderr: {stderr.strip()}")
            print(f"\033[33m[Nmap] Uyarı (kod {res.returncode}):\033[0m {stderr.strip()[:300]}")

        return res.returncode, xml_out, stdout, stderr

    except subprocess.TimeoutExpired:
        msg = f"[Nmap] Zaman aşımı ({timeout}s) — {cmd_str}"
        logger.warning(msg)
        print(f"\033[31m{msg}\033[0m")
        return -1, xml_out, "", "timeout"
    except Exception as e:
        logger.error(f"[Nmap] Hata: {e}")
        print(f"\033[31m[Nmap] Hata: {e}\033[0m")
        return -2, xml_out, "", str(e)
    # xml_out temizleme caller'a bırakılır


class NmapWrapper:
    """
    İki fazlı, servis-farkındalıklı, UDP destekli maksimum Nmap tarayıcısı.

    Faz 1 — Hızlı keşif  : tüm TCP portlarını hızla tara → açık portlar tespit
    Faz 2 — Derin analiz : tespit edilen portlara -sV + servis özelinde NSE scriptler
    UDP   — (root) kritik UDP servisleri
    """

    def __init__(self, binary_path: str = "nmap"):
        self.binary = binary_path
        self._find_binary()

    def _find_binary(self):
        found = shutil.which(self.binary)
        if found:
            self.binary = found
            return
        from pathlib import Path
        candidates = [
            r"C:\Program Files (x86)\Nmap\nmap.exe",
            r"C:\Program Files\Nmap\nmap.exe",
            str(Path(__file__).resolve().parent.parent.parent / "tools" / "Nmap" / "nmap.exe"),
        ]
        for c in candidates:
            if os.path.exists(c):
                self.binary = c
                logger.info(f"[Nmap] Binary: {c}")
                return
        logger.warning("[Nmap] Nmap bulunamadı. Kali: sudo apt install nmap")
        print("\033[31m[Nmap] Binary bulunamadı! Kali Linux: sudo apt install nmap\033[0m")

    def is_available(self) -> bool:
        return bool(shutil.which(self.binary)) or os.path.exists(self.binary)

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
        mode="aggressive" → 2-faz + UDP (root varsa)
        mode="stealth"    → TCP connect, yavaş, gizli
        mode="fast"       → tek faz, hızlı
        """
        if not self.is_available():
            print("\033[31m[Nmap] Bulunamadı. sudo apt install nmap\033[0m")
            return []

        root = _is_root()
        mode = (mode or "aggressive").lower()

        if mode in ("aggressive", "deep"):
            return self._scan_two_phase(target, root=root, proxy=proxy, timeout=timeout)
        elif mode == "stealth":
            return self._scan_stealth(target, proxy=proxy, timeout=timeout)
        elif mode == "full":
            return self._scan_two_phase(target, root=root, proxy=proxy,
                                         timeout=timeout, all_ports=True)
        elif mode == "fast":
            return self._scan_single(target,
                                     ["-F", "-T4", "--open"],
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
        Faz 1: Tüm TCP portlarını hızlıca tara → açık portları bul
        Faz 2: Bulunan portlarda derin servis + NSE script analizi
        UDP:   Root varsa kritik UDP portları
        """

        # ----- FAZ 1: Port Keşfi -----
        print(f"\033[36m[Nmap Faz-1]\033[0m Port keşfi başlıyor ({target})...")

        if root:
            # SYN scan — en hızlı ve güvenilir
            phase1_args = ["-sS", "-p-" if all_ports else "--top-ports", "65535" if all_ports else "",
                           "-T4", "--open", "--min-rate", "1000", "--max-retries", "2"]
            phase1_args = [a for a in phase1_args if a]  # boşları temizle
            if not all_ports:
                phase1_args = ["-sS", "--top-ports", "65535", "-T4", "--open",
                               "--min-rate", "1000", "--max-retries", "2"]
        else:
            # TCP connect scan — root gerektirmez
            phase1_args = ["-sT", "--top-ports", "10000", "-T4", "--open",
                           "--max-retries", "2"]

        self._inject_proxy(phase1_args, proxy)
        rc1, xml1, _, _ = _run_nmap(self.binary, phase1_args, target, timeout=max(timeout // 2, 180))

        # Açık portları ayıkla
        open_ports = self._extract_open_ports(xml1)
        try:
            os.remove(xml1)
        except Exception:
            pass

        if not open_ports:
            print(f"\033[33m[Nmap Faz-1]\033[0m {target} üzerinde açık port bulunamadı.")
            return []

        print(f"\033[32m[Nmap Faz-1]\033[0m {len(open_ports)} açık port bulundu: "
              f"{','.join(map(str, sorted(open_ports)[:30]))}{'...' if len(open_ports) > 30 else ''}")

        # ----- FAZ 2: Derin Analiz -----
        print(f"\033[36m[Nmap Faz-2]\033[0m Derin servis + script analizi ({len(open_ports)} port)...")

        ports_str = ",".join(map(str, sorted(open_ports)))

        # Hangi servislerin çalıştığını tahmin et (faz1 parse'dan)
        faz1_results = []  # faz1 artık silinmiş, faz2 parse edecek

        phase2_args = [
            "-sV", "--version-intensity", "9",
            "--version-all",          # tüm probe'ları dene
            "-sC",                    # default script kategorisi
            "-O" if root else "",     # OS detection (root)
            "--osscan-guess" if root else "",
            "-A" if root else "",     # aggressive: -sV -sC -O --traceroute
            "--script", self._build_script_list(),
            "--script-args",
            "http.useragent=Mozilla/5.0,brute.firstonly=true,"
            "vulns.showall=true,unsafe=1",
            "--script-timeout", "60s",
            "-p", ports_str,
            "-T4",
        ]
        phase2_args = [a for a in phase2_args if a]  # boşları temizle
        self._inject_proxy(phase2_args, proxy)

        rc2, xml2, _, _ = _run_nmap(self.binary, phase2_args, target, timeout=timeout)
        results = NmapParser.parse_xml(xml2)
        try:
            os.remove(xml2)
        except Exception:
            pass

        # ----- UDP Taraması (root) -----
        if root:
            print(f"\033[36m[Nmap UDP]\033[0m Kritik UDP portları taranıyor...")
            udp_args = [
                "-sU",
                "--version-intensity", "5",
                "--script", "snmp-info,snmp-sysdescr,snmp-brute,dns-recursion,"
                            "dns-service-discovery,ntp-info,tftp-enum,dhcp-discover,"
                            "sip-methods,broadcast-listener",
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
        """TCP connect, yavaş, gizli — root gerektirmez."""
        print(f"\033[36m[Nmap Stealth Faz-1]\033[0m Port keşfi ({target})...")

        phase1_args = ["-sT", "--top-ports", "5000", "-T2", "--open", "--max-retries", "1"]
        self._inject_proxy(phase1_args, proxy)
        _, xml1, _, _ = _run_nmap(self.binary, phase1_args, target, timeout=timeout // 2)
        open_ports = self._extract_open_ports(xml1)
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
            "-sT", "-sV", "--version-intensity", "6",
            "--script", self._build_script_list(safe_only=True),
            "--script-timeout", "30s",
            "-p", ports_str, "-T2",
        ]
        self._inject_proxy(phase2_args, proxy)
        _, xml2, _, _ = _run_nmap(self.binary, phase2_args, target, timeout=timeout)
        results = NmapParser.parse_xml(xml2)
        try:
            os.remove(xml2)
        except Exception:
            pass
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
        p = proxy.replace("socks5h://", "socks4://").replace("socks5://", "socks4://")
        args.extend(["--proxies", p])
        if "-n" not in args:
            args.append("-n")

    @staticmethod
    def _build_script_list(safe_only: bool = False) -> str:
        """Maksimum NSE script listesi oluşturur."""
        if safe_only:
            return (
                "default,auth,discovery,version,safe,"
                "banner,ssl-cert,ssl-enum-ciphers,http-title,http-headers,ssh-hostkey"
            )
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
        """XML dosyasından sadece açık port numaralarını çıkarır."""
        ports = []
        try:
            tree = ET.parse(xml_file)
            for port in tree.getroot().findall(".//port"):
                state = port.find("state")
                if state is not None and state.get("state") == "open":
                    try:
                        ports.append(int(port.get("portid", 0)))
                    except (ValueError, TypeError):
                        pass
        except Exception as e:
            logger.debug(f"[Nmap] Port çıkarma hatası: {e}")
        return ports

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
            logger.error(f"[Nmap] XML parse hatası: {e}")
        except FileNotFoundError:
            logger.error(f"[Nmap] Dosya yok: {file_path}")
        except Exception as e:
            logger.error(f"[Nmap] Parse hatası: {e}")

        logger.info(f"[Nmap] {len(results)} servis parse edildi.")
        return results
