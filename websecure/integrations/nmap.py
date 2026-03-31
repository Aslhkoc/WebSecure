import logging
import os
import re
import shutil
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


def _is_root() -> bool:
    """Kali/Linux'ta root olup olmadığını kontrol eder."""
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False  # Windows


class NmapWrapper:
    """
    Nmap binary wrapper.
    Modlar:
      - aggressive : -sV -sC --version-intensity 9 -T4 --top-ports 10000 + vuln/auth scriptler
                     (root ise -O -A da eklenir)
      - deep       : -sV -sC -T3 --top-ports 3000 + ssl/http scriptler
      - standard   : -sV -T4 --top-ports 1000 + default scriptler
      - stealth    : -sT -T2 --top-ports 500 (root gerektirmez, yavaş)
      - fast       : -F -T4 (top 100, hızlı keşif)
      - full       : -sV -sC -p- -T4 (tüm 65535 port — çok uzun sürer)
      - ssl        : SSL/TLS odaklı tarama
    """

    def __init__(self, binary_path: str = "nmap"):
        self.binary = binary_path
        self._find_binary()

    def _find_binary(self):
        # Önce PATH'te ara
        found = shutil.which(self.binary)
        if found:
            self.binary = found
            return
        # Windows fallback yolları
        from pathlib import Path
        possible = [
            r"C:\Program Files (x86)\Nmap\nmap.exe",
            r"C:\Program Files\Nmap\nmap.exe",
            str(Path(__file__).resolve().parent.parent.parent / "tools" / "Nmap" / "nmap.exe"),
            str(Path(__file__).resolve().parent.parent.parent / "tools" / "nmap" / "nmap.exe"),
        ]
        for p in possible:
            if os.path.exists(p):
                self.binary = p
                logger.info(f"[Nmap] Binary bulundu: {p}")
                return
        logger.warning("[Nmap] Binary bulunamadı — PATH'e nmap kurun veya tools/ altına koyun.")

    def is_available(self) -> bool:
        if shutil.which(self.binary):
            return True
        return os.path.exists(self.binary)

    def scan(self,
             target: str,
             ports: str = None,
             mode: str = "aggressive",
             extra_args: List[str] = None,
             timeout: int = 600,
             proxy: str = None) -> List[Dict[str, Any]]:
        """
        Nmap taraması başlatır.

        Args:
            target  : Hedef IP/hostname
            ports   : Port spec (örn. "80,443") — None ise mod varsayılanı kullanılır
            mode    : "aggressive" | "deep" | "standard" | "stealth" | "fast" | "full" | "ssl"
            extra_args: Ek nmap argümanları listesi
            timeout : Subprocess timeout saniye (default 600)
            proxy   : SOCKS proxy URL

        Returns:
            List[Dict] — açık port ve servis bilgileri
        """
        if not self.is_available():
            logger.warning("[Nmap] Binary bulunamadı — port taraması atlandı.")
            print("[!] Nmap bulunamadı. Kali Linux'ta: sudo apt install nmap")
            return []

        fd, temp_output = tempfile.mkstemp(suffix=".xml")
        os.close(fd)

        try:
            cmd = [self.binary]

            # Mode argümanları
            mode_args = self._mode_args(mode, ports)

            # Extra args'ta timing flag varsa mode'dakini sil
            if extra_args and any(re.match(r'^-T[0-5]$', a) for a in extra_args):
                mode_args = [a for a in mode_args if not re.match(r'^-T[0-5]$', a)]

            cmd.extend(mode_args)

            # Ek argümanlar
            if extra_args:
                cmd.extend(extra_args)

            # XML çıktı
            cmd.extend(["-oX", temp_output])

            # Proxy (Nmap SOCKS5 desteklemiyor → SOCKS4'e çevir)
            if proxy:
                _p = proxy.replace("socks5h://", "socks4://").replace("socks5://", "socks4://")
                cmd.extend(["--proxies", _p])
                if "-n" not in cmd:
                    cmd.append("-n")

            # Hedef en sona
            cmd.append(target)

            # Kullanıcıya tam komutu göster
            cmd_str = " ".join(cmd)
            print(f"\n[Nmap] Tarama başlatılıyor:")
            print(f"  $ {cmd_str}\n")
            logger.info(f"[Nmap] Komut: {cmd_str}")

            # stderr'i yakala — hataları gizleme
            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                timeout=timeout,
            )

            # Çıktıyı logla
            if result.returncode != 0:
                err = result.stderr.decode("utf-8", errors="replace").strip()
                logger.warning(f"[Nmap] Çıkış kodu {result.returncode}. Stderr:\n{err}")
                print(f"[!] Nmap hata kodu {result.returncode}:\n{err}")
            else:
                stdout_txt = result.stdout.decode("utf-8", errors="replace").strip()
                if stdout_txt:
                    logger.debug(f"[Nmap] stdout:\n{stdout_txt}")

            parsed = NmapParser.parse_xml(temp_output)
            if parsed:
                print(f"[Nmap] {len(parsed)} açık port bulundu.")
            else:
                print("[Nmap] Açık port bulunamadı (veya tarama tamamlanamadı).")
            return parsed

        except subprocess.TimeoutExpired:
            logger.warning(f"[Nmap] Zaman aşımı ({timeout}s).")
            print(f"[!] Nmap {timeout}s'de tamamlanamadı. Daha az port veya daha hızlı mod deneyin.")
            return []
        except Exception as e:
            logger.error(f"[Nmap] Hata: {e}")
            print(f"[!] Nmap hatası: {e}")
            return []
        finally:
            try:
                os.remove(temp_output)
            except Exception:
                pass

    @staticmethod
    def _mode_args(mode: str, ports: Optional[str]) -> List[str]:
        """Tarama moduna göre nmap argümanlarını döndürür."""
        mode = (mode or "aggressive").lower()
        root = _is_root()
        args = []

        if mode == "aggressive":
            # En güçlü ve kapsamlı tarama — Kali/root'ta maksimum etki
            args = [
                "-sV", "--version-intensity", "9",
                "-sC",   # = --script=default (güvenli + bilgi toplama scriptleri)
                "--script", (
                    "default,auth,banner,discovery,"
                    "http-title,http-headers,http-methods,http-robots.txt,"
                    "http-server-header,http-auth-finder,"
                    "ssl-cert,ssl-enum-ciphers,ssl-heartbleed,"
                    "ftp-anon,ftp-bounce,"
                    "smtp-commands,smtp-open-relay,"
                    "ssh-auth-methods,ssh-hostkey,"
                    "vuln"
                ),
                "--script-timeout", "30s",
                "--top-ports", "10000",
                "-T4",
            ]
            # Root varsa OS detection + traceroute
            if root:
                args = ["-A"] + args  # -A = -sV -sC -O --traceroute

        elif mode == "deep":
            args = [
                "-sV", "--version-intensity", "7",
                "--script", (
                    "default,http-title,http-headers,http-methods,"
                    "ssl-cert,ssl-enum-ciphers,ssl-heartbleed,banner,auth"
                ),
                "--top-ports", "3000", "-T3",
            ]
            if root:
                args += ["-O", "--osscan-guess"]

        elif mode == "standard":
            args = [
                "-sV", "--version-intensity", "5",
                "--script", "default,http-title,http-headers,ssl-cert,banner",
                "--top-ports", "1000", "-T4",
            ]

        elif mode == "stealth":
            # -sT TCP connect scan — root gerektirmez, yavaş ama güvenli
            args = [
                "-sT", "-sV", "--version-intensity", "3",
                "--top-ports", "500", "-T2",
            ]

        elif mode == "fast":
            args = ["-F", "-T4"]

        elif mode == "full":
            # Tüm 65535 port — ÇOK uzun sürer
            args = [
                "-sV", "--version-intensity", "9",
                "-sC",
                "--script", "default,vuln,auth,banner",
                "-p-", "-T4",
            ]
            if root:
                args += ["-O", "--osscan-guess"]

        elif mode == "ssl":
            args = [
                "-sV", "--version-intensity", "7",
                "--script", (
                    "ssl-cert,ssl-enum-ciphers,ssl-heartbleed,ssl-dh-params,"
                    "ssl-poodle,sslv2,sslv2-drown,ssl-ccs-injection,ssl-date,ssl-known-key"
                ),
                "--script-timeout", "30s",
                "-p", "443,8443,465,993,995,8080,8888,4443",
                "-T4",
            ]

        else:
            # Fallback: standard
            args = [
                "-sV", "--version-intensity", "5",
                "--script", "default,http-title,ssl-cert,banner",
                "--top-ports", "1000", "-T4",
            ]

        # Port override — config'den gelmişse uygula, yoksa mod varsayılanı
        if ports:
            clean = []
            skip_next = False
            for a in args:
                if skip_next:
                    skip_next = False
                    continue
                if a == "-F":
                    continue
                if a == "--top-ports":
                    skip_next = True
                    continue
                clean.append(a)
            args = clean
            p = ports.lstrip("-p ").strip()
            args.extend(["-p", p])

        return args

    def quick_web_scan(self, target: str) -> List[Dict[str, Any]]:
        """Web odaklı hızlı tarama."""
        return self.scan(target, ports="80,443,8080,8443,8000,8888,9090,3000,4000,5000",
                         mode="standard")

    def vuln_scan(self, target: str, ports: str = None) -> List[Dict[str, Any]]:
        """Sadece zafiyet scriptleri."""
        extra = ["--script", "vuln,exploit", "--script-timeout", "60s"]
        return self.scan(target, ports=ports, mode="standard", extra_args=extra, timeout=900)


class NmapParser:
    """Nmap XML (-oX) çıktısını parse eder."""

    @staticmethod
    def parse_xml(file_path: str) -> List[Dict[str, Any]]:
        results = []
        try:
            tree = ET.parse(file_path)
            root = tree.getroot()

            for host in root.findall("host"):
                status = host.find("status")
                if status is not None and status.get("state") != "up":
                    continue

                address = host.find("address")
                ip = address.get("addr") if address is not None else "unknown"

                hostname = ""
                hostnames = host.find("hostnames")
                if hostnames is not None:
                    hn = hostnames.find("hostname")
                    if hn is not None:
                        hostname = hn.get("name", "")

                os_guess = ""
                osmatch = host.find(".//osmatch")
                if osmatch is not None:
                    os_guess = osmatch.get("name", "")

                ports_el = host.find("ports")
                if ports_el is None:
                    continue

                for port in ports_el.findall("port"):
                    state = port.find("state")
                    if state is None or state.get("state") != "open":
                        continue

                    port_id = int(port.get("portid", 0))
                    protocol = port.get("protocol", "tcp")

                    service_el = port.find("service")
                    service_name = "unknown"
                    product = version = extra_info = ""
                    cpe_list = []

                    if service_el is not None:
                        service_name = service_el.get("name", "unknown")
                        product      = service_el.get("product", "")
                        version      = service_el.get("version", "")
                        extra_info   = service_el.get("extrainfo", "")
                        for cpe in service_el.findall("cpe"):
                            cpe_list.append(cpe.text or "")

                    scripts: Dict[str, str] = {}
                    for script in port.findall("script"):
                        sid = script.get("id", "")
                        output = script.get("output", "")
                        if sid:
                            scripts[sid] = output

                    results.append({
                        "ip":         ip,
                        "hostname":   hostname,
                        "port":       port_id,
                        "protocol":   protocol,
                        "service":    service_name,
                        "product":    product,
                        "version":    version,
                        "extra_info": extra_info,
                        "cpe":        cpe_list,
                        "os_guess":   os_guess,
                        "scripts":    scripts,
                    })

        except ET.ParseError as e:
            logger.error(f"[Nmap] XML parse hatası: {e}")
        except FileNotFoundError:
            logger.error(f"[Nmap] XML dosyası bulunamadı: {file_path}")
        except Exception as e:
            logger.error(f"[Nmap] Parse hatası: {e}")

        logger.info(f"[Nmap] {len(results)} açık port parse edildi.")
        return results
