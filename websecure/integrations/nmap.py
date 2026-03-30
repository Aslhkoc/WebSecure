import logging
import re
import xml.etree.ElementTree as ET
from typing import List, Dict, Optional, Any

import subprocess
import shutil
import tempfile
import os

logger = logging.getLogger(__name__)


class NmapWrapper:
    """
    Nmap binary wrapper.
    Desteklenen tarama modları:
      - fast:       -F (top 100 ports), hızlı keşif
      - standard:   -sV -sC --top-ports 1000 (servis+script)
      - deep:       -sV -sC -O -A --top-ports 3000 (OS+aggresive)
      - full:       -sV -sC -O -p- (tüm 65535 port)
      - stealth:    -sS -T2 (SYN stealth, yavaş)
    """

    def __init__(self, binary_path: str = "nmap"):
        self.binary = binary_path
        self._find_binary()

    def _find_binary(self):
        if shutil.which(self.binary):
            return
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
                break

    def is_available(self) -> bool:
        if shutil.which(self.binary):
            return True
        return os.path.exists(self.binary)

    def scan(self,
             target: str,
             ports: str = None,
             mode: str = "standard",
             extra_args: List[str] = None,
             timeout: int = 300,
             proxy: str = None) -> List[Dict[str, Any]]:
        """
        Nmap taraması başlatır.

        Args:
            target:     Hedef IP/hostname
            ports:      Port spec (örn. "-p80,443", "-p-"). None ise mode'dan seçilir.
            mode:       "fast" | "standard" | "deep" | "full" | "stealth"
            extra_args: Ek nmap argümanları
            timeout:    Subprocess timeout (saniye)

        Returns:
            List[Dict] — açık port ve servis bilgileri
        """
        if not self.is_available():
            logger.warning("Nmap binary bulunamadı.")
            return []

        fd, temp_output = tempfile.mkstemp(suffix=".xml")
        os.close(fd)

        try:
            cmd = [self.binary]

            # Mode-based scan args — strip timing flag if extra_args override it
            mode_args = self._mode_args(mode, ports)
            if extra_args and any(re.match(r'^-T[0-5]$', a) for a in extra_args):
                mode_args = [a for a in mode_args if not re.match(r'^-T[0-5]$', a)]
            cmd.extend(mode_args)

            # Extra args before target (nmap best practice)
            if extra_args:
                cmd.extend(extra_args)

            # XML output
            cmd.extend(["-oX", temp_output])

            # Nmap SOCKS4 proxy (Nmap socks5 desteklemiyor, socks4 yeterli)
            if proxy:
                _nmap_proxy = proxy.replace("socks5h://", "socks4://").replace("socks5://", "socks4://")
                cmd.extend(["--proxies", _nmap_proxy])

            # Target always last
            cmd.append(target)

            logger.info(f"[Nmap] {target} üzerinde '{mode}' taraması başlatılıyor...")
            logger.debug(f"[Nmap] {target} taranıyor (mod={mode}, portlar={ports or 'otomatik'})...")

            subprocess.run(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
                timeout=timeout
            )

            return NmapParser.parse_xml(temp_output)

        except subprocess.TimeoutExpired:
            logger.warning(f"[Nmap] {target} taraması zaman aşımına uğradı ({timeout}s).")
            return []
        except Exception as e:
            logger.error(f"[Nmap] Yürütme hatası: {e}")
            return []
        finally:
            if os.path.exists(temp_output):
                try:
                    os.remove(temp_output)
                except Exception as exc:
                    pass

    @staticmethod
    def _mode_args(mode: str, ports: Optional[str]) -> List[str]:
        """Tarama moduna göre nmap argümanlarını döndürür."""
        mode = (mode or "standard").lower()
        args = []

        if mode == "fast":
            args = ["-F", "-T4"]
        elif mode == "standard":
            args = ["-sV", "--version-intensity", "5", "-sC", "--top-ports", "1000", "-T4"]
        elif mode == "deep":
            args = ["-sV", "--version-intensity", "9", "-sC", "-O", "--osscan-guess",
                    "-A", "--top-ports", "3000", "-T3"]
        elif mode == "full":
            args = ["-sV", "--version-intensity", "9", "-sC", "-O", "--osscan-guess",
                    "-p-", "-T3"]
        elif mode == "stealth":
            args = ["-sS", "-sV", "--version-intensity", "3", "-T2", "--top-ports", "500"]
        else:
            args = ["-sV", "-sC", "--top-ports", "1000", "-T4"]

        # Override port spec if explicitly given
        if ports:
            # Remove any --top-ports or -F from args list first
            clean_args = []
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
                clean_args.append(a)
            args = clean_args
            args.extend(["-p", ports.lstrip("-p")] if not ports.startswith("-p") else [ports])

        return args

    def quick_web_scan(self, target: str) -> List[Dict[str, Any]]:
        """Web odaklı hızlı tarama: 80, 443, 8080, 8443, 8000, 8888, 9090."""
        return self.scan(target, ports="80,443,8080,8443,8000,8888,9090,3000,4000,5000", mode="standard")

    def vuln_scan(self, target: str, ports: str = None) -> List[Dict[str, Any]]:
        """Zafiyet script taraması (nmap --script vuln)."""
        extra = ["--script", "vuln,auth,default,discovery", "--script-timeout", "30s"]
        return self.scan(target, ports=ports, mode="standard", extra_args=extra, timeout=600)


class NmapParser:
    """
    Nmap XML (-oX) çıktısını parse eder.
    """

    @staticmethod
    def parse_xml(file_path: str) -> List[Dict[str, Any]]:
        """
        Parse eder ve açık port/servis listesi döndürür:
        [
          {
            "ip": "1.2.3.4",
            "hostname": "example.com",
            "port": 443,
            "protocol": "tcp",
            "service": "https",
            "product": "nginx",
            "version": "1.24.0",
            "os_guess": "Linux 5.x",
            "scripts": {"http-title": "...", "ssl-cert": "..."},
          }, ...
        ]
        """
        results = []
        try:
            tree = ET.parse(file_path)
            root = tree.getroot()

            for host in root.findall("host"):
                status = host.find("status")
                if status is not None and status.get("state") != "up":
                    continue

                # IP
                address = host.find("address")
                ip = address.get("addr") if address is not None else "unknown"

                # Hostname
                hostname = ""
                hostnames = host.find("hostnames")
                if hostnames is not None:
                    hn = hostnames.find("hostname")
                    if hn is not None:
                        hostname = hn.get("name", "")

                # OS guess
                os_guess = ""
                osmatch = host.find(".//osmatch")
                if osmatch is not None:
                    os_guess = osmatch.get("name", "")

                # Ports
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
                    product = ""
                    version = ""
                    extra_info = ""
                    cpe_list = []

                    if service_el is not None:
                        service_name = service_el.get("name", "unknown")
                        product = service_el.get("product", "")
                        version = service_el.get("version", "")
                        extra_info = service_el.get("extrainfo", "")
                        for cpe in service_el.findall("cpe"):
                            cpe_list.append(cpe.text or "")

                    # NSE script outputs
                    scripts: Dict[str, str] = {}
                    for script in port.findall("script"):
                        sid = script.get("id", "")
                        output = script.get("output", "")
                        if sid:
                            scripts[sid] = output

                    results.append({
                        "ip": ip,
                        "hostname": hostname,
                        "port": port_id,
                        "protocol": protocol,
                        "service": service_name,
                        "product": product,
                        "version": version,
                        "extra_info": extra_info,
                        "cpe": cpe_list,
                        "os_guess": os_guess,
                        "scripts": scripts,
                    })

        except ET.ParseError as e:
            logger.error(f"[Nmap] XML parse hatası ({file_path}): {e}")
        except FileNotFoundError:
            logger.error(f"[Nmap] Dosya bulunamadı: {file_path}")
        except Exception as e:
            logger.error(f"[Nmap] Beklenmeyen parse hatası: {e}")

        logger.info(f"[Nmap] {len(results)} açık port bulundu: {file_path}")
        return results
