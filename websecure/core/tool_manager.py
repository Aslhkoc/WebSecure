"""
websecure.core.tool_manager
~~~~~~~~~~~~~~~~~~~~~~~~~~~
Harici araç yönetimi — kurulum tespiti, başlatma, durdurma.

FAZ 17: Amass, httpx, katana, dalfox, Metasploit, Burp Suite desteği eklendi.
Tüm araçlar ToolRegistry üzerinden erişilebilir.
"""
import os
import sys
import time
import subprocess
import logging
import shutil
import socket
from pathlib import Path
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)


class ToolManager:
    """
    Harici araç yaşam döngüsünü yönetir.

    Yeni araçlar: Amass, httpx, katana, dalfox, Metasploit RPC, Burp Suite API.
    ToolRegistry ile entegre — araçlar otomatik kayıt edilir.
    """

    # Araç adı -> binary isimleri (birden fazla olabilir)
    _KNOWN_TOOLS: Dict[str, List[str]] = {
        "sqlmap":      ["sqlmapapi.py"],
        "ffuf":        ["ffuf", "ffuf.exe"],
        "feroxbuster": ["feroxbuster", "feroxbuster.exe"],
        "nmap":        ["nmap", "nmap.exe"],
        "nuclei":      ["nuclei", "nuclei.exe"],
        "amass":       ["amass", "amass.exe"],
        "httpx":       ["httpx", "httpx.exe"],
        "katana":      ["katana", "katana.exe"],
        "dalfox":      ["dalfox", "dalfox.exe"],
        "subfinder":   ["subfinder", "subfinder.exe"],
        "interactsh":  ["interactsh-client", "interactsh-client.exe"],
    }

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        from websecure.core import paths as _paths
        self.project_root = _paths.writable_root()
        self.tools_dir = _paths.tools_dir()
        self.sqlmap_process = None
        self.sqlmap_client = None

    def get_sqlmap_client(self):
        """Lazy loader for SQLMapClient"""
        if self.sqlmap_client: return self.sqlmap_client
        try:
            from websecure.integrations.sqlmap import SQLMapClient
            self.sqlmap_client = SQLMapClient()
        except ImportError as exc:
            logger.debug(f"[ToolManager] SQLMapClient yüklenemedi: {exc!r}")
        return self.sqlmap_client


    # ------------------------------------------------------------------ #
    # Araç tespiti yardımcıları
    # ------------------------------------------------------------------ #

    @staticmethod
    def _extra_search_dirs() -> List[Path]:
        """Go, pdtm ve yaygın güvenlik araç dizinlerini döndür."""
        home = Path.home()
        candidates = [
            # Go varsayılan bin dizini
            home / "go" / "bin",
            # GOPATH/bin (özel GOPATH varsa)
            Path(os.environ.get("GOPATH", home / "go")) / "bin",
            # ProjectDiscovery pdtm kurulum dizini
            home / "AppData" / "Local" / "pdtm" / "go" / "bin",
            home / ".pdtm" / "go" / "bin",
            # Linux/Mac Go kurulumu
            Path("/usr/local/go/bin"),
            Path("/usr/local/bin"),
            Path("/usr/bin"),
        ]
        return [d for d in candidates if d.exists()]

    def _find_binary(self, tool_name: str) -> Optional[str]:
        """Bir aracın binary yolunu bul (PATH + tools/ + Go bin dizinleri)."""
        binaries = self._KNOWN_TOOLS.get(tool_name, [tool_name])
        extra_dirs = self._extra_search_dirs()

        for binary in binaries:
            # 1. Sistem PATH'ında
            found = shutil.which(binary)
            if found:
                return found

            # 2. tools/ dizininde (alt dizinler dahil)
            for candidate in [
                self.tools_dir / tool_name / binary,
                self.tools_dir / binary,
                self.tools_dir / tool_name.capitalize() / binary,
            ]:
                if candidate.exists():
                    return str(candidate)

            # 3. Go bin / pdtm / yaygın güvenlik araç dizinleri
            for extra_dir in extra_dirs:
                candidate = extra_dir / binary
                if candidate.exists():
                    return str(candidate)

        return None

    def is_tool_available(self, tool_name: str) -> bool:
        """Araç sistemde kurulu mu?"""
        return self._find_binary(tool_name) is not None

    def discover_all_tools(self) -> Dict[str, bool]:
        """Tüm bilinen araçların durumunu tara."""
        status = {}
        for tool_name in self._KNOWN_TOOLS:
            status[tool_name] = self.is_tool_available(tool_name)
        # sqlmap özel kontrol
        status["sqlmap"] = (
            (self.tools_dir / "sqlmap").exists()
            or (self.tools_dir / "sqlmapproject-sqlmap-4a40101").exists()
            or shutil.which("sqlmap") is not None
        )
        return status

    def ask_user_interactive(self) -> Dict[str, bool]:
        """
        Tüm mevcut araçları otomatik olarak etkinleştirir ve durumu raporlar.
        """
        print("\n" + "="*60)
        print("  HARİCİ ARAÇ YÖNETİMİ (EXTERNAL TOOLS)")
        print("="*60)

        all_tools = self.discover_all_tools()
        results = {}

        _descriptions = {
            "sqlmap":      "SQL Enjeksiyon doğrulama motoru",
            "ffuf":        "Hızlı içerik/parametre keşif aracı",
            "feroxbuster": "Rust tabanlı hızlı dizin tarayıcı",
            "nmap":        "Ağ keşif ve port tarama",
            "nuclei":      "CVE + misconfiguration tarayıcı",
            "amass":       "Subdomain + ASN enumeration",
            "httpx":       "HTTP/2 hızlı prob + teknoloji tespiti",
            "katana":      "JavaScript-aware web crawler",
            "dalfox":      "XSS doğrulama ve analiz",
            "subfinder":   "Pasif subdomain enumeration",
            "interactsh":  "OOB/OAST callback sunucusu",
        }

        for tool_name, available in all_tools.items():
            if available:
                desc = _descriptions.get(tool_name, "")
                print(f"\n  [{'ok':>2}] {tool_name:<16} — {desc}")
                results[tool_name] = True
            else:
                print(f"\n  [--] {tool_name:<16} — bulunamadı (kurulu değil)")

        available_count = sum(1 for v in results.values() if v)
        print(f"\n{'='*60}")
        if results:
            print(f"  {available_count}/{len(all_tools)} araç etkinlestirildi.")
        else:
            print("  Hicbir harici arac bulunamadi.")
        print("="*60)
        return results

    def start_sqlmap_api(self):
        """
        Starts the SQLMap API server as a background subprocess.
        """
        # Finds the sqlmapapi.py path
        api_path = None
        possible_paths = [
            self.tools_dir / "sqlmap" / "sqlmapapi.py",
            self.tools_dir / "sqlmapproject-sqlmap-4a40101" / "sqlmapapi.py"
        ]
        
        for p in possible_paths:
            if p.exists():
                api_path = p
                break
        
        if not api_path:
            logger.error("[ToolManager] SQLMap API dosyası bulunamadı!")
            return False

        print(f"[launch] SQLMap API Başlatılıyor... ({api_path})")
        try:
            # Check if port 8775 is already in use
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1.0)  # firewall SYN-drop'ta süresiz bloklanmayı önle
                if s.connect_ex(('127.0.0.1', 8775)) == 0:
                    print("[!]  Port 8775 zaten dolu. SQLMap API zaten çalışıyor olabilir.")
                    return True

            # Start process
            self.sqlmap_process = subprocess.Popen(
                [sys.executable, str(api_path), "-s", "-H", "127.0.0.1", "-p", "8775"],
                cwd=api_path.parent,
                stdout=subprocess.DEVNULL, # Suppress stdout to keep console clean
                stderr=subprocess.DEVNULL
            )
            
            # Wait for startup
            for _ in range(10):
                time.sleep(1)
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(1.0)
                    if s.connect_ex(('127.0.0.1', 8775)) == 0:
                        # Extra Check: Use Client
                        cli = self.get_sqlmap_client()
                        if cli and cli.is_alive():
                            print("[OK] SQLMap API Başarıyla Çalıştı (Arka Plan Servisi)")
                        else:
                            print("[OK] SQLMap API Portu Açık (Servis Yanıt Veriyor)")
                        print("   (Program bu servisi otomatik kullanacaktır.)")
                        return True
            
            print("[X] SQLMap API başlatılamadı (Timeout).")
            return False

        except Exception as e:
            logger.error(f"SQLMap başlatma hatası: {e}")
            return False

    def stop_all(self):
        """
        Stops all started subprocesses.
        """
        if self.sqlmap_process:
            print("\n[stop] SQLMap API kapatılıyor...")
            self.sqlmap_process.terminate()
            try:
                self.sqlmap_process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.sqlmap_process.kill()
