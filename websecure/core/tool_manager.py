"""
websecure.core.tool_manager
~~~~~~~~~~~~~~~~~~~~~~~~~~~
Harici araç yönetimi — kurulum tespiti, başlatma, durdurma.

FAZ 17: Amass, httpx, katana, dalfox, Metasploit, Burp Suite desteği eklendi.
Tüm araçlar ToolRegistry üzerinden erişilebilir.
"""
import os
import subprocess
import logging
import shutil
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

    def prepare_sqlmap(self):
        """sqlmap ENJEKSIYON MOTORUNU hazırla ve DÜRÜSTÇE rapor et.

        [Fix 2026-06-20] Eskiden burada arka planda bir sqlmap **API sunucusu**
        (sqlmapapi.py, port 8775) başlatılıp "Program bu servisi otomatik
        kullanacaktır" deniyordu. AMA gerçek tarama (run_sqlmap_scan →
        SQLMapWrapper.scan) DOĞRUDAN sqlmap binary'sini subprocess olarak çalıştırır;
        API istemcisinin scan metotları (start_scan/get_data) HİÇBİR YERDE çağrılmaz.
        Yani sunucu boşuna açılıp tüm tarama boyunca atıl bekliyordu ve mesaj
        YANILTICIYDI. Artık gerçek motorun (subprocess) hazır olduğunu doğrularız ve
        ne yapacağını dürüstçe söyleriz — atıl sunucu yok.
        """
        try:
            from websecure.integrations.sqlmap import SQLMapWrapper
        except Exception as exc:
            logger.debug(f"[ToolManager] SQLMapWrapper yüklenemedi: {exc!r}")
            print("[X] sqlmap entegrasyon modülü yüklenemedi — SQLi motoru devre dışı.")
            return False

        wrapper = SQLMapWrapper()
        if not wrapper.is_available():
            print("[X] sqlmap bulunamadı (PATH veya tools/sqlmap/sqlmap.py) — SQLi motoru atlanacak.")
            return False

        print(f"[OK] sqlmap motoru hazır → {wrapper.binary}")
        print("     SQLi fazında DOĞRUDAN çalışır; ilerlemesi terminale CANLI yansır ([sqlmap] ...).")
        return True

    # Geriye dönük uyumluluk: eski ad hâlâ çağrılabilir.
    start_sqlmap_api = prepare_sqlmap

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
