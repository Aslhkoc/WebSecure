import os
import sys
import time
import subprocess
import logging
import socket
from pathlib import Path
from typing import Dict, Any

logger = logging.getLogger(__name__)

class ToolManager:
    """
    Manages external tools and their lifecycles.
    Handles user interaction for enabling/disabling tools and service startups.
    """
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.project_root = Path(__file__).resolve().parent.parent.parent
        self.tools_dir = self.project_root / "tools"
        self.sqlmap_process = None

    def ask_user_interactive(self) -> Dict[str, bool]:
        """
        Interactively asks the user which tools to enable.
        Returns a dict of tool_name -> enabled status.
        """
        print("\n" + "="*50)
        print("  HARİCİ ARAÇ YÖNETİMİ (EXTERNAL TOOLS)")
        print("="*50)
        print("Harici araçları (FFUF, SQLMap, Feroxbuster) kullanmak ister misiniz?")
        print("Bu araçlar tarama yeteneklerini artırır.")
        
        choice = input("Araçları etkinleştir? [E/h]: ").lower().strip()
        if choice == 'h':
            print("❌ Harici araçlar devre dışı bırakıldı.")
            return {}

        results = {}
        
        # SQLMap
        if (self.tools_dir / "sqlmap").exists() or (self.tools_dir / "sqlmapproject-sqlmap-4a40101").exists():
            print("\n[SQLMap] SQL Enjeksiyon doğrulama motoru.")
            use_sqlmap = input("  -> SQLMap API (otomatik başlatma) kullanılsın mı? [E/h]: ").lower().strip() != 'h'
            results['sqlmap'] = use_sqlmap
        
        # FFUF
        if (self.tools_dir / "ffuf" / "ffuf.exe").exists():
            print("\n[FFUF] Hızlı içerik keşif aracı.")
            use_ffuf = input("  -> FFUF kullanılsın mı? [E/h]: ").lower().strip() != 'h'
            results['ffuf'] = use_ffuf

        # Feroxbuster
        if (self.tools_dir / "feroxbuster" / "feroxbuster.exe").exists():
            print("\n[Feroxbuster] Alternatif Rust tabanlı tarayıcı.")
            use_ferox = input("  -> Feroxbuster kullanılsın mı? [E/h]: ").lower().strip() != 'h'
            results['feroxbuster'] = use_ferox

        # Nmap
        import shutil
        if shutil.which("nmap") or (self.tools_dir / "Nmap" / "nmap.exe").exists():
            print("\n[Nmap] Ağ keşif ve port tarama aracı.")
            use_nmap = input("  -> Nmap kullanılsın mı? [E/h]: ").lower().strip() != 'h'
            results['nmap'] = use_nmap

        print("\n✅ Seçimler kaydedildi.")
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

        print(f"🚀 SQLMap API Başlatılıyor... ({api_path})")
        try:
            # Check if port 8775 is already in use
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                if s.connect_ex(('127.0.0.1', 8775)) == 0:
                    print("⚠️  Port 8775 zaten dolu. SQLMap API zaten çalışıyor olabilir.")
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
                    if s.connect_ex(('127.0.0.1', 8775)) == 0:
                        print("✅ SQLMap API (API Mode) Başarıyla Çalıştı: http://127.0.0.1:8775")
                        return True
            
            print("❌ SQLMap API başlatılamadı (Timeout).")
            return False

        except Exception as e:
            logger.error(f"SQLMap başlatma hatası: {e}")
            return False

    def stop_all(self):
        """
        Stops all started subprocesses.
        """
        if self.sqlmap_process:
            print("\n🛑 SQLMap API kapatılıyor...")
            self.sqlmap_process.terminate()
            try:
                self.sqlmap_process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.sqlmap_process.kill()
