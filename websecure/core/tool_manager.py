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
        self.sqlmap_client = None

    def get_sqlmap_client(self):
        """Lazy loader for SQLMapClient"""
        if self.sqlmap_client: return self.sqlmap_client
        try:
            from websecure.integrations.sqlmap import SQLMapClient
            self.sqlmap_client = SQLMapClient()
        except ImportError:
            pass
        return self.sqlmap_client


    def ask_user_interactive(self) -> Dict[str, bool]:
        """
        Automatically enables all available tools and reports status.
        Returns a dict of tool_name -> enabled status.
        """
        import shutil

        print("\n" + "="*50)
        print("  HARİCİ ARAÇ YÖNETİMİ (EXTERNAL TOOLS)")
        print("="*50)

        results = {}

        # SQLMap
        sqlmap_available = (
            (self.tools_dir / "sqlmap").exists()
            or (self.tools_dir / "sqlmapproject-sqlmap-4a40101").exists()
        )
        if sqlmap_available:
            print("\n[SQLMap] SQL Enjeksiyon doğrulama motoru.")
            print("  -> SQLMap API (otomatik başlatma) kullanılıyor.")
            results['sqlmap'] = True

        # FFUF
        ffuf_available = (
            (self.tools_dir / "ffuf" / "ffuf.exe").exists()
            or shutil.which("ffuf") is not None
        )
        if ffuf_available:
            print("\n[FFUF] Hızlı içerik keşif aracı.")
            print("  -> FFUF kullanılıyor.")
            results['ffuf'] = True

        # Feroxbuster
        ferox_available = (
            (self.tools_dir / "feroxbuster" / "feroxbuster.exe").exists()
            or shutil.which("feroxbuster") is not None
        )
        if ferox_available:
            print("\n[Feroxbuster] Alternatif Rust tabanlı tarayıcı.")
            print("  -> Feroxbuster kullanılıyor.")
            results['feroxbuster'] = True

        # Nmap
        nmap_available = (
            shutil.which("nmap") is not None
            or (self.tools_dir / "Nmap" / "nmap.exe").exists()
        )
        if nmap_available:
            print("\n[Nmap] Ağ keşif ve port tarama aracı.")
            print("  -> Nmap kullanılıyor.")
            results['nmap'] = True

        if results:
            print("\n✅ Araçlar otomatik olarak etkinleştirildi.")
        else:
            print("\n⚠️  Hiçbir harici araç bulunamadı.")
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
                        # Extra Check: Use Client
                         cli = self.get_sqlmap_client()
                         if cli and cli.is_alive():
                             print("✅ SQLMap API Başarıyla Çalıştı (Arka Plan Servisi)")
                         else:
                             print("✅ SQLMap API Portu Açık (Servis Yanıt Veriyor)")
                         
                         print("   (Program bu servisi otomatik kullanacaktır.)")
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
