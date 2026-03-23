import socket
import time
import threading
import logging
from typing import Optional, TYPE_CHECKING

_logger = logging.getLogger(__name__)

class TorController:
    def __init__(self, control_port: int = 9051, password: Optional[str] = None):
        self.control_port = control_port
        self.password = password
        self._stop_event = threading.Event()
        self._thread = None

    def renew_identity(self) -> bool:
        """Sends SIGNAL NEWNYM to Tor Control Port to request a new IP."""
        try:
            with socket.create_connection(("127.0.0.1", self.control_port), timeout=5) as s:
                f = s.makefile('rw')
                
                # Authenticate
                if self.password:
                    f.write(f'AUTHENTICATE "{self.password}"\r\n')
                else:
                    f.write('AUTHENTICATE ""\r\n')
                f.flush()
                
                resp = f.readline()
                if "250" not in resp:
                    _logger.warning(f"[Tor] Auth failed: {resp.strip()}")
                    # Try fallback without auth if empty string failed? Usually 515
                    return False

                # Signal New Nym
                f.write('SIGNAL NEWNYM\r\n')
                f.flush()
                
                resp = f.readline()
                if "250" in resp:
                    _logger.info("[Tor] External IP rotation requested (SIGNAL NEWNYM).")
                    return True
                else:
                    _logger.warning(f"[Tor] Signal failed: {resp.strip()}")
                    return False
        except ConnectionRefusedError:
            _logger.error("[Tor] Could not connect to Control Port (9051). Is Tor running?")
            return False
        except Exception as e:
            _logger.error(f"[Tor] Error rotating IP: {e}")
            return False

    def start_rotation_loop(self, interval_seconds: int = 120):
        """Starts a background thread to rotate IP every interval_seconds."""
        if self._thread and self._thread.is_alive():
            return

        self._stop_event.clear()
        
        def _loop():
            _logger.info(f"[Tor] IP Rotation loop started (Every {interval_seconds}s).")
            while not self._stop_event.is_set():
                # Wait for interval
                if self._stop_event.wait(interval_seconds):
                    break
                # Rotate
                self.renew_identity()
        
        self._thread = threading.Thread(target=_loop, daemon=True, name="TorRotator")
        self._thread.start()

    def stop(self):
        """Stops the rotation loop."""
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=1.0)

# ============================================================================
# Compatibility / Global Helpers (Merged from tor_control.py)
# ============================================================================

_global_tor: Optional[TorController] = None

def init_tor_control(cfg: dict = None):
    """
    Initializes the global Tor controller.
    """
    global _global_tor
    if not cfg: 
        return
    
    enabled = cfg.get("enabled", False)
    if not enabled:
        return

    control_port = int(cfg.get("control_port", 9051))
    password = cfg.get("password", None)
    
    _global_tor = TorController(control_port=control_port, password=password)
    # Optional: Start rotation if configured in cfg? For now just init.

def rotate_tor_identity() -> bool:
    """Helper to rotate identity if global controller is init."""
    global _global_tor
    if _global_tor:
        return _global_tor.renew_identity()
    return False

def start_auto_rotation(interval: int = 120):
    """Starts the auto-rotation loop on the global Tor controller."""
    global _global_tor
    if _global_tor:
        _global_tor.start_rotation_loop(interval)
        return True
    return False


# ============================================================================
# EgressManager — Tor + Residential Proxy havuzunu birleştiren birleşik yönetici
# ============================================================================

class EgressManager:
    """
    Çıkış trafiği yöneticisi.

    Öncelik sırası:
      1. Tor (SOCKS5, 127.0.0.1:9050) — etkinse
      2. Residential Proxy Pool — kayıt varsa
      3. Doğrudan bağlantı (None döner)

    Kullanım::

        em = EgressManager(cfg)
        proxy_url = em.get_next_egress()
        # proxy_url örn: "socks5h://127.0.0.1:9050" veya "http://user:pass@host:port"
        # proxy_url None ise doğrudan bağlantı
    """

    def __init__(self, cfg: dict = None) -> None:
        cfg = cfg or {}

        # Tor ayarları
        tor_cfg = (cfg.get("privacy") or {}).get("tor") or cfg.get("tor") or {}
        self._tor_enabled = bool(tor_cfg.get("enabled", False))
        self._tor_socks_port = int(tor_cfg.get("socks_port", 9050))
        self._tor_proxy_url = f"socks5h://127.0.0.1:{self._tor_socks_port}"

        # Residential proxy havuzu
        try:
            from websecure.core.proxy_pool import ResidentialProxyPool
            self._pool: Optional[ResidentialProxyPool] = ResidentialProxyPool(cfg)
        except Exception:
            self._pool = None

        # Tor kontrolcüsü (opsiyonel — Tor kuruluysa)
        self._tor_ctrl: Optional[TorController] = None
        if self._tor_enabled:
            control_cfg = tor_cfg.get("control") or {}
            ctrl_port = int(control_cfg.get("port", 9051))
            ctrl_pass = control_cfg.get("password")
            self._tor_ctrl = TorController(control_port=ctrl_port, password=ctrl_pass)

        _logger.info(
            f"[EgressManager] tor_enabled={self._tor_enabled}, "
            f"pool_size={len(self._pool) if self._pool else 0}"
        )

    # ------------------------------------------------------------------

    def get_next_egress(self, key: str = "", country: Optional[str] = None) -> Optional[str]:
        """
        Bir sonraki çıkış proxy URL'sini döner.

        key     : sticky/hash stratejisi için anahtar (genellikle hedef host)
        country : ülke bazlı hedefleme (yalnızca proxy pool için)
        """
        # 1) Tor
        if self._tor_enabled and self._is_tor_alive():
            return self._tor_proxy_url

        # 2) Residential proxy havuzu
        if self._pool and self._pool.enabled:
            entry = self._pool.next(key=key, country=country)
            if entry:
                return entry.url

        # 3) Doğrudan
        return None

    def record_success(self, proxy_url: str) -> None:
        """Kullanılan proxy'nin başarısını kaydet."""
        if self._pool:
            entry = self._find_entry(proxy_url)
            if entry:
                self._pool.record_success(entry)

    def record_failure(self, proxy_url: str) -> None:
        """Kullanılan proxy'nin başarısızlığını kaydet."""
        if proxy_url == self._tor_proxy_url:
            # Tor başarısızlığı → yeni kimlik iste
            self.rotate_tor()
            return
        if self._pool:
            entry = self._find_entry(proxy_url)
            if entry:
                self._pool.record_failure(entry)

    def rotate_tor(self) -> bool:
        """Tor kimliğini yenile (SIGNAL NEWNYM)."""
        if self._tor_ctrl:
            return self._tor_ctrl.renew_identity()
        return rotate_tor_identity()

    def _find_entry(self, url: str):
        if self._pool:
            with self._pool._lock:
                for e in self._pool._entries:
                    if e.url == url:
                        return e
        return None

    def _is_tor_alive(self) -> bool:
        """Tor SOCKS portuna bağlanabilirliği hızlıca test eder."""
        import socket
        try:
            with socket.create_connection(("127.0.0.1", self._tor_socks_port), timeout=1):
                return True
        except Exception:
            return False

    def proxy_pool_stats(self) -> dict:
        if self._pool:
            return self._pool.stats()
        return {"total": 0, "active": 0, "disabled": 0}

    def health_check_pool(self, **kwargs) -> dict:
        if self._pool:
            return self._pool.health_check_all(**kwargs)
        return {}


# ---------------------------------------------------------------------------
# Global EgressManager singleton
# ---------------------------------------------------------------------------

_global_egress: Optional[EgressManager] = None


def init_egress_manager(cfg: dict = None) -> EgressManager:
    """Global EgressManager'ı başlatır."""
    global _global_egress
    _global_egress = EgressManager(cfg or {})
    return _global_egress


def get_egress_manager() -> Optional[EgressManager]:
    """Global EgressManager örneğini döner (başlatılmamışsa None)."""
    return _global_egress
