import socket
import time
import threading
import logging
from typing import Optional

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
