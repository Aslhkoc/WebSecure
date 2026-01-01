
import socket
import logging
import time
from typing import Optional

logger = logging.getLogger(__name__)

class TorController:
    """
    Controller to interact with Tor Control Port (default 9051 or 9151).
    Used to trigger circuit rotation (NEWNYM).
    """
    def __init__(self, host: str = "127.0.0.1", port: int = 9051, password: Optional[str] = None):
        self.host = host
        self.port = port
        self.password = password

    def renew_circuit(self) -> bool:
        """
        Sends SIGNAL NEWNYM to Tor Control Port to switch to a new circuit (new IP).
        Returns True if successful.
        """
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3.0)
            s.connect((self.host, self.port))
            
            # Authenticate
            # If no password set in torrc, default might be needed, or "AUTHENTICATE" empty
            # If cookie auth used, this simple method might fail, but efficient for standard setups
            pwd = f'"{self.password}"' if self.password else '""'
            s.sendall(f'AUTHENTICATE {pwd}\r\n'.encode())
            resp = s.recv(1024).decode()
            
            if "250 OK" not in resp:
                logger.warning(f"Tor Auth Failed: {resp.strip()}")
                s.close()
                return False

            # Signal New Nym
            s.sendall(b'SIGNAL NEWNYM\r\n')
            resp = s.recv(1024).decode()
            s.close()

            if "250 OK" in resp:
                logger.info("Tor Circuit Renovated (NEWNYM Signal Sent).")
                # Wait a bit for circuit to be built
                time.sleep(1.5) 
                return True
            else:
                logger.warning(f"Tor Signal Failed: {resp.strip()}")
                return False

        except ConnectionRefusedError:
            logger.debug(f"Tor Control Port not open at {self.host}:{self.port}")
            return False
        except Exception as e:
            logger.error(f"Tor Control Error: {e}")
            return False

_global_tor: Optional[TorController] = None

def init_tor_control(cfg: dict = None):
    global _global_tor
    if not cfg: 
        return
    
    enabled = cfg.get("enabled", False)
    if not enabled:
        return

    control_port = int(cfg.get("control_port", 9051))
    password = cfg.get("password", None)
    
    _global_tor = TorController(port=control_port, password=password)

def rotate_tor_identity() -> bool:
    """Helper to rotate identity if global controller is init."""
    global _global_tor
    if _global_tor:
        return _global_tor.renew_circuit()
    return False
