import hmac
import base64
import struct
import time
import hashlib
import logging
from typing import Optional

logger = logging.getLogger(__name__)

class TOTP:
    """
    RFC 6238 TOTP (Time-based One-Time Password) Implementation.
    Dependency-free (uses native hmac/hashlib).
    """
    def __init__(self, secret: str, digits: int = 6, interval: int = 30, digest=hashlib.sha1):
        """
        :param secret: Base32 encoded secret key (e.g. from QR code)
        :param digits: Number of digits (default 6)
        :param interval: Time interval in seconds (default 30)
        """
        self.secret = self._clean_secret(secret)
        self.digits = digits
        self.interval = interval
        self.digest = digest

    def _clean_secret(self, secret: str) -> bytes:
        """Correction for padding and whitespace."""
        s = secret.strip().replace(" ", "").upper()
        # Add padding if needed
        missing_padding = len(s) % 8
        if missing_padding:
            s += '=' * (8 - missing_padding)
        try:
            return base64.b32decode(s)
        except Exception as exc:
            logger.warning("[TOTP] Invalid Base32 secret — TOTP will not work: %s", exc)
            return b""

    def generate(self, timestamp: Optional[float] = None) -> str:
        """Generates the TOTP code for the given timestamp."""
        if timestamp is None:
            timestamp = time.time()
        
        counter = int(timestamp / self.interval)
        return self._generate_otp(counter)

    def _generate_otp(self, counter: int) -> str:
        # 8-byte big-endian counter
        msg = struct.pack(">Q", counter)
        
        # HMAC-SHA1
        mac = hmac.new(self.secret, msg, self.digest).digest()
        
        # Dynamic Truncation
        offset = mac[-1] & 0x0f
        binary = struct.unpack(">L", mac[offset : offset + 4])[0] & 0x7fffffff
        
        # Modulo
        code = str(binary % (10 ** self.digits))
        
        # Zero padding
        return code.zfill(self.digits)

    def now(self) -> str:
        return self.generate()

    def verify(self, code: str, window: int = 1) -> bool:
        """Verifies a code within the given window of intervals (drift)."""
        now = time.time()
        counter = int(now / self.interval)
        
        for i in range(-window, window + 1):
            if self._generate_otp(counter + i) == code:
                return True
        return False
