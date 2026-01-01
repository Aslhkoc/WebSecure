
import random
import logging
from typing import Dict

logger = logging.getLogger(__name__)

# Modern User-Agents (Windows, Mac, Linux)
_USER_AGENTS = [
    # Windows Chrome
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    # Windows Edge
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36 Edg/123.0.0.0",
    # Windows Firefox
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
    # Mac Chrome
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    # Mac Safari
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15",
    # Linux Chrome
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    # Linux Firefox
    "Mozilla/5.0 (X11; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0"
]

def get_random_user_agent() -> str:
    """Returns a random modern User-Agent string."""
    return random.choice(_USER_AGENTS)

def generate_random_ip() -> str:
    """Generates a random public IP address."""
    return ".".join(str(random.randint(1, 254)) for _ in range(4))

def get_spoof_headers() -> Dict[str, str]:
    """
    Returns a dictionary of headers to spoof the source IP and location.
    Commonly used to bypass simple IP-based blocks or WAF rules relying on XFF.
    """
    ip = generate_random_ip()
    return {
        "X-Forwarded-For": ip,
        "X-Real-IP": ip,
        "X-Client-IP": ip,
        "X-Originating-IP": ip,
        "X-Remote-IP": ip,
        "X-Remote-Addr": ip,
        "Client-IP": ip
    }

try:
    from requests.adapters import HTTPAdapter
    class WAFBypassAdapter(HTTPAdapter):
        """
        Custom HTTPAdapter that injects WAF bypass headers into every request.
        """
        def send(self, request, **kwargs):
            # 1. Rotate User-Agent if not explicitly set (or always rotate if policy dictates)
            # For now, we respect existing UA but if it's default python-requests, we swap it.
            if "User-Agent" not in request.headers or "python-requests" in request.headers["User-Agent"]:
                 request.headers["User-Agent"] = get_random_user_agent()

            # 2. Inject IP Spoofing Headers
            spoof_headers = get_spoof_headers()
            for k, v in spoof_headers.items():
                # Only add if not already present (allow override)
                if k not in request.headers:
                    request.headers[k] = v

            return super().send(request, **kwargs)

except ImportError:
    WAFBypassAdapter = None

