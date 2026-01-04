import random
import time
import logging
import string
from typing import Dict, Optional
from urllib.parse import urlparse, urlunparse

import requests
from requests.adapters import HTTPAdapter
from requests.models import PreparedRequest

logger = logging.getLogger(__name__)

# --- Enhanced User-Agents List ---
_USER_AGENTS = [
    # Windows Chrome
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    # Windows Edge
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36 Edg/123.0.0.0",
    # Windows Firefox
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    # Mac Chrome
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    # Mac Safari
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    # Linux Chrome
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    # Linux Firefox
    "Mozilla/5.0 (X11; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0",
    # Mobile
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; SM-S928B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.6312.80 Mobile Safari/537.36"
]

def get_random_user_agent() -> str:
    """Returns a random modern User-Agent string."""
    return random.choice(_USER_AGENTS)

def generate_random_ip() -> str:
    """Generates a random public IP address."""
    # Avoid private ranges approx
    first = random.choice([x for x in range(1, 224) if x not in (10, 127, 169, 172, 192)])
    return f"{first}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}"

def get_spoof_headers() -> Dict[str, str]:
    """Returns headers to spoof source IP."""
    ip = generate_random_ip()
    return {
        "X-Forwarded-For": ip,
        "X-Real-IP": ip,
        "X-Client-IP": ip,
        "X-Originating-IP": ip,
        "X-Remote-IP": ip,
        "X-Remote-Addr": ip,
        "Client-IP": ip,
        "True-Client-IP": ip,
        "X-Forwarded-Host": "localhost"
    }

def _randomize_header_case(header: str) -> str:
    """Randomly changes case of header characters."""
    return "".join(c.upper() if random.random() > 0.5 else c.lower() for c in header)

def _generate_junk_header() -> tuple[str, str]:
    """Generates a random junk header."""
    key = "X-" + "".join(random.choices(string.ascii_letters, k=random.randint(4, 8)))
    val = "".join(random.choices(string.ascii_letters + string.digits, k=random.randint(4, 12)))
    return key, val

class WAFBypassAdapter(HTTPAdapter):
    """
    Adapter that injects WAF bypass headers, randomizes casing,
    and performs path obfuscation.
    """
    def send(self, request: PreparedRequest, **kwargs):
        # 1. Rotate User-Agent
        if "User-Agent" not in request.headers or "python-requests" in request.headers["User-Agent"]:
             request.headers["User-Agent"] = get_random_user_agent()

        # 2. Inject IP Spoofing Headers
        spoof_headers = get_spoof_headers()
        for k, v in spoof_headers.items():
            if k not in request.headers:
                request.headers[k] = v

        # 3. Path Obfuscation
        if random.random() < 0.2: 
            try:
                parsed = urlparse(request.url)
                path = parsed.path
                if path and path.startswith("/"):
                    tactic = random.choice(["double_slash", "current_dir"])
                    new_path = path
                    if tactic == "double_slash":
                        new_path = "/" + path
                    elif tactic == "current_dir":
                        new_path = "/." + path
                    
                    request.url = urlunparse((
                        parsed.scheme, parsed.netloc, new_path,
                        parsed.params, parsed.query, parsed.fragment
                    ))
            except Exception:
                pass

        # 4. Header Modification (Junk & Case)
        # Note: requests/urllib3 might canonicalize headers, but we try.
        if random.random() < 0.3:
             junk_k, junk_v = _generate_junk_header()
             request.headers[junk_k] = junk_v

        # 5. Add common noise headers to look more like a browser
        if "Accept-Language" not in request.headers:
            request.headers["Accept-Language"] = random.choice(["en-US,en;q=0.9", "tr-TR,tr;q=0.9", "en-GB,en;q=0.8"])
        if "DNT" not in request.headers:
            request.headers["DNT"] = "1"
        if "Upgrade-Insecure-Requests" not in request.headers:
            request.headers["Upgrade-Insecure-Requests"] = "1"

        return super().send(request, **kwargs)

class WAFBypassSession(requests.Session):
    """
    A requests.Session subclass that automatically uses WAFBypassAdapter
    and adds random jitter/delay to requests.
    """
    def __init__(self, jitter_range: tuple[float, float] = (0.5, 2.0)):
        super().__init__()
        self.jitter_range = jitter_range
        self.mount("https://", WAFBypassAdapter())
        self.mount("http://", WAFBypassAdapter())
        self.headers.update({
            "User-Agent": get_random_user_agent()
        })

    def request(self, method, url, *args, **kwargs):
        # Add Jitter/Delay
        if self.jitter_range:
            sleep_time = random.uniform(*self.jitter_range)
            time.sleep(sleep_time)
        return super().request(method, url, *args, **kwargs)
