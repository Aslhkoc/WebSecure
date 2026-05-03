from __future__ import annotations

import threading
import time
import logging
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse

import requests as _requests

from ..core.http import hardened_session
from ..core.reporting import add_result, redact_sensitive
from ..core.payloads import get_payloads
from ..core.analysis import InputContext


class BaseScanner:
    """
    Standard base class for all WebSecure scanners.
    Replaces legacy BaseCheck and standardizes result reporting.

    Shared utilities (FAZ 2):
      - inject_param()       — URL query parameter injection
      - run_parallel_probes() — threaded probe execution
      - fetch_baseline()     — baseline HTTP request with proper error handling
      - report_finding()     — standardised finding emission

    Thread safety (FAZ 3):
      - self._results_lock protects self.results dict across threads
    """

    name: str = "base"

    def __init__(self, session=None, results: Dict = None, debug: bool = False):
        self.session = session or hardened_session()
        self.results: Dict = results if results is not None else {}
        self.debug = debug
        self.logger = logging.getLogger(f"websecure.scanners.{self.name}")
        self._results_lock = threading.Lock()
        # LRU cache: OrderedDict maps cache_key -> (response, timestamp)
        # Max 100 entries; entries older than _CACHE_TTL seconds are re-fetched.
        self._baseline_cache: OrderedDict[str, Tuple[Optional[_requests.Response], float]] = OrderedDict()
        self._baseline_cache_lock = threading.Lock()
        self._CACHE_TTL: int = 300          # seconds before a cached entry expires
        self._CACHE_MAX_SIZE: int = 100     # max LRU entries
        self._cache_hits: int = 0
        self._cache_misses: int = 0
        self._max_workers = self._resolve_max_workers()
        if debug:
            self.logger.setLevel(logging.DEBUG)

    def _resolve_max_workers(self) -> int:
        try:
            from websecure.core.payloads import _load_cfg
            cfg = _load_cfg()
            return int((cfg.get("scan") or {}).get("max_workers", 8))
        except Exception:
            return 8

    # ------------------------------------------------------------------
    # Core result methods
    # ------------------------------------------------------------------

    def add(self, bucket: str, entry: Dict[str, Any]) -> None:
        """
        Add a finding to the results bucket.
        Thread-safe: protects self.results with a lock.
        Handles redaction, enrichment (timestamp), and centralized reporting.
        """
        # 1. Enrich
        if "timestamp" not in entry:
            entry["timestamp"] = time.time()

        # 2. Redact
        safe_entry = redact_sensitive(entry)

        # 3. Store — protected by lock
        with self._results_lock:
            if bucket not in self.results:
                self.results[bucket] = []
            self.results[bucket].append(safe_entry)

        # 4. Central Report & Alert (has its own RLock internally)
        add_result(bucket, safe_entry)

        # 5. Log
        sev = safe_entry.get("severity", "Info")
        msg = safe_entry.get("type") or safe_entry.get("status") or safe_entry.get("issue")
        self.logger.debug(f"[{sev.upper()}] {bucket}: {msg}")

    def set_summary(self, bucket: str, count: int) -> None:
        self.results[f"{bucket}_summary"] = {"vulnerabilities": count}

    def create_finding(self, type: str, url: str, severity: str = "Info",
                       details: str = "", evidence: dict = None, **kwargs) -> dict:
        """Create a standardised finding dict."""
        finding = {
            "type": type,
            "url": url,
            "severity": severity,
            "detail": details,
        }
        if evidence:
            finding["evidence"] = evidence
        finding.update(kwargs)
        return finding

    def run(self, target: str, **kwargs) -> Any:
        raise NotImplementedError("Scanners must implement run()")

    # ------------------------------------------------------------------
    # FAZ 2.4 — Standardised finding emission
    # ------------------------------------------------------------------

    def report_finding(
        self,
        *,
        vuln_type: str,
        url: str,
        param: str = "",
        payload: str = "",
        severity: str,
        evidence: str = "",
        extra: Optional[Dict] = None,
    ) -> None:
        """
        Unified finding reporter used by all scanners.
        Replaces the per-scanner _report_vuln / _report_finding methods.
        Calls self.add() once — never call add_result() directly from scanners.
        """
        entry = {
            "type": vuln_type,
            "severity": severity,
            "url": url,
            "parameter": param,
            "payload": payload,
        }
        if evidence:
            entry["evidence"] = evidence
        if extra:
            entry.update(extra)
        self.add("offensive", entry)
        self.logger.warning(
            f"[{self.name.upper()}] {vuln_type} FOUND: {url}"
            + (f" (param={param})" if param else "")
        )

    # ------------------------------------------------------------------
    # FAZ 2.1 — URL parameter injection (replaces _inject_param duplicates)
    # ------------------------------------------------------------------

    def inject_param(self, url: str, param: str, value: str) -> str:
        """
        Inject *value* into URL query parameter *param*.
        Replaces the identical _inject_param implementations in xss, sqli, open_redirect.
        """
        parsed = urlparse(url)
        params = dict(parse_qsl(parsed.query))
        params[param] = value
        return urlunparse(parsed._replace(query=urlencode(params)))

    # ------------------------------------------------------------------
    # FAZ 2.2 — Parallel probe execution (replaces ThreadPoolExecutor boilerplate)
    # ------------------------------------------------------------------

    def run_parallel_probes(
        self,
        probe_fn: Callable[[str], Optional[Any]],
        payloads: List[str],
        *,
        max_workers: int = 0,
        stop_on_first: bool = True,
    ) -> List[Any]:
        if max_workers <= 0:
            max_workers = self._max_workers
        """
        Execute *probe_fn(payload)* for each payload in a thread pool.
        Returns a list of truthy results from probe_fn.

        If stop_on_first=True (default), cancels remaining futures after the
        first truthy result — equivalent to the early-exit pattern all scanners used.

        Any exception raised by probe_fn is logged at DEBUG and skipped (not swallowed
        silently — the log entry is always emitted).
        """
        hits: List[Any] = []

        with ThreadPoolExecutor(max_workers=max_workers) as exe:
            futures = {exe.submit(probe_fn, p): p for p in payloads}
            for fut in as_completed(futures):
                try:
                    result = fut.result()
                except _requests.exceptions.RequestException as exc:
                    self.logger.debug(
                        f"[{self.name}] Probe raised network error: {exc!r}"
                    )
                    continue
                except Exception as exc:  # noqa: BLE001 — last-resort catch with full logging
                    self.logger.error(
                        f"[{self.name}] Unexpected error in probe future: {exc!r}",
                        exc_info=True,
                    )
                    continue

                if result:
                    hits.append(result)
                    if stop_on_first:
                        for f in futures:
                            f.cancel()
                        break

        return hits

    # ------------------------------------------------------------------
    # FAZ 2.3 — Baseline response fetch (replaces duplicated baseline logic)
    # ------------------------------------------------------------------

    def get_cache_stats(self) -> dict:
        """Return baseline cache statistics."""
        with self._baseline_cache_lock:
            size = len(self._baseline_cache)
        return {
            "hits": self._cache_hits,
            "misses": self._cache_misses,
            "size": size,
        }

    def fetch_baseline(
        self,
        url: str,
        *,
        method: str = "GET",
        data: Optional[Dict] = None,
        timeout: int = 10,
    ) -> Optional[_requests.Response]:
        """
        Fetch a baseline response with explicit network error handling.
        Returns the Response on success, None on failure (always logs the failure).

        Caching policy (LRU + TTL):
          - Max 100 entries (LRU eviction of least-recently-used when full).
          - Entries expire after 300 seconds (TTL); stale entries are re-fetched.
          - Cache stats are tracked via _cache_hits / _cache_misses.
        """
        cache_key = f"{method}:{url}"
        now = time.monotonic()

        with self._baseline_cache_lock:
            if cache_key in self._baseline_cache:
                cached_resp, cached_ts = self._baseline_cache[cache_key]
                if now - cached_ts < self._CACHE_TTL:
                    # Fresh hit — move to end (most-recently-used)
                    self._baseline_cache.move_to_end(cache_key)
                    self._cache_hits += 1
                    return cached_resp
                # Stale — remove and re-fetch
                del self._baseline_cache[cache_key]
            self._cache_misses += 1

        resp: Optional[_requests.Response] = None
        try:
            if method == "POST":
                resp = self.session.post(url, data=data or {}, timeout=timeout)
            else:
                resp = self.session.get(url, timeout=timeout)
        except _requests.exceptions.Timeout as exc:
            self.logger.warning(f"[{self.name}] Baseline timed out for {url}: {exc!r}")
        except _requests.exceptions.ConnectionError as exc:
            self.logger.warning(f"[{self.name}] Baseline connection error for {url}: {exc!r}")
        except _requests.exceptions.RequestException as exc:
            self.logger.warning(f"[{self.name}] Baseline request failed for {url}: {exc!r}")

        with self._baseline_cache_lock:
            # LRU eviction: drop the oldest entry if at capacity
            while len(self._baseline_cache) >= self._CACHE_MAX_SIZE:
                self._baseline_cache.popitem(last=False)
            self._baseline_cache[cache_key] = (resp, time.monotonic())
        return resp

    # ------------------------------------------------------------------
    # Smart payload retrieval (unchanged)
    # ------------------------------------------------------------------

    def get_smart_payloads(self, category: str, param_name: str,
                           tech_stack: Optional[set] = None) -> List[str]:
        """
        Smart Payload Retriever:
        1. Checks if we have context for this parameter (from Crawler).
        2. Adjusts payload list based on context.
        3. Uses technology stack if provided.
        """
        contexts = self.results.get("param_contexts", {})
        ctx_result = contexts.get(param_name)

        if tech_stack is None:
            tech_stack = set(self.results.get("tech_stack", []))

        payloads = get_payloads(category, tech_tags=tech_stack)

        if ctx_result and self.debug:
            self.logger.debug(
                f"[SmartPayload] {param_name} ({ctx_result.context.name}) "
                f"fetching {category} payloads."
            )
        return payloads

    # ------------------------------------------------------------------
    # prepare_injection (unchanged — used by form submission logic)
    # ------------------------------------------------------------------

    def prepare_injection(self, url: str, param: str, payload: str,
                          method: str = "GET",
                          data: Optional[Dict] = None,
                          json_body: Optional[Dict] = None) -> Dict[str, Any]:
        """
        Constructs request arguments (params, data, json) with the payload injected.
        Returns a kwarg dict suitable for session.request(method, url, **kwargs).
        """
        req_kwargs: Dict[str, Any] = {}

        if method == "GET" or (param in dict(parse_qsl(urlparse(url).query))):
            parsed = urlparse(url)
            curr_params = dict(parse_qsl(parsed.query))
            if param in curr_params:
                curr_params[param] = payload
                new_query = urlencode(curr_params)
                req_kwargs["url"] = urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path,
                    parsed.params, new_query, parsed.fragment,
                ))
            else:
                req_kwargs["url"] = url
        else:
            req_kwargs["url"] = url

        if method in ("POST", "PUT", "PATCH") and data:
            new_data = data.copy()
            if param in new_data:
                new_data[param] = payload
            req_kwargs["data"] = new_data

        if method in ("POST", "PUT", "PATCH") and json_body:
            new_json = json_body.copy()
            if param in new_json:
                new_json[param] = payload
            req_kwargs["json"] = new_json

        return req_kwargs
