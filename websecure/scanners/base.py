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

# Circuit breaker — when the global breaker is OPEN (e.g. WAF returning a
# storm of 403s), every further request raises CircuitBreakerTripped. This is
# an *expected* operational condition, not a bug, so probe loops must treat it
# as a stop-signal rather than logging a full traceback per payload.
try:  # pragma: no cover - import guard mirrors core.http
    from ..core.circuit_breaker import CircuitBreakerTripped as _CircuitBreakerTripped
except ImportError:  # pragma: no cover
    class _CircuitBreakerTripped(Exception):  # type: ignore[no-redef]
        pass

# PhaseAbandoned — raised by the HTTP layer when this phase was skipped by the
# watchdog; treated exactly like a tripped breaker (abort the batch quietly).
try:  # pragma: no cover
    from ..core.http import PhaseAbandoned as _PhaseAbandoned
except ImportError:  # pragma: no cover
    class _PhaseAbandoned(Exception):  # type: ignore[no-redef]
        pass

# Turkish → English severity normalization (lowercase keys for case-insensitive lookup)
# Canonical values MUST match what the DB layer and reporting use: "Info" not "Informational"
_SEVERITY_NORMALIZE_MAP: Dict[str, str] = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "informational": "Info",
    "info": "Info",
    # Turkish variants
    "kritik": "Critical",
    "yüksek": "High",
    "orta": "Medium",
    "düşük": "Low",
    "bilgi": "Info",
}


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
        # Deduplication: prevent identical findings from being reported twice
        self._seen_findings: set = set()
        self._seen_lock = threading.Lock()
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

        # FalsePositiveReducer — lazy-loaded per scanner instance to avoid circular import
        try:
            from ..core.fp_reducer import FalsePositiveReducer as _FPR
            self._fpr = _FPR(self.session)
        except Exception:
            self._fpr = None

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

    def path_exists(self, resp: Any) -> bool:
        """Robust replacement for the ``status_code not in (404, 410)`` existence test.

        On a normal server this is identical to the legacy check (any non-404/410
        status ⇒ exists). On a soft-404 / catch-all server (SPA, parked domain,
        catch-all CDN that answers 200/redirect for EVERY path) it additionally
        requires the response to differ from the server's learned "not found" page,
        which kills the phantom-endpoint false-positive class project-wide.

        Fails safe: any error, or an undetermined origin, preserves legacy behaviour
        (returns True for non-404/410) — it never suppresses on uncertainty.
        """
        try:
            st = int(getattr(resp, "status_code", 0) or 0)
        except Exception:
            return False
        if st in (404, 410) or st == 0:
            return False
        try:
            from websecure.core.fp_reducer import SoftNotFoundBaseline
            url = getattr(resp, "url", "") or ""
            baseline = SoftNotFoundBaseline.for_target(self.session, url)
            return baseline.is_genuine_hit(resp)
        except Exception as exc:  # any failure → legacy behaviour, never over-suppress
            self.logger.debug(f"[{self.name}] path_exists fallback: {exc!r}")
            return True

    def run(self, target: str, **kwargs) -> Any:
        raise NotImplementedError("Scanners must implement run()")

    # ------------------------------------------------------------------
    # FAZ 2.4 — Standardised finding emission
    # ------------------------------------------------------------------

    @staticmethod
    def _normalize_severity(sev: str) -> str:
        """Normalize severity string, including Turkish variants."""
        return _SEVERITY_NORMALIZE_MAP.get((sev or "").lower().strip(), sev or "Info")

    def report_finding(
        self,
        *,
        vuln_type: str = "",
        url: str = "",
        param: str = "",
        payload: str = "",
        severity: str = "",
        evidence: str = "",
        extra: Optional[Dict] = None,
        # legacy alias used by some scanners
        type: str = "",
        **kwargs: Any,
    ) -> None:
        # SAVUNMACI: bazı prober'lar finding dict'ini **spread ile geçiriyor ve
        # dict'te `url`/`severity` olmayabiliyor. Eskiden bunlar zorunlu keyword
        # olduğundan "missing required argument" ile TÜM taramayı çökertiyordu.
        # url'i kwargs/extra/target'tan kurtar; severity yoksa Info varsay;
        # yine de url yoksa bulguyu sessizce atla (çökme yok).
        if not url:
            url = (
                str(kwargs.pop("url", "") or "")
                or str((extra or {}).get("url", "") or "")
                or str(kwargs.pop("target", "") or "")
            )
        if not severity:
            severity = str(kwargs.pop("severity", "") or "") or "Info"
        if not url:
            self.logger.debug(
                f"[{self.name}] report_finding atlandı (url yok): "
                f"{vuln_type or type or 'finding'}"
            )
            return
        """
        Unified finding reporter used by all scanners.
        Replaces the per-scanner _report_vuln / _report_finding methods.
        Calls self.add() once — never call add_result() directly from scanners.
        Severity is determined by CVSS v3.1 scoring; scanner-provided value is a hint.
        Accepts `type=` as a legacy alias for `vuln_type=`.
        Extra keyword arguments are merged into the finding entry.
        """
        resolved_type = vuln_type or type

        # Deduplicate: suppress exact-duplicate findings within this scanner instance
        dedup_key = (resolved_type, url, param, (payload or "")[:80])
        with self._seen_lock:
            if dedup_key in self._seen_findings:
                self.logger.debug(
                    f"[{self.name}] Duplicate finding suppressed: {resolved_type} @ {url}"
                    + (f" param={param}" if param else "")
                )
                return
            self._seen_findings.add(dedup_key)

        entry: Dict[str, Any] = {
            "type": resolved_type,
            "severity": self._normalize_severity(severity),
            "url": url,
            "parameter": param,
            "payload": payload,
        }
        if evidence:
            entry["evidence"] = evidence
        if kwargs:
            entry.update(kwargs)
        if extra:
            entry.update(extra)

        # Per-finding exploit evidence — attach exactly WHAT was sent (payload +
        # injection point, reconstructed) and WHAT came back (captured response).
        # Centralised here so every scanner gets it without per-scanner changes.
        self._attach_exchange_evidence(entry, resolved_type, url, param, payload)

        self.add("offensive", entry)
        self.logger.warning(
            f"[{self.name.upper()}] {resolved_type} FOUND: {url} [{entry['severity']}]"
            + (f" (param={param})" if param else "")
        )

    # ------------------------------------------------------------------
    # Per-finding exploit evidence (request sent + response received)
    # ------------------------------------------------------------------

    def _attach_exchange_evidence(self, entry: Dict[str, Any], vuln_type: str,
                                  url: str, param: str, payload: str) -> None:
        """
        Attach human-readable request/response evidence to a finding so the report
        can show exactly what the scanner did. Best-effort; never raises.

          • ``request``  — reconstructed from the known injection point (method,
                           url, param, payload). Always deterministic.
          • ``response`` — the most recent HTTP exchange captured for this thread
                           (status + headers + body snippet), but only attached if
                           it actually corresponds to this finding (same endpoint
                           or the payload is visible in it) so we never show a
                           misleading baseline response.

        Existing request/response/raw_* fields a scanner already set are preserved.
        """
        try:
            method = str(entry.get("method") or "GET").upper()
            if not entry.get("request") and not entry.get("raw_request"):
                entry["request"] = self._reconstruct_request(method, url, param, payload)

            if not entry.get("response") and not entry.get("raw_response"):
                try:
                    from ..core.http import get_last_exchange
                    ex = get_last_exchange()
                except Exception:
                    ex = None
                if isinstance(ex, dict):
                    same_endpoint = False
                    try:
                        fp, ep = urlparse(url), urlparse(str(ex.get("url", "")))
                        same_endpoint = (fp.netloc == ep.netloc and fp.path == ep.path)
                    except Exception:
                        same_endpoint = False
                    payload_seen = bool(payload) and (
                        payload in str(ex.get("url", ""))
                        or payload in str(ex.get("req_params", ""))
                        or payload in str(ex.get("req_data", ""))
                    )
                    if same_endpoint or payload_seen:
                        entry["response"] = self._format_response(ex)
                        entry.setdefault("http_status", ex.get("status"))
        except Exception as exc:  # evidence is best-effort, never break reporting
            self.logger.debug(f"[{self.name}] exchange evidence attach failed: {exc!r}")

    @staticmethod
    def _reconstruct_request(method: str, url: str, param: str, payload: str) -> str:
        """Build a readable HTTP request showing the exact injection point."""
        try:
            p = urlparse(url)
        except Exception:
            return f"{method} {url}"
        path = p.path or "/"
        query = f"?{p.query}" if p.query else ""
        lines = [f"{method} {path}{query} HTTP/1.1"]
        if p.netloc:
            lines.append(f"Host: {p.netloc}")
        if param and payload:
            lines.append("")
            lines.append(f"[*] Enjeksiyon noktası: parametre '{param}'")
            lines.append(f"[*] Gönderilen payload: {payload}")
        elif payload:
            lines.append("")
            lines.append(f"[*] Gönderilen payload: {payload}")
        return "\n".join(lines)

    @staticmethod
    def _format_response(ex: Dict[str, Any]) -> str:
        """Format a captured exchange snapshot into a readable response block."""
        lines = [f"HTTP {ex.get('status', '?')}  ({ex.get('elapsed_ms', '?')} ms)"]
        for k, v in (ex.get("resp_headers") or {}).items():
            lines.append(f"{k}: {v}")
        snippet = (ex.get("resp_snippet") or "").strip()
        if snippet:
            lines.append("")
            lines.append("--- Yanıt gövdesi (ilk 2KB) ---")
            lines.append(snippet)
        return "\n".join(lines)

    def verify_finding(
        self,
        vuln_type: str,
        url: str,
        param: str,
        payload: str,
        probe_fn: Callable[[], bool],
        detection_method: str = "error_based",
    ) -> bool:
        """
        FP-reduction pipeline gate.
        Re-runs probe_fn N times per detection_method threshold.
        Returns True if confirmed (safe to report), False if suppressed.
        Falls back to True when FPR is unavailable so scanners never silently drop findings.
        """
        if self._fpr is None:
            return True
        v = self._fpr.verify_and_gate(
            vuln_type=vuln_type,
            url=url,
            param=param,
            payload=payload,
            probe_fn=probe_fn,
            detection_method=detection_method,
        )
        if not v.is_confirmed:
            self.logger.debug(
                f"[FPR] Suppressed {vuln_type} @ {url} param={param} "
                f"({v.successes}/{v.attempts} confirmations, key={v.finding_key})"
            )
        return v.is_confirmed

    def _should_skip_param(self, param_name: str, attack_category: str, value: str = "") -> bool:
        """
        Context-aware param filter.
        Returns True when this param is irrelevant for the given attack category
        (e.g. a CSRF token for SQLi, or a redirect param for NoSQLi).
        Applies tech-stack filtering: if MongoDB detected, SQLi is skipped.
        Falls back to False (don't skip) on any import/analysis error.
        """
        try:
            from ..core.analysis import analyze_input_context, should_skip_payload_category
            tech = set(self.results.get("tech_stack", [])) or None
            ctx = analyze_input_context(name=param_name, value=value, source="param")
            return should_skip_payload_category(ctx.context, attack_category, tech_stack=tech)
        except Exception:
            return False

    def check_anomaly(
        self,
        baseline_len: int,
        baseline_time_ms: float,
        baseline_body: str,
        current_len: int,
        current_time_ms: float,
        current_body: str,
    ) -> float:
        """
        Anomaly scoring for blind injection detection.
        Compares response length, timing, and body similarity against baseline.
        Returns score 0.0–1.0; >0.5 = likely significant response change.
        """
        try:
            from ..core.analysis import anomaly_score
            return float(anomaly_score(
                baseline={"len": baseline_len, "time_samples": [baseline_time_ms], "body": baseline_body},
                current={"len": current_len, "time_ms": current_time_ms, "body": current_body},
            )["score"])
        except Exception:
            return 0.0

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
        """
        Execute *probe_fn(payload)* for each payload in a thread pool.
        Returns a list of truthy results from probe_fn.

        If stop_on_first=True (default), cancels remaining futures after the
        first truthy result — equivalent to the early-exit pattern all scanners used.

        Any exception raised by probe_fn is logged at DEBUG and skipped (not swallowed
        silently — the log entry is always emitted).
        """
        if max_workers <= 0:
            max_workers = self._max_workers
        hits: List[Any] = []

        cb_tripped = False
        with ThreadPoolExecutor(max_workers=max_workers) as exe:
            futures = {exe.submit(probe_fn, p): p for p in payloads}
            for fut in as_completed(futures):
                try:
                    result = fut.result()
                except (_CircuitBreakerTripped, _PhaseAbandoned) as exc:
                    # The global circuit breaker is OPEN — every remaining probe in
                    # this batch will instantly trip too. Aborting here avoids both
                    # the 200+ duplicate tracebacks seen in the wild and the wasted
                    # work of churning through payloads that cannot be sent. Logged
                    # once, at WARNING (not ERROR/traceback): this is expected.
                    if not cb_tripped:
                        cb_tripped = True
                        self.logger.warning(
                            f"[{self.name}] Aborting remaining probes in this batch "
                            f"(circuit breaker open or phase abandoned): {exc}"
                        )
                    for f in futures:
                        f.cancel()
                    break
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

        Uses the advanced PayloadEngine (v2) rather than the flat wordlist so every
        scanner gets: the base wordlist + CMS-specific PoCs + score-ranking (highest
        signal payloads first) and, when a WAF is in play, WAF-bypass MUTATION
        variants (case/comment/encoding tricks). This is what turns the engine from
        "generic wordlist spray" into context- and defence-aware attacking. Falls
        back to the flat wordlist if the engine is unavailable, so detection (and the
        100%-recall benchmark) never regresses.
        """
        contexts = self.results.get("param_contexts", {})
        ctx_result = contexts.get(param_name)

        if tech_stack is None:
            tech_stack = set(self.results.get("tech_stack", []))

        payloads: List[str] = []
        try:
            from websecure.core.payload_engine import get_payloads_v2
            waf_present = self._waf_detected()
            payloads = get_payloads_v2(
                category,
                tech_tags=list(tech_stack) if tech_stack else None,
                apply_mutations=waf_present,   # WAF-bypass mutation variants when a WAF/blocking is seen
                apply_encoding=waf_present,    # URL/double/unicode/hex/utf16 encoding variants too
                limit=600 if waf_present else 250,
            )
            # Escalate with the creative WAF-bypass arsenal (core.mutator.Mutator):
            # MySQL version-comments, boolean equivalents, fullwidth/confusables,
            # base85/zlib, protocol obfuscation, polyglots — the "unexpected"
            # evasions signature WAFs miss. Only when blocking is actually happening
            # so non-WAF scans stay fast and clean.
            if waf_present:
                payloads = self._apply_creative_waf_bypass(category, payloads)
        except Exception as exc:
            self.logger.debug(f"[SmartPayload] PayloadEngine v2 unavailable, flat list: {exc!r}")
            payloads = []
        if not payloads:
            payloads = get_payloads(category, tech_tags=tech_stack)

        if ctx_result and self.debug:
            self.logger.debug(
                f"[SmartPayload] {param_name} ({ctx_result.context.name}) "
                f"fetching {category} payloads ({len(payloads)} adet)."
            )
        return payloads

    def _waf_detected(self) -> bool:
        """Best-effort: has a WAF been fingerprinted / inferred for this target?

        Used to decide whether to spend extra requests on WAF-bypass payload
        mutations. Conservative — returns False on any uncertainty so non-WAF
        scans stay fast and low-noise.
        """
        try:
            r = self.results or {}
            for key in ("waf", "waf_detection", "waf_fingerprint", "waf_detect"):
                v = r.get(key)
                if isinstance(v, dict) and (v.get("detected") or v.get("vendor") or v.get("name")):
                    return True
                if isinstance(v, list) and any(
                    isinstance(x, dict) and (x.get("vendor") or x.get("name") or x.get("detected"))
                    for x in v
                ):
                    return True
            if r.get("waf_present"):
                return True
            # OBSERVED blocking is itself a reason to escalate to bypass payloads —
            # WAF fingerprinting frequently misses edge WAFs (e.g. the wild scan
            # logged "No WAF Detected" while the target was firing a 403 storm).
            if len(r.get("anti_block_event") or []) >= 3:
                return True
            try:
                from websecure.core.http import HTTP_METRICS as _M
                blocked = (int(_M.get("403", 0) or 0)
                           + int(_M.get("429", 0) or 0)
                           + int(_M.get("ban_403", 0) or 0))
                if blocked >= 5:
                    return True
            except Exception:
                pass
            # Circuit-breaker trips capture BOTH 403/429 floods AND silent blocking
            # (connection resets/timeouts trip it via consecutive errors) — so a
            # target that drops us without a clear 403 still escalates to bypass.
            try:
                from websecure.core.circuit_breaker import get_circuit_breaker
                cb = get_circuit_breaker()
                if hasattr(cb, "get_trip_log") and cb.get_trip_log():
                    return True
            except Exception:
                pass
            return False
        except Exception:
            return False

    def _apply_creative_waf_bypass(self, category: str, payloads: List[str]) -> List[str]:
        """
        Fold the creative WAF-bypass arsenal (core.mutator.Mutator) onto the base
        payloads. These category-specific transforms are exactly the evasions a
        signature WAF normalises/decodes but its regex misses: MySQL inline
        version-comments (/*!50000UNION*/), boolean equivalents (1 IN (1), 1=1e0),
        fullwidth & unicode confusables, base85/zlib/XOR encodings, JS protocol
        obfuscation (java\\tscript:, j&#97;vascript:), and multi-context polyglots.

        Bounded (mutates only the top base payloads) and dedup-preserving so it
        enriches without exploding the request count unboundedly.
        """
        out: List[str] = list(payloads)
        seen: set = set(payloads)
        _CAP = 1000
        # Famous multi-context polyglots first (high-value one-shot bypass) so they
        # are never crowded out by the mutation cap.
        try:
            from websecure.core.mutator import Mutator
            for pg in Mutator.mutate_polyglot("", max_variants=6):
                if pg and pg not in seen:
                    seen.add(pg)
                    out.append(pg)
        except Exception:
            pass
        # AdaptiveMutationEngine combines the generic tricks (case/comment/whitespace/
        # URL/double-URL/hex/concat) + UNICODE CONFUSABLES (Cyrillic look-alikes that
        # visually match but differ at byte level) + the full core.mutator.Mutator
        # category arsenal — in one call. Strictly richer than calling Mutator alone.
        try:
            from websecure.core.waf_bypass import AdaptiveMutationEngine
            engine = AdaptiveMutationEngine()
            for base in payloads[:20]:
                if not base or len(out) >= _CAP:
                    break
                try:
                    variants = engine.mutate(base, category=category)
                except Exception:
                    variants = []
                for v in variants:
                    if v and v not in seen and len(out) < _CAP:
                        seen.add(v)
                        out.append(v)
        except Exception as exc:
            self.logger.debug(f"[SmartPayload] AdaptiveMutationEngine unavailable: {exc!r}")
        self.logger.debug(
            f"[SmartPayload] creative WAF-bypass: {len(payloads)} -> {len(out)} payload ({category})"
        )
        return out

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
            curr_params[param] = payload          # add or replace — always inject
            new_query = urlencode(curr_params)
            req_kwargs["url"] = urlunparse((
                parsed.scheme, parsed.netloc, parsed.path,
                parsed.params, new_query, parsed.fragment,
            ))
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
