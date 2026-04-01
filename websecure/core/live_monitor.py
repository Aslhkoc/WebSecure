"""
websecure.core.live_monitor
~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Gerçek zamanlı terminal monitörü (LiveMonitor) ve konsol uyarı sistemi.

Her HTTP isteği, payload denemesi, IP rotasyonu, checkpoint resume
ve bulunan zafiyetleri renkli ANSI çıktısı olarak terminale yazar.
Opsiyonel olarak `rich` kütüphanesi kullanılırsa daha şık görünüm sağlar.

FAZ 4.1: reporting.py'den ayrıştırıldı.
Geriye dönük uyumluluk: reporting.py bu modülden import edip re-export eder.
"""
from __future__ import annotations

import logging
import threading
from typing import Any, Dict

_logger = logging.getLogger(__name__)


class LiveMonitor:
    """
    Gerçek zamanlı terminal monitörü.
    Singleton — `get_live_monitor()` ile erişin.
    """

    # ANSI renk kodları
    _R   = "\033[91m"   # kırmızı  — critical
    _Y   = "\033[93m"   # sarı     — high / warning
    _G   = "\033[92m"   # yeşil    — success / found
    _C   = "\033[96m"   # cyan     — info / request
    _M   = "\033[95m"   # magenta  — rotation / event
    _W   = "\033[97m"   # beyaz    — neutral
    _DIM = "\033[2m"    # soluk
    _B   = "\033[1m"    # bold
    _RS  = "\033[0m"    # reset

    # Teknik → simge eşlemesi
    _TECH_ICON: Dict[str, str] = {
        "sql":       "💉",
        "sqli":      "💉",
        "xss":       "⚡",
        "ssti":      "🔥",
        "ssrf":      "🌐",
        "lfi":       "📂",
        "rce":       "💥",
        "idor":      "🔑",
        "csrf":      "🔓",
        "crlf":      "↩",
        "smuggling": "🚢",
        "race":      "🏁",
        "prototype": "🧬",
        "jwt":       "🎫",
        "upload":    "📤",
        "redirect":  "↪",
        "discovery": "🔍",
        "crawler":   "🕷",
        "nmap":      "🗺",
    }

    def __init__(self, verbose: bool = True) -> None:
        self.verbose    = verbose
        self._lock      = threading.Lock()
        self._counters  = {"requests": 0, "findings": 0, "rotations": 0}
        try:
            from rich.console import Console
            self._console  = Console(highlight=False)
            self._has_rich = True
        except ImportError:
            self._console  = None
            self._has_rich = False

    def _ts(self) -> str:
        import time as _t
        return _t.strftime("%H:%M:%S")

    def _print(self, line: str) -> None:
        if self._has_rich:
            self._console.print(line, markup=False, highlight=False)
        else:
            print(line)

    # ── public API ────────────────────────────────────────────────────────

    def log_request(
        self,
        method: str,
        url: str,
        *,
        phase: str = "",
        payload: str = "",
        param: str = "",
    ) -> None:
        """Her giden HTTP isteği için bir satır yazar."""
        if not self.verbose:
            return
        with self._lock:
            self._counters["requests"] += 1
            n = self._counters["requests"]

        short_url = url if len(url) <= 80 else url[:77] + "…"
        tech      = phase.lower()
        icon      = self._TECH_ICON.get(tech, "→")

        parts = [
            f"{self._DIM}[{self._ts()}]{self._RS}",
            f"{self._C}{icon} #{n:05d}{self._RS}",
            f"{self._B}{method:6s}{self._RS}",
            short_url,
        ]
        if param:
            parts.append(f"{self._Y}param={param}{self._RS}")
        if payload:
            short_payload = payload if len(payload) <= 60 else payload[:57] + "…"
            parts.append(f"{self._M}payload={short_payload!r}{self._RS}")

        self._print("  ".join(parts))

    def log_rotation(self, req_count: int, proxy: str = "") -> None:
        """IP / proxy rotasyonu olayını yazar."""
        with self._lock:
            self._counters["rotations"] += 1
        proxy_hint = f" → {proxy}" if proxy else ""
        self._print(
            f"{self._DIM}[{self._ts()}]{self._RS}  "
            f"{self._M}↻ IP ROTATED{self._RS}  "
            f"req#{req_count}{proxy_hint}"
        )

    def log_ban_detected(self, status: int, url: str) -> None:
        """Ban / block tespitini yazar."""
        short = url if len(url) <= 70 else url[:67] + "…"
        self._print(
            f"{self._DIM}[{self._ts()}]{self._RS}  "
            f"{self._Y}⚠ BAN DETECTED{self._RS}  "
            f"HTTP {status}  {short}"
        )

    def log_resume(self, pages_crawled: int, url: str = "") -> None:
        """Checkpoint'ten devam olayını yazar."""
        self._print(
            f"{self._DIM}[{self._ts()}]{self._RS}  "
            f"{self._G}⟳ RESUME{self._RS}  "
            f"Checkpoint'ten devam: {pages_crawled} sayfa tarandı"
            + (f"  son={url}" if url else "")
        )

    def log_phase(self, phase: str) -> None:
        """Tarama fazı değişikliğini yazar."""
        self._print(
            f"\n{self._DIM}[{self._ts()}]{self._RS}  "
            f"{self._B}{self._C}{'─'*10} PHASE: {phase.upper()} {'─'*10}{self._RS}\n"
        )

    def log_finding(self, bucket: str, item: dict) -> None:
        """Bulunan zafiyeti öne çıkararak yazar (add_result'dan çağrılır)."""
        with self._lock:
            self._counters["findings"] += 1
            n = self._counters["findings"]

        sev     = str(item.get("severity") or "Info").lower()
        vtype   = str(item.get("type") or bucket)
        url     = str(item.get("url") or item.get("target") or "")[:70]
        param   = str(item.get("parameter") or item.get("param") or "")
        payload = str(item.get("payload") or "")[:60]

        if "critical" in sev or "kritik" in sev:
            color, icon = self._R, "🔴"
        elif "high" in sev or "yüksek" in sev:
            color, icon = self._Y, "🟠"
        elif "medium" in sev or "orta" in sev:
            color, icon = self._C, "🟡"
        else:
            color, icon = self._G, "🟢"

        # Ekstra bilgi: message veya details (url yoksa göster)
        msg = str(item.get("message") or item.get("details") or "")[:120]

        self._print(
            f"\n{color}{self._B}"
            f"{'▓'*60}\n"
            f"  {icon} VULN #{n}: {vtype.upper()}  [{sev.upper()}]\n"
            + (f"  URL    : {url}\n" if url else "")
            + (f"  PARAM  : {param}\n" if param else "")
            + (f"  PAYLOAD: {payload}\n" if payload else "")
            + (f"  DETAY  : {msg}\n" if msg and not url else "")
            + f"{'▓'*60}"
            f"{self._RS}\n"
        )

    def summary(self) -> None:
        """Tarama sonu özet satırını yazar."""
        c = self._counters
        try:
            from websecure.core.reporting import _counters as _gc
            global_reqs = int(_gc.get("http_requests", 0))
        except Exception as exc:
            global_reqs = 0
        total_reqs = max(c["requests"], global_reqs)
        self._print(
            f"\n{self._B}{self._G}"
            f"[SCAN COMPLETE]  "
            f"Requests: {total_reqs}  "
            f"Findings: {c['findings']}  "
            f"IP Rotations: {c['rotations']}"
            f"{self._RS}\n"
        )


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------
_live_monitor: "LiveMonitor | None" = None


def get_live_monitor(verbose: bool = True) -> LiveMonitor:
    """Global LiveMonitor singleton'ını döner, gerekirse oluşturur."""
    global _live_monitor
    if _live_monitor is None:
        _live_monitor = LiveMonitor(verbose=verbose)
    return _live_monitor


# ---------------------------------------------------------------------------
# Konsol uyarı fonksiyonu (_console_alert)
# ---------------------------------------------------------------------------

def console_alert(bucket: str, item: Dict[str, Any]) -> None:
    """Print a real-time 'Kill Cam' style alert to the terminal."""
    sev = str(item.get("severity") or "Info").lower()

    important = ["critical", "kritik", "high", "yüksek", "yuksek", "medium", "orta"]
    if not any(s in sev for s in important):
        return

    RED    = "\033[91m"
    YELLOW = "\033[93m"
    RESET  = "\033[0m"
    BOLD   = "\033[1m"

    color = YELLOW
    if "critical" in sev or "kritik" in sev:
        color = RED
    elif "high" in sev or "yüksek" in sev:
        color = RED

    icon = "[!]"
    if "critical" in sev:
        icon = "[⚡]"
    elif "high" in sev:
        icon = "[🔥]"
    elif "medium" in sev:
        icon = "[⚠️]"

    title   = item.get("type") or item.get("title") or "Vulnerability"
    url     = item.get("url") or item.get("target") or "N/A"
    payload = item.get("payload") or "N/A"

    print(f"\n{color}{BOLD}{icon} {title.upper()} DETECTED!{RESET}")
    print(f"{color} ├─ Target:  {url}{RESET}")
    print(f"{color} ├─ Payload: {payload}{RESET}")
    print(f"{color} └─ Severity: {sev.upper()}{RESET}\n")


__all__ = [
    "LiveMonitor",
    "get_live_monitor",
    "console_alert",
]
