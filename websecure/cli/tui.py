"""
websecure.cli.tui
~~~~~~~~~~~~~~~~~
İnteraktif Terminal Kullanıcı Arayüzü (TUI).

Rich kütüphanesi mevcutsa canlı bulgu tablosu + progress bar + log paneli gösterir.
Yoksa basit plain-text fallback kullanır — sıfır bağımlılık garantisi.

SOLID
-----
- SRP  : TUI görüntüleme tek sorumluluk.
- OCP  : Yeni widget eklemek mevcut kodu değiştirmez.
- LSP  : PlainTUI / RichTUI her ikisi de BaseTUI'dan türer.
- DIP  : ScanTUI(BaseTUI factory) -> Rich/Plain seçimini runtime'da yapar.
"""
from __future__ import annotations

import logging
import threading
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Severity renk haritası
# ---------------------------------------------------------------------------

_SEVERITY_COLORS = {
    "Critical": "bold red",
    "High":     "red",
    "Medium":   "yellow",
    "Low":      "cyan",
    "Info":     "green",
}

_SEVERITY_EMOJI = {
    "Critical": "[Critical]",
    "High":     "[High]",
    "Medium":   "[Medium]",
    "Low":      "[Low]",
    "Info":     "[Info]",
}


# ---------------------------------------------------------------------------
# Finding model (TUI içi — entegrasyon bağımsız)
# ---------------------------------------------------------------------------

@dataclass
class TUIFinding:
    """TUI'ye beslenecek bulgu modeli."""
    title: str
    severity: str        # "Critical" / "High" / "Medium" / "Low" / "Info"
    url: str
    tool: str = "websecure"
    description: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now().strftime("%H:%M:%S"))


# ---------------------------------------------------------------------------
# Soyut TUI temel sınıfı
# ---------------------------------------------------------------------------

class BaseTUI(ABC):
    """Tüm TUI implementasyonlarının sözleşmesi."""

    @abstractmethod
    def start(self) -> None:
        """TUI başlat (arka plan thread'i)."""

    @abstractmethod
    def stop(self) -> None:
        """TUI durdur."""

    @abstractmethod
    def add_finding(self, finding: TUIFinding) -> None:
        """Yeni bulgu ekle."""

    @abstractmethod
    def update_progress(
        self,
        completed: int,
        total: int,
        current_task: str = "",
        eta_s: Optional[float] = None,
    ) -> None:
        """İlerleme durumunu güncelle."""

    @abstractmethod
    def log(self, message: str, level: str = "info") -> None:
        """Log mesajı ekle."""

    @abstractmethod
    def set_target(self, target: str) -> None:
        """Tarama hedefini ayarla."""


# ---------------------------------------------------------------------------
# PlainTUI — Rich olmadan çalışan basit çıktı
# ---------------------------------------------------------------------------

class PlainTUI(BaseTUI):
    """
    Rich kütüphanesi olmadan çalışan düz-metin TUI.

    Tüm çıktı stdout'a gider. İlerleme ve bulgular anlık yazdırılır.
    """

    _SEP = "-" * 60
    _LEVEL_PREFIX = {
        "info":    "[*]",
        "warning": "[!]",
        "error":   "[[FAIL]]",
        "success": "[[OK]]",
        "debug":   "[~]",
    }

    def __init__(self) -> None:
        self._target = ""
        self._findings: List[TUIFinding] = []
        self._completed = 0
        self._total = 0
        self._lock = threading.Lock()
        self._start_time: float = 0.0

    def start(self) -> None:
        self._start_time = time.monotonic()
        print(self._SEP)
        print("  WebSecure — Tarama Başladı")
        print(self._SEP)

    def stop(self) -> None:
        elapsed = time.monotonic() - self._start_time
        print(self._SEP)
        print(f"  Tarama Tamamlandı — {elapsed:.1f}s  |  {len(self._findings)} bulgu")
        print(self._SEP)
        self._print_summary()

    def add_finding(self, finding: TUIFinding) -> None:
        with self._lock:
            self._findings.append(finding)
        emoji = _SEVERITY_EMOJI.get(finding.severity, "[o]")
        print(
            f"  {emoji} [{finding.severity:<8}] {finding.title[:55]:<55} "
            f"({finding.tool})  {finding.timestamp}"
        )

    def update_progress(
        self,
        completed: int,
        total: int,
        current_task: str = "",
        eta_s: Optional[float] = None,
    ) -> None:
        with self._lock:
            self._completed = completed
            self._total = total

        pct = int(completed / total * 100) if total else 0
        bar_len = 30
        filled = int(bar_len * pct / 100)
        bar = "#" * filled + "." * (bar_len - filled)
        eta_str = f"  ETA: {eta_s:.0f}s" if eta_s else ""
        task_str = f"  {current_task[:35]}" if current_task else ""
        print(f"\r  [{bar}] {pct:3d}%{task_str}{eta_str}", end="", flush=True)
        if pct == 100:
            print()

    def log(self, message: str, level: str = "info") -> None:
        prefix = self._LEVEL_PREFIX.get(level.lower(), "[*]")
        ts = datetime.now().strftime("%H:%M:%S")
        print(f"  {ts} {prefix} {message}")

    def set_target(self, target: str) -> None:
        self._target = target
        print(f"  Hedef: {target}")

    def _print_summary(self) -> None:
        if not self._findings:
            print("  Bulgu bulunamadı.")
            return
        counts: Dict[str, int] = {}
        for f in self._findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        print("  Özet:")
        for sev in ["Critical", "High", "Medium", "Low", "Info"]:
            n = counts.get(sev, 0)
            if n:
                emoji = _SEVERITY_EMOJI.get(sev, "")
                print(f"    {emoji} {sev:<10}: {n}")


# ---------------------------------------------------------------------------
# RichTUI — Rich kütüphanesi ile gelişmiş TUI
# ---------------------------------------------------------------------------

class RichTUI(BaseTUI):
    """
    Rich kütüphanesini kullanan canlı TUI.

    Layout:
    +---------------------------------+
    |           HEADER (banner)       |
    +------------------+--------------+
    |  FINDINGS TABLE  |  LOG PANEL   |
    +------------------+--------------+
    |         PROGRESS BAR            |
    +---------------------------------+
    """

    # Maksimum log satırı sayısı
    _MAX_LOG_LINES = 200
    _MAX_FINDINGS_DISPLAY = 500

    def __init__(self, refresh_rate: float = 0.5) -> None:
        from rich.console import Console
        from rich.layout import Layout
        from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn

        self._console = Console()
        self._refresh_rate = refresh_rate
        self._lock = threading.Lock()

        # State
        self._target = ""
        self._findings: List[TUIFinding] = []
        self._log_lines: List[str] = []
        self._completed = 0
        self._total = 0
        self._current_task = ""
        self._eta_s: Optional[float] = None
        self._start_time: float = 0.0
        self._running = False

        # Rich bileşenler
        self._live: Optional[Any] = None
        self._layout = Layout()
        self._render_loop_thread: Optional[threading.Thread] = None

        # Progress nesnesi (Layout dışında kullanılacak)
        self._progress = Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=self._console,
        )
        self._task_id = self._progress.add_task("Taranıyor...", total=100)

        self._layout.split_column(
            Layout(name="header", size=3),
            Layout(name="body"),
            Layout(name="footer", size=4),
        )
        self._layout["body"].split_row(
            Layout(name="findings", ratio=2),
            Layout(name="logs", ratio=1),
        )

    def start(self) -> None:
        from rich.live import Live
        self._start_time = time.monotonic()
        self._running = True
        self._live = Live(
            self._layout,
            console=self._console,
            refresh_per_second=1.0 / self._refresh_rate,
            screen=False,
        )
        self._live.start()
        self._render_loop_thread = threading.Thread(
            target=self._render_loop, daemon=True, name="TUI-RenderLoop"
        )
        self._render_loop_thread.start()

    def stop(self) -> None:
        self._running = False
        if self._render_loop_thread and self._render_loop_thread.is_alive():
            self._render_loop_thread.join(timeout=self._refresh_rate * 4)
        if self._live:
            self._live.stop()
        self._print_final_summary()

    def add_finding(self, finding: TUIFinding) -> None:
        with self._lock:
            self._findings.append(finding)

    def update_progress(
        self,
        completed: int,
        total: int,
        current_task: str = "",
        eta_s: Optional[float] = None,
    ) -> None:
        with self._lock:
            self._completed = completed
            self._total = total
            self._current_task = current_task
            self._eta_s = eta_s
        if total:
            self._progress.update(
                self._task_id,
                completed=completed,
                total=total,
                description=current_task or "Taranıyor...",
            )

    def log(self, message: str, level: str = "info") -> None:
        ts = datetime.now().strftime("%H:%M:%S")
        color_map = {
            "info":    "white",
            "warning": "yellow",
            "error":   "red",
            "success": "green",
            "debug":   "dim",
        }
        color = color_map.get(level.lower(), "white")
        with self._lock:
            self._log_lines.append(f"[{color}]{ts} {message}[/{color}]")
            if len(self._log_lines) > self._MAX_LOG_LINES:
                self._log_lines = self._log_lines[-self._MAX_LOG_LINES:]

    def set_target(self, target: str) -> None:
        self._target = target
        self.log(f"Hedef: {target}", "info")

    # ------------------------------------------------------------------
    # Render döngüsü
    # ------------------------------------------------------------------

    def _render_loop(self) -> None:
        while self._running:
            try:
                self._update_layout()
            except Exception as exc:
                logger.debug(f"[RichTUI] Render hatası: {exc!r}")
            time.sleep(self._refresh_rate)

    def _update_layout(self) -> None:
        from rich.panel import Panel
        from rich.table import Table

        with self._lock:
            findings = list(self._findings[-self._MAX_FINDINGS_DISPLAY:])
            logs = list(self._log_lines[-50:])
            completed = self._completed
            total = self._total
            eta_s = self._eta_s
            target = self._target

        # Header
        elapsed = time.monotonic() - self._start_time
        eta_str = f" | ETA: {eta_s:.0f}s" if eta_s else ""
        header_text = (
            f"[bold cyan]WebSecure[/bold cyan]  "
            f"[dim]{target}[/dim]  "
            f"[green]{completed}/{total}[/green]  "
            f"[dim]{elapsed:.0f}s{eta_str}[/dim]"
        )
        self._layout["header"].update(Panel(header_text, style="bold"))

        # Findings table
        table = Table(
            title=f"Bulgular ({len(findings)})",
            show_header=True,
            header_style="bold cyan",
            expand=True,
        )
        table.add_column("Saat",      style="dim",    width=8)
        table.add_column("Önem",      width=10)
        table.add_column("Başlık",    no_wrap=False,  ratio=3)
        table.add_column("Araç",      style="dim",    width=12)

        for f in findings[-40:]:
            color = _SEVERITY_COLORS.get(f.severity, "white")
            emoji = _SEVERITY_EMOJI.get(f.severity, "[o]")
            table.add_row(
                f.timestamp,
                f"[{color}]{emoji} {f.severity}[/{color}]",
                f.title,
                f.tool,
            )
        self._layout["findings"].update(Panel(table, title="Bulgular"))

        # Log panel
        log_text = "\n".join(logs[-30:])
        self._layout["logs"].update(Panel(log_text or "[dim]Bekleniyor...[/dim]", title="Loglar"))

        # Progress footer
        pct = int(completed / total * 100) if total else 0
        bar_width = 40
        filled = int(bar_width * pct / 100)
        bar = "#" * filled + "." * (bar_width - filled)
        footer_text = f"[cyan]{bar}[/cyan] [bold]{pct}%[/bold]"
        self._layout["footer"].update(Panel(footer_text))

    def _print_final_summary(self) -> None:
        from rich.table import Table
        from rich.console import Console

        console = Console()
        console.print("\n[bold cyan]=== Tarama Tamamlandı ===[/bold cyan]")

        counts: Dict[str, int] = {}
        for f in self._findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1

        if not counts:
            console.print("[dim]Bulgu bulunamadı.[/dim]")
            return

        table = Table(title=f"Özet — {len(self._findings)} bulgu")
        table.add_column("Önem", style="bold")
        table.add_column("Sayı", justify="right")

        for sev in ["Critical", "High", "Medium", "Low", "Info"]:
            n = counts.get(sev, 0)
            if n:
                color = _SEVERITY_COLORS.get(sev, "white")
                emoji = _SEVERITY_EMOJI.get(sev, "")
                table.add_row(f"[{color}]{emoji} {sev}[/{color}]", str(n))

        console.print(table)


# ---------------------------------------------------------------------------
# Factory — en uygun TUI'yi seç
# ---------------------------------------------------------------------------

class ScanTUI:
    """
    Runtime'da Rich/Plain TUI seçimi yapan fabrika.

    Kullanım
    --------
    ```python
    tui = ScanTUI.create()
    tui.set_target("https://example.com")
    tui.start()
    tui.add_finding(TUIFinding(title="XSS Found", severity="High", url=url))
    tui.update_progress(50, 100, "SQL Injection taranıyor")
    tui.stop()
    ```
    """

    @staticmethod
    def create(force_plain: bool = False) -> BaseTUI:
        """
        En uygun TUI implementasyonunu döndür.

        Parametreler
        ------------
        force_plain : True -> Rich yoksa/istemiyorsa PlainTUI kullan
        """
        if force_plain:
            return PlainTUI()

        try:
            import rich  # noqa: F401
            return RichTUI()
        except ImportError:
            logger.debug("[TUI] Rich kütüphanesi bulunamadı, PlainTUI kullanılıyor.")
            return PlainTUI()

    @staticmethod
    def is_rich_available() -> bool:
        try:
            import rich  # noqa: F401
            return True
        except ImportError:
            return False


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

__all__ = [
    "BaseTUI",
    "PlainTUI",
    "RichTUI",
    "ScanTUI",
    "TUIFinding",
]
