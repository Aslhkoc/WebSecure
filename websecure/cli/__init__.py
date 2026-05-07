"""
websecure.cli
~~~~~~~~~~~~~
WebSecure komut satırı arayüzü (CLI) paketi.

Adım 19 — CLI & Kullanıcı Arayüzü

Bileşenler
----------
commands      : Ana CLI giriş noktası (argparse, alt komutlar)
tui           : Terminal TUI (Rich / PlainText)
web_ui        : Yerel HTTP web dashboard (stdlib http.server)
scheduler     : Cron tabanlı tarama zamanlama
queue_manager : Çok hedefli tarama kuyruğu
wizard        : İnteraktif config sihirbazı (`websecure init`)
diff          : İki tarama sonucunu karşılaştırma motoru
autocomplete  : Bash / Zsh / Fish shell tamamlama betikleri
webhook       : HTTP webhook tetikleme sistemi

Hızlı Kullanım
--------------
```python
# CLI'dan:
# websecure scan --target https://example.com --tui
# websecure init
# websecure diff scan1.json scan2.json
# websecure serve --port 8080
# websecure queue add https://example.com
# websecure completion bash >> ~/.bashrc

# Programatik:
from websecure.cli import ScanTUI, TUIFinding, WebDashboard, DashboardState

state = DashboardState()
dashboard = WebDashboard(state=state, port=8080)
dashboard.start()

tui = ScanTUI.create()
tui.start()
tui.add_finding(TUIFinding(title="SQLi", severity="Critical", url="https://ex.com/login"))
tui.stop()
```
"""
from __future__ import annotations

# ---------------------------------------------------------------------------
# Core CLI
# ---------------------------------------------------------------------------
from websecure.cli.commands import main, cli_entry, build_parser

# ---------------------------------------------------------------------------
# TUI
# ---------------------------------------------------------------------------
from websecure.cli.tui import (
    BaseTUI,
    PlainTUI,
    ScanTUI,
    TUIFinding,
)

# ---------------------------------------------------------------------------
# Web Dashboard
# ---------------------------------------------------------------------------
from websecure.cli.web_ui import (
    DashboardState,
    WebDashboard,
)

# ---------------------------------------------------------------------------
# Webhook
# ---------------------------------------------------------------------------
from websecure.cli.webhook import (
    WebhookDispatcher,
    WebhookEndpoint,
    WebhookEvent,
    configure_webhook,
    get_dispatcher,
)

# ---------------------------------------------------------------------------
# Diff
# ---------------------------------------------------------------------------
from websecure.cli.diff import (
    DiffRenderer,
    DiffResult,
    ScanDiff,
)

# ---------------------------------------------------------------------------
# Scheduler
# ---------------------------------------------------------------------------
from websecure.cli.scheduler import (
    CronParser,
    CronScheduler,
    ScheduleEntry,
    get_scheduler,
)

# ---------------------------------------------------------------------------
# Queue
# ---------------------------------------------------------------------------
from websecure.cli.queue_manager import (
    QueueEntry,
    QueueStatus,
    ScanQueue,
    get_queue,
)

# ---------------------------------------------------------------------------
# Wizard
# ---------------------------------------------------------------------------
from websecure.cli.wizard import ConfigWizard

# ---------------------------------------------------------------------------
# Autocomplete
# ---------------------------------------------------------------------------
from websecure.cli.autocomplete import (
    BashCompletionGenerator,
    FishCompletionGenerator,
    ZshCompletionGenerator,
    get_generator,
)

# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

__all__ = [
    # CLI
    "main",
    "cli_entry",
    "build_parser",
    # TUI
    "BaseTUI",
    "PlainTUI",
    "ScanTUI",
    "TUIFinding",
    # Web
    "DashboardState",
    "WebDashboard",
    # Webhook
    "WebhookDispatcher",
    "WebhookEndpoint",
    "WebhookEvent",
    "configure_webhook",
    "get_dispatcher",
    # Diff
    "DiffRenderer",
    "DiffResult",
    "ScanDiff",
    # Scheduler
    "CronParser",
    "CronScheduler",
    "ScheduleEntry",
    "get_scheduler",
    # Queue
    "QueueEntry",
    "QueueStatus",
    "ScanQueue",
    "get_queue",
    # Wizard
    "ConfigWizard",
    # Autocomplete
    "BashCompletionGenerator",
    "ZshCompletionGenerator",
    "FishCompletionGenerator",
    "get_generator",
]
