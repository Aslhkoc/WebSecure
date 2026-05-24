"""
websecure.cli.web_ui
~~~~~~~~~~~~~~~~~~~~~
Yerel HTTP web dashboard sunucusu.

Bağımlılık yok — sadece stdlib (http.server, json, threading).
Tarayıcıda http://localhost:PORT adresinde açılır.

Özellikler
----------
* Canlı bulgu tablosu (SSE / polling)
* Tarama durumu (progress bar)
* Log paneli
* REST API: /api/status, /api/findings, /api/logs
* POST /api/scan -> yeni tarama başlat
* GET /api/sarif -> SARIF export
* Dashboard HTML/JS gömülü (dosya gerektirmez)

SOLID
-----
- SRP  : HTTP sunucu / dashboard state ayrı sınıflarda.
- OCP  : Yeni endpoint ekleme mevcut kodu değiştirmez.
"""
from __future__ import annotations

import json
import logging
import os
import queue
import threading
import time
import webbrowser
from datetime import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer, ThreadingHTTPServer
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Dashboard durumu
# ---------------------------------------------------------------------------

class DashboardState:
    """
    Web dashboard için paylaşılan state.
    Thread-safe read/write.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._findings: List[Dict[str, Any]] = []
        self._logs: List[Dict[str, Any]] = []
        self._status: Dict[str, Any] = {
            "running": False,
            "target": "",
            "completed": 0,
            "total": 0,
            "started_at": None,
            "elapsed_s": 0.0,
            "eta_s": None,
        }
        self._start_time: float = 0.0
        self._sse_clients: List[queue.Queue] = []

    # ------------------------------------------------------------------
    # Findings
    # ------------------------------------------------------------------

    def add_finding(self, finding: Dict[str, Any]) -> None:
        with self._lock:
            finding.setdefault("timestamp", datetime.now().isoformat())
            self._findings.append(finding)
        self._broadcast({"type": "finding", "data": finding})

    def get_findings(self) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self._findings)

    def clear_findings(self) -> None:
        with self._lock:
            self._findings.clear()

    # ------------------------------------------------------------------
    # Logs
    # ------------------------------------------------------------------

    def add_log(self, message: str, level: str = "info") -> None:
        entry = {
            "message": message,
            "level": level,
            "timestamp": datetime.now().strftime("%H:%M:%S"),
        }
        with self._lock:
            self._logs.append(entry)
            if len(self._logs) > 500:
                self._logs = self._logs[-500:]
        self._broadcast({"type": "log", "data": entry})

    def get_logs(self, limit: int = 100) -> List[Dict[str, Any]]:
        with self._lock:
            return self._logs[-limit:]

    # ------------------------------------------------------------------
    # Status
    # ------------------------------------------------------------------

    def update_status(self, **kwargs: Any) -> None:
        with self._lock:
            self._status.update(kwargs)
            if kwargs.get("running") and self._start_time == 0:
                self._start_time = time.monotonic()
            if not kwargs.get("running", True):
                pass
        self._broadcast({"type": "status", "data": self._get_status()})

    def _get_status(self) -> Dict[str, Any]:
        s = dict(self._status)
        if self._start_time > 0:
            s["elapsed_s"] = round(time.monotonic() - self._start_time, 1)
        return s

    def get_status(self) -> Dict[str, Any]:
        with self._lock:
            return self._get_status()

    # ------------------------------------------------------------------
    # SSE (Server-Sent Events) — canlı güncelleme
    # ------------------------------------------------------------------

    def subscribe(self) -> "queue.Queue[Optional[str]]":
        """Yeni SSE client ekle — event kuyruğu döndür."""
        q: queue.Queue = queue.Queue(maxsize=200)
        with self._lock:
            self._sse_clients.append(q)
        return q

    def unsubscribe(self, q: queue.Queue) -> None:
        with self._lock:
            try:
                self._sse_clients.remove(q)
            except ValueError as _fix_e:
                logger.debug(f"[cli.web_ui] {type(_fix_e).__name__}: {_fix_e!r}")

    def _broadcast(self, data: Dict[str, Any]) -> None:
        msg = f"data: {json.dumps(data, ensure_ascii=False)}\n\n"
        dead: List[queue.Queue] = []
        with self._lock:
            clients = list(self._sse_clients)
        for q in clients:
            try:
                q.put_nowait(msg)
            except queue.Full:
                dead.append(q)
        for q in dead:
            self.unsubscribe(q)


# ---------------------------------------------------------------------------
# Gömülü HTML Dashboard
# ---------------------------------------------------------------------------

_DASHBOARD_HTML = """\
<!DOCTYPE html>
<html lang="tr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>WebSecure Dashboard</title>
<style>
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: 'Segoe UI', Arial, sans-serif; background: #0f1117; color: #e0e0e0; }
header { background: #1a1d2e; padding: 1rem 2rem; border-bottom: 2px solid #0d6efd;
         display: flex; align-items: center; gap: 1rem; }
header h1 { color: #0d6efd; font-size: 1.4rem; }
.badge { background: #0d6efd; color: #fff; padding: .2rem .6rem;
         border-radius: 1rem; font-size: .75rem; }
.container { display: grid; grid-template-columns: 2fr 1fr;
             grid-template-rows: auto 1fr; gap: 1rem; padding: 1rem; height: calc(100vh - 60px); }
.card { background: #1a1d2e; border-radius: .5rem; padding: 1rem;
        border: 1px solid #2a2d3e; overflow: hidden; display: flex; flex-direction: column; }
.card h2 { font-size: .9rem; color: #6c757d; margin-bottom: .75rem;
           text-transform: uppercase; letter-spacing: .05em; }
.progress-bar { height: 6px; background: #2a2d3e; border-radius: 3px; margin: .5rem 0; }
.progress-fill { height: 100%; background: linear-gradient(90deg, #0d6efd, #6610f2);
                 border-radius: 3px; transition: width .3s; }
#status-text { font-size: .85rem; color: #adb5bd; }
table { width: 100%; border-collapse: collapse; font-size: .82rem; }
th { color: #6c757d; text-align: left; padding: .4rem .5rem;
     border-bottom: 1px solid #2a2d3e; font-weight: 500; }
td { padding: .4rem .5rem; border-bottom: 1px solid #1e2130; }
.sev-Critical { color: #dc3545; font-weight: bold; }
.sev-High     { color: #fd7e14; }
.sev-Medium   { color: #ffc107; }
.sev-Low      { color: #17a2b8; }
.sev-Info     { color: #28a745; }
#log-panel { font-family: monospace; font-size: .78rem; overflow-y: auto;
             flex: 1; color: #adb5bd; }
.log-entry { padding: .1rem 0; border-bottom: 1px solid #1a1d2e; }
.log-error   { color: #dc3545; }
.log-warning { color: #ffc107; }
.log-success { color: #28a745; }
#findings-table-wrap { overflow-y: auto; flex: 1; }
.stat-bar { display: flex; gap: 1rem; padding: .5rem 0; flex-wrap: wrap; }
.stat { background: #0d1117; border: 1px solid #2a2d3e; border-radius: .4rem;
        padding: .5rem 1rem; text-align: center; min-width: 70px; }
.stat .n { font-size: 1.4rem; font-weight: bold; }
.stat .l { font-size: .7rem; color: #6c757d; }
#scan-form { display: flex; gap: .5rem; align-items: center; padding: .5rem 0; }
#scan-url  { flex: 1; background: #0d1117; border: 1px solid #2a2d3e; color: #e0e0e0;
             padding: .4rem .8rem; border-radius: .3rem; font-size: .9rem; }
button { background: #0d6efd; color: #fff; border: none; padding: .4rem 1rem;
         border-radius: .3rem; cursor: pointer; font-size: .85rem; }
button:hover { background: #0b5ed7; }
button.danger { background: #dc3545; }
</style>
</head>
<body>
<header>
  <h1>[!] WebSecure</h1>
  <span class="badge" id="version-badge">v2.0</span>
  <span id="connection-status" style="margin-left:auto;font-size:.8rem;color:#28a745">[*] Bağlı</span>
</header>

<div class="container">
  <!-- Sol üst: Status + yeni tarama -->
  <div class="card" style="grid-column:1;grid-row:1">
    <h2>Durum</h2>
    <div id="scan-form">
      <input id="scan-url" type="url" placeholder="https://hedef.com" />
      <button onclick="startScan()">Tara</button>
    </div>
    <div class="progress-bar"><div class="progress-fill" id="prog" style="width:0%"></div></div>
    <p id="status-text">Bekleniyor...</p>
    <div class="stat-bar" id="stat-bar">
      <div class="stat"><div class="n sev-Critical" id="sc">0</div><div class="l">Critical</div></div>
      <div class="stat"><div class="n sev-High"     id="sh">0</div><div class="l">High</div></div>
      <div class="stat"><div class="n sev-Medium"   id="sm">0</div><div class="l">Medium</div></div>
      <div class="stat"><div class="n sev-Low"      id="sl">0</div><div class="l">Low</div></div>
      <div class="stat"><div class="n sev-Info"     id="si">0</div><div class="l">Info</div></div>
    </div>
  </div>

  <!-- Sağ: Logs -->
  <div class="card" style="grid-column:2;grid-row:1 / span 2">
    <h2>Loglar <small style="font-size:.7rem;color:#6c757d">(son 200)</small></h2>
    <div id="log-panel"></div>
  </div>

  <!-- Sol alt: Bulgular -->
  <div class="card" style="grid-column:1;grid-row:2">
    <h2>Bulgular <span id="finding-count" style="color:#0d6efd">0</span></h2>
    <div id="findings-table-wrap">
      <table>
        <thead><tr><th>Saat</th><th>Önem</th><th>Başlık</th><th>Araç</th></tr></thead>
        <tbody id="findings-tbody"></tbody>
      </table>
    </div>
  </div>
</div>

<script>
const findings = [];
const sev_counts = {Critical:0,High:0,Medium:0,Low:0,Info:0};

// SSE bağlantısı
const evtSource = new EventSource('/api/events');
evtSource.onmessage = (e) => {
  const msg = JSON.parse(e.data);
  if (msg.type === 'finding')  handleFinding(msg.data);
  if (msg.type === 'log')      handleLog(msg.data);
  if (msg.type === 'status')   handleStatus(msg.data);
};
evtSource.onerror = () => {
  document.getElementById('connection-status').textContent = '[*] Bağlantı kesildi';
  document.getElementById('connection-status').style.color = '#dc3545';
};

function handleFinding(f) {
  findings.push(f);
  sev_counts[f.severity] = (sev_counts[f.severity]||0) + 1;
  document.getElementById('sc').textContent = sev_counts.Critical||0;
  document.getElementById('sh').textContent = sev_counts.High||0;
  document.getElementById('sm').textContent = sev_counts.Medium||0;
  document.getElementById('sl').textContent = sev_counts.Low||0;
  document.getElementById('si').textContent = sev_counts.Info||0;
  document.getElementById('finding-count').textContent = findings.length;
  const tb = document.getElementById('findings-tbody');
  const tr = document.createElement('tr');
  const ts = (f.timestamp||'').substring(11,19);
  tr.innerHTML = `<td>${ts}</td><td class="sev-${f.severity}">${f.severity}</td>`
    + `<td title="${f.url||''}">${escHtml(f.title||'')}</td><td>${f.tool||''}</td>`;
  tb.prepend(tr);
}

function handleLog(entry) {
  const div = document.getElementById('log-panel');
  const p = document.createElement('div');
  p.className = 'log-entry log-' + (entry.level||'');
  p.textContent = `${entry.timestamp} ${entry.message}`;
  div.prepend(p);
  if (div.children.length > 200) div.removeChild(div.lastChild);
}

function handleStatus(s) {
  const pct = s.total ? Math.round(s.completed / s.total * 100) : 0;
  document.getElementById('prog').style.width = pct + '%';
  const eta = s.eta_s ? ` | ETA: ${Math.round(s.eta_s)}s` : '';
  document.getElementById('status-text').textContent =
    `${s.target||''}  ${s.completed||0}/${s.total||0} (${pct}%)  ${Math.round(s.elapsed_s||0)}s${eta}`;
}

function startScan() {
  const url = document.getElementById('scan-url').value.trim();
  if (!url) return alert('Hedef URL girin');
  fetch('/api/scan', {
    method: 'POST',
    headers: {'Content-Type':'application/json'},
    body: JSON.stringify({target: url})
  }).then(r => r.json()).then(d => {
    if (d.error) alert('Hata: ' + d.error);
    else handleLog({message:'Tarama başlatıldı: ' + url, level:'success', timestamp: new Date().toTimeString().slice(0,8)});
  });
}

function escHtml(s) {
  return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

// İlk yükleme — mevcut findings/logs/status
fetch('/api/findings').then(r=>r.json()).then(d=>(d.findings||[]).forEach(handleFinding));
fetch('/api/logs').then(r=>r.json()).then(d=>(d.logs||[]).forEach(handleLog));
fetch('/api/status').then(r=>r.json()).then(handleStatus);
</script>
</body>
</html>
"""


# ---------------------------------------------------------------------------
# HTTP İşleyicisi
# ---------------------------------------------------------------------------

class _DashboardHandler(BaseHTTPRequestHandler):
    """HTTP istek işleyicisi — tüm endpoint'leri yönetir."""

    # state class variable (server tarafından ayarlanır)
    state: DashboardState
    scan_callback: Optional[Callable[[str, Dict[str, Any]], None]]

    def log_message(self, format: str, *args: Any) -> None:
        # Varsayılan HTTP log'u sustur
        logger.debug(f"[WebUI] {format % args}")

    def _send_json(self, data: Any, status: int = 200) -> None:
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def _send_html(self, html: str) -> None:
        body = html.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        path = self.path.split("?")[0]

        if path in ("/", "/dashboard"):
            self._send_html(_DASHBOARD_HTML)

        elif path == "/api/status":
            self._send_json(self.state.get_status())

        elif path == "/api/findings":
            self._send_json({"findings": self.state.get_findings()})

        elif path == "/api/logs":
            self._send_json({"logs": self.state.get_logs()})

        elif path == "/api/events":
            # Server-Sent Events
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "keep-alive")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()

            q = self.state.subscribe()
            try:
                # Keep-alive ping her 15 saniyede
                while True:
                    try:
                        msg = q.get(timeout=15)
                        self.wfile.write(msg.encode("utf-8"))
                        self.wfile.flush()
                    except queue.Empty:
                        # Ping
                        self.wfile.write(b": ping\n\n")
                        self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError):
                pass
            finally:
                self.state.unsubscribe(q)

        elif path == "/api/sarif":
            findings = self.state.get_findings()
            try:
                from websecure.integrations.sarif import findings_to_sarif
                from websecure.integrations.base import ToolFinding, ToolSeverity
                tool_findings = []
                for f in findings:
                    tool_findings.append(ToolFinding(
                        title=f.get("title","?"),
                        severity=ToolSeverity.from_str(f.get("severity","Info")),
                        url=f.get("url",""),
                        tool=f.get("tool","websecure"),
                    ))
                sarif = findings_to_sarif(tool_findings)
            except Exception:
                sarif = {"$schema": "sarif-2.1.0.json", "runs": []}
            body = json.dumps(sarif, ensure_ascii=False, indent=2).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/sarif+json")
            self.send_header("Content-Disposition", "attachment; filename=report.sarif.json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        else:
            self._send_json({"error": "Not found"}, 404)

    def do_POST(self) -> None:
        path = self.path.split("?")[0]

        if path == "/api/scan":
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length) if length else b""
            try:
                data = json.loads(body) if body else {}
            except json.JSONDecodeError:
                self._send_json({"error": "Invalid JSON"}, 400)
                return

            target = data.get("target", "")
            if not target:
                self._send_json({"error": "target gerekli"}, 400)
                return

            if self.scan_callback:
                try:
                    threading.Thread(
                        target=self.scan_callback,
                        args=(target, data.get("options", {})),
                        daemon=True,
                    ).start()
                    self._send_json({"status": "started", "target": target})
                except Exception as exc:
                    self._send_json({"error": str(exc)}, 500)
            else:
                self._send_json({"error": "Scan runner tanımlanmamış"}, 503)

        else:
            self._send_json({"error": "Not found"}, 404)

    def do_OPTIONS(self) -> None:
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()


# ---------------------------------------------------------------------------
# WebDashboard — sunucu yaşam döngüsü
# ---------------------------------------------------------------------------

class WebDashboard:
    """
    Yerel HTTP web dashboard.

    Kullanım
    --------
    ```python
    state = DashboardState()
    dashboard = WebDashboard(state=state, port=8080)
    dashboard.start(open_browser=True)

    # Tarama sırasında:
    state.add_finding({"title": "XSS", "severity": "High", "url": url})
    state.update_status(running=True, target=url, completed=5, total=100)
    state.add_log("SQLi taranıyor...", "info")

    dashboard.stop()
    ```
    """

    def __init__(
        self,
        state: Optional[DashboardState] = None,
        host: str = "127.0.0.1",
        port: int = 8080,
        scan_callback: Optional[Callable[[str, Dict[str, Any]], None]] = None,
    ) -> None:
        self.state = state or DashboardState()
        self.host = host
        self.port = port
        self.scan_callback = scan_callback
        self._server: Optional[ThreadingHTTPServer] = None
        self._thread: Optional[threading.Thread] = None

    @property
    def url(self) -> str:
        return f"http://{self.host}:{self.port}"

    def start(self, open_browser: bool = True) -> None:
        """Sunucuyu arka plan thread'inde başlat."""
        # Handler sınıfına state'i bağla (class variable)
        class Handler(_DashboardHandler):
            pass
        Handler.state = self.state
        Handler.scan_callback = self.scan_callback

        try:
            self._server = ThreadingHTTPServer((self.host, self.port), Handler)
        except OSError as exc:
            logger.error(f"[WebUI] Port {self.port} açılamadı: {exc}")
            raise

        self._thread = threading.Thread(
            target=self._server.serve_forever,
            name="WebDashboard",
            daemon=True,
        )
        self._thread.start()
        logger.info(f"[WebUI] Dashboard başlatıldı: {self.url}")

        if open_browser:
            try:
                webbrowser.open(self.url)
            except Exception as _fix_e:
                logger.debug(f"[cli.web_ui] {type(_fix_e).__name__}: {_fix_e!r}")
        print(f"  [*] Web Dashboard: {self.url}")

    def stop(self) -> None:
        if self._server:
            self._server.shutdown()
            self._server = None
        logger.info("[WebUI] Dashboard durduruldu.")


# ---------------------------------------------------------------------------
# Scan callback fabrikası
# ---------------------------------------------------------------------------

def _make_scan_callback(state: "DashboardState") -> Optional[Callable[[str, dict], None]]:
    """
    WebDashboard için gerçek WebSecure scan callback'i oluşturur.
    ScanRunner'ı arka plan thread'inde çalıştırır ve bulguları DashboardState'e aktarır.
    """
    try:
        from websecure.core.scan_runner import ScanRunner as _ScanRunner

        def _callback(target: str, options: dict) -> None:
            state.update_status(running=True, target=target)
            state.add_log(f"Tarama başlatıldı: {target}", "success")
            try:
                sr = _ScanRunner(target=target, config=options or {})
                ctx = sr.run()
                findings_flat: list = []
                for bucket_items in (getattr(ctx, "results", None) or {}).values():
                    if isinstance(bucket_items, list):
                        findings_flat.extend(bucket_items)
                for f in findings_flat:
                    if isinstance(f, dict):
                        state.add_finding(f)
                state.add_log(
                    f"Tarama tamamlandı: {target} — {len(findings_flat)} bulgu", "success"
                )
            except Exception as exc:
                state.add_log(f"Tarama hatası: {exc}", "error")
                logger.error(f"[WebUI] Tarama hatası: {exc!r}")
            finally:
                state.update_status(running=False)

        return _callback
    except ImportError:
        logger.warning("[WebUI] ScanRunner import edilemedi — POST /api/scan devre dışı")
        return None


# ---------------------------------------------------------------------------
# CLI kısayol
# ---------------------------------------------------------------------------

def run_serve_cli(args: list) -> int:
    """websecure serve komutu."""
    import argparse

    parser = argparse.ArgumentParser(prog="websecure serve")
    parser.add_argument("--host", default="127.0.0.1", help="Bind adresi")
    parser.add_argument("--port", "-p", type=int, default=8080, help="HTTP portu")
    parser.add_argument("--no-browser", action="store_true", help="Tarayıcı açma")
    ns = parser.parse_args(args)

    state = DashboardState()
    scan_cb = _make_scan_callback(state)
    dashboard = WebDashboard(state=state, host=ns.host, port=ns.port, scan_callback=scan_cb)

    try:
        dashboard.start(open_browser=not ns.no_browser)
        print(f"  Dashboard: {dashboard.url}  (Ctrl+C ile durdur)")
        import time
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n  [*] Dashboard durduruluyor...")
        dashboard.stop()

    return 0


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

__all__ = [
    "DashboardState",
    "WebDashboard",
    "run_serve_cli",
]
