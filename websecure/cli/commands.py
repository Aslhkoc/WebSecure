"""
websecure.cli.commands
~~~~~~~~~~~~~~~~~~~~~~~
Ana CLI giriş noktası — tüm alt komutları yönetir.

Komutlar
--------
scan        Web güvenlik taraması başlat (TUI + webhook destekli)
init        İnteraktif config sihirbazı
diff        İki tarama sonucunu karşılaştır
serve       Web dashboard HTTP sunucusu
queue       Tarama kuyruğu yönet (add/list/run/cancel/stats/clear)
schedule    Cron zamanlamaları yönet (add/list/enable/disable/run)
completion  Shell autocomplete betiği üret (bash/zsh/fish)
api         REST API sunucusu başlat
setup       Dış araçları kontrol et ve kur
db          Veritabanı yönetimi (init/stats/vacuum/list-scans)

Genel Flag'ler
--------------
--config    Yapılandırma dosyası yolu (varsayılan: ./config.json)
--verbose   Ayrıntılı log çıktısı
--quiet     Sadece hata çıktısı
--version   Sürüm bilgisi

SOLID
-----
- SRP  : Her alt komut kendi handler fonksiyonunda.
- OCP  : Yeni komut eklemek sadece handler + registry kaydı gerektirir.
- DIP  : CommandRunner alt komut modüllerinden soyut arayüz üzerinden çalışır.
"""
from __future__ import annotations

import argparse
import logging
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

_VERSION = "20.0.0"
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Logging kurulumu
# ---------------------------------------------------------------------------

def _setup_logging(verbose: bool = False, quiet: bool = False) -> None:
    level = logging.WARNING if quiet else (logging.DEBUG if verbose else logging.INFO)
    logging.basicConfig(
        format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
        datefmt="%H:%M:%S",
        level=level,
    )


# ---------------------------------------------------------------------------
# Config yükleme
# ---------------------------------------------------------------------------

def _load_config(path: Optional[str]) -> Dict[str, Any]:
    """Config JSON dosyasını yükle."""
    import json

    candidates = [path, "./config.json", os.path.expanduser("~/.websecure/config.json")]
    for c in candidates:
        if c and Path(c).exists():
            try:
                cfg = json.loads(Path(c).read_text(encoding="utf-8"))
                logger.debug(f"[CLI] Config yüklendi: {c}")
                return cfg
            except Exception as exc:
                logger.warning(f"[CLI] Config yükleme hatası {c}: {exc!r}")
    return {}


# ---------------------------------------------------------------------------
# scan komutu
# ---------------------------------------------------------------------------

def _cmd_scan(ns: argparse.Namespace, cfg: Dict[str, Any]) -> int:
    """
    websecure scan komutu — mevcut main.py üzerinde wrapper.

    TUI ve webhook entegrasyonu sağlar.
    """
    from websecure.cli.tui import ScanTUI
    from websecure.cli.webhook import configure_webhook, get_dispatcher

    target = ns.target or cfg.get("target", "")
    if not target:
        print("[!] Hedef URL gerekli: --target https://example.com", file=sys.stderr)
        return 1

    # TUI kur
    use_tui = getattr(ns, "tui", True) and not getattr(ns, "no_tui", False)
    tui = ScanTUI.create(force_plain=not use_tui or not ScanTUI.is_rich_available())

    # Webhook kur
    webhook_url = getattr(ns, "on_finding_webhook", None) or cfg.get("webhook_url")
    if webhook_url:
        min_sev = cfg.get("webhook_min_severity", "Info")
        configure_webhook(webhook_url, min_severity=min_sev)

    # Scan ID
    import uuid
    scan_id = str(uuid.uuid4())[:8]

    tui.set_target(target)
    tui.start()
    tui.log(f"Tarama başlatıldı — ID: {scan_id}")

    dispatcher = get_dispatcher()
    if webhook_url:
        dispatcher.dispatch_scan_start(scan_id, target)

    start_t = time.monotonic()
    exit_code = 0

    try:
        # mevcut main.py entegrasyonu — argv üzerinden
        argv_backup = sys.argv[:]
        # main.py yalnızca target (pozisyonel) ve --profile kabul eder.
        # --proxy / --threads / --timeout / --resume main.py argparse'inde
        # tanımsız: sys.argv'ye eklenmesi "unrecognized arguments" hatası
        # verir ve tarama sys.exit(2) ile kesilir.
        new_argv = [sys.argv[0], target]

        profile = getattr(ns, "profile", None) or cfg.get("profile")
        if profile:
            new_argv += ["--profile", profile]

        sys.argv = new_argv

        tui.log(f"Hedef: {target}", "info")

        from websecure.main import main as _ws_main
        _ws_main()

    except SystemExit as exc:
        exit_code = exc.code if isinstance(exc.code, int) else 0
    except KeyboardInterrupt:
        tui.log("Tarama kullanıcı tarafından durduruldu.", "warning")
        exit_code = 130
    except Exception as exc:
        tui.log(f"Hata: {exc!r}", "error")
        logger.error(f"[scan] Beklenmedik hata: {exc!r}", exc_info=True)
        if webhook_url:
            dispatcher.dispatch_error(scan_id, target, str(exc))
        exit_code = 1
    finally:
        sys.argv = argv_backup
        duration = time.monotonic() - start_t

        if webhook_url:
            dispatcher.dispatch_scan_complete(
                scan_id, target,
                duration_s=duration,
            )

        tui.stop()

        # Çıktı dosyası
        try:
            from websecure.core import paths as _ws_paths
            _default_out = str(_ws_paths.output_dir()) if _ws_paths.is_frozen() else "./websecure_reports"
        except Exception:
            _default_out = "./websecure_reports"
        output_dir = getattr(ns, "output", None) or cfg.get("output_dir", _default_out)
        if output_dir:
            Path(output_dir).mkdir(parents=True, exist_ok=True)
            tui.log(f"Çıktı: {output_dir}", "info")

    return exit_code


# ---------------------------------------------------------------------------
# Ana argparse yapısı
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    """Ana CLI argparse parser'ını oluştur."""

    parser = argparse.ArgumentParser(
        prog="websecure",
        description="WebSecure — Endüstri Liderli Web Güvenlik Tarayıcı",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Örnekler:
  websecure scan --target https://example.com --tui
  websecure scan --target https://example.com --on-finding-webhook https://hooks.slack.com/...
  websecure init --output config.json
  websecure diff scan_old.json scan_new.json --format html --output diff.html
  websecure serve --port 8080
  websecure queue add https://example.com --priority 5
  websecure queue run --workers 3
  websecure schedule add https://example.com "0 2 * * *" --label "Gece taraması"
  websecure completion bash >> ~/.bashrc
""",
    )

    parser.add_argument("--version", "-V", action="version", version=f"WebSecure {_VERSION}")
    parser.add_argument("--config", metavar="FILE", help="Config dosyası yolu")
    parser.add_argument("--verbose", "-v", action="store_true", help="Ayrıntılı log")
    parser.add_argument("--quiet", "-q",   action="store_true", help="Sadece hata çıktısı")

    subparsers = parser.add_subparsers(dest="command", metavar="KOMUT")
    subparsers.required = False

    # --------------------------------------------------------
    # scan
    # --------------------------------------------------------
    scan_p = subparsers.add_parser("scan", help="Web güvenlik taraması başlat")
    scan_p.add_argument("--target", "-t", metavar="URL", help="Tarama hedefi")
    scan_p.add_argument("--profile", "-p",
                        choices=["default","aggressive","stealth","cicd","bugbounty","compliance","api-only"],
                        help="Tarama profili")
    scan_p.add_argument("--output", "-o", metavar="DIR",  help="Çıktı dizini")
    scan_p.add_argument("--format", "-f",
                        choices=["json","html","markdown","sarif","pdf","csv"],
                        default="json",  help="Rapor formatı")
    scan_p.add_argument("--threads",  type=int, metavar="N", help="Paralel thread sayısı")
    scan_p.add_argument("--timeout",  type=int, metavar="S", help="Bağlantı timeout (saniye)")
    scan_p.add_argument("--proxy",    metavar="URL",          help="Proxy URL")
    scan_p.add_argument("--config",   metavar="FILE",         help="Config dosyası")
    scan_p.add_argument("--resume",   action="store_true",    help="Checkpoint'ten devam et")
    scan_p.add_argument("--tui",      action="store_true",    help="TUI modunu etkinleştir",     default=True)
    scan_p.add_argument("--no-tui",   action="store_true",    help="TUI'yi devre dışı bırak")
    scan_p.add_argument("--on-finding-webhook", metavar="URL", help="Her bulguda webhook tetikle")
    scan_p.add_argument("--no-verify-ssl",     action="store_true", help="SSL doğrulamayı atla")

    # --------------------------------------------------------
    # init
    # --------------------------------------------------------
    init_p = subparsers.add_parser("init", help="İnteraktif yapılandırma sihirbazı")
    init_p.add_argument("--output", "-o", default="config.json", help="Config çıktı yolu")

    # --------------------------------------------------------
    # diff
    # --------------------------------------------------------
    diff_p = subparsers.add_parser("diff", help="İki tarama sonucunu karşılaştır")
    diff_p.add_argument("scan1", help="Eski (baseline) tarama JSON")
    diff_p.add_argument("scan2", help="Yeni tarama JSON")
    diff_p.add_argument("--format", choices=["terminal","json","markdown","html"],
                        default="terminal", help="Çıktı formatı")
    diff_p.add_argument("--output", "-o", help="Çıktı dosyası yolu")
    diff_p.add_argument("--no-rich",    action="store_true")
    diff_p.add_argument("--exit-code",  action="store_true",
                        help="Yeni Critical/High bulgu varsa exit 2")

    # --------------------------------------------------------
    # serve
    # --------------------------------------------------------
    serve_p = subparsers.add_parser("serve", help="Web dashboard başlat")
    serve_p.add_argument("--host",       default="127.0.0.1")
    serve_p.add_argument("--port", "-p", type=int, default=8080)
    serve_p.add_argument("--no-browser", action="store_true")

    # --------------------------------------------------------
    # queue  (tüm argümanları pass-through yapar)
    # --------------------------------------------------------
    queue_p = subparsers.add_parser("queue", help="Tarama kuyruğu")
    queue_p.add_argument("queue_args", nargs=argparse.REMAINDER)

    # --------------------------------------------------------
    # schedule
    # --------------------------------------------------------
    sched_p = subparsers.add_parser("schedule", help="Cron zamanlamaları")
    sched_p.add_argument("schedule_args", nargs=argparse.REMAINDER)

    # --------------------------------------------------------
    # completion
    # --------------------------------------------------------
    comp_p = subparsers.add_parser("completion", help="Shell autocomplete betiği")
    comp_p.add_argument("shell", nargs="?", choices=["bash","zsh","fish"], default="bash")
    comp_p.add_argument("--install", action="store_true")

    # --------------------------------------------------------
    # setup  — dış araçları indir/kur
    # --------------------------------------------------------
    setup_p = subparsers.add_parser(
        "setup",
        help="Tüm dış araçları kontrol et ve eksik olanları otomatik kur",
    )
    setup_p.add_argument(
        "--tool", "-t",
        metavar="ARAÇ",
        help="Sadece belirli bir aracı kur (nuclei/httpx/katana/…)",
    )

    # --------------------------------------------------------
    # api  (Adım 20 — REST API sunucusu)
    # --------------------------------------------------------
    api_p = subparsers.add_parser("api", help="REST API sunucusu başlat")
    api_p.add_argument("--host",       default="127.0.0.1",
                       help="Dinlenecek adres (varsayılan: 127.0.0.1)")
    api_p.add_argument("--port", "-p", type=int, default=8888,
                       help="Port numarası (varsayılan: 8888)")
    api_p.add_argument("--no-auth",    action="store_true",
                       help="API key doğrulamasını devre dışı bırak (geliştirme)")
    api_p.add_argument("--no-db",      action="store_true",
                       help="DB bağlantısını devre dışı bırak")

    # --------------------------------------------------------
    # db  (Adım 20 — DB yönetimi)
    # --------------------------------------------------------
    db_p = subparsers.add_parser("db", help="Veritabanı yönetimi")
    db_p.add_argument("action", choices=["init","stats","vacuum","list-scans"],
                      help="Yapılacak işlem")
    db_p.add_argument("--limit", type=int, default=20)

    return parser


# ---------------------------------------------------------------------------
# Adım 20 — REST API & DB komut handler'ları
# ---------------------------------------------------------------------------

def _cmd_api(ns: argparse.Namespace) -> int:
    """
    `websecure api` — REST API sunucusunu başlat ve bekle.

    Örnek
    -----
    websecure api --port 8888 --no-auth
    """
    try:
        from websecure.api.server import APIServer
        db = None
        if not getattr(ns, "no_db", False):
            try:
                from websecure.db import get_db
                db = get_db()
            except Exception as exc:
                logger.warning(f"[API] DB bağlantısı kurulamadı: {exc}  (no-db modda devam)")

        server = APIServer(
            host=ns.host,
            port=ns.port,
            no_auth=getattr(ns, "no_auth", False),
            db=db,
        )
        server.start(daemon=False)   # blocking=False olduğunda daemon=False ile join bekler
        print(f"[+] REST API: http://{ns.host}:{ns.port}/api/v1/")
        print("    Durdurmak için Ctrl+C")
        try:
            while server.is_running():
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n[*] API sunucusu durduruluyor...")
            server.stop()
        return 0
    except Exception as exc:
        logger.error(f"[API] Sunucu hatası: {exc!r}", exc_info=True)
        print(f"[!] REST API başlatılamadı: {exc}", file=sys.stderr)
        return 1


def _cmd_setup(ns: argparse.Namespace, cfg: dict) -> int:
    """
    `websecure setup` — Tüm dış araçları kontrol et ve eksik olanları kur.

    Kullanım
    --------
    websecure setup               # hepsini kontrol et / indir
    websecure setup --tool nuclei # sadece nuclei'yi kur
    """
    from websecure.core.startup import setup_all, _ensure_go_binary, _GO_TOOLS

    tool = getattr(ns, "tool", None)

    if tool:
        if tool not in _GO_TOOLS:
            valid = ", ".join(sorted(_GO_TOOLS.keys()))
            print(f"[!] Bilinmeyen araç: '{tool}'\n    Geçerliler: {valid}", file=sys.stderr)
            return 1
        ok = _ensure_go_binary(tool)
        print(f"[{'OK' if ok else 'FAIL'}] {tool}")
        return 0 if ok else 1

    results = setup_all(cfg)
    failed  = [k for k, v in results.items() if not v]
    return 0 if not failed else 1


def _cmd_db(ns: argparse.Namespace) -> int:
    """
    `websecure db` — Veritabanı yönetim komutları.

    Kullanım
    --------
    websecure db init
    websecure db stats
    websecure db vacuum
    websecure db list-scans [--limit N]
    """
    action = ns.action
    try:
        from websecure.db import get_db, ScanRepository
        db = get_db()

        if action == "init":
            print(f"[+] Veritabanı başlatıldı.")
            stats = db.stats()
            for table, cnt in stats.items():
                print(f"    {table}: {cnt} kayıt")

        elif action == "stats":
            stats = db.stats()
            print("Veritabanı İstatistikleri:")
            for table, cnt in stats.items():
                print(f"  {table:20s}: {cnt:>6} kayıt")

        elif action == "vacuum":
            db.vacuum()
            print("[+] VACUUM tamamlandı.")

        elif action == "list-scans":
            repo = ScanRepository(db)
            scans = repo.list_recent(limit=ns.limit)
            if not scans:
                print("Henüz hiç tarama kaydedilmemiş.")
            else:
                print(f"{'ID':<16}  {'Hedef':<40}  {'Profil':<12}  {'Durum':<12}  {'Skor'}")
                print("-" * 90)
                for s in scans:
                    score = f"{s.score:.1f}" if s.score is not None else "-"
                    print(f"{s.id:<16}  {s.target[:40]:<40}  {s.profile:<12}  {s.status:<12}  {score}")

        return 0
    except Exception as exc:
        logger.error(f"[DB] Komut hatası: {exc!r}", exc_info=True)
        print(f"[!] DB hatası: {exc}", file=sys.stderr)
        return 1


# ---------------------------------------------------------------------------
# Ana giriş noktası
# ---------------------------------------------------------------------------

def main(argv: Optional[List[str]] = None) -> int:
    """
    WebSecure CLI giriş noktası.

    Döndürür
    --------
    int — çıkış kodu (0=başarı, 1=hata, 2=bulgu var)
    """
    parser = build_parser()
    ns = parser.parse_args(argv)

    _setup_logging(verbose=getattr(ns, "verbose", False), quiet=getattr(ns, "quiet", False))
    cfg = _load_config(getattr(ns, "config", None))

    cmd = getattr(ns, "command", None)

    # Komut belirlenmemişse main.py'yi doğrudan çağır (geriye uyumluluk)
    if cmd is None:
        try:
            from websecure.main import main as _ws_main
            return _ws_main() or 0
        except SystemExit as exc:
            return exc.code if isinstance(exc.code, int) else 0
        except Exception as exc:
            logger.error(f"[CLI] Hata: {exc!r}", exc_info=True)
            return 1

    # Komut yönlendirme
    try:
        if cmd == "scan":
            return _cmd_scan(ns, cfg)

        elif cmd == "init":
            from websecure.cli.wizard import run_wizard_cli
            return run_wizard_cli(["--output", ns.output])

        elif cmd == "diff":
            from websecure.cli.diff import run_diff_cli
            diff_args = [ns.scan1, ns.scan2, "--format", ns.format]
            if ns.output:
                diff_args += ["--output", ns.output]
            if ns.no_rich:
                diff_args.append("--no-rich")
            if ns.exit_code:
                diff_args.append("--exit-code")
            return run_diff_cli(diff_args)

        elif cmd == "serve":
            from websecure.cli.web_ui import run_serve_cli
            serve_args = ["--host", ns.host, "--port", str(ns.port)]
            if ns.no_browser:
                serve_args.append("--no-browser")
            return run_serve_cli(serve_args)

        elif cmd == "queue":
            from websecure.cli.queue_manager import run_queue_cli
            return run_queue_cli(ns.queue_args)

        elif cmd == "schedule":
            from websecure.cli.scheduler import run_scheduler_cli
            return run_scheduler_cli(ns.schedule_args)

        elif cmd == "completion":
            from websecure.cli.autocomplete import run_completion_cli
            comp_args = [ns.shell]
            if ns.install:
                comp_args.append("--install")
            return run_completion_cli(comp_args)

        elif cmd == "setup":
            return _cmd_setup(ns, cfg)

        elif cmd == "api":
            return _cmd_api(ns)

        elif cmd == "db":
            return _cmd_db(ns)

        else:
            parser.print_help()
            return 0

    except KeyboardInterrupt:
        print("\n[*] İptal edildi.")
        return 130
    except Exception as exc:
        logger.error(f"[CLI] Beklenmedik hata: {exc!r}", exc_info=True)
        print(f"[!] Hata: {exc}", file=sys.stderr)
        return 1


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def cli_entry() -> None:
    """setup.py / pyproject.toml entry_points için."""
    sys.exit(main())


if __name__ == "__main__":
    sys.exit(main())
