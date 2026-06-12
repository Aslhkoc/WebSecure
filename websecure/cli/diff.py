"""
websecure.cli.diff
~~~~~~~~~~~~~~~~~~~
İki tarama sonucu JSON dosyasını karşılaştırır.

Çıktı
-----
- Yeni bulgular  (new)       — önceki taramada yoktu
- Düzelen bulgular (fixed)   — önceki taramada vardı, şimdi yok
- Gerileme (regressed)       — önceki taramada düşük önem, şimdi yüksek
- Değişmeyen (unchanged)     — her iki taramada da aynı

Eşleştirme Algoritması
----------------------
SHA256(title + url + severity) -> fingerprint bazlı dedup.
Gerileme: aynı title+url, severity yükselmiş.

Çıktı Formatları
----------------
- Terminal (plain / Rich tablo)
- JSON  — machine-readable diff
- Markdown — rapor içine gömülecek diff bölümü
- HTML — standalone diff sayfası

SOLID
-----
- SRP  : Diff hesaplama / çıktı üretimi ayrı sınıflar.
- OCP  : Yeni çıktı formatı eklemek mevcut kodu değiştirmez.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Tuple

from websecure.reporters import severity_rank


# ---------------------------------------------------------------------------
# Yardımcılar
# ---------------------------------------------------------------------------

# Severity rank tek kaynak: reporters.severity_rank (T11). Eski yerel _SEVERITY_ORDER
# {Critical:4..Info:0} kopyası kaldırıldı. _SEVERITY_EMOJI format-özel (terminal etiketi), kalır.
_SEVERITY_EMOJI: Dict[str, str] = {
    "Critical": "[Critical]",
    "High":     "[High]",
    "Medium":   "[Medium]",
    "Low":      "[Low]",
    "Info":     "[Info]",
}


def _fingerprint(finding: Dict[str, Any]) -> str:
    """Bulgu fingerprint — title + url + (tool|type)."""
    key = "|".join([
        (finding.get("title") or finding.get("type") or "unknown").lower(),
        (finding.get("url") or finding.get("endpoint") or "").lower(),
    ])
    return hashlib.sha256(key.encode()).hexdigest()[:16]



def _load_scan(path: Path) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    """
    Tarama JSON dosyasını yükle.

    Döndürür
    --------
    (meta, findings_list)
    """
    raw = json.loads(path.read_text(encoding="utf-8"))

    # Farklı report formatlarını normalize et
    if isinstance(raw, list):
        return {}, raw

    meta: Dict[str, Any] = {k: v for k, v in raw.items() if k != "findings"}
    findings = raw.get("findings") or raw.get("results") or raw.get("vulnerabilities") or []

    if isinstance(findings, dict):
        # {category: [findings]} formatı
        flat: List[Dict[str, Any]] = []
        for cat, items in findings.items():
            if isinstance(items, list):
                for item in items:
                    item.setdefault("category", cat)
                    flat.append(item)
        findings = flat

    return meta, findings


# ---------------------------------------------------------------------------
# DiffResult
# ---------------------------------------------------------------------------

@dataclass
class DiffResult:
    """İki tarama arasındaki fark özeti."""
    scan1_path: str
    scan2_path: str
    scan1_meta: Dict[str, Any] = field(default_factory=dict)
    scan2_meta: Dict[str, Any] = field(default_factory=dict)

    # Bulgular
    new_findings:       List[Dict[str, Any]] = field(default_factory=list)
    fixed_findings:     List[Dict[str, Any]] = field(default_factory=list)
    regressed_findings: List[Dict[str, Any]] = field(default_factory=list)
    unchanged_findings: List[Dict[str, Any]] = field(default_factory=list)

    @property
    def risk_delta(self) -> int:
        """Risk delta: yeni - düzelen (pozitif = kötüleşme, negatif = iyileşme)."""
        new_score  = sum(severity_rank(f.get("severity")) for f in self.new_findings)
        fix_score  = sum(severity_rank(f.get("severity")) for f in self.fixed_findings)
        return new_score - fix_score

    @property
    def summary(self) -> Dict[str, int]:
        return {
            "new":       len(self.new_findings),
            "fixed":     len(self.fixed_findings),
            "regressed": len(self.regressed_findings),
            "unchanged": len(self.unchanged_findings),
        }

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scan1": self.scan1_path,
            "scan2": self.scan2_path,
            "summary": self.summary,
            "risk_delta": self.risk_delta,
            "new_findings":       self.new_findings,
            "fixed_findings":     self.fixed_findings,
            "regressed_findings": self.regressed_findings,
            "unchanged_findings": self.unchanged_findings,
        }


# ---------------------------------------------------------------------------
# ScanDiff — ana karşılaştırma motoru
# ---------------------------------------------------------------------------

class ScanDiff:
    """
    İki tarama JSON dosyasını karşılaştıran diff motoru.

    Kullanım
    --------
    ```python
    diff = ScanDiff.compare("scan_old.json", "scan_new.json")
    print(diff.summary)
    DiffRenderer.print_terminal(diff)
    DiffRenderer.save_json(diff, "diff.json")
    ```
    """

    @classmethod
    def compare(
        cls,
        path1: str | Path,
        path2: str | Path,
    ) -> DiffResult:
        """
        İki tarama dosyasını karşılaştır.

        Parametreler
        ------------
        path1 : Eski (baseline) tarama JSON
        path2 : Yeni tarama JSON

        Döndürür
        --------
        DiffResult
        """
        p1 = Path(path1)
        p2 = Path(path2)

        if not p1.exists():
            raise FileNotFoundError(f"Tarama dosyası bulunamadı: {p1}")
        if not p2.exists():
            raise FileNotFoundError(f"Tarama dosyası bulunamadı: {p2}")

        meta1, findings1 = _load_scan(p1)
        meta2, findings2 = _load_scan(p2)

        return cls._diff(
            str(p1), str(p2),
            meta1, meta2,
            findings1, findings2,
        )

    @staticmethod
    def _diff(
        path1: str, path2: str,
        meta1: Dict[str, Any], meta2: Dict[str, Any],
        findings1: List[Dict[str, Any]],
        findings2: List[Dict[str, Any]],
    ) -> DiffResult:
        # Fingerprint -> bulgu haritaları
        map1: Dict[str, Dict[str, Any]] = {_fingerprint(f): f for f in findings1}
        map2: Dict[str, Dict[str, Any]] = {_fingerprint(f): f for f in findings2}

        # title+url bazlı haritalar (severity değişimi tespiti)
        sev_map1: Dict[str, str] = {}
        for f in findings1:
            base_fp = _fingerprint(f)
            sev_map1[base_fp] = f.get("severity", "Info")

        result = DiffResult(
            scan1_path=path1, scan2_path=path2,
            scan1_meta=meta1, scan2_meta=meta2,
        )

        fp1_set = set(map1.keys())
        fp2_set = set(map2.keys())

        # Yeni bulgular — sadece scan2'de var
        for fp in fp2_set - fp1_set:
            result.new_findings.append(map2[fp])

        # Düzelen bulgular — sadece scan1'de var
        for fp in fp1_set - fp2_set:
            result.fixed_findings.append(map1[fp])

        # Değişmeyen + gerileme tespiti
        for fp in fp1_set & fp2_set:
            f2 = map2[fp]
            old_sev = sev_map1.get(fp, "Info")
            new_sev = f2.get("severity", "Info")

            old_val = severity_rank(old_sev)
            new_val = severity_rank(new_sev)

            if new_val > old_val:
                # Severity yükseldi — gerileme
                regressed = dict(f2)
                regressed["_old_severity"] = old_sev
                result.regressed_findings.append(regressed)
            else:
                result.unchanged_findings.append(f2)

        return result


# ---------------------------------------------------------------------------
# DiffRenderer — çıktı üretimi
# ---------------------------------------------------------------------------

class DiffRenderer:
    """Diff sonuçlarını farklı formatlarda çıktılar."""

    # ------------------------------------------------------------------
    # Terminal
    # ------------------------------------------------------------------

    @staticmethod
    def print_terminal(diff: DiffResult, use_rich: bool = True) -> None:
        """Terminal çıktısı — Rich mevcutsa renkli tablo."""
        if use_rich and importlib.util.find_spec("rich") is not None:
            DiffRenderer._print_rich(diff)
            return
        DiffRenderer._print_plain(diff)

    @staticmethod
    def _print_plain(diff: DiffResult) -> None:
        sep = "-" * 60
        print(f"\n{sep}")
        print(f"  WebSecure Diff: {diff.scan1_path}  ->  {diff.scan2_path}")
        print(sep)
        s = diff.summary
        delta = diff.risk_delta
        delta_str = f"+{delta}" if delta > 0 else str(delta)
        print(f"  Yeni: {s['new']}  |  Düzelen: {s['fixed']}  |  "
              f"Gerileme: {s['regressed']}  |  Risk delta: {delta_str}")
        print(sep)

        if diff.new_findings:
            print("\n[+] Yeni Bulgular:")
            for f in sorted(diff.new_findings,
                            key=lambda x: severity_rank(x.get("severity")),
                            reverse=True):
                sev = f.get("severity", "Info")
                print(f"  {_SEVERITY_EMOJI.get(sev,'')} [{sev}] {f.get('title','?')}  "
                      f"— {f.get('url','')}")

        if diff.fixed_findings:
            print("\n[OK] Düzelen Bulgular:")
            for f in diff.fixed_findings:
                sev = f.get("severity", "Info")
                print(f"  [{sev}] {f.get('title','?')}  — {f.get('url','')}")

        if diff.regressed_findings:
            print("\n[!]  Kötüleşen Bulgular:")
            for f in diff.regressed_findings:
                old = f.get("_old_severity", "?")
                new = f.get("severity", "?")
                print(f"  {old} -> {new}  {f.get('title','?')}  — {f.get('url','')}")

        print()

    @staticmethod
    def _print_rich(diff: DiffResult) -> None:
        from rich.console import Console
        from rich.table import Table
        from rich.panel import Panel

        console = Console()
        s = diff.summary
        delta = diff.risk_delta
        delta_color = "red" if delta > 0 else "green"
        delta_str = f"+{delta}" if delta > 0 else str(delta)

        console.print(Panel(
            f"[bold]Scan 1:[/bold] {diff.scan1_path}\n"
            f"[bold]Scan 2:[/bold] {diff.scan2_path}\n\n"
            f"[red]Yeni: {s['new']}[/red]  |  "
            f"[green]Düzelen: {s['fixed']}[/green]  |  "
            f"[yellow]Gerileme: {s['regressed']}[/yellow]  |  "
            f"Risk delta: [{delta_color}]{delta_str}[/{delta_color}]",
            title="WebSecure Diff",
            style="bold cyan",
        ))

        def _table(title: str, findings: list, color: str) -> None:
            if not findings:
                return
            t = Table(title=title, show_header=True, header_style=f"bold {color}")
            t.add_column("Önem", width=10)
            t.add_column("Başlık")
            t.add_column("URL")
            for f in sorted(findings,
                            key=lambda x: severity_rank(x.get("severity")),
                            reverse=True):
                sev = f.get("severity", "Info")
                t.add_row(
                    f"[{color}]{_SEVERITY_EMOJI.get(sev,'')} {sev}[/{color}]",
                    f.get("title", "?"),
                    f.get("url", ""),
                )
            console.print(t)

        _table("[+] Yeni Bulgular",      diff.new_findings,       "red")
        _table("[OK] Düzelen Bulgular",   diff.fixed_findings,     "green")
        _table("[!]  Kötüleşen Bulgular", diff.regressed_findings, "yellow")

    # ------------------------------------------------------------------
    # JSON
    # ------------------------------------------------------------------

    @staticmethod
    def to_json(diff: DiffResult, indent: int = 2) -> str:
        return json.dumps(diff.to_dict(), ensure_ascii=False, indent=indent)

    @staticmethod
    def save_json(diff: DiffResult, path: str | Path) -> Path:
        p = Path(path)
        p.write_text(DiffRenderer.to_json(diff), encoding="utf-8")
        return p

    # ------------------------------------------------------------------
    # Markdown
    # ------------------------------------------------------------------

    @staticmethod
    def to_markdown(diff: DiffResult) -> str:
        s = diff.summary
        delta = diff.risk_delta
        delta_str = f"+{delta}" if delta > 0 else str(delta)
        ts = datetime.now().strftime("%Y-%m-%d %H:%M")

        lines = [
            "# WebSecure Diff Raporu\n",
            f"**Tarih:** {ts}\n",
            f"**Eski Tarama:** `{diff.scan1_path}`  ",
            f"**Yeni Tarama:** `{diff.scan2_path}`\n",
            "| Kategori | Sayı |",
            "|---|---|",
            f"| [+] Yeni Bulgular | {s['new']} |",
            f"| [OK] Düzelen Bulgular | {s['fixed']} |",
            f"| [!] Kötüleşen | {s['regressed']} |",
            f"| Değişmeyen | {s['unchanged']} |",
            f"| **Risk Delta** | **{delta_str}** |\n",
        ]

        def _section(title: str, findings: list) -> None:
            if not findings:
                return
            lines.append(f"\n## {title}\n")
            lines.append("| Önem | Başlık | URL |")
            lines.append("|---|---|---|")
            for f in sorted(findings,
                            key=lambda x: severity_rank(x.get("severity")),
                            reverse=True):
                sev = f.get("severity", "Info")
                title_f = f.get("title", "?").replace("|", "\\|")
                url = f.get("url", "")
                lines.append(f"| {_SEVERITY_EMOJI.get(sev,'')} {sev} | {title_f} | {url} |")

        _section("[+] Yeni Bulgular",     diff.new_findings)
        _section("[OK] Düzelen Bulgular",  diff.fixed_findings)
        _section("[!] Kötüleşen",        diff.regressed_findings)

        return "\n".join(lines)

    @staticmethod
    def save_markdown(diff: DiffResult, path: str | Path) -> Path:
        p = Path(path)
        p.write_text(DiffRenderer.to_markdown(diff), encoding="utf-8")
        return p

    # ------------------------------------------------------------------
    # HTML
    # ------------------------------------------------------------------

    @staticmethod
    def to_html(diff: DiffResult) -> str:
        s = diff.summary
        delta = diff.risk_delta
        delta_color = "#dc3545" if delta > 0 else "#28a745"
        ts = datetime.now().strftime("%Y-%m-%d %H:%M")

        def _rows(findings: list, badge_class: str) -> str:
            rows = []
            for f in sorted(findings,
                            key=lambda x: severity_rank(x.get("severity")),
                            reverse=True):
                sev = f.get("severity", "Info")
                sev_colors = {
                    "Critical": "#dc3545", "High": "#fd7e14",
                    "Medium": "#ffc107", "Low": "#17a2b8", "Info": "#28a745"
                }
                c = sev_colors.get(sev, "#6c757d")
                old_sev_html = ""
                if "_old_severity" in f:
                    old_sev_html = (
                        f' <small style="color:#6c757d">'
                        f'({f["_old_severity"]} -> {sev})</small>'
                    )
                rows.append(
                    f'<tr><td><span class="badge" style="background:{c}">'
                    f'{sev}</span>{old_sev_html}</td>'
                    f'<td>{f.get("title","?")}</td>'
                    f'<td><small>{f.get("url","")}</small></td></tr>'
                )
            return "\n".join(rows)

        return f"""<!DOCTYPE html>
<html lang="tr">
<head>
<meta charset="UTF-8">
<title>WebSecure Diff — {ts}</title>
<style>
body{{font-family:Arial,sans-serif;margin:2rem;background:#f8f9fa;color:#212529}}
h1{{color:#0d6efd}}h2{{color:#495057;border-bottom:2px solid #dee2e6;padding-bottom:.5rem}}
table{{width:100%;border-collapse:collapse;background:#fff;box-shadow:0 1px 3px rgba(0,0,0,.1)}}
th{{background:#343a40;color:#fff;padding:.75rem;text-align:left}}
td{{padding:.6rem;border-bottom:1px solid #dee2e6}}
.badge{{color:#fff;padding:.25rem .5rem;border-radius:.25rem;font-size:.85rem}}
.stat{{display:inline-block;margin:.5rem;padding:.75rem 1.5rem;border-radius:.5rem;
       background:#fff;box-shadow:0 1px 3px rgba(0,0,0,.1);text-align:center}}
.stat span{{display:block;font-size:1.5rem;font-weight:bold}}
</style>
</head>
<body>
<h1>WebSecure Diff Raporu</h1>
<p><b>Tarih:</b> {ts}<br>
<b>Eski:</b> <code>{diff.scan1_path}</code><br>
<b>Yeni:</b> <code>{diff.scan2_path}</code></p>

<div>
  <div class="stat"><span style="color:#dc3545">{s['new']}</span>Yeni</div>
  <div class="stat"><span style="color:#28a745">{s['fixed']}</span>Düzelen</div>
  <div class="stat"><span style="color:#ffc107">{s['regressed']}</span>Kötüleşen</div>
  <div class="stat"><span style="color:{delta_color}">{'+' if delta>0 else ''}{delta}</span>Risk Delta</div>
</div>

{f'''<h2>[+] Yeni Bulgular ({s['new']})</h2>
<table><tr><th>Önem</th><th>Başlık</th><th>URL</th></tr>
{_rows(diff.new_findings, "danger")}</table>''' if diff.new_findings else ''}

{f'''<h2>[OK] Düzelen Bulgular ({s['fixed']})</h2>
<table><tr><th>Önem</th><th>Başlık</th><th>URL</th></tr>
{_rows(diff.fixed_findings, "success")}</table>''' if diff.fixed_findings else ''}

{f'''<h2>[!] Kötüleşen Bulgular ({s['regressed']})</h2>
<table><tr><th>Önem</th><th>Başlık</th><th>URL</th></tr>
{_rows(diff.regressed_findings, "warning")}</table>''' if diff.regressed_findings else ''}

</body></html>"""

    @staticmethod
    def save_html(diff: DiffResult, path: str | Path) -> Path:
        p = Path(path)
        p.write_text(DiffRenderer.to_html(diff), encoding="utf-8")
        return p


# ---------------------------------------------------------------------------
# CLI kısayol
# ---------------------------------------------------------------------------

def run_diff_cli(args: list) -> int:
    """
    CLI'dan çağrılan diff komutu.

    Parametreler
    ------------
    args : [scan1.json, scan2.json, --format json|md|html, --output path]

    Döndürür
    --------
    int — çıkış kodu (0=ok, 1=hata, 2=yeni bulgu var)
    """
    import argparse

    parser = argparse.ArgumentParser(
        prog="websecure diff",
        description="İki tarama sonucunu karşılaştır",
    )
    parser.add_argument("scan1", help="Eski/baseline tarama JSON dosyası")
    parser.add_argument("scan2", help="Yeni tarama JSON dosyası")
    parser.add_argument(
        "--format", choices=["terminal", "json", "markdown", "html"],
        default="terminal", help="Çıktı formatı",
    )
    parser.add_argument("--output", "-o", help="Çıktı dosyası yolu")
    parser.add_argument("--no-rich", action="store_true", help="Rich olmadan plain text")
    parser.add_argument(
        "--exit-code", action="store_true",
        help="Yeni kritik/high bulgu varsa çıkış kodu 2 döndür",
    )
    ns = parser.parse_args(args)

    try:
        diff = ScanDiff.compare(ns.scan1, ns.scan2)
    except FileNotFoundError as exc:
        print(f"[!] Hata: {exc}", file=sys.stderr)
        return 1

    fmt = ns.format
    if fmt == "terminal":
        DiffRenderer.print_terminal(diff, use_rich=not ns.no_rich)
    elif fmt == "json":
        out = DiffRenderer.to_json(diff)
        if ns.output:
            Path(ns.output).write_text(out, encoding="utf-8")
            print(f"[[OK]] JSON diff kaydedildi: {ns.output}")
        else:
            print(out)
    elif fmt == "markdown":
        out = DiffRenderer.to_markdown(diff)
        if ns.output:
            DiffRenderer.save_markdown(diff, ns.output)
            print(f"[[OK]] Markdown diff kaydedildi: {ns.output}")
        else:
            print(out)
    elif fmt == "html":
        if ns.output:
            DiffRenderer.save_html(diff, ns.output)
            print(f"[[OK]] HTML diff kaydedildi: {ns.output}")
        else:
            print(DiffRenderer.to_html(diff))

    # Çıkış kodu 2 — yeni kritik/high bulgu varsa
    if ns.exit_code:
        critical_new = [
            f for f in diff.new_findings
            if severity_rank(f.get("severity")) >= 3
        ]
        if critical_new:
            return 2

    return 0


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

__all__ = [
    "DiffResult",
    "DiffRenderer",
    "ScanDiff",
    "run_diff_cli",
]
