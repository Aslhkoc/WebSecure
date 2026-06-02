"""
WebSecure Full Codebase Audit
Kategoriler:
  A. Hata yutan kod   (bare except/pass, debug-only exception handling)
  B. Kopuk veri akışı (add_result bucket'ları vs reporter'in okuduğu key'ler)
  C. Yanlış config    (kodun kullandigi config path vs config.json'daki gercek path)
  D. Eksik dosyalar   (kodda referans edilen wordlist/dosya yolları var mi diskte)
  E. Phantom kod      (tanimli ama hic cagirilmayan runner/fonksiyon)
"""

import ast, os, re, json, sys
from pathlib import Path
from collections import defaultdict

ROOT = Path(__file__).resolve().parent
SRC  = ROOT / "websecure"
CFG  = ROOT / "config.json"

# ── helpers ──────────────────────────────────────────────────────────────────

def py_files():
    for p in SRC.rglob("*.py"):
        yield p

def read(p):
    try:
        return p.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return ""

def load_config():
    try:
        return json.loads(CFG.read_text(encoding="utf-8"))
    except Exception:
        return {}

def flatten_keys(d, prefix=""):
    """config.json'daki tüm dot-notation key'leri çıkar"""
    keys = set()
    if isinstance(d, dict):
        for k, v in d.items():
            full = f"{prefix}.{k}" if prefix else k
            keys.add(full)
            keys |= flatten_keys(v, full)
    elif isinstance(d, list):
        for i, v in enumerate(d):
            keys |= flatten_keys(v, f"{prefix}[{i}]")
    return keys

# ─────────────────────────────────────────────────────────────────────────────
# KATEGORİ A — Hata yutan kod
# ─────────────────────────────────────────────────────────────────────────────

def audit_A():
    print("\n" + "="*70)
    print("KATEGORİ A — HATA YUTAN KOD (silent failures)")
    print("="*70)
    findings = []

    for p in py_files():
        src = read(p)
        lines = src.splitlines()
        rel = p.relative_to(ROOT)

        # Pattern 1: except + pass (next non-empty line is pass)
        # Kabul edilebilir: ImportError, BrokenPipe, ConnectionReset, OSError (CLI/network)
        ACCEPTABLE_PASS = {
            "except ImportError:", "except ImportError as e:", "except ImportError as exc:",
            "except (BrokenPipeError, ConnectionResetError):",
            "except (BrokenPipeError, ConnectionResetError) as e:",
            "except OSError:", "except OSError as e:", "except OSError as exc:",
            "except KeyboardInterrupt:", "except SystemExit:",
            "except (KeyboardInterrupt, SystemExit):",
            "except winsound.error:", "except AttributeError:",
            # SSL handshake check: failure = "protocol not supported" (expected)
            "except (ssl.SSLError, socket.error):",
            "except (ssl.SSLError, socket.error) as e:",
            # ValueError in SSL cert fetch: fallback handled below
            "except ValueError:", "except ValueError as e:", "except ValueError as exc:",
            # NameError: intentional forward-reference guard
            "except NameError:", "except NameError as e:",
            # TypeError/ValueError in JSON/parsing
            "except (TypeError, ValueError):", "except (TypeError, ValueError) as e:",
        }
        # Cleanup context patterns — try block içinde temizlik yapılıyorsa pass OK
        CLEANUP_PATTERNS = [
            r"os\.remove\b", r"os\.unlink\b", r"os\.close\b", r"os\.rmdir\b",
            r"shutil\.rmtree\b", r"shutil\.move\b",
            r"\.close\(\)", r"\.shutdown\(", r"\.terminate\(\)", r"\.kill\(\)",
            r"\.communicate\(", r"proc\.wait\(", r"\.send\(", r"sock\.",
        ]
        def is_cleanup_block(lines, except_idx):
            """try bloğunun içeriğine bakarak cleanup mi kontrol et (try: ile except: arası)."""
            # try: satırını geriye doğru ara
            for k in range(except_idx - 1, max(0, except_idx - 12), -1):
                if lines[k].strip() == "try:":
                    block = " ".join(lines[k+1:except_idx])
                    return any(re.search(p, block) for p in CLEANUP_PATTERNS)
            # Bulamazsa 4 satır öncesine bak
            ctx = " ".join(lines[max(0, except_idx-4):except_idx])
            return any(re.search(p, ctx) for p in CLEANUP_PATTERNS)

        for i, line in enumerate(lines):
            stripped = line.strip()
            if re.match(r'^except[\s:(]', stripped) or stripped == 'except:':
                # Kabul edilebilir pattern'leri atla
                if stripped in ACCEPTABLE_PASS:
                    continue
                # Cleanup bağlamı → pass OK
                if is_cleanup_block(lines, i):
                    continue
                # Look ahead for pass/... or only a comment
                body_lines = []
                j = i + 1
                while j < len(lines) and j < i + 6:
                    bl = lines[j].strip()
                    if bl and not bl.startswith('#'):
                        body_lines.append(bl)
                        break
                    j += 1
                if body_lines:
                    body = body_lines[0]
                    severity = None
                    if body in ('pass', '...'):
                        severity = "CRITICAL"
                    elif body.startswith('_logger.debug') or body.startswith('logging.debug'):
                        severity = "HIGH"  # debug-only = still effectively silenced in prod
                    elif re.match(r'^(logger|_logger|log)\.(debug)', body):
                        severity = "HIGH"
                    if severity:
                        findings.append((severity, str(rel), i+1, stripped, body))

    # Sort: CRITICAL first
    findings.sort(key=lambda x: (0 if x[0]=="CRITICAL" else 1, x[1], x[2]))
    crit = [f for f in findings if f[0]=="CRITICAL"]
    high = [f for f in findings if f[0]=="HIGH"]
    print(f"\n  CRITICAL (pass/...): {len(crit)}")
    for sev, fp, ln, exc, body in crit[:40]:
        print(f"    [{ln:5d}] {fp}  |  {exc}  =>  {body}")
    if len(crit) > 40:
        print(f"    ... ve {len(crit)-40} tane daha")

    print(f"\n  HIGH (debug-only log): {len(high)}")
    for sev, fp, ln, exc, body in high[:25]:
        print(f"    [{ln:5d}] {fp}  |  {exc}  =>  {body}")
    if len(high) > 25:
        print(f"    ... ve {len(high)-25} tane daha")

    return findings

# ─────────────────────────────────────────────────────────────────────────────
# KATEGORİ B — Kopuk veri akışı (bucket mismatch)
# ─────────────────────────────────────────────────────────────────────────────

def audit_B():
    print("\n" + "="*70)
    print("KATEGORİ B — KOPUK VERİ AKIŞI (add_result bucket'lari)")
    print("="*70)

    # 1. Tüm add_result("X", ...) çağrılarını topla
    written = defaultdict(list)  # bucket -> [(file, line)]
    for p in py_files():
        src = read(p)
        rel = str(p.relative_to(ROOT))
        for m in re.finditer(r'add_result\(\s*["\']([^"\']+)["\']', src):
            bucket = m.group(1)
            line = src[:m.start()].count('\n') + 1
            written[bucket].append((rel, line))

    # 2. Reporter'in okuduğu key'leri bul (reporting.py + main.py içinde)
    reporter_reads = set()
    for p in list(SRC.rglob("reporting*.py")) + [ROOT/"websecure"/"main.py"]:
        if not p.exists():
            continue
        src = read(p)
        # g_res.get("X") veya results["X"] veya results.get("X")
        for m in re.finditer(r'(?:g_res|results|global_results|_results)\s*(?:\.get\(\s*|\.pop\(\s*|\[)["\']([a-z_A-Z0-9]+)["\']', src):
            reporter_reads.add(m.group(1))
        # Ayrıca "final" gibi known reporter keys
        for m in re.finditer(r'bucket(?:_key)?\s*(?:==|in)\s*["\']([a-z_A-Z0-9]+)["\']', src):
            reporter_reads.add(m.group(1))

    # Known reporter keys (from report template analysis)
    KNOWN_REPORTER_KEYS = {
        "nmap", "tls", "tls_summary", "headers", "vulnerability", "sqli",
        "xss", "ssrf", "idor", "ssti", "cmdi", "lfi", "cors", "csrf", "jwt",
        "nosqli", "xxe", "race_condition", "prototype_pollution", "crlf_injection",
        "subdomain_takeover", "dom_xss", "waf", "subdomain", "nuclei",
        "ffuf", "feroxbuster", "katana", "technologies", "endpoints", "js",
        "session", "cookies", "oast", "meta", "errors", "final",
        "correlation", "exploitation", "auth_matrix", "security_headers",
        "httpx", "passive", "discovery", "crawl",
        # _VERIFY_BUCKETS — verify_and_score tarafindan okunuyor
        "offensive", "sqlmap", "auth_matrix", "nosqli",
        # OAST — verify_and_score tarafindan okunuyor
        "oast_callbacks",
        # Internal tracking — intentional, raporda gozukmesi gerekmiyor
        "phase", "phase_error", "phase_event", "phase_metrics", "profile_event",
        "egress_degraded",
    }
    reporter_reads |= KNOWN_REPORTER_KEYS

    all_written = set(written.keys())
    orphaned = all_written - reporter_reads

    print(f"\n  Yazilan bucket sayisi:  {len(all_written)}")
    print(f"  Reporter'in okudugu:    {len(reporter_reads)}")
    print(f"  ORPHAN (hicbir yere bagli olmayan): {len(orphaned)}")

    if orphaned:
        print("\n  ORPHAN BUCKET'LAR:")
        for b in sorted(orphaned):
            locs = written[b][:3]
            loc_str = ", ".join(f"{f}:{l}" for f,l in locs)
            extra = f" (+{len(written[b])-3} more)" if len(written[b]) > 3 else ""
            print(f"    '{b}'  ->  {loc_str}{extra}")

    return written, reporter_reads, orphaned

# ─────────────────────────────────────────────────────────────────────────────
# KATEGORİ C — Yanlış config path'leri
# ─────────────────────────────────────────────────────────────────────────────

def audit_C():
    print("\n" + "="*70)
    print("KATEGORİ C — YANLIS CONFIG PATH'LERI")
    print("="*70)

    cfg = load_config()
    real_keys = flatten_keys(cfg)
    # Tüm top-level + 2-level keys
    top_level = {k.split('.')[0] for k in real_keys}

    # Tüm _get_config / _get(cfg, "path") / cfg.get("path") çağrılarını bul
    used_paths = defaultdict(list)  # path -> [(file, line)]
    # SADECE gercek config path accessor'lari: _get_config, get_config
    # cfg.get/off.get/config.get CIKARILDI — bunlar sub-dict erisimi yapar,
    # config.json root key kontrolu icin yanlis sonuc verir
    patterns = [
        r'_get_config\s*\(\s*\w+\s*,\s*["\']([^"\']+[\.][^"\']+)["\']',  # dotted path only
        r'\bget_config\s*\(\s*\w+\s*,\s*["\']([^"\']+[\.][^"\']+)["\']',  # dotted path only
    ]

    for p in py_files():
        src = read(p)
        rel = str(p.relative_to(ROOT))
        for pat in patterns:
            for m in re.finditer(pat, src):
                path = m.group(1)
                line = src[:m.start()].count('\n') + 1
                used_paths[path].append((rel, line))

    # Kontrol: path'in config.json'da var olup olmadığı
    missing = {}
    partial = {}
    for path, locs in used_paths.items():
        if path in real_keys:
            continue  # tam eşleşme, OK
        # partial match: en az ilk segment var mı?
        first = path.split('.')[0]
        if first not in top_level:
            missing[path] = locs
        else:
            # ilk segment var ama full path yok
            if path not in real_keys:
                partial[path] = locs

    print(f"\n  Kodda kullanilan config path sayisi: {len(used_paths)}")
    print(f"  Hic bulunmayan (top-level bile yok): {len(missing)}")
    print(f"  Kismen esleyen (root var ama full path yok): {len(partial)}")

    if missing:
        print("\n  TAMAMEN YANLIS (config'de hic yok):")
        for path, locs in sorted(missing.items()):
            loc_str = ", ".join(f"{f}:{l}" for f,l in locs[:2])
            print(f"    '{path}'  ->  {loc_str}")

    if partial:
        print("\n  KISMEN YANLIS (root var ama path yok):")
        for path, locs in sorted(partial.items()):
            loc_str = ", ".join(f"{f}:{l}" for f,l in locs[:2])
            print(f"    '{path}'  ->  {loc_str}")

    return missing, partial

# ─────────────────────────────────────────────────────────────────────────────
# KATEGORİ D — Eksik dosyalar (wordlist/config referanslari)
# ─────────────────────────────────────────────────────────────────────────────

def audit_D():
    print("\n" + "="*70)
    print("KATEGORİ D — EKSIK DOSYA/WORDLIST REFERANSLARI")
    print("="*70)

    # Kodda string literal olarak gecen .txt/.json/.yaml/.wordlist yollarını bul
    # Filtre: sadece kisa yol-gibi stringler (80 karakter alti, bosluk yok, / veya . iceriyor)
    file_refs = defaultdict(list)  # path -> [(src_file, line)]
    path_patterns = [
        r'["\']([^"\']{5,80}(?:wordlist|\.txt|\.yaml|\.lst|\.conf)[^"\' ]{0,40})["\']',
    ]
    for p in py_files():
        src = read(p)
        rel = str(p.relative_to(ROOT))
        for pat in path_patterns:
            for m in re.finditer(pat, src, re.IGNORECASE):
                ref = m.group(1)
                # Sadece proje icindeki yollar (websecure/ ile baslayan veya ./ ile)
                if any(ref.startswith(prefix) for prefix in ('./websecure', 'websecure/', './wordlists', 'wordlists/')):
                    line = src[:m.start()].count('\n') + 1
                    file_refs[ref].append((rel, line))

    # config.json'daki dosya yollarini da ekle
    cfg = load_config()
    def find_file_paths(d, source="config.json"):
        refs = {}
        if isinstance(d, dict):
            for k, v in d.items():
                if isinstance(v, str) and ('/' in v or '\\' in v) and any(ext in v for ext in ['.txt','.json','.yaml','.lst']):
                    refs[v] = [(source, 0)]
                refs.update(find_file_paths(v, source))
        elif isinstance(d, list):
            for item in d:
                refs.update(find_file_paths(item, source))
        return refs
    cfg_file_refs = find_file_paths(cfg)
    for k, v in cfg_file_refs.items():
        file_refs[k].extend(v)

    missing_files = {}
    for ref, locs in file_refs.items():
        # Normalize path
        norm = ref.replace('./', '').replace('\\', '/')
        # Try relative to ROOT
        candidate = ROOT / norm
        if not candidate.exists():
            # Try relative to SRC parent
            candidate2 = ROOT / norm.lstrip('/')
            if not candidate2.exists():
                missing_files[ref] = locs

    print(f"\n  Referans edilen dosya sayisi: {len(file_refs)}")
    print(f"  EKSIK (diskte yok): {len(missing_files)}")
    for ref, locs in sorted(missing_files.items()):
        loc_str = ", ".join(f"{f}:{l}" for f,l in locs[:2])
        print(f"    '{ref}'  ->  {loc_str}")

    return missing_files

# ─────────────────────────────────────────────────────────────────────────────
# KATEGORİ E — Phantom kod (tanimli ama bagli olmayan)
# ─────────────────────────────────────────────────────────────────────────────

def audit_E():
    print("\n" + "="*70)
    print("KATEGORİ E — PHANTOM KOD (tanimli ama hic cagirilmayan)")
    print("="*70)

    phases_file = SRC / "core" / "phases" / "__init__.py"
    phases_src = read(phases_file)

    # E1: _runner_X fonksiyonlari tanımlanmış ama _offensive_phases'e eklenmemiş
    defined_runners = set(re.findall(r'^def (_runner_\w+)\s*\(', phases_src, re.MULTILINE))
    # _offensive_phases içinde hangi runner'lar çağrılıyor?
    # _safe(c, lambda: _runner_X(c), ...) veya runner=lambda c: _safe(c, lambda: _runner_X(c),
    called_in_phases = set(re.findall(r'_safe\s*\(\s*\w\s*,\s*lambda\s*:\s*(_runner_\w+)\s*\(', phases_src))
    # Direkt lambda runner'ları da (run_X gibi)
    called_direct = set(re.findall(r'runner=lambda\s+\w:\s*_safe\s*\(\s*\w\s*,\s*lambda\s*:\s*(\w+)\s*\(', phases_src))

    phantom_runners = defined_runners - called_in_phases
    print(f"\n  E1 — _runner_X tanimli: {len(defined_runners)}")
    print(f"       _offensive_phases'e bagli: {len(called_in_phases)}")
    if phantom_runners:
        print(f"       PHANTOM (_runner_X tanimli ama phases'e eklenmemis): {len(phantom_runners)}")
        for r in sorted(phantom_runners):
            # Find definition line
            m = re.search(r'^def ' + re.escape(r) + r'\s*\(', phases_src, re.MULTILINE)
            ln = phases_src[:m.start()].count('\n') + 1 if m else '?'
            print(f"    line {ln}: {r}")
    else:
        print("       Tum _runner_X fonksiyonlari bagli -- OK")

    # E2: run_X (public scanner fonksiyonlari) tanimlanmis ama hicbir _runner_ tarafindan cagirilmiyor
    # Tum py dosyalarinda def run_X bul
    defined_run_fns = defaultdict(str)  # fname -> file
    for p in py_files():
        src = read(p)
        rel = str(p.relative_to(ROOT))
        for m in re.finditer(r'^def (run_\w+)\s*\(', src, re.MULTILINE):
            defined_run_fns[m.group(1)] = rel

    # Tüm projede hangi run_X'ler çağrılıyor?
    all_src = ""
    for p in py_files():
        all_src += read(p) + "\n"
    called_run = set(re.findall(r'\b(run_\w+)\s*\(', all_src))

    phantom_run = {fn: f for fn, f in defined_run_fns.items() if fn not in called_run}
    print(f"\n  E2 — run_X fonksiyonu tanimli: {len(defined_run_fns)}")
    uncalled = {fn: f for fn, f in defined_run_fns.items() if fn not in called_run}
    if uncalled:
        print(f"       HICBIR YERDE CAGIRILMAYAN: {len(uncalled)}")
        for fn, fp in sorted(uncalled.items()):
            print(f"    {fn}  in  {fp}")
    else:
        print("       Tum run_X fonksiyonlari cagriliyor -- OK")

    # E3: Import edilen ama hicbir yerde kullanilmayan modul/sinif
    # (sadece integrations/ altindaki modullere bak)
    integrations = SRC / "integrations"
    integration_modules = {p.stem for p in integrations.glob("*.py") if p.stem != "__init__"}
    used_integrations = set()
    for p in py_files():
        src = read(p)
        for mod in integration_modules:
            if f"from websecure.integrations.{mod}" in src or f"import {mod}" in src:
                used_integrations.add(mod)
    unused_integrations = integration_modules - used_integrations
    print(f"\n  E3 — integrations/ modul sayisi: {len(integration_modules)}")
    if unused_integrations:
        print(f"       HIC IMPORT EDILMEYEN moduller: {len(unused_integrations)}")
        for m in sorted(unused_integrations):
            print(f"    websecure/integrations/{m}.py")
    else:
        print("       Tum integration modulleri import ediliyor -- OK")

    return phantom_runners, uncalled, unused_integrations

# ─────────────────────────────────────────────────────────────────────────────
# KATEGORİ F — Import hatası yutan bloklar (tool binary missing = silent skip)
# ─────────────────────────────────────────────────────────────────────────────

def audit_F():
    print("\n" + "="*70)
    print("KATEGORİ F — ARAC BINARY EKSIK = SESSIZ ATLAMA")
    print("="*70)

    # "is_available()" false donunce ne oluyor? Sadece log mu var, add_result var mi?
    # "binary not found" mesajlari
    findings = []
    for p in py_files():
        src = read(p)
        rel = str(p.relative_to(ROOT))
        lines = src.splitlines()
        for i, line in enumerate(lines):
            stripped = line.strip()
            # Sadece "if not self.is_available(): return ..." pattern
            if not (stripped.startswith("if not") and "is_available()" in stripped):
                continue
            # base.py registry management → false positive, atla
            if "base.py" in rel:
                continue
            # version() / get_template_version() / _get_version_major() → utility, scan yapmaz
            # Hangi metodun içinde olduğunu bul: geriye git, def satırını ara
            method_name = ""
            for k in range(i - 1, max(0, i - 20), -1):
                ml = lines[k].strip()
                m = re.match(r'def (\w+)\s*\(', ml)
                if m:
                    method_name = m.group(1)
                    break
            if "version" in method_name.lower() or method_name in (
                "_get_version_major", "get_template_version", "version",
            ):
                continue
            # Sonraki 8 satırda add_result veya logger var mı?
            context = '\n'.join(lines[i:i+8])
            has_feedback = (
                'add_result' in context
                or 'logger.' in context
                or '_logger.' in context
                or 'logging.' in context
                or 'log.' in context
                or 'print(' in context          # visible terminal output
                or 'NOT_FOUND' in context       # ToolStatus.NOT_FOUND carries tool name
                or '"error"' in context         # error key in return dict
            )
            if not has_feedback and 'return' in context:
                findings.append((rel, i+1, stripped))

    print(f"\n  Sessiz atlama (add_result olmadan return): {len(findings)}")
    for f, l, line in findings[:20]:
        print(f"    [{l:5d}] {f}  |  {line[:80]}")

    return findings

# ─────────────────────────────────────────────────────────────────────────────
# ÖZET
# ─────────────────────────────────────────────────────────────────────────────

def main():
    print("WebSecure Full Codebase Audit")
    print(f"Root: {ROOT}")
    total_files = sum(1 for _ in py_files())
    print(f"Python dosyasi: {total_files}")

    a = audit_A()
    b_written, b_reads, b_orphaned = audit_B()
    c_missing, c_partial = audit_C()
    d = audit_D()
    e_phantom_runners, e_uncalled, e_unused_int = audit_E()
    f = audit_F()

    print("\n" + "="*70)
    print("OZET TABLOSU")
    print("="*70)
    crit_a = len([x for x in a if x[0]=="CRITICAL"])
    high_a = len([x for x in a if x[0]=="HIGH"])
    print(f"  A. Hata yutan kod:           CRITICAL={crit_a}  HIGH={high_a}")
    print(f"  B. Orphan bucket:            {len(b_orphaned)} bucket hicbir yere baglanmiyor")
    print(f"  C. Yanlis config path:       {len(c_missing)} tamamen yanlis, {len(c_partial)} kismen yanlis")
    print(f"  D. Eksik dosya/wordlist:     {len(d)} dosya diskte yok")
    print(f"  E. Phantom runner/fonksiyon: {len(e_phantom_runners)} _runner, {len(e_uncalled)} run_X, {len(e_unused_int)} integration modulu")
    print(f"  F. Sessiz arac atlamasi:     {len(f)} yer")
    total = crit_a + high_a + len(b_orphaned) + len(c_missing) + len(c_partial) + len(d) + len(e_phantom_runners) + len(e_uncalled) + len(f)
    print(f"\n  TOPLAM SORUN: {total}")

if __name__ == "__main__":
    main()
