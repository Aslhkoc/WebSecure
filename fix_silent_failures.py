"""
fix_silent_failures.py
Tüm bare `except: pass` bloklarını debug-logged versiyona çevirir.
"""
import re
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SRC  = ROOT / "websecure"

# Bu pattern'ler dokunulmadan bırakılır (cleanup / opsiyonel / acceptable)
ACCEPTABLE_EXACT = {
    "except ImportError:",
    "except ImportError as e:",
    "except ImportError as exc:",
    "except ImportError as _e:",
    "except (BrokenPipeError, ConnectionResetError):",
    "except (BrokenPipeError, ConnectionResetError) as e:",
    "except OSError:",
    "except OSError as e:",
    "except OSError as exc:",
    "except OSError as _e:",
    "except KeyboardInterrupt:",
    "except SystemExit:",
    "except (KeyboardInterrupt, SystemExit):",
    "except winsound.error:",
    "except AttributeError:",
}

# Cleanup bağlamı — sadece temp dosya / soket kapama / cleanup
CLEANUP_PATTERNS = [
    r"os\.remove\b", r"os\.unlink\b", r"os\.close\b",
    r"\.close\(\)", r"\.shutdown\(", r"shutil\.",
    r"tempfile\.", r"\.terminate\(", r"\.kill\(",
]

def get_module_name(path: Path) -> str:
    """websecure/core/foo.py → [core.foo]"""
    try:
        rel = path.relative_to(SRC)
        parts = list(rel.parts)
        parts[-1] = parts[-1].replace(".py", "")
        return ".".join(parts)
    except Exception:
        return path.stem

def is_cleanup_context(lines: list, except_idx: int) -> bool:
    """except bloğunun 3 satır öncesine bakarak cleanup mi diye kontrol et."""
    start = max(0, except_idx - 4)
    context = " ".join(lines[start:except_idx])
    return any(re.search(p, context) for p in CLEANUP_PATTERNS)

def ensure_logger(src: str, module_name: str) -> str:
    """Dosyada logger yoksa en uygun yere ekle."""
    # Zaten logger/logging var mı?
    if re.search(r'\b(logger|_logger)\s*=\s*', src):
        return src
    if "import logging" not in src and "from logging" not in src:
        # logging import ekle
        # ilk import'tan sonra ekle
        m = re.search(r'^(import |from )', src, re.M)
        if m:
            src = src[:m.start()] + "import logging\n" + src[m.start():]
        else:
            src = "import logging\n" + src
    # logger tanımı ekle — ilk class/def'ten önce
    if not re.search(r'^(logger|_logger)\s*=', src, re.M):
        # En üst seviyeye ekle
        m = re.search(r'^(class |def |\w+ = )', src, re.M)
        if m:
            insert = f'_logger = logging.getLogger(__name__)\n\n'
            src = src[:m.start()] + insert + src[m.start():]
    return src

def fix_file(path: Path) -> bool:
    """Dosyadaki bare except:pass'leri loglu versiyona çevir. True = değişiklik yapıldı."""
    try:
        src = path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return False

    lines = src.splitlines(keepends=True)
    module = get_module_name(path)

    # Hangi logger adı kullanılıyor?
    if re.search(r'^logger\s*=', src, re.M):
        log_var = "logger"
    elif re.search(r'^_logger\s*=', src, re.M):
        log_var = "_logger"
    elif re.search(r'\blogger\b', src):
        log_var = "logger"
    else:
        log_var = "_logger"

    changed = False
    new_lines = []
    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.rstrip("\n").strip()

        # except satırı mı?
        if re.match(r'^except[\s:(]', stripped) or stripped == "except:":
            # Acceptable pattern → dokunma
            if stripped in ACCEPTABLE_EXACT:
                new_lines.append(line)
                i += 1
                continue

            # Sonraki non-empty satır pass mı?
            j = i + 1
            while j < len(lines) and not lines[j].strip():
                j += 1
            if j < len(lines) and lines[j].strip() in ("pass", "..."):
                # Cleanup context → except OSError:pass bırak
                if is_cleanup_context([l.rstrip("\n") for l in lines], i):
                    new_lines.append(line)
                    i += 1
                    continue

                # Indent hesapla
                indent = len(line) - len(line.lstrip())
                body_indent = " " * (indent + 4)

                # except değişken adını çıkar
                m_var = re.search(r'except\s+(?:[^:]+)\s+as\s+(\w+)\s*:', stripped)
                if m_var:
                    var = m_var.group(1)
                    # Satırı olduğu gibi bırak (var zaten var)
                    new_lines.append(line)
                    # pass → log satırıyla değiştir
                    pass_line = lines[j]
                    pass_indent = len(pass_line) - len(pass_line.lstrip())
                    log_line = " " * pass_indent + f'{log_var}.debug(f"[{module}] {{type({var}).__name__}}: {{{var}!r}}")\n'
                    new_lines.append(log_line)
                    changed = True
                    # except satırı + pass satırı atlandı
                    i = j + 1
                    continue
                else:
                    # except X: pass  (değişken yok) → except X as _fix_e:
                    # Satırı as _fix_e: ile değiştir
                    new_stripped = re.sub(r':\s*$', ' as _fix_e:', stripped)
                    new_line = line[:indent] + new_stripped + "\n"
                    new_lines.append(new_line)
                    # pass → log
                    pass_line = lines[j]
                    pass_indent = len(pass_line) - len(pass_line.lstrip())
                    log_line = " " * pass_indent + f'{log_var}.debug(f"[{module}] {{type(_fix_e).__name__}}: {{_fix_e!r}}")\n'
                    new_lines.append(log_line)
                    changed = True
                    i = j + 1
                    continue

        new_lines.append(line)
        i += 1

    if not changed:
        return False

    new_src = "".join(new_lines)

    # Logger yoksa ekle
    new_src = ensure_logger(new_src, module)

    path.write_text(new_src, encoding="utf-8")
    return True


def main():
    fixed_files = []
    total_before = 0

    for p in sorted(SRC.rglob("*.py")):
        if fix_file(p):
            fixed_files.append(str(p.relative_to(ROOT)))

    print(f"Düzeltilen dosya sayısı: {len(fixed_files)}")
    for f in fixed_files:
        print(f"  {f}")


if __name__ == "__main__":
    main()
