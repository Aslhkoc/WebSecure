"""
websecure.cli.autocomplete
~~~~~~~~~~~~~~~~~~~~~~~~~~~
Bash / Zsh / Fish shell tamamlama betikleri üretici.

Kullanım
--------
```bash
# Bash
websecure completion bash >> ~/.bashrc
source ~/.bashrc

# Zsh
websecure completion zsh >> ~/.zshrc

# Fish
websecure completion fish > ~/.config/fish/completions/websecure.fish
```

SOLID
-----
- SRP  : Her shell için ayrı üretici sınıf.
- OCP  : Yeni shell desteği mevcut kodu değiştirmez.
- LSP  : Tüm üreticiler BaseCompletionGenerator'dan türer.
"""
from __future__ import annotations

import os
import sys
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# CLI komut ağacı — autocomplete için referans
# ---------------------------------------------------------------------------

# (komut, alt_komutlar, flagler)
_CLI_TREE: Dict[str, Dict] = {
    "scan": {
        "flags": [
            ("--target", "-t",        "Tarama hedefi URL"),
            ("--profile", "-p",       "Tarama profili"),
            ("--output", "-o",        "Çıktı dizini"),
            ("--format", "-f",        "Rapor formatı"),
            ("--threads",             "Paralel thread sayısı"),
            ("--timeout",             "Bağlantı timeout"),
            ("--proxy",               "Proxy URL"),
            ("--no-verify-ssl",       "SSL doğrulamayı atla"),
            ("--on-finding-webhook",  "Bulgu webhook URL"),
            ("--tui",                 "TUI modunu etkinleştir"),
            ("--no-tui",              "TUI'yi devre dışı bırak"),
            ("--resume",              "Checkpoint'ten devam et"),
            ("--checkpoint",          "Checkpoint dosyası yolu"),
            ("--config",              "Config dosyası yolu"),
        ],
        "choices": {
            "--profile":  ["default","aggressive","stealth","cicd","bugbounty","compliance","api-only"],
            "--format":   ["json","html","markdown","sarif","pdf","csv"],
            "--threads":  [],
        },
    },
    "init": {
        "flags": [("--output", "-o", "Config dosyası çıktı yolu")],
        "choices": {},
    },
    "diff": {
        "flags": [
            ("--format",     "Çıktı formatı"),
            ("--output","-o","Çıktı dosyası"),
            ("--no-rich",    "Rich kullanma"),
            ("--exit-code",  "Yeni bulgu varsa exit 2"),
        ],
        "choices": {
            "--format": ["terminal","json","markdown","html"],
        },
    },
    "serve": {
        "flags": [
            ("--port","-p", "HTTP sunucu portu"),
            ("--host",      "Bind adresi"),
            ("--no-browser","Tarayıcı açma"),
        ],
        "choices": {},
    },
    "queue": {
        "subcommands": ["add","cancel","list","stats","clear","run"],
        "flags": {
            "add":    [("--priority","-p","Öncelik 1-5"), ("--label","Etiket")],
            "list":   [("--status","Durum filtresi")],
            "run":    [("--workers","-w","Worker sayısı")],
        },
        "choices": {
            "--status": ["pending","running","completed","failed","cancelled"],
        },
    },
    "schedule": {
        "subcommands": ["add","remove","enable","disable","list","run"],
        "flags": {
            "add": [("--label","Etiket"), ("--disabled","Devre dışı başlat")],
        },
        "choices": {},
    },
    "completion": {
        "flags": [],
        "choices": {},
        "positional": ["bash","zsh","fish"],
    },
}

_TOP_COMMANDS = list(_CLI_TREE.keys())
_GLOBAL_FLAGS = [
    "--help", "-h",
    "--version",
    "--config",
    "--verbose", "-v",
    "--quiet", "-q",
]


# ---------------------------------------------------------------------------
# Temel sınıf
# ---------------------------------------------------------------------------

class BaseCompletionGenerator(ABC):
    """Shell tamamlama betiği üreticisi."""

    @abstractmethod
    def generate(self) -> str:
        """Tamamlama betiği döndür."""

    @abstractmethod
    def install_path(self) -> Optional[Path]:
        """Betiğin kurulacağı standart yol."""

    def install(self) -> Optional[Path]:
        """Betiği uygun konuma kur."""
        path = self.install_path()
        if path is None:
            return None
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.generate(), encoding="utf-8")
        return path


# ---------------------------------------------------------------------------
# Bash tamamlama
# ---------------------------------------------------------------------------

class BashCompletionGenerator(BaseCompletionGenerator):
    """Bash autocomplete betiği üretici."""

    def generate(self) -> str:
        cmds = " ".join(_TOP_COMMANDS)
        global_flags = " ".join(_GLOBAL_FLAGS)

        # Her komut için flag listesi
        cmd_flags: Dict[str, str] = {}
        for cmd, spec in _CLI_TREE.items():
            flags = spec.get("flags", [])
            flat = []
            for f in flags:
                flat.append(f[0])
                if len(f) > 1 and f[1].startswith("-"):
                    flat.append(f[1])
            cmd_flags[cmd] = " ".join(flat)

        # choice listesi (--flag -> değerler)
        choice_cases: List[str] = []
        for cmd, spec in _CLI_TREE.items():
            for flag, vals in spec.get("choices", {}).items():
                if vals:
                    vals_str = " ".join(vals)
                    choice_cases.append(
                        f'            {flag})\n'
                        f'                COMPREPLY=($(compgen -W "{vals_str}" -- "$cur"))\n'
                        f'                return\n'
                        f'                ;;'
                    )

        choice_block = "\n".join(choice_cases)

        return f'''# WebSecure bash completion
# Kaynak: websecure completion bash >> ~/.bashrc

_websecure_complete() {{
    local cur prev words cword
    _init_completion || return

    # Üst düzey komutlar
    local commands="{cmds}"
    local global_flags="{global_flags}"

    if [[ $cword -eq 1 ]]; then
        COMPREPLY=($(compgen -W "$commands $global_flags" -- "$cur"))
        return
    fi

    local cmd="${{words[1]}}"

    # Önceki flag için değer tamamlama
    case "$prev" in
        --config|--output|-o)
            _filedir "*.json"
            return
            ;;
        --proxy)
            return
            ;;
{choice_block}
    esac

    # Komut bazlı flag tamamlama
    case "$cmd" in
        scan)
            COMPREPLY=($(compgen -W "{cmd_flags.get('scan','')}" -- "$cur"))
            ;;
        init)
            COMPREPLY=($(compgen -W "{cmd_flags.get('init','')}" -- "$cur"))
            ;;
        diff)
            if [[ $cword -le 3 ]]; then
                _filedir "*.json"
            else
                COMPREPLY=($(compgen -W "{cmd_flags.get('diff','')}" -- "$cur"))
            fi
            ;;
        serve)
            COMPREPLY=($(compgen -W "{cmd_flags.get('serve','')}" -- "$cur"))
            ;;
        queue)
            local subcmds="add cancel list stats clear run"
            if [[ $cword -eq 2 ]]; then
                COMPREPLY=($(compgen -W "$subcmds" -- "$cur"))
            fi
            ;;
        schedule)
            local subcmds="add remove enable disable list run"
            if [[ $cword -eq 2 ]]; then
                COMPREPLY=($(compgen -W "$subcmds" -- "$cur"))
            fi
            ;;
        completion)
            COMPREPLY=($(compgen -W "bash zsh fish" -- "$cur"))
            ;;
        *)
            COMPREPLY=($(compgen -W "$commands $global_flags" -- "$cur"))
            ;;
    esac
}}

complete -F _websecure_complete websecure
'''

    def install_path(self) -> Optional[Path]:
        home = Path.home()
        # Linux/Mac standart konumu
        for p in [
            Path("/etc/bash_completion.d/websecure"),
            home / ".local/share/bash-completion/completions/websecure",
        ]:
            if p.parent.exists():
                return p
        return home / ".bash_completion.d" / "websecure"


# ---------------------------------------------------------------------------
# Zsh tamamlama
# ---------------------------------------------------------------------------

class ZshCompletionGenerator(BaseCompletionGenerator):
    """Zsh autocomplete betiği üretici."""

    def generate(self) -> str:
        cmds_block: List[str] = []
        for cmd in _TOP_COMMANDS:
            spec = _CLI_TREE.get(cmd, {})
            flags = spec.get("flags", [])
            desc = {
                "scan":       "Web güvenlik taraması başlat",
                "init":       "İnteraktif yapılandırma sihirbazı",
                "diff":       "İki tarama sonucunu karşılaştır",
                "serve":      "Web dashboard başlat",
                "queue":      "Tarama kuyruğu yönet",
                "schedule":   "Cron zamanlamaları yönet",
                "completion": "Shell tamamlama betiği üret",
            }.get(cmd, cmd)
            cmds_block.append(f"    '{cmd}:{desc}'")

        scan_args = []
        for flag_tuple in _CLI_TREE["scan"]["flags"]:
            flag = flag_tuple[0]
            desc = flag_tuple[-1]
            scan_args.append(f"        '{flag}[{desc}]'")

        return f'''#compdef websecure
# WebSecure zsh completion
# Kaynak: websecure completion zsh >> ~/.zshrc  (veya ~/.zshrc.d/ altına koy)

_websecure() {{
    local state line
    typeset -A opt_args

    _arguments -C \\
        '--help[Yardım göster]' \\
        '--version[Sürüm göster]' \\
        '--config[Config dosyası]:dosya:_files -g "*.json"' \\
        '--verbose[Ayrıntılı çıktı]' \\
        '1: :->command' \\
        '*:: :->args' && return 0

    case $state in
        command)
            _values "websecure komutu" \\
{chr(10).join(cmds_block)}
            ;;
        args)
            case $line[1] in
                scan)
                    _arguments \\
{chr(10).join(scan_args)} \\
                        '--profile[Tarama profili]:(default aggressive stealth cicd bugbounty compliance)' \\
                        '--format[Rapor formatı]:(json html markdown sarif pdf csv)' \\
                        '*:hedef:_urls'
                    ;;
                diff)
                    _arguments \\
                        '1:eski tarama:_files -g "*.json"' \\
                        '2:yeni tarama:_files -g "*.json"' \\
                        '--format[Çıktı formatı]:(terminal json markdown html)' \\
                        '--output[Çıktı dosyası]:dosya:_files'
                    ;;
                init)
                    _arguments '--output[Config yolu]:dosya:_files -g "*.json"'
                    ;;
                serve)
                    _arguments '--port[Port]' '--host[Host]'
                    ;;
                queue)
                    _values "queue komutu" add cancel list stats clear run
                    ;;
                schedule)
                    _values "schedule komutu" add remove enable disable list run
                    ;;
                completion)
                    _values "shell" bash zsh fish
                    ;;
            esac
            ;;
    esac
}}

_websecure "$@"
'''

    def install_path(self) -> Optional[Path]:
        # Kullanıcının zsh fpath'indeki standart konum — önce parent dizin varlığı kontrol et
        home = Path.home()
        for p in [
            home / ".zsh/completions/_websecure",
            home / ".local/share/zsh/site-functions/_websecure",
        ]:
            if p.parent.exists():
                return p
        return home / ".zsh/completions/_websecure"


# ---------------------------------------------------------------------------
# Fish tamamlama
# ---------------------------------------------------------------------------

class FishCompletionGenerator(BaseCompletionGenerator):
    """Fish autocomplete betiği üretici."""

    def generate(self) -> str:
        lines: List[str] = [
            "# WebSecure fish completion",
            "# Kaynak: websecure completion fish > ~/.config/fish/completions/websecure.fish",
            "",
            "# Üst düzey komutlar",
        ]

        cmd_descs = {
            "scan":       "Web güvenlik taraması başlat",
            "init":       "İnteraktif yapılandırma sihirbazı",
            "diff":       "İki tarama sonucunu karşılaştır",
            "serve":      "Web dashboard başlat",
            "queue":      "Tarama kuyruğu yönet",
            "schedule":   "Cron zamanlamaları yönet",
            "completion": "Shell tamamlama betiği üret",
        }

        for cmd, desc in cmd_descs.items():
            lines.append(
                f'complete -c websecure -f -n "__fish_use_subcommand" '
                f'-a "{cmd}" -d "{desc}"'
            )

        lines.append("")
        lines.append("# scan flags")
        scan_flags = [
            ("--target",   "-t", "Tarama hedefi URL"),
            ("--profile",  "-p", "Tarama profili"),
            ("--output",   "-o", "Çıktı dizini"),
            ("--format",   "-f", "Rapor formatı"),
            ("--threads",  "",   "Thread sayısı"),
            ("--timeout",  "",   "Timeout saniye"),
            ("--proxy",    "",   "Proxy URL"),
            ("--tui",      "",   "TUI modunu etkinleştir"),
            ("--no-tui",   "",   "TUI'yi kapat"),
            ("--resume",   "",   "Checkpoint'ten devam"),
            ("--on-finding-webhook", "", "Bulgu webhook URL"),
        ]
        for f in scan_flags:
            flag, short, desc = f
            short_part = f"-s {short[1:]} " if short else ""
            lines.append(
                f'complete -c websecure -n "__fish_seen_subcommand_from scan" '
                f'-l {flag[2:]} {short_part}-d "{desc}"'
            )

        lines.append("")
        lines.append("# profile choices")
        for prof in ["default","aggressive","stealth","cicd","bugbounty","compliance"]:
            lines.append(
                f'complete -c websecure -n "__fish_seen_subcommand_from scan" '
                f'-l profile -a "{prof}"'
            )

        lines.append("")
        lines.append("# diff flags")
        diff_flags = [
            ("--format", "Çıktı formatı"),
            ("--output", "Çıktı dosyası"),
            ("--exit-code", "Yeni bulgu varsa exit 2"),
        ]
        for flag, desc in diff_flags:
            lines.append(
                f'complete -c websecure -n "__fish_seen_subcommand_from diff" '
                f'-l {flag[2:]} -d "{desc}"'
            )

        lines.append("")
        lines.append("# queue subcommands")
        for sub in ["add","cancel","list","stats","clear","run"]:
            lines.append(
                f'complete -c websecure -n "__fish_seen_subcommand_from queue" '
                f'-a "{sub}"'
            )

        lines.append("")
        lines.append("# schedule subcommands")
        for sub in ["add","remove","enable","disable","list","run"]:
            lines.append(
                f'complete -c websecure -n "__fish_seen_subcommand_from schedule" '
                f'-a "{sub}"'
            )

        lines.append("")
        lines.append("# completion shells")
        for sh in ["bash","zsh","fish"]:
            lines.append(
                f'complete -c websecure -n "__fish_seen_subcommand_from completion" '
                f'-a "{sh}"'
            )

        return "\n".join(lines) + "\n"

    def install_path(self) -> Optional[Path]:
        home = Path.home()
        return home / ".config" / "fish" / "completions" / "websecure.fish"


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------

_GENERATORS: Dict[str, type] = {
    "bash": BashCompletionGenerator,
    "zsh":  ZshCompletionGenerator,
    "fish": FishCompletionGenerator,
}


def get_generator(shell: str) -> BaseCompletionGenerator:
    """Shell için tamamlama üreticisi döndür."""
    cls = _GENERATORS.get(shell.lower())
    if cls is None:
        raise ValueError(f"Desteklenmeyen shell: {shell!r}  — bash / zsh / fish")
    return cls()


# ---------------------------------------------------------------------------
# CLI kısayol
# ---------------------------------------------------------------------------

def run_completion_cli(args: list) -> int:
    """websecure completion [bash|zsh|fish] [--install]"""
    import argparse

    parser = argparse.ArgumentParser(prog="websecure completion")
    parser.add_argument(
        "shell", choices=["bash","zsh","fish"],
        help="Shell tipi",
    )
    parser.add_argument(
        "--install", action="store_true",
        help="Tamamlama betiğini sistem konumuna kur",
    )
    ns = parser.parse_args(args)

    try:
        gen = get_generator(ns.shell)
    except ValueError as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 1

    if ns.install:
        path = gen.install()
        if path:
            print(f"[[OK]] Tamamlama betiği kuruldu: {path}")
            print(f"    Aktifleştirmek için shell'i yeniden başlatın veya:")
            if ns.shell == "bash":
                print(f"    source {path}")
            elif ns.shell == "zsh":
                print(f"    source {path}  # veya fpath'e ekleyin")
            elif ns.shell == "fish":
                print(f"    (fish otomatik yükler)")
        else:
            print("[!] Kurulum yolu belirlenemedi — manuel kurulum gerekebilir.")
            print(gen.generate())
    else:
        print(gen.generate(), end="")

    return 0


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

__all__ = [
    "BaseCompletionGenerator",
    "BashCompletionGenerator",
    "ZshCompletionGenerator",
    "FishCompletionGenerator",
    "get_generator",
    "run_completion_cli",
]
