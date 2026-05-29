"""
websecure.cli.wizard
~~~~~~~~~~~~~~~~~~~~~
İnteraktif config sihirbazı — `websecure init` komutu.

Kullanıcıyı adım adım sorularla yönlendirip config.json üretir.

Sorular
-------
1. Hedef URL (varsayılan: http://localhost)
2. Tarama profili (aggressive / default / stealth / cicd / bugbounty)
3. Kimlik doğrulama (anonim / form login / cookie / bearer token)
4. Proxy (opsiyonel)
5. Rapor formatı (json / html / markdown / sarif / pdf)
6. Bildirim kanalları (slack / teams / pagerduty / none)
7. Wordlist senkronizasyonu (evet/hayır)
8. Çıktı dizini
9. Paralel thread sayısı
10. Timeout

SOLID
-----
- SRP  : Her soru kendi Question sınıfında — tek sorumluluk.
- OCP  : Yeni soru eklemek mevcut kodu değiştirmez.
- LSP  : Tüm Question tipleri BaseQuestion'dan türer.
"""
from __future__ import annotations

import json
import sys
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Soru temel sınıfı
# ---------------------------------------------------------------------------

class BaseQuestion(ABC):
    """Tek bir wizard sorusu."""

    def __init__(
        self,
        key: str,
        prompt: str,
        default: Any = None,
        required: bool = False,
    ) -> None:
        self.key = key
        self.prompt = prompt
        self.default = default
        self.required = required

    @abstractmethod
    def ask(self) -> Any:
        """Kullanıcıya sor ve dönüştürülmüş değeri döndür."""

    def _input(self, prompt: str) -> str:
        try:
            return input(prompt).strip()
        except (KeyboardInterrupt, EOFError):
            print("\n[!] Sihirbaz iptal edildi.")
            sys.exit(0)


class TextQuestion(BaseQuestion):
    """Serbest metin sorusu."""

    def __init__(self, key, prompt, default="", required=False, validator=None):
        super().__init__(key, prompt, default, required)
        self._validator = validator

    def ask(self) -> str:
        default_str = f" [{self.default}]" if self.default else ""
        while True:
            val = self._input(f"  {self.prompt}{default_str}: ")
            if not val:
                val = self.default or ""
            if self.required and not val:
                print("    Bu alan zorunlu.")
                continue
            if self._validator and val:
                err = self._validator(val)
                if err:
                    print(f"    Geçersiz: {err}")
                    continue
            return val


class ChoiceQuestion(BaseQuestion):
    """Seçenekli soru."""

    def __init__(self, key, prompt, choices: List[str], default: str = ""):
        super().__init__(key, prompt, default)
        self.choices = choices

    def ask(self) -> str:
        default_str = f" [{self.default}]" if self.default else ""
        choices_str = " / ".join(self.choices)
        print(f"  {self.prompt} ({choices_str}){default_str}")
        while True:
            val = self._input("    Seçim: ").lower()
            if not val and self.default:
                return self.default
            if val in self.choices:
                return val
            # Kısmi eşleşme
            matches = [c for c in self.choices if c.startswith(val)]
            if len(matches) == 1:
                return matches[0]
            print(f"    Geçerli seçenekler: {choices_str}")


class BoolQuestion(BaseQuestion):
    """Evet/Hayır sorusu."""

    def ask(self) -> bool:
        default_str = "E/h" if self.default else "e/H"
        while True:
            val = self._input(f"  {self.prompt} [{default_str}]: ").lower()
            if not val:
                return bool(self.default)
            if val in ("e", "evet", "y", "yes", "1", "true"):
                return True
            if val in ("h", "hayır", "n", "no", "0", "false"):
                return False
            print("    Lütfen E (evet) veya H (hayır) girin.")


class IntQuestion(BaseQuestion):
    """Tam sayı sorusu."""

    def __init__(self, key, prompt, default=0, min_val=None, max_val=None):
        super().__init__(key, prompt, default)
        self.min_val = min_val
        self.max_val = max_val

    def ask(self) -> int:
        while True:
            val = self._input(f"  {self.prompt} [{self.default}]: ")
            if not val:
                return self.default
            try:
                n = int(val)
                if self.min_val is not None and n < self.min_val:
                    print(f"    Minimum değer: {self.min_val}")
                    continue
                if self.max_val is not None and n > self.max_val:
                    print(f"    Maximum değer: {self.max_val}")
                    continue
                return n
            except ValueError:
                print("    Lütfen geçerli bir tam sayı girin.")


class MultiChoiceQuestion(BaseQuestion):
    """Çoklu seçim sorusu (virgülle ayrılmış)."""

    def __init__(self, key, prompt, choices: List[str], default: List[str] = None):
        super().__init__(key, prompt, default or [])
        self.choices = choices

    def ask(self) -> List[str]:
        default_str = ", ".join(self.default) if self.default else "none"
        choices_str = " / ".join(self.choices)
        print(f"  {self.prompt}")
        print(f"    Seçenekler: {choices_str}  (virgülle ayır, boş=none)")
        val = self._input(f"    [{default_str}]: ")
        if not val:
            return list(self.default)
        selected = [v.strip().lower() for v in val.split(",")]
        return [s for s in selected if s in self.choices]


# ---------------------------------------------------------------------------
# URL validator
# ---------------------------------------------------------------------------

def _validate_url(url: str) -> Optional[str]:
    """URL temel doğrulama."""
    if not url.startswith(("http://", "https://")):
        return "URL http:// veya https:// ile başlamalı"
    return None


# ---------------------------------------------------------------------------
# ConfigWizard
# ---------------------------------------------------------------------------

class ConfigWizard:
    """
    İnteraktif config sihirbazı.

    Kullanım
    --------
    ```python
    wizard = ConfigWizard(output_path="config.json")
    cfg = wizard.run()
    ```
    """

    _PROFILES = ["default", "aggressive", "stealth", "cicd", "bugbounty", "compliance"]
    _AUTH_TYPES = ["none", "form", "cookie", "bearer", "basic"]
    _REPORT_FORMATS = ["json", "html", "markdown", "sarif", "pdf", "csv"]
    _NOTIFY_CHANNELS = ["none", "slack", "teams", "pagerduty", "email", "webhook"]

    def __init__(self, output_path: str | Path = "config.json") -> None:
        self.output_path = Path(output_path)

    def run(self) -> Dict[str, Any]:
        """Sihirbazı çalıştır, üretilen config dict'i döndür."""
        self._print_header()
        cfg = self._collect_answers()
        self._print_summary(cfg)

        if BoolQuestion("confirm", "Yapılandırmayı kaydet?", default=True).ask():
            self._save(cfg)
            print(f"\n[[OK]] Config kaydedildi: {self.output_path.resolve()}")
        else:
            print("[!] Config kaydedilmedi.")

        return cfg

    # ------------------------------------------------------------------
    # Sorular
    # ------------------------------------------------------------------

    def _collect_answers(self) -> Dict[str, Any]:
        cfg: Dict[str, Any] = {}

        print("\n" + "=" * 60)
        print("  1/10 — Hedef")
        print("=" * 60)
        cfg["target"] = TextQuestion(
            "target", "Tarama hedefi URL",
            default="http://localhost",
            validator=_validate_url,
        ).ask()

        print("\n" + "=" * 60)
        print("  2/10 — Tarama Profili")
        print("=" * 60)
        cfg["profile"] = ChoiceQuestion(
            "profile", "Tarama profili",
            self._PROFILES, default="default",
        ).ask()

        print("\n" + "=" * 60)
        print("  3/10 — Kimlik Doğrulama")
        print("=" * 60)
        auth_type = ChoiceQuestion(
            "auth_type", "Kimlik doğrulama tipi",
            self._AUTH_TYPES, default="none",
        ).ask()
        cfg["auth"] = {"type": auth_type}

        if auth_type == "form":
            cfg["auth"]["login_url"]    = TextQuestion("login_url", "Login URL", required=True).ask()
            cfg["auth"]["username"]     = TextQuestion("username", "Kullanıcı adı alanı adı", default="username").ask()
            cfg["auth"]["password"]     = TextQuestion("password", "Şifre alanı adı", default="password").ask()
            cfg["auth"]["username_val"] = TextQuestion("username_val", "Kullanıcı adı değeri").ask()
            # Şifre değerini düz metin saklamıyoruz — env var kullan
            print("    [i] Şifre için WS_PASSWORD ortam değişkenini kullanın.")

        elif auth_type == "cookie":
            cfg["auth"]["cookie"] = TextQuestion("cookie", "Cookie değeri (name=value)").ask()

        elif auth_type == "bearer":
            print("    [i] Token için WS_TOKEN ortam değişkenini kullanın.")
            cfg["auth"]["header"] = "Authorization"

        elif auth_type == "basic":
            cfg["auth"]["username_val"] = TextQuestion("username_val", "Kullanıcı adı").ask()
            print("    [i] Şifre için WS_PASSWORD ortam değişkenini kullanın.")

        print("\n" + "=" * 60)
        print("  4/10 — Proxy")
        print("=" * 60)
        use_proxy = BoolQuestion("use_proxy", "Proxy kullan?", default=False).ask()
        if use_proxy:
            cfg["proxy"] = TextQuestion(
                "proxy", "Proxy URL",
                default="http://127.0.0.1:8080",
            ).ask()
        else:
            cfg["proxy"] = None

        print("\n" + "=" * 60)
        print("  5/10 — Rapor Formatı")
        print("=" * 60)
        cfg["report_formats"] = MultiChoiceQuestion(
            "report_formats", "Rapor formatları",
            self._REPORT_FORMATS, default=["json", "html"],
        ).ask()
        cfg["output_dir"] = TextQuestion(
            "output_dir", "Çıktı dizini",
            default="./websecure_reports",
        ).ask()

        print("\n" + "=" * 60)
        print("  6/10 — Bildirimler")
        print("=" * 60)
        notify_channels = MultiChoiceQuestion(
            "notify", "Bildirim kanalları",
            self._NOTIFY_CHANNELS, default=["none"],
        ).ask()
        cfg["notifications"] = {}
        if "none" not in notify_channels:
            for ch in notify_channels:
                if ch == "slack":
                    cfg["notifications"]["slack"] = {
                        "webhook_url": TextQuestion("slack_url", "Slack Webhook URL", required=True).ask()
                    }
                elif ch == "teams":
                    cfg["notifications"]["teams"] = {
                        "webhook_url": TextQuestion("teams_url", "Teams Webhook URL", required=True).ask()
                    }
                elif ch == "pagerduty":
                    cfg["notifications"]["pagerduty"] = {
                        "routing_key": TextQuestion("pd_key", "PagerDuty Routing Key", required=True).ask()
                    }
                elif ch == "email":
                    cfg["notifications"]["email"] = {
                        "to": TextQuestion("email_to", "E-posta adresi", required=True).ask(),
                    }
                    print("    [i] SMTP ayarları için WS_SMTP_HOST/WS_SMTP_USER/WS_SMTP_PASS ortam değişkenlerini kullanın.")
                elif ch == "webhook":
                    cfg["notifications"]["webhook"] = {
                        "url": TextQuestion("webhook_url", "Webhook URL", required=True).ask(),
                        "min_severity": ChoiceQuestion(
                            "min_sev", "Minimum önem seviyesi",
                            ["Info","Low","Medium","High","Critical"], default="High"
                        ).ask(),
                    }

        print("\n" + "=" * 60)
        print("  7/10 — Wordlist Senkronizasyonu")
        print("=" * 60)
        cfg["payloads"] = {
            "sync": BoolQuestion("sync", "Wordlist'leri otomatik güncelle?", default=False).ask(),
            "max_per_category": IntQuestion(
                "max_payloads", "Kategori başına maksimum payload",
                default=500, min_val=10, max_val=10000,
            ).ask(),
        }

        print("\n" + "=" * 60)
        print("  8/10 — Performans")
        print("=" * 60)
        cfg["concurrency"] = IntQuestion(
            "threads", "Paralel thread sayısı",
            default=10, min_val=1, max_val=200,
        ).ask()
        cfg["timeout"]     = IntQuestion(
            "timeout", "Bağlantı timeout (saniye)",
            default=15, min_val=1, max_val=120,
        ).ask()

        print("\n" + "=" * 60)
        print("  9/10 — Gelişmiş")
        print("=" * 60)
        cfg["verify_ssl"]  = BoolQuestion("ssl", "SSL sertifikasını doğrula?", default=True).ask()
        cfg["follow_redirects"] = BoolQuestion("redir", "Yönlendirmeleri takip et?", default=True).ask()
        cfg["user_agent"]  = TextQuestion(
            "ua", "User-Agent",
            default="Mozilla/5.0 (WebSecure Scanner/2.0)",
        ).ask()

        print("\n" + "=" * 60)
        print("  10/10 — Tarama Kapsamı")
        print("=" * 60)
        cfg["scope"] = {
            "included_paths": TextQuestion(
                "inc_paths",
                "Dahil edilecek path pattern (boşsa tümü, regex)",
                default="",
            ).ask() or "",
            "excluded_paths": TextQuestion(
                "exc_paths",
                "Hariç tutulacak path pattern (regex)",
                default="^/(logout|signout|delete)",
            ).ask(),
            "max_depth": IntQuestion(
                "depth", "Maksimum tarama derinliği",
                default=5, min_val=1, max_val=20,
            ).ask(),
        }

        return cfg

    # ------------------------------------------------------------------
    # Özet ve kayıt
    # ------------------------------------------------------------------

    def _print_header(self) -> None:
        print("\n" + "=" * 60)
        print("  WebSecure — İnteraktif Yapılandırma Sihirbazı")
        print("  Ctrl+C ile iptal edilebilir")
        print("=" * 60)

    def _print_summary(self, cfg: Dict[str, Any]) -> None:
        print("\n" + "-" * 60)
        print("  Yapılandırma Özeti")
        print("-" * 60)
        print(f"  Hedef   : {cfg.get('target')}")
        print(f"  Profil  : {cfg.get('profile')}")
        print(f"  Auth    : {cfg.get('auth', {}).get('type', 'none')}")
        print(f"  Proxy   : {cfg.get('proxy') or '(yok)'}")
        print(f"  Rapor   : {', '.join(cfg.get('report_formats', []))}")
        print(f"  Thread  : {cfg.get('concurrency')}")
        print(f"  Timeout : {cfg.get('timeout')}s")
        print(f"  Çıktı   : {cfg.get('output_dir')}")
        print("-" * 60)

    def _save(self, cfg: Dict[str, Any]) -> None:
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        self.output_path.write_text(
            json.dumps(cfg, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )


# ---------------------------------------------------------------------------
# CLI kısayol
# ---------------------------------------------------------------------------

def run_wizard(output_path: str = "config.json") -> bool:
    """
    Sihirbazı çalıştır; hedef URL girilip config kaydedildiyse True döner.

    main.py tarafından `--wizard` flag ve argümansız interactive mod için kullanılır.
    True dönüşü "hemen tara" sinyali — main.py kaydedilen config'i yükler ve devam eder.
    """
    cfg = ConfigWizard(output_path=output_path).run()
    return bool(cfg.get("target"))


def run_wizard_cli(args: list) -> int:
    """websecure init komutu."""
    import argparse

    parser = argparse.ArgumentParser(prog="websecure init")
    parser.add_argument(
        "--output", "-o", default="config.json",
        help="Config dosyası çıktı yolu"
    )
    ns = parser.parse_args(args)

    wizard = ConfigWizard(output_path=ns.output)
    wizard.run()
    return 0


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

__all__ = [
    "BaseQuestion",
    "TextQuestion",
    "ChoiceQuestion",
    "BoolQuestion",
    "IntQuestion",
    "MultiChoiceQuestion",
    "ConfigWizard",
    "run_wizard",
    "run_wizard_cli",
]
