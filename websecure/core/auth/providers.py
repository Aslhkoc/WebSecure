import os
import logging
from dataclasses import dataclass
from typing import Optional, Dict, Any, Protocol

from .totp import TOTP
from .flows import EmailOtpProvider  # merged from email.py

logger = logging.getLogger(__name__)

class TwoFactorProvider(Protocol):
    def verify(self, ctx: Any) -> bool: ...

@dataclass
class TwoFAConfig:
    method: str = "none"
    totp_secret: Optional[str] = None
    imap_host: Optional[str] = None
    imap_port: int = 993
    imap_use_ssl: bool = True
    imap_user: Optional[str] = None
    imap_password: Optional[str] = None
    imap_folder: str = "INBOX"
    subject_hint: str = "verification code"
    body_regex: str = r"\b(\d{6})\b"
    search_unseen_first: bool = True
    push_timeout_sec: int = 120
    push_poll_interval_sec: int = 4
    strict_subject: bool = False

def read_2fa_config(config: Dict[str, Any] | None) -> TwoFAConfig:
    sec = (config or {}).get("settings", {}).get("security", {}) if config else {}
    c = sec.get("two_factor", {}) if isinstance(sec, dict) else {}
    
    # Fallback/Priority: check config['auth']['two_factor'] (matches config.json)
    if not c and config and "auth" in config:
        auth_conf = config.get("auth", {})
        if isinstance(auth_conf, dict):
            c = auth_conf.get("two_factor", {}) or {}
    
    return TwoFAConfig(
        method=c.get("method") or c.get("provider") or os.getenv("OTP_METHOD", "none"),
        totp_secret=c.get("totp_secret") or os.getenv("TOTP_SECRET"),
        imap_host=c.get("imap_host") or os.getenv("IMAP_HOST"),
        imap_port=int(c.get("imap_port") or os.getenv("IMAP_PORT") or 993),
        imap_use_ssl=(str(c.get("imap_use_ssl", "1")).lower() in ("1", "true")),
        imap_user=c.get("imap_user") or os.getenv("IMAP_USER"),
        imap_password=c.get("imap_password") or os.getenv("IMAP_PASS"),
        imap_folder=c.get("imap_folder", "INBOX"),
        subject_hint=c.get("subject_hint", "verification code"),
        body_regex=c.get("body_regex", r"\b(\d{6})\b"),
        search_unseen_first=bool(c.get("search_unseen_first", True)),
        strict_subject=bool(c.get("strict_subject", False))
    )

# --- Concrete Providers Wrappers ---

class _Base2FA(TwoFactorProvider):
    def _submit_code(self, ctx: Any, code: str) -> bool:
        submit = getattr(ctx, "submit_2fa", None)
        if callable(submit):
            return bool(submit(code))
        setter = getattr(ctx, "set_twofa_code", None)
        if callable(setter):
            setter(code)
            return True
        setattr(ctx, "twofa_code", code)
        return True

class Totp2FA(_Base2FA):
    def __init__(self, secret: str):
        self.totp = TOTP(secret)

    def verify(self, ctx: Any) -> bool:
        code = self.totp.generate() # Assumes native TOTP class
        return self._submit_code(ctx, code)

class EmailOtp2FA(_Base2FA):
    def __init__(self, cfg: TwoFAConfig):
        self.provider = EmailOtpProvider(
            host=cfg.imap_host or "",
            user=cfg.imap_user or "",
            password=cfg.imap_password or "",
            folder=cfg.imap_folder,
            subject_hint=cfg.subject_hint,
            body_regex=cfg.body_regex,
            port=cfg.imap_port,
            use_ssl=cfg.imap_use_ssl,
            search_unseen_first=cfg.search_unseen_first,
            strict_subject=cfg.strict_subject
        )

    def verify(self, ctx: Any) -> bool:
        code = self.provider.get_code()
        if code:
            return self._submit_code(ctx, code)
        logger.warning("Email 2FA failed: No code found.")
        return False

class Null2FA(_Base2FA):
    def verify(self, ctx: Any) -> bool:
        return True

def create_twofactor_provider(cfg: TwoFAConfig) -> TwoFactorProvider:
    method = (cfg.method or "none").lower()
    if method == "totp":
        if cfg.totp_secret:
            return Totp2FA(cfg.totp_secret)
        logger.warning(
            "[2FA] method='totp' configured but totp_secret is missing — 2FA bypassed"
        )
    elif method == "email":
        if cfg.imap_host and cfg.imap_user:
            return EmailOtp2FA(cfg)
        logger.warning(
            "[2FA] method='email' configured but imap_host/imap_user missing — 2FA bypassed"
        )
    # SMS, Push placeholders can be added here
    return Null2FA()
