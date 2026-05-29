"""
websecure.core.auth.flows
--------------------------
Auth flow implementations: Email OTP and OAuth 2.0 Device Code grant.
(Merged from email.py + device_flow.py)
"""
import imaplib
import email as _email_lib
import logging
import time
import re
import random
from email.header import decode_header
from websecure.core.http import hardened_session
from typing import Optional, List, Dict, Any

logger = logging.getLogger(__name__)


# ============================================================================
# SECTION 1: Email OTP (formerly email.py)
# ============================================================================

class EmailOtpProvider:
    """
    IMAP-based OTP fetcher.
    Searches for emails matching specific criteria (subject/body regex) to extract verification codes.
    """

    def __init__(
        self,
        host: str,
        user: str,
        password: str,
        folder: str = "INBOX",
        subject_hint: str = "verification code",
        body_regex: str = r"\b(\d{6})\b",
        poll_interval: int = 5,
        max_wait: int = 90,
        port: int = 993,
        use_ssl: bool = True,
        search_unseen_first: bool = True,
        strict_subject: bool = False,
    ):
        self.host = host
        self.port = int(port or 993)
        self.use_ssl = bool(use_ssl)
        self.user = user
        self.password = password
        self.folder = folder or "INBOX"
        self.subject_hint = (subject_hint or "").casefold()
        self.strict_subject = bool(strict_subject)
        self.body_re = re.compile(body_regex or r"\b(\d{6})\b")
        self.poll_interval = max(1, int(poll_interval))
        self.max_wait = max(1, int(max_wait))
        self.search_unseen_first = bool(search_unseen_first)

    def get_code(self) -> Optional[str]:
        deadline = time.time() + self.max_wait
        conn = None
        try:
            conn = self._connect()
            if not self._login_and_select(conn):
                logger.error("IMAP login failed.")
                return None
            while time.time() < deadline:
                ids = self._search_ids(conn)
                if ids:
                    for uid in reversed(ids[-20:]):
                        code = self._process_message(conn, uid)
                        if code:
                            return code
                time.sleep(self.poll_interval + random.uniform(0, 0.75))
        except Exception as e:
            logger.error(f"Email OTP error: {e}")
        finally:
            if conn:
                try:
                    conn.logout()
                except Exception as exc:
                    logger.debug(f"[core.auth.flows] {type(exc).__name__}: {exc!r}")
        return None

    def _connect(self) -> imaplib.IMAP4:
        if self.use_ssl:
            return imaplib.IMAP4_SSL(self.host, self.port)
        return imaplib.IMAP4(self.host, self.port)

    def _login_and_select(self, conn: imaplib.IMAP4) -> bool:
        try:
            conn.login(self.user, self.password)
            typ, _ = conn.select(self.folder)
            return typ == "OK"
        except Exception as e:
            logger.error(f"IMAP Auth Error: {e}")
            return False

    def _search_ids(self, conn: imaplib.IMAP4) -> List[bytes]:
        order = []
        if self.search_unseen_first:
            order.append(("UNSEEN",))
        order.append(("ALL",))
        for criteria in order:
            try:
                typ, data = conn.uid("search", None, *criteria)
                if typ == "OK" and data and data[0]:
                    return data[0].split()
            except Exception as exc:
                logger.debug(f"[core.auth.flows] {type(exc).__name__}: {exc!r}")
        return []

    def _process_message(self, conn: imaplib.IMAP4, uid: bytes) -> Optional[str]:
        try:
            typ, msg_data = conn.uid("fetch", uid, "(RFC822)")
            if typ != "OK" or not msg_data or not msg_data[0]:
                return None
            raw = msg_data[0][1]
            if not raw:
                return None
            msg = _email_lib.message_from_bytes(raw)
            subj = self._decode_subject(msg).casefold()
            match = False
            if not self.subject_hint:
                match = True
            elif self.strict_subject:
                match = (subj.strip() == self.subject_hint.strip())
            else:
                match = (self.subject_hint in subj)
            if not match:
                return None
            body = self._extract_body(msg)
            m = self.body_re.search(body)
            if m:
                return m.group(1)
        except Exception as exc:
            logger.debug(f"[core.auth.flows] {type(exc).__name__}: {exc!r}")
        return None

    def _decode_subject(self, msg) -> str:
        raw = msg.get("Subject", "") or ""
        parts = decode_header(raw)
        out = []
        for txt, enc in parts:
            if isinstance(txt, bytes):
                out.append(txt.decode(enc or "utf-8", "ignore"))
            else:
                out.append(str(txt))
        return "".join(out)

    def _extract_body(self, msg) -> str:
        body = ""
        if msg.is_multipart():
            for part in msg.walk():
                ctype = part.get_content_type()
                if ctype in ("text/plain", "text/html"):
                    payload = part.get_payload(decode=True)
                    if payload is None:
                        continue
                    charset = part.get_content_charset() or "utf-8"
                    body += payload.decode(charset, "ignore") if isinstance(payload, bytes) else str(payload)
        else:
            payload = msg.get_payload(decode=True)
            if payload is not None:
                charset = msg.get_content_charset() or "utf-8"
                body = payload.decode(charset, "ignore") if isinstance(payload, bytes) else str(payload)
        return body


# ============================================================================
# SECTION 2: Device Code Flow (formerly device_flow.py)
# ============================================================================

class DeviceCodeAuth:
    """
    RFC 8628 OAuth 2.0 Device Authorization Grant implementation.
    Used for 'Assisted Auth': User authorizes the scan on another device/browser.
    """

    def __init__(self, client_id: str, device_auth_url: str, token_url: str,
                 scope: str = "openid profile", client_secret: Optional[str] = None):
        self.client_id = client_id
        self.client_secret = client_secret
        self.device_auth_url = device_auth_url
        self.token_url = token_url
        self.scope = scope
        self.session = hardened_session({})

    def authenticate(self) -> Optional[Dict[str, Any]]:
        """
        Executes the full Device Flow:
        1. Request device code.
        2. Display code to user (Assisted).
        3. Poll for access token.
        """
        resp_data = self._initiate_auth()
        if not resp_data:
            return None

        device_code = resp_data.get("device_code")
        user_code = resp_data.get("user_code")
        verification_uri = resp_data.get("verification_uri") or resp_data.get("verification_uri_complete")
        interval = int(resp_data.get("interval", 5))
        expires_in = int(resp_data.get("expires_in", 300))

        if not device_code or not user_code or not verification_uri:
            logger.error("Invalid device auth response.")
            return None

        print("\n" + "=" * 60)
        print("ASSISTED AUTHENTICATION REQUIRED")
        print(f"Please visit: {verification_uri}")
        print(f"And enter code: {user_code}")
        print("=" * 60 + "\n")
        logger.info(f"Waiting for user to authorize with code: {user_code}")

        return self._poll_for_token(device_code, interval, expires_in)

    def _initiate_auth(self) -> Optional[Dict]:
        data = {"client_id": self.client_id, "scope": self.scope}
        try:
            r = self.session.post(self.device_auth_url, data=data, timeout=10)
            if r.status_code == 200:
                return r.json()
            logger.error(f"Device auth init failed ({r.status_code}): {r.text}")
        except Exception as e:
            logger.error(f"Device auth connection error: {e}")
        return None

    def _poll_for_token(self, device_code: str, interval: int, expires_in: int) -> Optional[Dict]:
        deadline = time.time() + expires_in
        while time.time() < deadline:
            time.sleep(interval)
            data = {
                "client_id": self.client_id,
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                "device_code": device_code,
            }
            if self.client_secret:
                data["client_secret"] = self.client_secret
            try:
                r = self.session.post(self.token_url, data=data, timeout=10)
                resp = r.json()
                if r.status_code == 200 and "access_token" in resp:
                    logger.info("Device auth successful! Token received.")
                    return resp
                error = resp.get("error")
                if error == "slow_down":
                    interval += 5
                elif error in ["access_denied", "expired_token"]:
                    logger.warning(f"Device auth failed: {error}")
                    return None
            except Exception as e:
                logger.debug(f"Polling error: {e}")
        logger.error("Device auth timed out.")
        return None
