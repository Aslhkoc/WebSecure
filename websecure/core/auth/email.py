import imaplib
import email
import logging
import time
import re
import random
from email.header import decode_header
from typing import Optional, Callable, List

logger = logging.getLogger(__name__)

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
                    # Check latest 20 emails
                    for uid in reversed(ids[-20:]):
                        code = self._process_message(conn, uid)
                        if code:
                            return code

                # Jitter sleep
                time.sleep(self.poll_interval + random.uniform(0, 0.75))

        except Exception as e:
            logger.error(f"Email OTP error: {e}")
        finally:
            if conn:
                try:
                    conn.logout()
                except:
                    pass
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
            order.append(('UNSEEN',))
        order.append(('ALL',))
        
        for criteria in order:
            try:
                typ, data = conn.uid('search', None, *criteria)
                if typ == 'OK' and data and data[0]:
                    return data[0].split()
            except:
                pass
        return []

    def _process_message(self, conn: imaplib.IMAP4, uid: bytes) -> Optional[str]:
        try:
            typ, msg_data = conn.uid("fetch", uid, "(RFC822)")
            if typ != "OK" or not msg_data or not msg_data[0]:
                return None
            
            raw = msg_data[0][1]
            if not raw:
                return None

            msg = email.message_from_bytes(raw)
            subj = self._decode_subject(msg).casefold()
            
            # Subject Check
            match = False
            if not self.subject_hint:
                match = True
            elif self.strict_subject:
                match = (subj.strip() == self.subject_hint.strip())
            else:
                match = (self.subject_hint in subj)
            
            if not match:
                return None

            # Body Check
            body = self._extract_body(msg)
            m = self.body_re.search(body)
            if m:
                return m.group(1)
        except Exception:
            pass
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
                    charset = part.get_content_charset() or "utf-8"
                    body += payload.decode(charset, "ignore") if isinstance(payload, bytes) else str(payload)
        else:
            payload = msg.get_payload(decode=True)
            charset = msg.get_content_charset() or "utf-8"
            body = payload.decode(charset, "ignore") if isinstance(payload, bytes) else str(payload)
        return body
