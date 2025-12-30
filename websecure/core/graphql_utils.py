from __future__ import annotations
import base64
import json
import time
from dataclasses import dataclass
from typing import Any, Dict, Iterator, List, Optional, Tuple, Mapping
import re
import hashlib as _hl

# ---------------------------------------------------------------------------
# Basit auth yardımcıları (cookie + header snapshot/drop)
# ---------------------------------------------------------------------------

SUSPECT_COOKIE_KEYS = {"session", "sid", "auth", "jwt", "token"}

_B64URL_RE = re.compile(r"^[A-Za-z0-9_\-]*$")


def _is_valid_b64url(s: str) -> bool:
    return bool(_B64URL_RE.match(s or ""))


def _safe_b64url_decode(data: str) -> bytes:
    """
    Base64url padding'i normalize edip decode eder.
    Geçersiz karakter varsa boş byte döner (sessiz fallback, hata yükseltmez).
    """
    s = data or ""
    if not _is_valid_b64url(s):
        return b""
    s = s + "=" * (-len(s) % 4)
    try_bytes = base64.urlsafe_b64decode(s.encode("utf-8"))
    # base64.urlsafe_b64decode, regex ile doğrulandıktan sonra tipik olarak hata yükseltmez
    return try_bytes


def _safe_b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")


def extract_auth_snapshot(session) -> Dict[str, Any]:
    """Session üzerindeki Authorization header ve şüpheli cookie'leri yakala."""
    headers = getattr(session, "headers", {}) or {}
    auth = headers.get("Authorization")
    ck: Dict[str, str] = {}

    jar = getattr(session, "cookies", None)
    if jar is not None:
        for c in list(jar):
            name = (getattr(c, "name", "") or "").lower()
            if name in SUSPECT_COOKIE_KEYS:
                ck[getattr(c, "name", "")] = getattr(c, "value", "")

    return {"auth_header": auth, "cookies": ck}


class _DropAuth:
    """Authorization ve şüpheli cookie’leri geçici kaldıran context manager (try/finally yok)."""
    def __init__(self, session):
        self._s = session
        snap = extract_auth_snapshot(session)
        self._prev_auth = snap.get("auth_header")
        self._suspects = list((snap.get("cookies") or {}).keys())

    def __enter__(self):
        headers = getattr(self._s, "headers", None)
        if isinstance(headers, dict) and "Authorization" in headers:
            headers.pop("Authorization")
        jar = getattr(self._s, "cookies", None)
        if jar is not None:
            for name in self._suspects:
                # requests CookieJar set(name, None) temizler
                jar.set(name, None)
        return self

    def __exit__(self, exc_type, exc, tb):
        headers = getattr(self._s, "headers", None)
        if isinstance(headers, dict):
            if self._prev_auth is None:
                headers.pop("Authorization", None)
            else:
                headers["Authorization"] = self._prev_auth
        # Cookie'leri tam restore etmek genelde mümkün değil; üst katman login akışı tekrar ayarlar.
        return False  # istisnaları bastırmaz


def drop_auth(session) -> Iterator[None]:
    """Authorization header ve şüpheli cookie'leri geçici kaldır (context manager döner)."""
    return _DropAuth(session)  # type: ignore[return-value]


def set_invalid_token(session, token: str = "Bearer invalid.invalid.invalid"):
    """Geçersiz token yerleştir (önceki Authorization'u override eder)."""
    headers = getattr(session, "headers", None)
    if isinstance(headers, dict):
        headers["Authorization"] = token


# ---------------------------------------------------------------------------
# JWT işlevleri — parse/compose ve varyasyon üretimi
# ---------------------------------------------------------------------------

def _json_loads_or_empty(b: bytes) -> Dict[str, Any]:
    """
    Basit ve güvenli JSON decode: içeriğin { ile başladığına bakarak dener,
    aksi halde {} döner. Hata yükseltmez.
    """
    if not b:
        return {}
    s = b.decode("utf-8", "ignore").strip()
    if not (s.startswith("{") and s.endswith("}")):
        return {}
    # JSON hatası yükselirse bastırmayız; ancak yukarıdaki guard ile tipik hataları engelledik.
    return json.loads(s)


@dataclass
class JWTParts:
    header_raw: str
    payload_raw: str
    signature_raw: str

    @property
    def header(self) -> Dict[str, Any]:
        return _json_loads_or_empty(_safe_b64url_decode(self.header_raw))

    @property
    def payload(self) -> Dict[str, Any]:
        return _json_loads_or_empty(_safe_b64url_decode(self.payload_raw))

    def as_compact(self) -> str:
        return ".".join([self.header_raw, self.payload_raw, self.signature_raw])


def parse_bearer_jwt_from_session(session) -> Optional[JWTParts]:
    """Session.Authorization içinden JWT ayıkla (Bearer <token>)."""
    headers = getattr(session, "headers", {}) or {}
    auth = headers.get("Authorization") or ""
    if not isinstance(auth, str) or not auth.lower().startswith("bearer "):
        return None
    token = auth.split(" ", 1)[1].strip()
    parts = token.split(".")
    if len(parts) != 3:
        return None
    return JWTParts(*parts)


def compose_jwt_unverified(header: Dict[str, Any], payload: Dict[str, Any], signature: Optional[str] = "") -> str:
    """
    İmza doğrulaması yapmadan JWT compact string üret.
    - signature None ise boş imza (alg=none senaryosu) üretir.
    - signature "" (default) ise 3. parça boş bırakılır.
    """
    h_raw = _safe_b64url_encode(json.dumps(header, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))
    p_raw = _safe_b64url_encode(json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))
    s_raw = signature if signature is not None else ""
    return ".".join([h_raw, p_raw, s_raw])


def bearer(token: str) -> str:
    return f"Bearer {token}"


def _try_mutate_roles(payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Rol/Scope içeren yaygın claim adları:
    - 'role', 'roles' (dize veya liste)
    - 'scope' (boşluk ayrımlı dizge), 'scopes' (liste)
    - 'permissions' (liste)
    Bu fonksiyon *rol düşürme* yapar: admin→user→guest; scope/permission'ları daraltır.
    """
    p = json.loads(json.dumps(payload))  # deep copy

    # Tekil rol
    if isinstance(p.get("role"), str):
        p["role"] = "guest"

    # Liste roller
    if isinstance(p.get("roles"), list):
        new_roles = [r for r in p["roles"] if str(r).lower() in {"guest", "user"}]
        if not new_roles:
            new_roles = ["guest"]
        p["roles"] = new_roles

    # scope dizge (space-separated)
    if isinstance(p.get("scope"), str):
        scopes = [s for s in p["scope"].split() if s.lower() in {"read"}]
        p["scope"] = " ".join(scopes or ["read"])

    # scopes liste
    if isinstance(p.get("scopes"), list):
        p["scopes"] = [s for s in p["scopes"] if str(s).lower() in {"read"}] or ["read"]

    # permissions
    if isinstance(p.get("permissions"), list):
        keep = {"read", "view", "basic", "self"}
        p["permissions"] = [x for x in p["permissions"] if str(x).lower() in keep] or ["read"]

    # opsiyonel tier
    p["tier"] = "free"

    return p


def _set_exp(payload: Dict[str, Any], delta_seconds: int) -> Dict[str, Any]:
    p = json.loads(json.dumps(payload))  # deep copy
    p["exp"] = int(time.time()) + delta_seconds
    return p


def jwt_role_downgrade_variants(session) -> Dict[str, str]:
    """
    Session'daki JWT'yi baz alarak çeşitli varyasyonlar döndürür:
      - alg=none + rol düşürme
      - mevcut header alg korunarak sadece payload rol düşürme (imza korunamaz; boş bırakılır)
      - token'ı 'expired' yapma (exp geçmişte)
      - token'ı 'far-future' yapma (exp ileriye)
    Dönen değerler Bearer prefix içeren header değeridir.
    """
    parts = parse_bearer_jwt_from_session(session)
    if not parts:
        return {}

    h = parts.header or {}
    p = parts.payload or {}

    # 1) alg=none + rol düşürme
    h_none = dict(h)
    h_none["alg"] = "none"
    p_downgraded = _try_mutate_roles(p)
    tok_none = compose_jwt_unverified(h_none, p_downgraded, signature=None)

    # 2) alg korunur; imza boş (çoğu sunucu reddeder ama hatalılar ayırt edilebilir)
    tok_sigless = compose_jwt_unverified(h, p_downgraded, signature="")

    # 3) expired
    tok_expired = compose_jwt_unverified(h_none, _set_exp(p_downgraded, -3600), signature=None)

    # 4) far future
    tok_future = compose_jwt_unverified(h_none, _set_exp(p_downgraded, +365 * 24 * 3600), signature=None)

    return {
        "none_alg_downgraded": bearer(tok_none),
        "sigless_downgraded": bearer(tok_sigless),
        "expired_downgraded": bearer(tok_expired),
        "future_downgraded": bearer(tok_future),
    }


class _WithJWTHeader:
    """Authorization header'ı geçici override eden context manager."""
    def __init__(self, session, authorization_value: str):
        self._s = session
        self._val = authorization_value
        self._prev = getattr(getattr(session, "headers", {}), "get", lambda *_: None)("Authorization")

    def __enter__(self):
        headers = getattr(self._s, "headers", None)
        if isinstance(headers, dict):
            headers["Authorization"] = self._val
        return self

    def __exit__(self, exc_type, exc, tb):
        headers = getattr(self._s, "headers", None)
        if isinstance(headers, dict):
            if self._prev is None:
                headers.pop("Authorization", None)
            else:
                headers["Authorization"] = self._prev
        return False  # istisnaları bastırmaz


def with_jwt_header(session, authorization_value: str) -> Iterator[None]:
    """Authorization header'ı geçici override eder (context manager döner)."""
    return _WithJWTHeader(session, authorization_value)  # type: ignore[return-value]


# ---------------------------------------------------------------------------
# GraphQL batching ve sorgu yardımcıları
# ---------------------------------------------------------------------------

def batch_payload(operations: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    GraphQL HTTP batching (array of operations).
    Örnek operasyon:
      {"query": "query A($id:ID!){node(id:$id){id}}", "variables":{"id":"123"}, "operationName":"A"}
    """
    return operations


def build_operation(query: str, variables: Optional[Dict[str, Any]] = None, operation_name: Optional[str] = None) -> Dict[str, Any]:
    op: Dict[str, Any] = {"query": query}
    if variables is not None:
        op["variables"] = variables
    if operation_name:
        op["operationName"] = operation_name
    return op


def alias_collision_query() -> Dict[str, Any]:
    """Aynı alias iki farklı field için kullanılır; spec'e göre hata vermeli."""
    q = "query C { a: __typename a: __typename }"
    return {"query": q}


def introspection_query(minimal: bool = True) -> Dict[str, Any]:
    """Minimal introspection (şema hash’i için faydalı) veya genişletilmiş."""
    if minimal:
        q = "query I { __schema { queryType { name } mutationType { name } subscriptionType { name } types { name kind } directives { name } } }"
    else:
        q = "query I { __schema { types { name kind fields { name type { kind name ofType { kind name } } } } } }"
    return {"query": q, "operationName": "I"}


def current_user_probe() -> Dict[str, Any]:
    """Yaygın bir self endpoint'i. Yoksa hata dönebilir; yine de authz farkını anlarız."""
    q = "query Me { me { id username email role roles } }"
    return {"query": q, "operationName": "Me"}


def build_probe_batch(include_me: bool = True, extended_introspection: bool = False) -> List[Dict[str, Any]]:
    """
    HTTP batch içinde karşılaştırılacak temel probeler.
    """
    ops = [introspection_query(minimal=not extended_introspection)]
    if include_me:
        ops.append(current_user_probe())
    ops.append(alias_collision_query())
    return batch_payload(ops)


# ---------------------------------------------------------------------------
# Authz farklarını kıyaslamak için test matrisi
# ---------------------------------------------------------------------------

@dataclass
class RequestPlan:
    label: str
    headers: Dict[str, str]
    body: Any  # dict veya list (batch)

    def as_tuple(self) -> Tuple[str, Dict[str, str], Any]:
        return self.label, self.headers, self.body


def build_authz_diff_matrix(session, base_endpoint_headers: Optional[Dict[str, str]] = None,
                            include_me: bool = True, extended_introspection: bool = False) -> List[RequestPlan]:
    """
    Aynı GraphQL batch'i farklı auth bağlamlarında gönderme planı üretir.
    Üst katman HTTP istemcisi bu planı döngüyle POST edebilir.
    Dönüş: [RequestPlan]
    """
    base_headers = dict(base_endpoint_headers or {})
    batch = build_probe_batch(include_me=include_me, extended_introspection=extended_introspection)

    plans: List[RequestPlan] = []

    # 0) Orijinal Authorization ile
    h0 = dict(base_headers)
    session_headers = getattr(session, "headers", {}) or {}
    if "Authorization" in session_headers:
        h0["Authorization"] = session_headers["Authorization"]
    plans.append(RequestPlan("auth_original", h0, batch))

    # 1) Auth düşürülmüş (alg=none vb.)
    variants = jwt_role_downgrade_variants(session)
    for key, authv in variants.items():
        h = dict(base_headers)
        h["Authorization"] = authv
        plans.append(RequestPlan(f"auth_{key}", h, batch))

    # 2) Geçersiz token
    h_invalid = dict(base_headers)
    h_invalid["Authorization"] = "Bearer invalid.invalid.invalid"
    plans.append(RequestPlan("auth_invalid", h_invalid, batch))

    # 3) No-auth
    plans.append(RequestPlan("no_auth", dict(base_headers), batch))

    return plans


# ---------------------------------------------------------------------------
# Basit diff yardımı: JSON gövdeleri/şema hash’i
# ---------------------------------------------------------------------------

def stable_schema_fingerprint(introspection_json: Dict[str, Any]) -> str:
    """
    Çok büyük şemaları kıyaslarken kolaylık için basit bir fingerprint.
    (Tür adlarını ve kind alanını alfabetik olarak normalize eder.)
    """
    data = introspection_json.get("data") if isinstance(introspection_json, dict) else None
    schema = data.get("__schema") if isinstance(data, dict) else None
    types = schema.get("types") if isinstance(schema, dict) else None
    if not isinstance(types, list):
        return ""
    simplified = sorted(
        [{"name": t.get("name"), "kind": t.get("kind")} for t in types if isinstance(t, dict)],
        key=lambda x: ((x.get("kind") or ""), (x.get("name") or "")),
    )
    blob = json.dumps(simplified, separators=(",", ":"), ensure_ascii=False)
    return _safe_b64url_encode(blob.encode("utf-8"))


# ---------------------------------------------------------------------------
# [WS3-ANCHOR] GraphQL helpers (alias set, APQ, introspection detect)
# ---------------------------------------------------------------------------

def build_alias_set(fields: List[str]) -> str:
    """a0:field0 a1:field1 ..."""
    return " ".join([f"a{i}:{f}" for i, f in enumerate(fields or [])])


def is_introspection_disabled(text: str) -> bool:
    t = (text or "").lower()
    return ("introspection" in t and "disable" in t) or "insufficient permissions for introspection" in t


def make_apq_extensions_sha(query: str, version: int = 1) -> Dict[str, Any]:
    sha = _hl.sha256((query or "").encode()).hexdigest()
    return {"persistedQuery": {"version": int(version), "sha256Hash": sha}}


# ---------------------------------------------------------------------------
# APQ helpers: POST/GET payloads
# ---------------------------------------------------------------------------

def apq_post_payload(query: str, version: int = 1) -> Dict[str, Any]:
    return {
        "query": query,
        "extensions": make_apq_extensions_sha(query, version)
    }


def apq_get_params(query: str, version: int = 1) -> Dict[str, Any]:
    return {
        "extensions": json.dumps(make_apq_extensions_sha(query, version)),
        "query": query
    }


def apq_only_hash(version: int = 1, sha: Optional[str] = None) -> Dict[str, Any]:
    return {
        "extensions": {"persistedQuery": {"version": int(version), "sha256Hash": sha or make_apq_extensions_sha('')['persistedQuery']['sha256Hash']}},
        "query": None
    }


# ---------------------------------------------------------------------------
# Suggestion parser consolidator (server-dependent phrasing)
# ---------------------------------------------------------------------------

_SUG_PATTERNS = [
    r'Did you mean\s+"([^"]+)"',
    r'did you mean\s+"([^"]+)"',
    r'Did you mean\s+(\[.*?\])',
    r"Unknown (?:type|argument|field).*?(?:Did you mean|did you mean)[:\s]+([A-Za-z0-9_,\s\"']+)",
    r"Suggestions?:\s*(\[.*?\])",
    r'Perhaps you meant\s+"([^"]+)"',
    r'Known argument.*?Did you mean\s+"([^"]+)"',
]


def _split_list_literal(s: str) -> List[str]:
    """JSON'a başvurmadan [a,b,'c'] benzeri listeleri kaba biçimde ayrıştır."""
    inner = s.strip()
    if not (inner.startswith("[") and inner.endswith("]")):
        return []
    inner = inner[1:-1]
    parts = [p.strip() for p in inner.split(",")]
    out: List[str] = []
    for p in parts:
        # çevreleyen tek/çift tırnakları temizle
        if (p.startswith('"') and p.endswith('"')) or (p.startswith("'") and p.endswith("'")):
            p = p[1:-1]
        p = p.strip()
        if p:
            out.append(p)
    return out


def parse_suggestions(msg: str) -> List[str]:
    raw: List[str] = []
    for pat in _SUG_PATTERNS:
        for m in re.finditer(pat, msg or "", re.IGNORECASE | re.DOTALL):
            raw.append(m.group(1))

    # normalize
    out: List[str] = []
    for s in raw:
        ss = (s or "").strip()
        if not ss:
            continue
        if ss.startswith("[") and ss.endswith("]"):
            out.extend(_split_list_literal(ss))
        else:
            out.append(ss.strip(" '\""))

    # unique preserve order
    uniq: List[str] = []
    for x in out:
        if x and x not in uniq:
            uniq.append(x)
    return uniq


__all__ = [
    # cookie/header helpers
    "extract_auth_snapshot",
    "drop_auth",
    "set_invalid_token",
    "with_jwt_header",
    # jwt utils
    "JWTParts",
    "parse_bearer_jwt_from_session",
    "compose_jwt_unverified",
    "jwt_role_downgrade_variants",
    "bearer",
    # gql ops
    "batch_payload",
    "build_operation",
    "alias_collision_query",
    "introspection_query",
    "current_user_probe",
    "build_probe_batch",
    "build_alias_set", "is_introspection_disabled", "make_apq_extensions_sha",
    # authz diff
    "RequestPlan",
    "build_authz_diff_matrix",
    # schema fingerprint
    "stable_schema_fingerprint",
    # APQ helpers
    "apq_post_payload",
    "apq_get_params",
    "apq_only_hash",
    # suggestion helpers
    "parse_suggestions",
]