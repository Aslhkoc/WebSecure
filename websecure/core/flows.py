from __future__ import annotations
import logging
import types
from json import loads as _json_loads
import re, json, time, threading
from typing import Dict, Any, List, Tuple, Optional, Mapping
from urllib.parse import urljoin
import importlib.util as _iul
import importlib
import requests

# add_result (opsiyonel, try/except yok)
if _iul.find_spec("websecure.core.reporting") is not None:
    _rep = importlib.import_module("websecure.core.reporting")
    add_result = getattr(_rep, "add_result", lambda *a, **k: None)
else:
    def add_result(*a, **k): return None

# ================== Yardımcılar ==================

_logger = logging.getLogger(__name__)

def _looks_like_json(s: str) -> bool:
    if not isinstance(s, str):
        return False
    t = s.strip()
    return (t.startswith("{") and t.endswith("}")) or (t.startswith("[") and t.endswith("]"))

def _json_get(d, path: str):
    cur = d
    for part in (path or "").split("."):
        if not part:
            continue
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur

def _store_values(resp_text: str, resp_headers: dict, stores, state: dict):
    for st in (stores or []):
        typ = (st.get("from") or "").lower()
        key = str(st.get("as") or st.get("var") or "")
        if not key:
            continue
        if typ == "regex":
            pat = st.get("pattern") or st.get("regex")
            if not pat:
                continue
            m = re.search(pat, resp_text or "", re.I | re.S)
            if m:
                state[key] = m.group(1) if m.groups() else m.group(0)
        elif typ == "json":
            path = st.get("path") or ""
            if not path or not _looks_like_json(resp_text or ""):
                continue
            j = _json_loads(resp_text or "{}")
            state[key] = _json_get(j, path)
        elif typ == "header":
            name = st.get("name")
            if name:
                state[key] = (resp_headers or {}).get(name)

def _assertions(resp, text: str, asserts):
    fails = []
    for ex in (asserts or []):
        if "status" in ex and int(ex["status"]) != getattr(resp, "status_code", 0):
            fails.append({"status": [ex["status"], getattr(resp, "status_code", 0)]})
        if "contains" in ex and str(ex["contains"]) not in (text or ""):
            fails.append({"contains": ex["contains"]})
        if "not_contains" in ex and str(ex["not_contains"]) in (text or ""):
            fails.append({"not_contains": ex["not_contains"]})
        if "json" in ex:
            jx = ex["json"]; path = jx.get("path", ""); eq = jx.get("equals")
            got = None
            if _looks_like_json(text or ""):
                j = _json_loads(text or "{}")
                got = _json_get(j, path)
            if eq is not None and got != eq:
                fails.append({"json": [path, got, eq]})
        if "regex" in ex:
            pat = ex["regex"]
            if not re.search(pat, text or "", re.I | re.S):
                fails.append({"regex": pat})
    return fails

def _mk_finding_from_step(flow_name: str, step_item: dict, role: str, base_url: str) -> dict:
    url = step_item.get("url") or ""
    return {
        "url": url,
        "location": "",
        "param": "",
        "type": "BUSINESS_LOGIC",
        "severity": "Medium",
        "reason": f"Flow '{flow_name}' adım {step_item.get('step')} beklenti hatası",
        "method": step_item.get("method","GET"),
        "payload": "",
        "authenticated": (role or "").lower() != "anon",
    }

# Basit şablonlayıcı: {{var}} değişkenlerini state içinden doldur
_VAR_RE = re.compile(r"{{\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*}}")

def _tpl(s: str, state: Dict[str, Any]) -> str:
    if not isinstance(s, str):
        return s
    def rep(m):
        key = m.group(1)
        return str(state.get(key, m.group(0)))
    return _VAR_RE.sub(rep, s)

# Extractor: response.text regex yakala -> state['var']=value
def _apply_extractors(text: str, extractors: List[Dict[str, Any]], state: Dict[str, Any]):
    for ex in (extractors or []):
        var = ex.get("var")
        pat = ex.get("regex")
        if not (var and pat):
            continue
        m = re.search(pat, text or "", re.I | re.S)
        if m:
            state[var] = m.group(1) if m.groups() else m.group(0)

def _merge_headers(base: Dict[str, str], add: Dict[str, str]) -> Dict[str,str]:
    h = dict(base or {})
    for k, v in (add or {}).items():
        h[str(k)] = str(v)
    return h

# ================== Eski Koşucu (korundu) ==================

def run_business_logic_flows_legacy(session: requests.Session, base_url: str, cfg: Dict[str, Any], results: Dict[str, Any], *, debug: bool=False) -> int:
    """
    config.business_logic.flows tanımlı DSL'i yürütür.
    DSL: name, steps[]. step: method,url,headers,body/json,extract[],expect[]
    """
    bl = (cfg.get("business_logic") or {})
    flows = bl.get("flows") or []
    if not flows:
        add_result("meta", {"stage":"bizlogic","status":"skipped:no-flows"})
        return 0

    state: Dict[str, Any] = {}
    completed = 0

    for flow in flows:
        name = str(flow.get("name") or "flow")
        steps: List[Dict[str, Any]] = list(flow.get("steps") or [])
        base_headers = flow.get("base_headers") or {}
        base_cookies = flow.get("base_cookies") or {}
        ok = True
        step_report: List[Dict[str, Any]] = []

        for i, st in enumerate(steps, start=1):
            method = str(st.get("method","GET")).upper()
            url = st.get("url") or "/"
            url = url if url.startswith("http") else urljoin(base_url if base_url.endswith("/") else base_url+"/", url.lstrip("/"))
            url = _tpl(url, state)
            headers = _merge_headers(base_headers, {k:_tpl(str(v), state) for k,v in (st.get("headers") or {}).items()})
            data = st.get("body")
            jsn = st.get("json")
            if isinstance(data, str): data = _tpl(data, state)
            if isinstance(jsn, dict): jsn = {k:_tpl(str(v), state) for k,v in jsn.items()}

            r = session.request(method, url, headers=headers, data=data, json=jsn, allow_redirects=True, timeout=bl.get("timeout", 12), verify=bl.get("verify_tls", False), cookies=base_cookies)
            item = {"flow": name, "step": i, "method": method, "url": url, "status": r.status_code, "len": len(r.text or "")}
            expects = st.get("expect") or []
            passed = True
            for ex in expects:
                if "status" in ex and int(ex["status"]) != r.status_code:
                    passed = False; item.setdefault("expect_failures", []).append({"status": [ex["status"], r.status_code]})
                if "contains" in ex and str(ex["contains"]) not in (r.text or ""):
                    passed = False; item.setdefault("expect_failures", []).append({"contains": ex["contains"]})
                if "not_contains" in ex and str(ex["not_contains"]) in (r.text or ""):
                    passed = False; item.setdefault("expect_failures", []).append({"not_contains": ex["not_contains"]})
            item["passed"] = passed

            _apply_extractors(r.text or "", st.get("extract") or [], state)
            step_report.append(item)
            if debug: item["_debug_sample"] = (r.text or "")[:400]
            if not passed and st.get("required", True):
                ok = False; break

        add_result("vulnerability", {"source": "bizlogic_flows", "name": name, "ok": ok, "steps": step_report})
        completed += int(ok)

    add_result("meta", {"stage":"bizlogic","flows_defined": len(flows), "flows_ok": completed})
    results.setdefault("bizlogic_summary", {})["flows_ok"] = completed
    return completed

# ================== PATCH: Modern Koşucu ==================

# Yerel http istemcisi (opsiyonel)
if _iul.find_spec("websecure.core.http") is not None:
    _http_mod = importlib.import_module("websecure.core.http")
    get_http = getattr(_http_mod, "get_http", None)
else:
    get_http = None  # type: ignore

def _ws_normalize_url(base_url: str, url: str) -> str:
    if url.startswith("http://") or url.startswith("https://"):
        return url
    base = (base_url or "").rstrip("/") + "/"
    return urljoin(base, url.lstrip("/"))

# Orijinal isim korunarak override edilir (imza aynı tutuldu)
def run_business_logic_flows(session, base_url: str, cfg: Mapping[str, Any], results: Mapping[str, Any], *, debug: bool = False) -> int:  # type: ignore[override]
    _sv = globals().get("_store_values")
    _as = globals().get("_assertions")

    # add_result global assumed available via module-level init; no inner fallback required.

    bl = (cfg.get("business_logic") or {})
    flows = bl.get("flows") or []
    if not flows:
        add_result("meta", {"stage": "bizlogic", "status": "skipped:no-flows"})
        return 0

    client = get_http(cfg.get("http") or {}) if callable(get_http) else None
    findings = 0

    for flow in flows:
        fname = flow.get("name") or "flow"
        steps = flow.get("steps") or []
        ctx_store: dict[str, Any] = {}
        ok_so_far = True

        for idx, step in enumerate(steps, 1):
            method = str(step.get("method", "GET")).upper()
            url = _ws_normalize_url(base_url, str(step.get("url") or "/"))
            headers = dict(step.get("headers") or {})

            body = step.get("body")
            if isinstance(body, str) and isinstance(ctx_store, dict):
                for k, v in ctx_store.items():
                    body = body.replace(f"{{{{{k}}}}}", str(v))
            json_obj = step.get("json")

            timeout_s = float(step.get("timeout", bl.get("timeout", 20)))
            verify_tls = bool(step.get("verify_tls", bl.get("verify_tls", True)))

            if client is not None:
                resp_u = client.request(method, url, headers=headers, data=body, json=json_obj, timeout=timeout_s, verify=verify_tls)  # type: ignore
                status = resp_u.status_code
                text = resp_u.text
                r_headers = getattr(resp_u, "headers", {}) or {}
            else:
                r = session.request(method, url, headers=headers, data=body, json=json_obj, timeout=timeout_s, verify=verify_tls)
                status = r.status_code
                text = r.text
                r_headers = getattr(r, "headers", {}) or {}

            if callable(_sv):
                _sv(text, r_headers, step.get("store") or step.get("extract") or [], ctx_store)
            failures = _as(types.SimpleNamespace(status_code=status), text, step.get("expect") or []) if callable(_as) else []
            if failures:
                ok_so_far = False
                add_result("vulnerability", {"source": "bizlogic_flow_step", "flow": fname, "step": idx, "url": url, "status": status, "failures": failures})
                if step.get("stop_on_fail", True):
                    break
            else:
                add_result("meta", {"source": "bizlogic_flow_step", "flow": fname, "step": idx, "url": url, "status": status, "ok": True})

        if ok_so_far:
            add_result("meta", {"source": "bizlogic_flow", "name": fname, "status": "ok"})
        else:
            findings += 1
            add_result("vulnerability", {"source": "bizlogic_flow", "severity": "Medium", "type": "Business Logic Flow Failure", "name": fname, "status": "failed"})

    results.setdefault("bizlogic_summary", {})["flow_failures"] = findings  # type: ignore[index]
    add_result("meta", {"stage":"bizlogic","flows_defined": len(flows), "flows_failed": findings})
    return findings

# ================== İdempotensi Testleri ==================

def run_idempotency_checks(
    session,
    base_url: str,
    cfg: Mapping[str, Any],
    results: Mapping[str, Any],
    *,
    debug: bool = False,
) -> int:
    """
    Idempotency checks from config.business_logic.idempotency.checks.
    Returns the number of anomalies found.
    """
    # response_fingerprint / idempotency_anomaly helpers
    _rfp: Any = None
    _idem_anom: Any = None
    if _iul.find_spec("websecure.core.detect") is not None:
        try:
            _d = importlib.import_module("websecure.core.detect")
            _rfp = getattr(_d, "response_fingerprint", None)
            _idem_anom = getattr(_d, "idempotency_anomaly", None)
        except Exception as _fix_e:
            _logger.debug(f"[core.flows] {type(_fix_e).__name__}: {_fix_e!r}")
    if not callable(_rfp):
        def _rfp(txt: str) -> str: return str(hash(txt))  # type: ignore[misc]
    if not callable(_idem_anom):
        def _idem_anom(fps: list) -> bool: return len(set(fps)) > 1  # type: ignore[misc]

    bl = (cfg.get("business_logic") or {})
    idem = (bl.get("idempotency") or {})
    if not idem.get("enabled", True):
        add_result("meta", {"stage": "idempotency", "status": "skipped"})
        return 0
    checks = list(idem.get("checks") or [])
    if not checks:
        add_result("meta", {"stage": "idempotency", "status": "skipped:no-checks"})
        return 0

    client = get_http(cfg.get("http") or {}) if callable(get_http) else None
    findings = 0
    repeat = max(2, int(idem.get("repeat", 2)))
    for chk in checks:
        method = str(chk.get("method", "POST")).upper()
        url = _ws_normalize_url(base_url, str(chk.get("url") or "/"))
        headers = dict(chk.get("headers") or {})
        payload = chk.get("json")
        timeout_s = float(idem.get("timeout", bl.get("timeout", 20)))
        verify_tls = bool(idem.get("verify_tls", bl.get("verify_tls", True)))
        fps: List[str] = []
        codes: List[int] = []
        for _ in range(repeat):
            if client is not None:
                resp_u = client.request(method, url, headers=headers, json=payload, timeout=timeout_s, verify=verify_tls)  # type: ignore[union-attr]
                fps.append(_rfp(resp_u.text or ""))
                codes.append(resp_u.status_code)
            else:
                r = session.request(method, url, headers=headers, json=payload, timeout=timeout_s, verify=verify_tls)
                fps.append(_rfp(r.text or ""))
                codes.append(r.status_code)
        anom = _idem_anom(fps)
        item = {
            "name": chk.get("name") or "idempotency",
            "url": url,
            "status_set": sorted(set(codes)),
            "unique_fp": len(set(fps)),
            "unique_status": len(set(codes)),
            "anomaly": bool(anom),
        }
        add_result("meta", {"source": "bizlogic_idempotency", **item})
        if anom:
            findings += 1
            add_result("vulnerability", {
                "source": "bizlogic_idempotency", "severity": "Medium",
                "type": "Business Logic: Idempotency Anomaly",
                "url": url,
                "note": "Aynı istek farklı yanıtlar üretiyor (idempotency anomalisi)",
                "method": method,
                "authenticated": False,
            })
    results.setdefault("bizlogic_summary", {})["idempotency_anomalies"] = findings  # type: ignore[union-attr]
    add_result("meta", {"stage": "idempotency", "tests": len(checks), "anomalies": findings})
    return findings
