from __future__ import annotations
from urllib.parse import urlsplit, urlunsplit, urlparse, urlencode, parse_qsl, urlunparse, quote_plus, quote
from websecure.core.http import hardened_session
import os
import logging
import re
import time
import random
import string
import base64
import json
import socket
import ssl
import time as _time
from pathlib import Path
from functools import lru_cache
from contextlib import suppress
from dataclasses import dataclass
from html import unescape as html_unescape
from typing import Tuple, Optional, Dict, List, Any
from importlib.util import find_spec as _find_spec
from websecure.core.analysis import mutate_payload, build_waf_headers, get_waf_cfg


# Harici payload sağlayıcı (SecLists + PayloadsAllTheThings + wordlists_custom)
# --- Payload sağlayıcı (çekirdek varsa onu kullan, yoksa dosya tabanlı fallback) ---
if _find_spec("websecure.core.payloads") is not None:
    from websecure.core.payloads import load_external_payloads, get_builtin_payloads  # type: ignore
else:
    def get_builtin_payloads(category: str) -> list[str]: return []

    # Dosya tabanlı payload sağlayıcı (SecLists / PayloadsAllTheThings)
    _CAT_PATTERNS: dict[str, list[str]] = {
        "sqli": [r"sqli", r"sql[-_ ]?injection", r"generic[-_ ]?sqli"],
        "xss":  [r"xss", r"cross[-_ ]?site[-_ ]?scripting"],
        "rce":  [r"command[-_ ]?injection", r"rce", r"os[-_ ]?command"],
    }

    def _candidate_dirs() -> list[Path]:
        envs = [
            os.getenv("SECLISTS_DIR"),
            os.getenv("PAYLOADS_DIR"),
            os.getenv("PAYLOADS_ALL_THE_THINGS_DIR"),
        ]
        guesses = [
            "./SecLists",
            "./seclists",
            "./wordlists/seclists",
            "./PayloadsAllTheThings",
            "./payloads-all-the-things",
            "./payloads",
        ]
        out: list[Path] = []
        for d in envs + guesses:
            if not d:
                continue
            p = Path(d)
            if p.exists() and p.is_dir():
                out.append(p)
        return out

    def _iter_files_for_category(category: str):
        pats = [re.compile(pat, re.I) for pat in _CAT_PATTERNS.get(category, [re.escape(category)])]
        for root in _candidate_dirs():
            for path in root.rglob("*"):
                if not path.is_file():
                    continue
                name = path.name.lower()
                if not (name.endswith(".txt") or name.endswith(".payload") or name.endswith(".list")):
                    continue
                full = str(path).lower().replace("\\", "/")
                if any(p.search(full) for p in pats):
                    yield path

    @lru_cache(maxsize=16)
    def load_external_payloads(category: str, marker: str | None = None) -> list[str]:
        lines: list[str] = []
        seen: set[str] = set()
        count_limit = 4000
        for f in _iter_files_for_category(category):
            # Okunabilirlik kontrolü; open başarısız olursa hata üst katmana doğal taşınır (saklanmaz).
            if not os.access(f, os.R_OK):
                continue
            with open(f, "r", encoding="utf-8", errors="ignore") as fh:
                for line in fh:
                    s = line.strip()
                    if not s or s.startswith("#") or s.startswith("//"):
                        continue
                    if len(s) > 512:
                        continue
                    if marker:
                        for key in ("{MARK}", "{MARKER}", "FUZZ", "INJECT_HERE", "PAYLOAD", "§", "XSS", "MARKER"):
                            if key in s:
                                s = s.replace(key, marker)
                    if s in seen:
                        continue
                    lines.append(s)
                    seen.add(s)
                    if len(lines) >= count_limit:
                        break
            if len(lines) >= count_limit:
                break
        return lines

# --- Selenium opsiyonel – yoksa DOM-XSS adımları zarifçe atlanır ---
if _find_spec("selenium") is not None:
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
else:
    WebDriverWait = None  # type: ignore
    EC = None  # type: ignore

# --- Anomali metrikleri (opsiyonel): core.detect varsa kullan ---
if _find_spec("websecure.core.detect") is not None:
    from websecure.core.detect import anomaly_score as _anomaly_score  # type: ignore
else:
    _anomaly_score = None  # type: ignore

# --- Tarama derinliği (main.py detaylı modda WEBSECURE_DEPTH=2 set edilebilir) ---
def _safe_int_env(name: str, default_val: int) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default_val
    v = raw.strip()
    if re.fullmatch(r"[+-]?\d+", v) is None:
        return default_val
    return int(v)

_DEPTH = _safe_int_env("WEBSECURE_DEPTH", 1)
# =========================
# Ortak yardımcılar (SOLID)
# =========================

def generate_fuzz_payload(length: int = 20) -> str:
    chars = string.ascii_letters + string.digits + "!@#$%^&*()_+-=[]{}|;:,.<>?"
    return ''.join(random.choices(chars, k=length))

def _inject_into_query(url: str, key: str, value: str) -> str:
    p = urlparse(url)
    q = dict(parse_qsl(p.query, keep_blank_values=True))
    q[key] = value
    new_query = urlencode(q, doseq=True)
    return urlunparse((p.scheme, p.netloc, p.path, p.params, new_query, p.fragment))

def _append_param_if_missing(url: str, key: str, value: str) -> str:
    p = urlparse(url)
    q = list(parse_qsl(p.query, keep_blank_values=True))
    q.append((key, value))
    return urlunparse((p.scheme, p.netloc, p.path, p.params, urlencode(q, doseq=True), p.fragment))

def _measure(session, method: str, url: str, form_data: Optional[Dict] = None, timeout: int = 10) -> Tuple[int, float, str, Dict[str, str]]:
    """
    İstek ölçümü. Hata SAKLANMAZ; ağ/HTTP istisnaları üst katmana yükselir.
    """
    t0 = time.monotonic()

    m = (method or "").upper()
    if m not in ("GET", "POST"):
        raise ValueError(f"unsupported HTTP method: {method!r}")

    sp = urlsplit(url or "")
    if not sp.scheme or not sp.netloc:
        raise ValueError(f"invalid url: {url!r}")

    hdrs = build_waf_headers({}, get_waf_cfg())
    verify_flag = getattr(session, "verify", True)

    if m == "GET":
        r = session.get(url, headers=hdrs, timeout=timeout, verify=verify_flag, allow_redirects=True)
    else:
        r = session.post(url, data=(form_data or {}), headers=hdrs, timeout=timeout, verify=verify_flag, allow_redirects=True)

    dt = time.monotonic() - t0
    # getattr kullanımı burada AttributeError riskini kaldırır; istisna fırlatmadan alanları okur.
    return int(getattr(r, "status_code", -1)), dt, (getattr(r, "text", "") or ""), dict(getattr(r, "headers", {}) or {})

def _html_contains_unescaped(text: str, payload: str) -> bool:
    if payload in (text or ""):
        return True
    un = html_unescape(text or "")
    if payload in un:
        return True
    compact = re.sub(r"\s+", "", text or "", flags=re.S)
    if re.sub(r"\s+", "", payload) in compact:
        return True
    return False

def _domain_of(url: str) -> str:
    return urlsplit(url).netloc.lower()

def _origin_of(url: str) -> Tuple[str, int, str, str]:
    """host, port, scheme, path"""
    p = urlparse(url)
    host = p.hostname or ""
    scheme = (p.scheme or "http").lower()
    port = p.port or (443 if scheme == "https" else 80)
    path = p.path or "/"
    return host, port, scheme, path

def _similarity(a: str, b: str) -> float:
    """
    0..1 arası benzerlik. core.detect varsa kullanır; çıktı beklenen tipte değilse
    sessizce düşmek yerine güvenli kontrollerle yerel hesaplamaya geçer.
    """
    if callable(_anomaly_score):
        base = {"len": len(a or ""), "time_samples": [0.0], "body": a or ""}
        cur  = {"len": len(b or ""), "time_ms": 0.0, "body": b or ""}
        sc = _anomaly_score(base, cur)  # Hata olursa istisna yükselir; saklama yok.
        if isinstance(sc, dict):
            met = sc.get("metrics") or {}
            lev = met.get("lev_ratio")
            if isinstance(lev, (int, float)):
                return float(lev)

    # Fallback – kaba oran (deterministik)
    a = (a or "")[:2000]
    b = (b or "")[:2000]
    if not a and not b:
        return 1.0
    same = sum(1 for i in range(min(len(a), len(b))) if a[i] == b[i])
    return same / max(1, max(len(a), len(b)))

def _vary_headers(headers: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    # WAF kaçınma: request bazlı başlık seti oluştur (session.headers’ı globalde kirletme)
    h = dict(headers or {})
    h.update({
        "X-Requested-With": random.choice(["XMLHttpRequest", "Fetch"]),
        "Accept": random.choice(["text/html,application/xhtml+xml", "*/*"]),
        "Cache-Control": random.choice(["no-cache", "max-age=0", "no-store"]),
    })
    return h

# Redirect yardımcıları
_REDIRECT_KEYS = [
    "next", "redirect", "redirect_uri", "redirect_url", "return", "returnTo",
    "continue", "url", "dest", "destination", "goto", "forward", "to"
]

def _is_external(to_url: str, base_url: str) -> bool:
    bu = urlparse(base_url)
    tu = urlparse(to_url)
    if not tu.scheme or not tu.netloc:
        return False
    return (tu.hostname or "").lower() != (bu.hostname or "").lower()

# ============================
# Strategy-temelli çekirdekler
# ============================

class BaseCheck:
    """Tek sorumluluk: bir güvenlik kontrolünü yürütmek ve raporlamak."""
    name: str = "base"
    def __init__(self, session, results: Dict[str, Any], debug: bool = False):
        self.session = session
        self.results = results
        self.debug = debug

    def add(self, bucket: str, entry: Dict[str, Any]) -> None:
        self.results.setdefault(bucket, []).append(entry)

    def set_summary(self, bucket: str, vulns: int) -> None:
        self.results[f"{bucket}_summary"] = {"vulnerabilities": int(vulns)}

# --------------------
# SQL Injection Check
# --------------------

_SQLI_BASE = {
    "boolean": [
        "' OR '1'='1'--",
        "\" OR \"1\"=\"1\"--",
        "') OR ('1'='1",
        "1 OR 1=1--",
        "1') OR '1'='1' -- -",
    ],
    "error-based": [
        "' AND updatexml(1,concat(0x3a,user()),1)--",
        "' AND extractvalue(1,concat(0x3a,version()))--",
        "\" AND extractvalue(1,concat(0x3a,version()))--",
        "'||pg_sleep(0)--",
    ],
    "time-based": [
        "' AND SLEEP(5)--",
        "1' AND SLEEP(5)--",
        "\" AND SLEEP(5)--",
        "'; WAITFOR DELAY '0:0:5'--",
        "' AND pg_sleep(5)--",
    ],
    "bypass": [
        "' OR '1'='1' /*",
        "'/**/OR/**/'1'='1",
        "%27%20OR%201%3D1--",
        "'||(SELECT%201)%7C%7C'"
    ]
}
_SQLI_PAYLOADS = {k: (v * _DEPTH) for k, v in _SQLI_BASE.items()}
# --- Harici SQLi payloadları (SecLists/PayloadsAllTheThings/wordlists_custom) ---
# --- Dış SQLi payloadlarının yüklenmesi  ---
_load_ext = globals().get("load_external_payloads", None)
_EXT_SQLI = _load_ext("sqli") if callable(_load_ext) else []
if not isinstance(_EXT_SQLI, list):
    _EXT_SQLI = []

if _EXT_SQLI:
    _seen_ext: set[str] = set()
    if isinstance(_SQLI_PAYLOADS, dict):
        _SQLI_PAYLOADS.setdefault("external", [])
        for _p in _EXT_SQLI:
            _ps = (_p or "").strip()
            if _ps and _ps not in _seen_ext:
                _seen_ext.add(_ps)
                _SQLI_PAYLOADS["external"].append(_ps)

_SQLI_ERRORS = [
    "you have an error in your sql syntax","warning: mysql","unclosed quotation mark after the character string",
    "quoted string not properly terminated","syntax error","pg_query","mysql_fetch",
    "ORA-01756","SQLite3::query","SQLSTATE"
]

class SQLiCheck(BaseCheck):
    name = "sql_injection"

    def run(self, url: str, method: str = "GET", form_data: Optional[Dict] = None) -> int:
        bucket = f"{self.name}_{method.lower()}"
        self.results[bucket] = []

        # ---- Girdi/ortam doğrulamaları (saklama yok) ----
        m = (method or "").upper()
        if m not in ("GET", "POST"):
            raise ValueError(f"unsupported HTTP method: {method!r}")

        parsed = urlparse(url or "")
        if not parsed.scheme or not parsed.netloc:
            raise ValueError(f"invalid url: {url!r}")

        qp = parse_qsl(parsed.query, keep_blank_values=True)

        if m == "GET":
            if not qp:
                url = _append_param_if_missing(url, "sqltest", "1")
                qp = [("sqltest", "1")]
            target_params = [k for k, _ in qp]
        else:
            if not form_data:
                self.add(bucket, {"issue": "POST verisi eksik", "severity": "Yok"})
                self.set_summary(bucket, 0)
                return 0
            target_params = list(form_data.keys())

        # ---- Baz çizgisi ----
        b_code, b_dt, b_text, _ = _measure(self.session, m, url, form_data)
        vulns = 0

        def record(payload, ptype, key, dt, text, note=None, sev="Yüksek", status="Potansiyel açık"):
            nonlocal vulns
            self.add(bucket, {
                "param": key, "payload": payload, "type": ptype,
                "status": status, "details": (note or "")[:300],
                "severity": sev,
                "remediation": "Parametreleri prepared statements ile bağlayın; hata mesajlarını maskeleyin; WAF/IPS uygulayın."
            })
            if status.startswith("Potansiyel"):
                vulns += 1

        # ---- Deterministik payload çalıştırma (saklama yok) ----
        # 1. Polyglots ekle
        polyglots = get_builtin_payloads("polyglot")
        if polyglots:
            _SQLI_PAYLOADS["polyglot"] = polyglots

        for ptype, plist in _SQLI_PAYLOADS.items():

            logging.info(f"[SQLi] Test türü: {ptype}")
            for key in target_params:
                waf_cfg = get_waf_cfg()
                for payload in (v for _p in plist for v in mutate_payload('sqli', _p, waf_cfg)):
                    if m == "GET":
                        test_url = _inject_into_query(url, key, payload)
                        code, dt, text, _ = _measure(self.session, "GET", test_url, None)
                    else:
                        data = (form_data or {}).copy()
                        data[key] = payload
                        code, dt, text, _ = _measure(self.session, "POST", url, data)

                    tl = (text or "").lower()

                    # Hata imzası ya da 500
                    if any(k in tl for k in _SQLI_ERRORS) or code == 500:
                        record(payload, ptype, key, dt, text, "Hata imzası/500")
                        continue

                    # time-based – anomaly_score varsa kullan
                    if ptype == "time-based":
                        if callable(_anomaly_score):
                            base = {"len": len(b_text), "time_samples": [b_dt * 1000], "body": b_text}
                            cur  = {"len": len(text),  "time_ms": dt * 1000,  "body": text}
                            sc = _anomaly_score(base, cur)  # beklenen: dict
                            if isinstance(sc, dict):
                                sig = sc.get("signals") or {}
                                met = sc.get("metrics") or {}
                                if bool(sig.get("time")):
                                    stdv = met.get("time_stddev")
                                    note = f"Zaman sapması (stddev): {round(float(stdv), 2)}ms" if isinstance(stdv, (int, float)) else "Zaman sapması"
                                    record(payload, ptype, key, dt, text, note)
                                    continue
                        # lokal eşik
                        if dt > max(b_dt + 2.5, b_dt * 2.5, 4.5):
                            record(payload, ptype, key, dt, text, f"Gecikme: {dt:.2f}s")
                            continue

                    # boolean – içerik benzerliği
                    if ptype == "boolean":
                        pos, neg = "' AND 1=1--", "' AND 1=2--"
                        if m == "GET":
                            u_pos = _inject_into_query(url, key, pos)
                            u_neg = _inject_into_query(url, key, neg)
                            s1, _, t1, _ = _measure(self.session, "GET", u_pos, None)
                            s2, _, t2, _ = _measure(self.session, "GET", u_neg, None)
                        else:
                            d1 = (form_data or {}).copy(); d1[key] = pos
                            d2 = (form_data or {}).copy(); d2[key] = neg
                            s1, _, t1, _ = _measure(self.session, "POST", url, d1)
                            s2, _, t2, _ = _measure(self.session, "POST", url, d2)
                        sim = _similarity(t1, t2)
                        if (len(t1) != len(t2)) or (s1 != s2) or sim < 0.85:
                            record(payload, ptype, key, dt, text, f"Boolean içerik farkı (sim={sim:.2f})")
                            continue

                    if self.debug:
                        self.add(bucket, {"param": key, "payload": payload, "type": ptype, "status": "Açık bulunamadı", "severity": "Yok"})

        # ---- Fuzz (hafif) ----
        logging.info("[SQLi] Fuzz Testi")
        for _ in range(4 * _DEPTH):
            fuzz = generate_fuzz_payload(36)
            for key in target_params:
                if m == "GET":
                    test_url = _inject_into_query(url, key, fuzz)
                    code, dt, text, _ = _measure(self.session, "GET", test_url, None)
                else:
                    data = (form_data or {}).copy(); data[key] = fuzz
                    code, dt, text, _ = _measure(self.session, "POST", url, data)
                if any(k in (text or "").lower() for k in _SQLI_ERRORS):
                    self.add(bucket, {
                        "param": key, "payload": fuzz, "type": "fuzz",
                        "status": "Potansiyel açık", "details": "Hata imzası", "severity": "Yüksek",
                        "remediation": "Girdi doğrulaması, genel hata mesajları, parametrik sorgu."
                    })
                    vulns += 1

        self.set_summary(bucket, vulns)
        logging.info(f"[SQLi] Toplam potansiyel: {vulns}")
        return vulns

# -------
# XSS
# -------

def _xss_payloads(marker: str) -> List[str]:
    mk = "" if marker is None else str(marker)
    m = quote_plus(mk)

    base = [
        f"<script>alert('{mk}')</script>",
        f'" autofocus onfocus=alert(\'{mk}\') x="',
        f"'><svg/onload=alert('{mk}')>",
        f"<img src=x onerror=alert('{mk}')>",
        f"<iframe src=javascript:alert('{mk}')></iframe>",
        f"<details open ontoggle=alert('{mk}')>x</details>",
        f"<body onload=alert('{mk}')>",
        f"<math><mtext></mtext><annotation-xml><svg/onload=alert('{mk}')></svg></annotation-xml></math>",
        f"'></textarea><script>alert('{mk}')</script>",
        f"%3Cscript%3Ealert('{m}')%3C/script%3E",
    ]

    # Dış XSS payloadları: çekirdek varsa kullan; yoksa boş liste.
    ext: List[str] = []
    _load = globals().get("load_external_payloads")
    if callable(_load):
        res = _load("xss", marker=mk)
        if isinstance(res, list):
            ext = res

    seen: set[str] = set()
    out: List[str] = []
    for s in (base + ext):
        if s not in seen:
            seen.add(s)
            out.append(s)

    if _DEPTH > 1:
        out *= _DEPTH

    return out

def _xss_payloads_extended(marker: str) -> List[str]:
    """Basic + Advanced + Polyglots for XSS"""
    base = _xss_payloads(marker)
    adv = get_builtin_payloads("xss_advanced")
    pol = get_builtin_payloads("polyglot")
    
    # Marker inject into advanced payloads if possible, simplistic replace
    final_adv = []
    for p in adv:
        if "alert(1)" in p:
             final_adv.append(p.replace("alert(1)", f"alert('{marker}')"))
        else:
             final_adv.append(p)
             
    return _dedup_list(base + final_adv + pol)

def _dedup_list(seq):
    seen = set()
    return [x for x in seq if not (x in seen or seen.add(x))]


def _dom_sink_probe_js(marker: str) -> str:
    return f"""
    (function(){{
        window.__xssProbe=window.__xssProbe||{{fired:false,notes:[]}};
        var mk='{marker}';
        function note(n){{ try{{ if(__xssProbe.notes.indexOf(n)<0) __xssProbe.notes.push(n); }}catch(e){{}} }}
        var _write=document.write; document.write=function(s){{ try{{ if((s||'').indexOf(mk)>-1) note('document.write'); }}catch(e){{}} return _write.apply(document, arguments); }};
        var _eval=window.eval; window.eval=function(s){{ try{{ if((s||'').indexOf(mk)>-1) note('eval'); }}catch(e){{}} return _eval.call(window, s); }};
        var _ac = Element.prototype.appendChild;
        Element.prototype.appendChild = function(child){{
            try{{ if(child && child.outerHTML && child.outerHTML.indexOf(mk)>-1) note('appendChild'); }}catch(e){{}}
            return _ac.call(this, child);
        }};
        var s=(location.search||'')+(location.hash||'');
        if(s.indexOf(mk)>-1) note('url_reflect');
    }})();
    """

class XSSCheck(BaseCheck):
    name = "xss"

    def run(self, url: str, method: str = "GET", form_data: Optional[Dict] = None, driver=None) -> int:
        bucket = f"{self.name}_{method.lower()}"
        self.results[bucket] = []

        # ---- Girdi/ortam doğrulamaları (saklama yok) ----
        m = (method or "").upper()
        if m not in ("GET", "POST"):
            raise ValueError(f"unsupported HTTP method: {method!r}")

        parsed = urlparse(url or "")
        if not parsed.scheme or not parsed.netloc:
            raise ValueError(f"invalid url: {url!r}")

        qp = parse_qsl(parsed.query, keep_blank_values=True)
        if m == "GET":
            if not qp:
                url = _append_param_if_missing(url, "xsstest", "")
                qp = [("xsstest", "")]
            target_params = [k for k, _ in qp]
        else:
            if not form_data:
                self.add(bucket, {"issue": "POST verisi eksik", "severity": "Yok"})
                self.set_summary(bucket, 0)
                return 0
            target_params = list(form_data.keys())

        marker = f"WSXSS_{random.randint(10**5, 10**6-1)}"
        payloads = _xss_payloads_extended(marker)

        waf_cfg = get_waf_cfg()
        payloads = [v for p in payloads for v in mutate_payload('xss', p, waf_cfg)]
        vulns = 0

        # ---- DOM XSS  ----
        # Selenium mevcut ve sürücü temel API'leri varsa çalıştır
        if (
            m == "GET"
            and driver is not None
            and callable(getattr(driver, "get", None))
            and callable(getattr(driver, "execute_script", None))
            and target_params
        ):
            key0 = target_params[0]
            for p in payloads:
                test_url = _inject_into_query(url, key0, p)

                # Boş sayfa + prob enjekte
                driver.get("about:blank")
                driver.execute_script(_dom_sink_probe_js(marker))  # __xssProbe.{alerted,notes[]} beklenir
                driver.get(test_url)

                # 4 sn boyunca bayrak/nota bakarak anketle
                deadline = time.monotonic() + 4.0
                fired = False
                probe_notes = ""
                while time.monotonic() < deadline:
                    res = driver.execute_script(
                        "return (function(){var s=window.__xssProbe||{};"
                        "return {a:!!s.alerted, n:(s.notes||[]).join(',')};})();"
                    )
                    if isinstance(res, dict):
                        fired = bool(res.get("a"))
                        probe_notes = (res.get("n") or "")
                    if fired or probe_notes:
                        break
                    time.sleep(0.2)

                if fired or probe_notes:
                    proof_b64 = ""
                    if callable(getattr(driver, "get_screenshot_as_png", None)):
                        png = driver.get_screenshot_as_png()
                        proof_b64 = base64.b64encode(png).decode()
                        if len(proof_b64) > 200000:
                            proof_b64 = proof_b64[:200000]

                    self.add(bucket, {
                        "payload": p, "type": "DOM", "status": "Potansiyel açık",
                        "details": f"Sink: {probe_notes}" if probe_notes else "Alert/Hook tetiklendi",
                        "severity": "Yüksek",
                        "proof": {"screenshot_b64": proof_b64} if proof_b64 else {},
                        "remediation": "Tehlikeli DOM sink’lerini (document.write/innerHTML/eval) kaçının; DOMPurify + sıkı CSP."
                    })
                    vulns += 1
                elif self.debug:
                    self.add(bucket, {"payload": p, "type": "DOM", "status": "Açık bulunamadı", "severity": "Yok"})

        # ---- Reflected / Stored ----
        for p in payloads:
            if m == "GET":
                for key in target_params:
                    test_url = _inject_into_query(url, key, p)
                    code, dt, text, _ = _measure(self.session, "GET", test_url, None)
                    if _html_contains_unescaped(text, p):
                        self.add(bucket, {
                            "payload": p, "type": f"Reflected:{key}", "status": "Potansiyel açık",
                            "details": "Payload yanıtta encode edilmeden döndü", "severity": "Yüksek",
                            "proof": {"body_sample": (text or "")[:400]},
                            "remediation": "Context-uyumlu encoding (HTML/Attr/JS/CSS/URL) uygulayın."
                        })
                        vulns += 1
                    elif self.debug:
                        self.add(bucket, {"payload": p, "type": f"Reflected:{key}", "status": "Açık bulunamadı", "severity": "Yok"})
            else:
                for key in target_params:
                    data = (form_data or {}).copy()
                    data[key] = p
                    code, dt, text, _ = _measure(self.session, "POST", url, data)
                    if _html_contains_unescaped(text, p):
                        self.add(bucket, {
                            "payload": p, "type": f"Stored/Reflected:{key}", "status": "Potansiyel açık",
                            "details": "Payload encode edilmeden döndü", "severity": "Yüksek",
                            "proof": {"body_sample": (text or "")[:400]},
                            "remediation": "Depolanan çıktılar için encode + CSP; şablon motoru ile otomatik escaping."
                        })
                        vulns += 1
                    elif self.debug:
                        self.add(bucket, {"payload": p, "type": f"Stored/Reflected:{key}", "status": "Açık bulunamadı", "severity": "Yok"})

        # ---- Fuzz ----
        logging.info("[XSS] Fuzz Testi")
        for _ in range(4 * _DEPTH):
            fuzz = generate_fuzz_payload(28)
            for key in target_params:
                if m == "GET":
                    test_url = _inject_into_query(url, key, fuzz)
                    code, dt, text, _ = _measure(self.session, "GET", test_url, None)
                else:
                    data = (form_data or {}).copy()
                    data[key] = fuzz
                    code, dt, text, _ = _measure(self.session, "POST", url, data)

                if _html_contains_unescaped(text, fuzz):
                    self.add(bucket, {
                        "payload": fuzz, "type": f"fuzz:{key}", "status": "Potansiyel açık",
                        "details": "Fuzz payload encode edilmeden döndü", "severity": "Orta",
                        "proof": {"body_sample": (text or "")[:300]},
                        "remediation": "Tüm çıktılara uygun context encoding ve şablon motoru."
                    })
                    vulns += 1

        self.set_summary(bucket, vulns)
        logging.info(f"[XSS] Toplam potansiyel: {vulns}")
        return vulns

# -------------------------------
# CMD Injection + LFI/Traversal
# -------------------------------

_CMDI_PAYLOADS = [
    "&& id", "; id", "| id", "|| whoami", "`id`", "$(id)",
    "& cmd.exe /c whoami",    # Windows
]

# Harici RCE/CMDi payloadları ekle
# --- Dış RCE payloadları (çekirdek sağlayıcı varsa kullan;) ---
_load_ext = globals().get("load_external_payloads", None)
_EXT_RCE = _load_ext("rce") if callable(_load_ext) else []
if not isinstance(_EXT_RCE, list):
    _EXT_RCE = []

if _EXT_RCE:
    _seen_cmdi = set(_CMDI_PAYLOADS)
    for _p in _EXT_RCE:
        _ps = (_p or "").strip()
        if _ps and _ps not in _seen_cmdi:
            _CMDI_PAYLOADS.append(_ps)
            _seen_cmdi.add(_ps)

_LFI_PAYLOADS = [
    "../../etc/passwd", "../../../etc/passwd", "../../../../etc/passwd",
    "..\\..\\..\\windows\\win.ini", "/etc/passwd",
]
_LFI_SIGNS = ["root:x:0:0:", "[extensions]", "[fonts]", "daemon:x:"]
_SHELL_SIGNS = ["uid=", "gid=", "groups=", "nt authority", "windows", "whoami"]

class CMDICheck(BaseCheck):
    name = "cmd_injection"

    def run(self, url: str, method: str = "GET", form_data: Optional[Dict] = None) -> int:
        bucket = f"{self.name}_{method.lower()}"
        self.results[bucket] = []
        vulns = 0

        # ---- Girdi/ortam doğrulamaları ----
        m = (method or "").upper()
        if m not in ("GET", "POST"):
            raise ValueError(f"unsupported HTTP method: {method!r}")

        parsed = urlparse(url or "")
        if not parsed.scheme or not parsed.netloc:
            raise ValueError(f"invalid url: {url!r}")

        qp = parse_qsl(parsed.query, keep_blank_values=True)
        if m == "GET":
            targets = [k for k, _ in (qp or [("cmdtest", "")])]
            if not qp:
                url = _append_param_if_missing(url, "cmdtest", "")
        else:
            if not form_data:
                self.set_summary(bucket, 0)
                return 0
            targets = list(form_data.keys())

        waf_cfg = get_waf_cfg()
        mutated_payloads = [v for _p in (_CMDI_PAYLOADS * _DEPTH) for v in mutate_payload("rce", _p, waf_cfg)]

        for key in targets:
            for p in mutated_payloads:
                if m == "GET":
                    test_url = _inject_into_query(url, key, p)
                    code, dt, text, _ = _measure(self.session, "GET", test_url, None)
                else:
                    data = (form_data or {}).copy()
                    data[key] = p
                    code, dt, text, _ = _measure(self.session, "POST", url, data)

                low = (text or "").lower()
                if any(sig in low for sig in _SHELL_SIGNS):
                    self.add(bucket, {
                        "param": key, "payload": p, "status": "Potansiyel açık",
                        "details": "Komut çıktısı benzeri imza", "severity": "Kritik",
                        "remediation": "Kullanıcı girdisini shell'e iletmeyin; whitelist + argüman ayrımı."
                    })
                    vulns += 1
                    break  # aynı param için daha fazla deneme yapma

                if self.debug and code >= 500:
                    self.add(bucket, {"param": key, "payload": p, "status": "Sunucu hatası", "severity": "Uyarı"})

        self.set_summary(bucket, vulns)
        return vulns

class LFITraversalCheck(BaseCheck):
    name = "path_traversal"

    def run(self, url: str, method: str = "GET", form_data: Optional[Dict] = None) -> int:
        bucket = f"{self.name}_{method.lower()}"
        self.results[bucket] = []
        vulns = 0

        # Girdi/ortam doğrulama
        m = (method or "").upper()
        if m not in ("GET", "POST"):
            raise ValueError(f"unsupported HTTP method: {method!r}")

        parsed = urlparse(url or "")
        if not parsed.scheme or not parsed.netloc:
            raise ValueError(f"invalid url: {url!r}")

        qp = parse_qsl(parsed.query, keep_blank_values=True)
        if m == "GET":
            targets = [k for k, _ in (qp or [("file", "")])]
            if not qp:
                url = _append_param_if_missing(url, "file", "")
        else:
            if not form_data:
                self.set_summary(bucket, 0)
                return 0
            targets = list(form_data.keys())

        for key in targets:
            for p in _LFI_PAYLOADS * _DEPTH:
                if m == "GET":
                    test_url = _inject_into_query(url, key, p)
                    code, dt, text, _ = _measure(self.session, "GET", test_url, None)
                else:
                    data = (form_data or {}).copy()
                    data[key] = p
                    code, dt, text, _ = _measure(self.session, "POST", url, data)

                low = (text or "").lower()
                if any(sig in low for sig in _LFI_SIGNS):
                    self.add(bucket, {
                        "param": key, "payload": p, "status": "Potansiyel açık",
                        "details": "İçerikte sistem dosyası imzası", "severity": "Yüksek",
                        "remediation": "Path birleştirmeyi sabit kökte yapın; '..' filtreleyin; allowlist + gerçek FS kontrolleri."
                    })
                    vulns += 1
                    break

                if self.debug and code in (403, 406):
                    self.add(bucket, {"param": key, "payload": p, "status": f"{code} yanıt", "severity": "Uyarı"})

        self.set_summary(bucket, vulns)
        return vulns

        return vulns

# ---------------
# Exploit Injection Check
# ---------------
class ExploitCheck(BaseCheck):
    name = "exploit_injection"

    def run(self, url: str, method: str = "GET", form_data: Optional[Dict] = None) -> int:
        bucket = f"{self.name}_{method.lower()}"
        self.results[bucket] = []
        vulns = 0
        
        # Sadece known dangerous payloadları dener (Log4J, SSTI, ShellShock)
        payloads = get_builtin_payloads("exploit")
        if not payloads:
            return 0
            
        m = (method or "").upper()
        parsed = urlparse(url or "")
        qp = parse_qsl(parsed.query, keep_blank_values=True)
        
        if m == "GET":
            targets = [k for k, _ in qp]
            if not targets: targets = ["q"] # fallback
        else:
            targets = list(form_data.keys()) if form_data else []

        waf_cfg = get_waf_cfg()
        # Mutate payloads (obfuscation, encoding)
        final_payloads = []
        for p in payloads:
            final_payloads.extend(mutate_payload("exploit", p, waf_cfg))
        # Add a few raw ones just in case mutation breaks logic
        final_payloads = list(dict.fromkeys(payloads + final_payloads))

        for key in targets:
            for p in final_payloads:
                # OAST token injection (simple substitution)
                # Burasi komplex olabilir, simdilik raw atiyoruz
                # Payload icinde {{HOST}} varsa oast ile degistirilebilir ama su an basit tutalim
                
                if m == "GET":
                     test_url = _inject_into_query(url, key, p)
                     code, dt, text, headers = _measure(self.session, "GET", test_url)
                else:
                     data = (form_data or {}).copy()
                     data[key] = p
                     code, dt, text, headers = _measure(self.session, "POST", url, data)
                
                # Basit imza kontrolü (SSTI matematik sonucu vb)
                # 7*7 = 49
                if "49" in (text or "") and ("{{7*7}}" in p or "${7*7}" in p):
                     self.add(bucket, {"param": key, "payload": p, "type": "SSTI", "severity": "Yüksek", "details": "Template injection aritmetik sonuc dondu (49)"})
                     vulns += 1
                
                # ShellShock
                if "root:x:0:0" in (text or "") and "ShellShock" in p: # payload logic check
                     self.add(bucket, {"param": key, "payload": p, "type": "RCE", "severity": "Kritik", "details": "/etc/passwd okundu (ShellShock)"})
                     vulns += 1
                     
        self.set_summary(bucket, vulns)
        return vulns

# Open Redirect
# ---------------

class OpenRedirectCheck(BaseCheck):
    name = "open_redirect"

    def run(self, url: str, method: str = "GET", form_data: Optional[Dict] = None) -> int:
        bucket = f"{self.name}_{method.lower()}"
        self.results[bucket] = []
        vulns = 0

        # Doğrulama
        m = (method or "").upper()
        if m not in ("GET", "POST"):
            raise ValueError(f"unsupported HTTP method: {method!r}")

        parsed = urlparse(url or "")
        if not parsed.scheme or not parsed.netloc:
            raise ValueError(f"invalid url: {url!r}")

        qp = parse_qsl(parsed.query, keep_blank_values=True)
        keys = [k for k, _ in qp] or _REDIRECT_KEYS
        if m == "GET" and not qp:
            url = _append_param_if_missing(url, "redirect", "http://attacker.example")

        candidates = [
            "https://attacker.example", "http://attacker.example", "//attacker.example",
            "https://attacker.example/%2f%2e%2e",
        ]

        for key in keys[:12]:
            for val in candidates:
                if m == "GET":
                    test_url = _inject_into_query(url, key, val)
                    r_code, _, _, hdrs = _measure(self.session, "GET", test_url, None)
                    loc = (hdrs or {}).get("Location", "")
                else:
                    data = (form_data or {}).copy()
                    data[key] = val
                    r_code, _, _, hdrs = _measure(self.session, "POST", url, data)
                    loc = (hdrs or {}).get("Location", "")

                if 300 <= r_code < 400 and _is_external(loc, url):
                    self.add(bucket, {
                        "param": key, "payload": val, "status": "Potansiyel açık",
                        "details": f"3xx Location: {loc}", "severity": "Yüksek",
                        "remediation": "Yönlendirme hedeflerinde allowlist; göreceli yolları dış URL’ye çevirmeyin."
                    })
                    vulns += 1
                    break

        self.set_summary(bucket, vulns)
        return vulns

# -------------------------
# CORS aktif yanlış yapılandırma
# -------------------------

class CORSActiveCheck(BaseCheck):
    name = "cors_active"

    def run(self, url: str) -> int:
        bucket = self.name
        self.results[bucket] = []
        vulns = 0

        parsed = urlparse(url or "")
        if not parsed.scheme or not parsed.netloc:
            raise ValueError(f"invalid url: {url!r}")

        test_origins = ["https://evil.attacker", "http://evil.local"]
        for origin in test_origins:
            r = self.session.get(
                url,
                timeout=8,
                allow_redirects=True,
                verify=getattr(self.session, "verify", True),
                headers={"Origin": origin, "Referer": origin + "/"},
            )
            acao = r.headers.get("Access-Control-Allow-Origin", "")
            acac = r.headers.get("Access-Control-Allow-Credentials", "")
            vary = r.headers.get("Vary", "")

            if (acao == "*" and acac.lower() == "true") or (acao == origin and acac.lower() == "true"):
                self.add(bucket, {
                    "origin": origin, "status": "Potansiyel açık",
                    "details": f"ACAO={acao}, ACAC={acac}, Vary={vary}",
                    "severity": "Yüksek" if acac.lower() == "true" else "Orta",
                    "remediation": "CORS’ta kredential’larla '*' kullanmayın; domain allowlist + Vary: Origin."
                })
                vulns += 1
            elif acao == origin and "Origin" not in vary:
                self.add(bucket, {
                    "origin": origin, "status": "Zayıf yapılandırma",
                    "details": f"Vary: Origin eksik (ACAO={acao})",
                    "severity": "Düşük",
                    "remediation": "Dinamik CORS yanıtlarında Vary: Origin kullanın."
                })

        self.set_summary(bucket, vulns)
        return vulns

# -------------------------
# Host Header Injection yardımcıları
# -------------------------

_HOST_POISON_HEADERS = {
    "Host": "evil.attacker",
    "X-Forwarded-Host": "evil.attacker",
    "X-Forwarded-Proto": "http",
    "X-Original-Host": "evil.attacker",
}

def _body_sig_struct(r_code: int, body: str, hdrs: Dict[str, str]) -> Tuple[int, int, str]:

    # status code
    if isinstance(r_code, int):
        code = r_code
    elif isinstance(r_code, str) and r_code.lstrip("+-").isdigit():
        code = int(r_code)
    else:
        code = 0

    # body length
    if isinstance(body, (str, bytes)):
        blen = len(body)
    else:
        # beklenmeyen tipleri stringleştirerek ölç
        blen = len(str(body)) if body is not None else 0

    # location header
    location = ""
    if isinstance(hdrs, dict):
        loc = hdrs.get("Location")
        if isinstance(loc, str):
            location = loc

    return (int(code), int(blen), location)
# Gerekli importlar (dosyada zaten varsa yinelenmesine gerek yok)
import time
import socket
import ssl as pyssl
from typing import Optional, Dict, Tuple, List
from urllib.parse import urlparse, parse_qsl

# -------------------------
# LFI / Path Traversal
# -------------------------

class HostHeaderInjectionCheck(BaseCheck):
    name = "host_header_injection"

    def run(self, url: str) -> int:
        bucket = self.name
        self.results[bucket] = []
        vulns = 0

        parsed = urlparse(url or "")
        if not parsed.scheme or not parsed.netloc:
            raise ValueError(f"invalid url: {url!r}")

        code0, _, text0, hdrs0 = _measure(self.session, "GET", url, None)
        s0 = _body_sig_struct(code0, text0, hdrs0)

        poisoned = _vary_headers({"Host": _HOST_POISON_HEADERS["Host"]})
        poisoned.update({k: v for k, v in _HOST_POISON_HEADERS.items() if k != "Host"})

        verify_flag = getattr(self.session, "verify", True)
        r = self.session.get(
            url, timeout=8, allow_redirects=True, verify=verify_flag, headers=poisoned
        )
        s1 = _body_sig_struct(r.status_code, (r.text or ""), dict(r.headers or {}))

        low = (r.text or "").lower()
        if ("evil.attacker" in low) or s1[2].startswith(("http://evil.attacker", "https://evil.attacker")):
            self.add(bucket, {
                "status": "Potansiyel açık",
                "details": f"Header yansıması veya Location saptandı (baseline={s0}, poisoned={s1})",
                "severity": "Yüksek",
                "remediation": "Host başlığını reverse proxy’de sabitleyin; X-Forwarded-* başlıklarını doğrulayın."
            })
            vulns += 1
        elif s0 != s1 and abs(s0[1] - s1[1]) > 200:
            self.add(bucket, {
                "status": "Şüpheli davranış",
                "details": f"Gövde imzası ciddi değişti (baseline={s0}, poisoned={s1})",
                "severity": "Orta",
                "remediation": "Proxy’de Host/Forwarded başlıklarını allowlist ile sınırlandırın."
            })
            vulns += 1

        self.set_summary(bucket, vulns)
        return vulns

# -------------------------
# SSTI mini-probe
# -------------------------

_SSTI_PAYLOADS = ["{{7*7}}", "${{7*7}}", "#{7*7}".replace("{", "{").replace("}", "}"), "<%= 7*7 %>", "${7*7}"]

def _ssti_match(txt: str) -> bool:
    t = (txt or "")
    return ("49" in t) or ("<49>" in t) or ("=49" in t)

class SSTICheck(BaseCheck):
    name = "ssti"

    def run(self, url: str, method: str = "GET", form_data: Optional[Dict] = None) -> int:
        bucket = f"{self.name}_{method.lower()}"
        self.results[bucket] = []
        vulns = 0

        m = (method or "").upper()
        if m not in ("GET", "POST"):
            raise ValueError(f"unsupported HTTP method: {method!r}")

        parsed = urlparse(url or "")
        if not parsed.scheme or not parsed.netloc:
            raise ValueError(f"invalid url: {url!r}")

        qp = parse_qsl(parsed.query, keep_blank_values=True)
        if m == "GET":
            targets = [k for k, _ in (qp or [("tpl", "")])]
            if not qp:
                url = _append_param_if_missing(url, "tpl", "")
        else:
            if not form_data:
                self.set_summary(bucket, 0)
                return 0
            targets = list(form_data.keys())

        for key in targets:
            for p in _SSTI_PAYLOADS * _DEPTH:
                if m == "GET":
                    test_url = _inject_into_query(url, key, p)
                    code, dt, text, _ = _measure(self.session, "GET", test_url, None)
                else:
                    data = (form_data or {}).copy()
                    data[key] = p
                    code, dt, text, _ = _measure(self.session, "POST", url, data)

                if _ssti_match(text):
                    self.add(bucket, {
                        "param": key, "payload": p, "status": "Potansiyel açık",
                        "details": "SSTI işaretleri (49) görüldü",
                        "severity": "Yüksek",
                        "proof": {"body_sample": (text or "")[:400]},
                        "remediation": "Şablonda otomatik escaping açın; güvenilmeyen ifadeleri evaluate etmeyin."
                    })
                    vulns += 1
                    break

        self.set_summary(bucket, vulns)
        return vulns

# -------------------------
# HTTP Request Smuggling
# -------------------------

def _hrs_send(host: str, port: int, scheme: str, raw: bytes, timeout: int = 6) -> Tuple[int, bytes]:
    """
    Basit H1 gönderici.
    """
    # TCP bağlantısı
    with socket.create_connection((host, port), timeout=timeout) as s_plain:
        s_plain.settimeout(timeout)
        if scheme == "https":
            ctx = pyssl.create_default_context()
            with ctx.wrap_socket(s_plain, server_hostname=host) as s:
                s.sendall(raw)
                s.settimeout(timeout)
                data = s.recv(4096) or b""
        else:
            s_plain.sendall(raw)
            data = s_plain.recv(4096) or b""

    status = 0
    if data.startswith(b"HTTP/1."):
        parts = data.split(b" ", 2)
        if len(parts) >= 2:
            code_bytes = parts[1]
            if code_bytes.isdigit():
                status = int(code_bytes.decode())
            else:
                # Bazı durumlarda (örn. 1xx) farklı format olabilir; status 0 bırakılır
                status = 0
    return status, data

class RequestSmugglingCheck(BaseCheck):
    name = "request_smuggling"

    def run(self, get_url: str) -> int:
        bucket = self.name
        self.results[bucket] = []
        vulns = 0

        host, port, scheme, path = _origin_of(get_url)

        probe1 = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            "Content-Length: 4\r\n"
            "Transfer-Encoding: chunked\r\n"
            "Connection: keep-alive\r\n\r\n"
            "5\r\nabcde\r\n0\r\n\r\n"
        ).encode()

        probe2 = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            "Transfer-Encoding: chunked\r\n"
            "Content-Length: 3\r\n"
            "Connection: keep-alive\r\n\r\n"
            "0\r\n\r\nX"
        ).encode()

        st1, d1 = _hrs_send(host, port, scheme, probe1)
        time.sleep(0.2)
        st2, d2 = _hrs_send(host, port, scheme, probe2)

        if (st1 in (200, 202, 204)) or (st2 in (200, 202, 204)):
            self.add(bucket, {
                "status": "Şüpheli davranış",
                "details": f"CL/TE={st1}, TE/CL={st2}",
                "severity": "Orta",
                "remediation": "Proxy uyumlu TE/CL işleme; HTTP/2; reverse proxy’de TE başlıklarını strip edin."
            })
            vulns += 1
        elif (st1 == 0 and len(d1) == 0) or (st2 == 0 and len(d2) == 0):
            self.add(bucket, {
                "status": "Belirsiz",
                "details": "Yanıt yok/kapandı (olasılı: middlebox/timeout)",
                "severity": "Düşük",
                "remediation": "Zincirde CL/TE çakışmasını engelleyin veya tek biçem zorlayın."
            })

        self.set_summary(bucket, vulns)
        return vulns
# -------------------------
# GraphQL Introspection
# -------------------------

_GRAPHQL_PATHS = ["/graphql", "/api/graphql", "/graphiql", "/playground"]

def _base_of(u: str) -> str:
    p = urlparse(u); return f"{p.scheme}://{p.netloc}"

# Gerekli importlar (dosyada zaten varsa yinelenmesine gerek yok)
import os
import json
from typing import Optional, Dict, Tuple, List
from urllib.parse import urlparse, parse_qsl

# -------------------------
# GraphQL Introspection
# -------------------------

class GraphQLIntrospectionCheck(BaseCheck):
    name = "graphql_introspection"

    def run(self, get_url: str) -> int:
        bucket = self.name
        self.results[bucket] = []
        vulns = 0

        base = _base_of(get_url)
        payload = {"query": "query IntrospectionQuery { __schema { types { name } } }"}
        headers = {"Content-Type": "application/json"}

        for path in _GRAPHQL_PATHS:
            ep = base.rstrip("/") + (path if path.startswith("/") else f"/{path}")
            r = self.session.post(
                ep,
                data=json.dumps(payload),
                headers=headers,
                timeout=10,
                verify=getattr(self.session, "verify", True),
                allow_redirects=True,
            )
            txt = (r.text or "")
            if r.status_code == 200 and "__schema" in txt:
                self.add(bucket, {
                    "endpoint": ep, "status": "Introspection açık",
                    "severity": "Orta",
                    "remediation": "Prod’da introspection’ı kapatın veya yalnız yetkili rollere sınırlayın."
                })
                vulns += 1
                break
            elif self.debug and r.status_code not in (404, 405):
                self.add(bucket, {"endpoint": ep, "status": f"Yanıt {r.status_code}", "severity": "Yok"})

        self.set_summary(bucket, vulns)
        return vulns

# -------------------------
# SSRF Gelişmiş
# -------------------------

_SSRF_KEYS = [
    "url","uri","link","image","image_url","avatar","feed","fetch","u","target","dest",
    "destination","next","callback","continue","redirect","download","path","resource"
]
_SSRF_VALUES_BASE = [
    "http://127.0.0.1:80/","http://localhost:80/","http://169.254.169.254/latest/meta-data/","http://[::1]/",
]

class SSRFAdvancedCheck(BaseCheck):
    name = "ssrf"

    def run(self, url: str, method: str = "GET", form_data: Optional[Dict] = None) -> int:
        bucket = f"{self.name}_{method.lower()}"
        self.results[bucket] = []
        vulns = 0

        ssrf_values = list(_SSRF_VALUES_BASE)
        collab = os.getenv("COLLABORATOR_DOMAIN") or os.getenv("OAST_DOMAIN")
        if collab:
            ssrf_values += [f"http://{collab}/x", f"https://{collab}/x"]

        parsed = urlparse(url or "")
        if not parsed.scheme or not parsed.netloc:
            raise ValueError(f"invalid url: {url!r}")

        qp = parse_qsl(parsed.query, keep_blank_values=True)
        if (method or "").upper() == "GET":
            keys = [k for k, _ in qp] or _SSRF_KEYS
            if not qp:
                url = _append_param_if_missing(url, "url", "http://127.0.0.1/")
        else:
            keys = list((form_data or {}).keys()) or _SSRF_KEYS

        uniq_vals = list(dict.fromkeys(ssrf_values))
        m = (method or "").upper()

        for key in keys[:12]:
            for val in uniq_vals:
                if m == "GET":
                    test_url = _inject_into_query(url, key, val)
                    r = self.session.get(
                        test_url, timeout=10, allow_redirects=True, verify=getattr(self.session, "verify", True)
                    )
                else:
                    data = (form_data or {}).copy()
                    data[key] = val
                    r = self.session.post(
                        url, data=data, timeout=10, allow_redirects=True, verify=getattr(self.session, "verify", True)
                    )
                txt = (r.text or "").lower()
                if ("127.0.0.1" in txt) or ("latest/meta-data" in txt) or ("localhost" in txt) or (collab and collab in txt):
                    self.add(bucket, {
                        "param": key, "payload": val, "status": "Potansiyel SSRF",
                        "details": "Yanıtta hedef URL/anahtar kelimeler",
                        "severity": "Yüksek" if "meta-data" in txt else "Orta",
                        "remediation": "Dış istek yapan serviste allowlist; 169.254.169.254/localhost gibi özel ağları bloklayın."
                    })
                    vulns += 1
                    break
                if any(s in txt for s in ["connection refused", "timed out", "invalid host", "refused to connect"]):
                    self.add(bucket, {
                        "param": key, "payload": val, "status": "Şüpheli davranış",
                        "details": "Sunucu tarafı istek girişimi iması",
                        "severity": "Düşük",
                        "remediation": "URL şeması/host allowlist; DNS rebind koruması; protokol kısıtlaması."
                    })
                    vulns += 1
                    break

        self.set_summary(bucket, vulns)
        return vulns

# -------------------------
# File Upload (form meta)
# -------------------------

class FileUploadActiveCheck(BaseCheck):
    name = "file_upload_active"

    def run(self, results_context: Dict, driver=None) -> int:
        bucket = self.name
        self.results[bucket] = []
        vulns = 0

        if not isinstance(results_context, dict):
            raise ValueError("results_context must be a dict")

        forms = results_context.get("detected_forms") or []
        for fm in forms[:10]:
            inputs = fm.get("inputs") or []
            if not any((i.get("type") or "").lower() == "file" for i in inputs):
                continue
            action = fm.get("action_abs") or fm.get("action")
            if not action:
                continue

            files: Dict[str, Tuple[str, bytes, str]] = {}
            data: Dict[str, str] = {}
            for i in inputs:
                t = (i.get("type") or "text").lower()
                n = i.get("name")
                if not n:
                    continue
                if t == "file":
                    files[n] = ("poc.jpg", b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01", "image/jpeg")
                elif t in ("hidden", "submit"):
                    continue
                else:
                    data[n] = "test"

            r = self.session.post(
                action,
                data=data,
                files=files,
                timeout=12,
                allow_redirects=True,
                verify=getattr(self.session, "verify", True),
            )
            txt = (r.text or "").lower()
            if r.status_code in (200, 201) and ("poc.jpg" in txt or "uploads" in txt or "files" in txt):
                self.add(bucket, {
                    "form": fm.get("form_id") or fm.get("index"),
                    "action": action, "status": "Yükleme kabul edilmiş olabilir",
                    "severity": "Orta",
                    "remediation": "MIME/uzantı doğrulama, içerik tespiti, yürütülemez upload dizini."
                })
                vulns += 1

        self.set_summary(bucket, vulns)
        return vulns
# ==================================
# Dışa açık fonksiyonlar (geriye uyum)
# ==================================

def check_sql_injection(url: str, results: Dict, session, method: str = "GET",
                        form_data: Optional[Dict] = None, debug: bool = False) -> int:
    return SQLiCheck(session, results, debug).run(url, method, form_data)

def check_xss(url: str, results: Dict, session, method: str = "GET",
              form_data: Optional[Dict] = None, driver=None, debug: bool = False) -> int:
    return XSSCheck(session, results, debug).run(url, method, form_data, driver)

def check_command_injection(url: str, results: Dict, session, method: str = "GET",
                            form_data: Optional[Dict] = None, debug: bool = False) -> int:
    return CMDICheck(session, results, debug).run(url, method, form_data)

def check_path_traversal(url: str, results: Dict, session, method: str = "GET",
                         form_data: Optional[Dict] = None, debug: bool = False) -> int:
    return LFITraversalCheck(session, results, debug).run(url, method, form_data)

def check_open_redirect(url: str, results: Dict, session, method: str = "GET",
                        form_data: Optional[Dict] = None, debug: bool = False) -> int:
    return OpenRedirectCheck(session, results, debug).run(url, method, form_data)

def check_cors_misconfig_active(url: str, results: Dict, session, debug: bool = False) -> int:
    return CORSActiveCheck(session, results, debug).run(url)

def check_host_header_injection(url: str, results: Dict, session, debug: bool = False) -> int:
    return HostHeaderInjectionCheck(session, results, debug).run(url)

def check_ssti(url: str, results: Dict, session, method: str = "GET",
               form_data: Optional[Dict] = None, debug: bool = False) -> int:
    return SSTICheck(session, results, debug).run(url, method, form_data)

def check_request_smuggling(get_url: str, results: Dict, debug: bool = False) -> int:
    # HRS düşük seviyeli socket ister; session’a bağımlı değil → psödo-session yok
    return RequestSmugglingCheck(session=None, results=results, debug=debug).run(get_url)

def check_graphql_introspection(get_url: str, results: Dict, session, debug: bool = False) -> int:
    return GraphQLIntrospectionCheck(session, results, debug).run(get_url)

def check_ssrf_advanced(url: str, results: Dict, session, method: str = "GET",
                        form_data: Optional[Dict] = None, debug: bool = False) -> int:
    return SSRFAdvancedCheck(session, results, debug).run(url, method, form_data)

def check_file_upload_active(results: Dict, session, driver=None, debug: bool = False) -> int:
    return FileUploadActiveCheck(session, results, debug).run(results, driver)

def check_exploit_injection(url: str, results: Dict, session, method: str = "GET",
                            form_data: Optional[Dict] = None, debug: bool = False) -> int:
    return ExploitCheck(session, results, debug).run(url, method, form_data)

# -------------------------
# Brute-force / Rate-limit (login formu varsa)
# -------------------------

def _looks_like_login_form(fmeta: Dict) -> bool:
    if not isinstance(fmeta, dict):
        return False
    ins = fmeta.get("inputs") or []
    if not isinstance(ins, list):
        return False
    # Sadece dict olan inputları değerlendir
    dinputs = [i for i in ins if isinstance(i, dict)]
    if any("password" in (i.get("type") or "").lower() for i in dinputs):
        return True
    names = [(i.get("name") or "").lower() for i in dinputs]
    return any(("login" in n) or ("user" in n) or ("email" in n) for n in names)

def check_bruteforce_login(form_meta: Dict, results: Dict, session, debug: bool = False) -> int:
    logging.info("[Brute] Rate-limit kontrolü (hafif)")
    bucket = "bruteforce_login"
    if isinstance(results, dict):
        results[bucket] = []
    vulns = 0

    if not isinstance(form_meta, dict) or not isinstance(results, dict):
        logging.warning("[Brute] Geçersiz argümanlar (form_meta/results dict değil)")
        return 0

    action = form_meta.get("action") or form_meta.get("action_abs")
    if not action:
        results[f"{bucket}_summary"] = {"vulnerabilities": 0}
        return 0

    # Input’ları oku (yalnızca dict girdiler)
    data_base: Dict[str, str] = {}
    for inp in (form_meta.get("inputs") or []):
        if not isinstance(inp, dict):
            continue
        n = inp.get("name")
        if not n:
            continue
        t = (inp.get("type") or "text").lower()
        if ("pass" in t) or ("password" in n.lower()):
            data_base[n] = "Wrong@123!"
        elif ("user" in n.lower()) or ("login" in n.lower()) or ("email" in n.lower()):
            data_base[n] = "testuser@example.com"
        elif t in ("hidden", "submit"):
            continue
        else:
            data_base[n] = "x"

    tries, statuses, too_many_flags, last_r = 5, [], [], None
    verify_flag = getattr(session, "verify", True)

    for i in range(tries):
        data = data_base.copy()
        # Parola alanlarını her denemede farklılaştır (Wrong@… pattern’ini değiştir)
        data.update({k: (v + str(i)) if isinstance(v, str) and "Wrong@" in v else v for k, v in data.items()})
        r = session.post(action, data=data, timeout=8, allow_redirects=True, verify=verify_flag)
        last_r = r
        statuses.append(int(getattr(r, "status_code", 0)))
        too_many_flags.append("too many" in (getattr(r, "text", "") or "").lower())
        time.sleep(0.3)

    if all(s < 429 for s in statuses):
        ra = (last_r.headers.get("Retry-After", "") if last_r is not None else "")
        if not ra and not any(too_many_flags):
            results[bucket].append({
                "status": "Rate-limit zayıf",
                "details": f"Denemeler: {statuses}",
                "severity": "Orta",
                "remediation": "429 + Retry-After, hesap kilidi ve exponential backoff uygulayın."
            })
            vulns += 1

    results[f"{bucket}_summary"] = {"vulnerabilities": vulns}
    return vulns

# -------------------------
# Koşu & Toplayıcı (geriye uyum)
# -------------------------

def run_injection_checks(get_url: str, url: str, results: Dict, session, driver=None,
                         form_data: Optional[Dict] = None, debug: bool = False) -> Dict:
    total = 0
    total += check_sql_injection(get_url, results, session, "GET", None, debug)
    total += check_xss(get_url, results, session, "GET", None, driver, debug)
    total += check_command_injection(get_url, results, session, "GET", None, debug)
    total += check_path_traversal(get_url, results, session, "GET", None, debug)
    total += check_open_redirect(get_url, results, session, "GET", None, debug)
    total += check_cors_misconfig_active(get_url, results, session, debug)
    total += check_host_header_injection(get_url, results, session, debug)
    total += check_ssti(get_url, results, session, "GET", None, debug)
    total += check_exploit_injection(get_url, results, session, "GET", None, debug)

    total += check_request_smuggling(get_url, results, debug)
    total += check_graphql_introspection(get_url, results, session, debug)
    total += check_ssrf_advanced(get_url, results, session, "GET", None, debug)

    if form_data:
        total += check_sql_injection(get_url, results, session, "POST", form_data, debug)
        total += check_xss(url, results, session, "POST", form_data, driver, debug)
        total += check_command_injection(get_url, results, session, "POST", form_data, debug)
        total += check_path_traversal(get_url, results, session, "POST", form_data, debug)
        total += check_open_redirect(get_url, results, session, "POST", form_data, debug)
        total += check_ssti(get_url, results, session, "POST", form_data, debug)
        total += check_ssrf_advanced(get_url, results, session, "POST", form_data, debug)
        total += check_exploit_injection(get_url, results, session, "POST", form_data, debug)

    forms = results.get("detected_forms") or []
    for fm in forms[:3]:
        if _looks_like_login_form(fm):
            total += check_bruteforce_login(fm, results, session, debug)
            break

    total += check_file_upload_active(results, session, driver, debug)

    results["injection_overall_summary"] = {"vulnerabilities": total}
    return results

# ============================================================================
# ENTEGRASYON BLOĞU — kısa nottaki geliştirmeler entegre
# 1) Raporlama köprüsü (core.reporting.add_result / redact_sensitive) — opsiyonel
# 2) Kanıt zenginleştirme: timing_ms, headers örneği, match_offset
# 3) Hız sınırlama: config.fuzz.rate_ms + config.fuzz.rate_limit.{backoff_factor,max_rate_ms,max_consecutive_429}
#    429 için basit üstel backoff uygulanır.
# ============================================================================
from importlib.util import find_spec as _find_spec
import time
import re
import logging
from typing import Any, Dict, Optional, Tuple

# Opsiyonel raporlama entegrasyonu (circular import kaçınmak için dinamik)
if _find_spec("websecure.core.reporting") is not None:
    pass  # İleride burada hook tanımlanabilir
    from websecure.core.reporting import add_result as _core_add_result, redact_sensitive as _core_redact  # type: ignore
else:
    _core_add_result = None  # type: ignore
    def _core_redact(x):  # type: ignore
        return x

# Global son ölçüm bilgisi (son HTTP isteğinden)
_LAST_MEASURE: Dict[str, Any] = {"timing_ms": None, "headers": None, "text": None}

# --- Config yükle (saklama yok) ---
if _find_spec("websecure.core.utils") is not None:
    from websecure.core.utils import load_config as _load_config  # type: ignore
    _CFG = _load_config()
    if not isinstance(_CFG, dict):
        _CFG = {}
else:
    _CFG = {}

def _as_int(v, default: int) -> int:
    if isinstance(v, bool):
        return default
    if isinstance(v, int):
        return v
    if isinstance(v, str) and re.fullmatch(r"[+-]?\d+", v.strip() or ""):
        return int(v.strip())
    return default

def _as_float(v, default: float) -> float:
    if isinstance(v, (int, float)) and not isinstance(v, bool):
        return float(v)
    if isinstance(v, str) and re.fullmatch(r"[+-]?(\d+(\.\d*)?|\.\d+)", v.strip() or ""):
        return float(v.strip())
    return default

_fuzz = (_CFG.get("fuzz") or {}) if isinstance(_CFG, dict) else {}
_rl = (_fuzz.get("rate_limit") or {}) if isinstance(_fuzz, dict) else {}

_BASE_RATE_MS: int = _as_int(_fuzz.get("rate_ms", 0), 0)
_BACKOFF: float = _as_float(_rl.get("backoff_factor", 2.0), 2.0)
_MAX_RATE_MS: int = _as_int(_rl.get("max_rate_ms", max(2000, _BASE_RATE_MS if _BASE_RATE_MS else 0)),
                            max(2000, _BASE_RATE_MS if _BASE_RATE_MS else 0))
_MAX_429: int = _as_int(_rl.get("max_consecutive_429", 6), 6)
_RATE_STATE: Dict[str, int] = {"current_ms": _BASE_RATE_MS, "consec_429": 0}

def _report_add_result(bucket: str, entry: dict) -> None:
    if callable(_core_add_result):  # type: ignore
        _core_add_result(bucket, entry)  # type: ignore

def _compute_match_offset(text: str, payload: str) -> int:
    t = (text or "")
    p = (payload or "")
    return t.lower().find(p.lower()) if (t and p) else -1

# --- BaseCheck.add için monkey-patch (kanıt zenginleştirme + rapor yazımı) ---
def _enhanced_add(self, bucket: str, entry: Dict[str, Any]) -> None:  # type: ignore
    lm = _LAST_MEASURE
    proof = dict(entry.get("proof") or {})

    # timing_ms
    tms = lm.get("timing_ms")
    if (tms is not None) and ("timing_ms" not in proof):
        if isinstance(tms, (int, float)):
            proof["timing_ms"] = int(tms)

    # match_offset
    if ("payload" in entry) and lm.get("text") and ("match_offset" not in proof):
        idx = _compute_match_offset(lm.get("text") or "", entry.get("payload"))  # type: ignore
        if isinstance(idx, int) and idx >= 0:
            proof["match_offset"] = idx

    # headers (örnek ilk 5)
    if lm.get("headers") and ("headers" not in proof):
        hdrs = lm.get("headers")
        if isinstance(hdrs, dict):
            sample: Dict[str, Any] = {}
            for i, k in enumerate(hdrs.keys()):
                if i >= 5:
                    break
                sample[k] = hdrs[k]
            proof["headers"] = sample

    if proof:
        entry = dict(entry)
        entry["proof"] = proof

    entry = _core_redact(entry)  # type: ignore
    self.results.setdefault(bucket, []).append(entry)
    _report_add_result(bucket, entry)

# Sınıf metodu yaması (BaseCheck mevcutsa uygula)
_BaseCheck_cls = globals().get("BaseCheck")
if _BaseCheck_cls is not None and hasattr(_BaseCheck_cls, "add"):
    setattr(_BaseCheck_cls, "add", _enhanced_add)  # type: ignore

# --- _measure fonksiyonunu gelişmiş sürümle override et ---
def _measure_adv(session, method: str, url: str, form_data: Optional[Dict[str, Any]] = None, timeout: int = 10) -> Tuple[int, float, str, Dict[str, str]]:  # type: ignore
    # Hız sınırlama (basit): her isteğin öncesinde bekle
    ms = int(_RATE_STATE.get("current_ms") or 0)
    if ms > 0:
        time.sleep(ms / 1000.0)

    t0 = time.monotonic()

    hdrs = build_waf_headers({}, get_waf_cfg())
    verify_flag = getattr(session, "verify", True)
    m = (method or "").upper()

    if m == "GET":
        r = session.get(url, headers=hdrs, timeout=timeout, verify=verify_flag, allow_redirects=True)
    elif m == "POST":
        r = session.post(url, data=(form_data or {}), headers=hdrs, timeout=timeout, verify=verify_flag, allow_redirects=True)
    else:
        raise ValueError(f"unsupported HTTP method: {method!r}")

    dt = time.monotonic() - t0

    # Son ölçümü kaydet
    _LAST_MEASURE["timing_ms"] = int(dt * 1000)
    _LAST_MEASURE["headers"] = dict(getattr(r, "headers", {}) or {})
    _LAST_MEASURE["text"] = getattr(r, "text", "") or ""

    # 429 yanıtında basit üstel backoff
    sc = int(getattr(r, "status_code", 0) or 0)
    if sc == 429:
        _RATE_STATE["consec_429"] = int(_RATE_STATE.get("consec_429", 0)) + 1
        cur = int(_RATE_STATE.get("current_ms") or 0) or _BASE_RATE_MS
        nxt = int(cur * _BACKOFF) if cur > 0 else int(_BASE_RATE_MS * _BACKOFF)
        if _MAX_RATE_MS:
            nxt = min(nxt, _MAX_RATE_MS)
        _RATE_STATE["current_ms"] = nxt
        if _RATE_STATE["consec_429"] >= _MAX_429 and _BASE_RATE_MS > 0:
            _RATE_STATE["current_ms"] = _BASE_RATE_MS
            _RATE_STATE["consec_429"] = 0
    else:
        if _RATE_STATE.get("consec_429", 0) > 0:
            _RATE_STATE["consec_429"] = 0
            _RATE_STATE["current_ms"] = _BASE_RATE_MS

    return sc, dt, (_LAST_MEASURE["text"] or ""), dict(_LAST_MEASURE["headers"] or {})

# === 3B/7B: SSRF/XXE temel taraması (saklama yok) ===

# Use enhanced _measure implementation without redefining the name
_measure = _measure_adv
def scan_ssrf_xxe(session, url: str, params: list[str], cfg: dict, add, oast_client=None):
    base = str((((cfg or {}).get("oast") or {}).get("base_url")) or "http://oast.local").rstrip("/")

    # Fuzzer sağlayıcı
    _ssrf_payloads = None
    if _find_spec("fuzzing.param_fuzzer") is not None:
        from websecure.fuzzing.param_fuzzer import ssrf_payloads as _ssrf_payloads  # type: ignore

    def _fallback_ssrf(b: str) -> list[str]:
        return [b + "/p"]

    _ssrf = _ssrf_payloads or _fallback_ssrf

    for k in (params or []):
        for p in _ssrf(base):  # type: ignore
            r = session.get(url, params={k: p}, timeout=8, allow_redirects=True, verify=getattr(session, "verify", True))
            if int(getattr(r, "status_code", 0) or 0) >= 500:
                add("ssrf_xxe", {"param": k, "payload": p, "status": "Sunucu hatası", "severity": "Uyarı"})

# ============================================================================
# SQLMap API Entegrasyonu (Cleaned & Decoupled)
# ============================================================================
# Bu bölüm, SQLi bulgularını otomatik doğrulamak için harici entegrasyonu kullanır.
# Mantık artık 'websecure.integrations.sqlmap' modülündedir.
# ----------------------------------------------------------------------------

from websecure.integrations.sqlmap import SQLMapClient

def run_sqlmap_api_scan(target_url: str, api_url: str = "http://127.0.0.1:8775",
                       options: Optional[Dict] = None) -> List[Dict]:
    """
    SQLMap API üzerinden tarama başlatır ve sonuçları döner.
    Delegates to integrations.sqlmap.SQLMapClient.
    """
    # İstemciyi başlat
    client = SQLMapClient(api_url)
    if not client.is_alive(api_url):
        logging.getLogger(__name__).warning(f"SQLMap API erişilemez: {api_url}")
        return []

    # Task oluştur
    task_id = client.new_task()
    if not task_id:
        return []
        
    logging.getLogger(__name__).info(f"SQLMap Task {task_id} @ {target_url}")

    # Varsayılan seçenekler (API'ye uygun formatta)
    # Not: SQLMapClient.start_scan clean dict bekler
    final_opts = options or {}
    final_opts.setdefault("risk", 1)
    final_opts.setdefault("level", 1)
    
    if not client.start_scan(target_url, final_opts):
        client.delete_task()
        return []

    # İzleme döngüsü (basit)
    while True:
        status = client.get_status()
        if status in ("terminated", "not running"):
            break
        if status == "unknown":
            break
        time.sleep(2.0)

    # Sonuçları al
    data = client.get_data()
    client.delete_task()
    
    return data

_NORM_SEV_MAP = {
    "critical": "Kritik", "kritik": "Kritik",
    "high": "Yüksek",     "yüksek": "Yüksek",
    "medium": "Orta",     "orta": "Orta",
    "low": "Düşük",       "düşük": "Düşük",
    "info": "Bilgi",      "bilgi": "Bilgi",
}

def _tr_sev(x: str) -> str:
    x = (x or "").strip().lower()
    return _NORM_SEV_MAP.get(x, "Bilgi")

# --- OAST doğrulama köprüsü (sync, try/except yok) -------------------------
def verify_oast_findings(candidates, session=None, timeout: int = 10):
    """OAST bulgularını doğrulama için sade köprü.
    Not: Bu sürüm, harici OAST sağlayıcısıyla doğrudan konuşmaz.
    Girdi bulgularını 'verified=False' ve 'status=pending' ile geri döndürür.
    Akış: flow_runner bu dönüşü rapora ekler; gerçek doğrulama sağlanırsa
    osat.py içindeki client üzerinden genişletilebilir.
    """
    if not isinstance(candidates, (list, tuple)):
        return []
    out = []
    for it in candidates:
        if isinstance(it, dict):
            d = dict(it)
            if 'verified' not in d:
                d['verified'] = False
            if 'status' not in d:
                d['status'] = 'pending'
            out.append(d)
    return out


# --- Bulguları doğrula + skorla (deterministik, try/except yok) -----------
_SEV_SCORE = {
    "Kritik": 9,
    "Yüksek": 7,
    "Orta":   5,
    "Düşük":  2,
    "Bilgi":  0,
}

def _norm_severity(val) -> str:
    if not val:
        return "Bilgi"
    x = str(val).strip().lower()
    return _NORM_SEV_MAP.get(x, "Bilgi")


def verify_findings_and_score(candidates, session=None):
    """Bulgu yapısını normalize eder ve özet skor döndürür.
    Giriş bir liste/tuple ya da {kategori: [bulgu,...]} sözlüğü olabilir.
    Çıkış: { 'counts': {sev: n}, 'total': N, 'score': S, 'by_category': {...} }
    """
    def _score_item(d: dict) -> dict:
        sev = d.get('severity') or d.get('risk') or d.get('level')
        sev = _norm_severity(sev)
        d['severity'] = sev
        d['score'] = int(_SEV_SCORE.get(sev, 0))
        if not d.get('status'):
            d['status'] = 'pending'
        return d

    summary = {"counts": {"Kritik":0,"Yüksek":0,"Orta":0,"Düşük":0,"Bilgi":0}, "total":0, "score":0, "by_category": {}}

    if isinstance(candidates, dict):
        for cat, items in candidates.items():
            if not isinstance(items, (list, tuple)):
                continue
            cat_list = []
            for it in items:
                if isinstance(it, dict):
                    dd = _score_item(dict(it))
                    cat_list.append(dd)
                    summary["counts"][dd["severity"]] += 1
                    summary["total"] += 1
                    summary["score"] += dd["score"]
            summary["by_category"][cat] = cat_list
        return summary

    out = []
    if isinstance(candidates, (list, tuple)):
        for it in candidates:
            if isinstance(it, dict):
                out.append(_score_item(dict(it)))
        # liste için de özet döndürelim
        for dd in out:
            summary["counts"][dd["severity"]] += 1
            summary["total"] += 1
            summary["score"] += dd["score"]
        summary["by_category"]["_"] = out
        return summary
    return summary
