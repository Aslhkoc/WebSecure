import csv
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from typing import Any, Dict, List, Optional

try:
    import requests as _requests
except ImportError:
    _requests = None  # type: ignore[assignment]

from websecure.integrations.base import (
    ToolFinding,
    ToolIntegration,
    ToolResult,
    ToolSeverity,
    ToolStatus,
    effective_timeout,
)

logger = logging.getLogger(__name__)

# sqlmap canlı çıktısında kullanıcıya GÖSTERILECEK anlamlı satırlar. Aksi halde
# tarama tamamen sessiz koşuyordu (stdout PIPE'a yutuluyordu) → kullanıcı "sqlmap
# çalıştığını HİÇ görmedim" diyordu. Bu işaretler sqlmap'in gerçek ilerlemesidir:
# parametre testi, dinamiklik, injectable tespiti, DBMS/banner, WAF, enjeksiyon
# noktaları. Gürültülü "loading"/"fetched" satırları echolanmaz.
_SQLMAP_ECHO_MARKERS = (
    "testing connection", "target url content is stable", "is dynamic",
    "might be injectable", "appears to be", "testing for sql injection",
    "is vulnerable", "injectable", "identified the following injection",
    "the back-end dbms", "banner:", "current user", "current database",
    "hostname:", "is dba", "available databases", "WAF/IPS", "web application",
    "heuristic", "parameter '", "retrieved:", "resumed:",
)
# Her seviye [CRITICAL]/[WARNING]/[ERROR] satırı daima gösterilir.
_SQLMAP_ECHO_LEVELS = ("[CRITICAL]", "[WARNING]", "[ERROR]")
# DBMS/observation çıkarımı için (run summary'de gösterilir). Yalnız ONAYLANMIŞ
# DBMS adını yakala (kısa token); "it looks like ... Do you want" tahmin/prompt
# satırlarını DEĞİL.
_SQLMAP_DBMS_RE = re.compile(
    r"back-end DBMS(?:\s+is|:)\s*'?([A-Za-z][A-Za-z0-9 .>=_-]{1,30}?)'?(?:\.|,|\s*$|\s+Do you|\s+\()",
    re.IGNORECASE,
)


# Tekrarlayan/gürültülü satırlar — echolama (terminali boğar, anlam katmaz).
# "parsed DBMS error message" sqlmap her payload denemesinde basar (onlarca kez).
_SQLMAP_ECHO_SKIP = (
    "parsed DBMS error message",
    "reflective value(s) found",
    "skip test payloads specific",
    "using '",  # "using '...tmp' as the output directory"
)


def _sqlmap_echo_line(line: str) -> bool:
    """Bu sqlmap log satırı kullanıcıya canlı gösterilsin mi?"""
    s = line.strip()
    if not s:
        return False
    if any(sk.lower() in s.lower() for sk in _SQLMAP_ECHO_SKIP):
        return False
    if any(lv in s for lv in _SQLMAP_ECHO_LEVELS):
        return True
    low = s.lower()
    return any(m.lower() in low for m in _SQLMAP_ECHO_MARKERS)

class SQLMapClient:
    """
    Client for interacting with the SQLMap REST-JSON API.
    """
    def __init__(self, api_url: str = "http://127.0.0.1:8775"):
        self.api_url = api_url.rstrip("/")
        self.task_id: Optional[str] = None
        self.admin_id: Optional[str] = None

    def _req(self, method: str, path: str, json_data: Dict = None) -> Dict:
        """Internal helper for Making API requests."""
        if _requests is None:
            return {}
        url = f"{self.api_url}{path}"
        try:
            resp = _requests.request(method, url, json=json_data, timeout=5)
            resp.raise_for_status()
            return resp.json()
        except Exception as e:
            logger.debug(f"SQLMap API error ({path}): {e}")
            return {}

    def new_task(self) -> Optional[str]:
        """Creates a new task ID."""
        r = self._req("GET", "/task/new")
        if r.get("success"):
            self.task_id = r.get("taskid")
            return self.task_id
        return None

    def start_scan(self, url: str, options: Dict[str, Any] = None) -> bool:
        """Starts a scan on the current task ID."""
        if not self.task_id:
            return False
            
        opts = options or {}
        opts["url"] = url
        
        # Start scan
        r = self._req("POST", f"/scan/{self.task_id}/start", opts)
        return bool(r.get("success"))

    def get_status(self) -> str:
        """Returns scan status: 'running', 'terminated', 'not running'."""
        if not self.task_id:
            return "unknown"
        r = self._req("GET", f"/scan/{self.task_id}/status")
        return r.get("status", "unknown")

    def get_data(self) -> list:
        """Retrieves findings data."""
        if not self.task_id:
            return []
        r = self._req("GET", f"/scan/{self.task_id}/data")
        return r.get("data", [])

    def get_log(self) -> list:
        """Retrieves scan logs."""
        if not self.task_id:
            return []
        r = self._req("GET", f"/scan/{self.task_id}/log")
        return r.get("log", [])

    def delete_task(self) -> bool:
        """Clean up."""
        if not self.task_id:
            return True
        r = self._req("GET", f"/task/{self.task_id}/delete")
        self.task_id = None
        return bool(r.get("success"))

    @staticmethod
    def is_alive(api_url="http://127.0.0.1:8775") -> bool:
        """Fast check if API server is up."""
        if _requests is None:
            return False
        try:
            _requests.get(f"{api_url}/admin/list", timeout=3)
            return True
        except Exception:
            return False

class SQLMapWrapper(ToolIntegration):
    """
    Wrapper for SQLMap binary (direct execution).
    """

    @property
    def tool_name(self) -> str:
        return "sqlmap"

    def __init__(self, binary_path: str = "sqlmap"):
        super().__init__(binary_path)
        # Son scan() çalışmasının meta verisi (run_sqlmap_scan özetinde gösterilir).
        self.last_run_meta: Dict[str, Any] = {}

    def is_available(self) -> bool:
        if shutil.which(self.binary) is not None:
            return True
        # SQLMap is often a Python script in the tools/ directory — check there too
        from websecure.core.platform_compat import binary_candidates as _bc
        from websecure.core.paths import writable_root as _ws_root
        root = _ws_root()
        _script_candidates = [
            root / "tools" / "sqlmap" / "sqlmap.py",
            root / "tools" / "sqlmapproject-sqlmap-4a40101" / "sqlmap.py",
        ]
        for candidate in _script_candidates + list(_bc(root, "sqlmap")):
            if candidate.exists():
                self._binary_path = str(candidate)
                return True
        return False

    def run(self, target: str, **kwargs) -> ToolResult:
        """ToolIntegration interface — SQL injection scan on target."""
        start = time.monotonic()
        raw = self.scan(
            target,
            risk=kwargs.get("risk", 3),
            level=kwargs.get("level", 5),
            proxy=kwargs.get("proxy"),
            profile_cfg=kwargs.get("profile_cfg"),
        )
        findings = self._results_to_tool_findings(raw, target)
        return ToolResult(
            tool=self.tool_name, target=target, status=ToolStatus.SUCCESS,
            findings=findings, duration_s=time.monotonic() - start,
            extra={"raw": raw},
        )

    def _results_to_tool_findings(self, results: List[Dict[str, Any]], target: str) -> List[ToolFinding]:
        findings: List[ToolFinding] = []
        for r in results:
            param = r.get("parameter", "?")
            method = r.get("method", "GET")
            inj_types = ", ".join(i.get("type", "") for i in r.get("injections", []))
            evidence = json.dumps(r.get("evidence", {}))[:400]
            findings.append(ToolFinding(
                title=f"SQL Injection — {param} ({method})",
                severity=ToolSeverity.CRITICAL,
                url=r.get("url", target),
                tool=self.tool_name,
                description=r.get("description", f"SQLi in {param} via {inj_types}"),
                evidence=evidence,
                confidence="high",
                verified=True,
                tags=["sqli", "injection", method.lower()],
                raw=r,
            ))
        return findings

    def scan(self, target: str, batch: bool = True, risk: int = 3, level: int = 5, extra_args: List[str] = None, proxy: str = None, profile_cfg: dict = None, run_timeout: Optional[int] = None) -> List[Dict[str, Any]]:
        """
        Runs sqlmap on the target.
        Note: Parsing sqlmap textual output is hard. 
        We often use --batch and look for output folder or use known findings format.
        For integration purposes, we verify it runs. 
        Parsing results from stdout/csv is implemented basically.
        """
        if not self.is_available():
            logger.warning("SQLMap binary not found.")
            return []

        out_dir = tempfile.mkdtemp()
        fd, csv_path = tempfile.mkstemp(suffix=".csv")
        os.close(fd)

        try:
            # Profil ayarlarını uygula (_sqlmap config'den)
            _p = profile_cfg or {}
            _risk  = _p.get("risk", risk)
            _level = _p.get("level", level)
            _prof_extra = list(_p.get("extra_args", []))

            if not self.binary:
                logger.warning("[SQLMap] Binary path boş — atlanıyor")
                return []
            if self.binary.endswith(".py"):
                cmd = [sys.executable, self.binary]
            else:
                cmd = [self.binary]

            # -m flag varsa -u ekleme: sqlmap -u ve -m aynı anda verilirse
            # -u öncelik alır ve -m yoksayılır — URL listesi hiç okunmaz.
            _has_m_flag = extra_args and "-m" in extra_args
            if not _has_m_flag:
                cmd.extend(["-u", target])

            cmd.extend([
                "--batch",
                "--risk", str(_risk),
                "--level", str(_level),
                "--output-dir", out_dir,
                "--results-file", csv_path,
                "--disable-coloring",
                "--parse-errors",
            ])
            # [Fix] '--forms' ARTIK KOŞULSUZ EKLENMİYOR. Parametreli bir URL'de
            # (-u url?id=1) '--forms' sqlmap'i FORM aramaya zorluyor; form yoksa
            # "[CRITICAL] there were no forms found" deyip URL'nin KENDİ parametresini
            # (id) HİÇ test etmeden çıkıyordu → sqlmap'in "veri vermemesinin" sessiz
            # nedenlerinden biri. Form testi gerektiğinde çağıran (self-crawl yolu)
            # '--forms'u extra_args ile zaten ekliyor; POST/form hedefinde de öyle.
            if _prof_extra:
                cmd.extend(_prof_extra)
            if extra_args:
                cmd.extend(extra_args)

            # [robustness] Profil 'threads' ayarını --threads'e bağla. Config-ghost
            # fix: önceden _sqlmap.threads HİÇ komuta geçmiyordu (yalnız risk/level/
            # extra_args/timeout okunuyordu) → deep/fast profillerinin threads:10
            # paralelliği boşa gidiyordu. Yalnız ≥2 ve --delay YOKKEN ekle: sqlmap
            # --delay ile çoklu-thread'i tek thread'e düşürür/uyarır, o yüzden stealth
            # (delay=5, threads=1) etkilenmez. Bütçe içinde daha çok kapsam = sağlamlık.
            _threads = _p.get("threads")
            try:
                _threads = int(_threads) if _threads is not None else 0
            except (TypeError, ValueError):
                _threads = 0
            _has_threads = any(str(a).startswith("--threads") for a in cmd)
            _has_delay = any(str(a).startswith("--delay") for a in cmd)
            if _threads >= 2 and not _has_threads and not _has_delay:
                cmd.extend(["--threads", str(min(_threads, 10))])

            if proxy:
                cmd.extend(["--proxy", proxy.replace("socks5h://", "socks5://")])

            # Süre tavanı: kullanıcı-yönetimli FİRM bütçe (run_timeout) verilmişse onu
            # DOĞRUDAN kullan — no_timeout çarpanıyla (effective_timeout) ŞİŞİRME YOK
            # (sqlmap max-power modda bile sınırsız koşmasın, kullanıcı talebi). Bütçe
            # dolunca proc öldürülür ve --results-file/log'dan KISMİ sonuçlar
            # ayrıştırılır → onaylanan injection'lar kaybolmaz. run_timeout yoksa
            # (ör. ToolIntegration.run yolu) geriye dönük uyumluluk için eski davranış.
            if run_timeout is not None:
                _budget = int(run_timeout)
                _subproc_timeout = _budget
            else:
                _budget = int(_p.get("timeout", 600))
                _subproc_timeout = effective_timeout(_budget)

            print(f"\n  [sqlmap] Tarama başlıyor → {target}  (bütçe {int(_subproc_timeout)}s, level={_level} risk={_risk})")
            logger.info(f"Starting SQLMap binary scan on {target}...")
            # [Fix] CANLI ÇIKTI: eskiden stdout/stderr PIPE'a yutulup hiç gösterilmiyordu
            # → sqlmap'in çalıştığı GÖRÜLMÜYORDU. Artık satır satır okunur; anlamlı
            # satırlar terminale yansır (kullanıcı ilerlemeyi görür) ve TÜMÜ ayrıştırma
            # için biriktirilir. Timeout'ta bile o ana kadarki çıktı KAYBOLMAZ (eski
            # kod b"","" yapıp her şeyi atıyordu). stderr → stdout'a birleştirilir.
            import threading as _threading
            import queue as _queue
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                errors="replace",
            )
            _unreg = None
            try:
                from websecure.core.phases import register_child_proc, unregister_child_proc
                register_child_proc(proc)
                _unreg = unregister_child_proc
            except Exception:
                pass

            _lines: List[str] = []
            _dbms_seen = ""
            _echoed = 0
            _ECHO_CAP = 400  # terminali boğmamak için echo tavanı (parsing yine tam)
            _q: "_queue.Queue" = _queue.Queue()

            def _reader():
                try:
                    assert proc.stdout is not None
                    for _ln in proc.stdout:
                        _q.put(_ln)
                except Exception:
                    pass
                finally:
                    _q.put(None)  # sentinel: stdout kapandı

            _rt = _threading.Thread(target=_reader, daemon=True)
            _rt.start()

            _deadline = time.monotonic() + _subproc_timeout
            _timed_out = False
            while True:
                _remaining = _deadline - time.monotonic()
                if _remaining <= 0:
                    _timed_out = True
                    try:
                        proc.kill()
                    except Exception:
                        pass
                    logger.warning(
                        "[SQLMap] Firm bütçe doldu (%ds) — durduruldu; o ana kadarki çıktı korundu",
                        int(_subproc_timeout),
                    )
                    print(f"  [sqlmap] Bütçe doldu ({int(_subproc_timeout)}s) — durduruldu, kısmi sonuçlar ayrıştırılıyor.")
                    break
                try:
                    _ln = _q.get(timeout=min(1.0, _remaining))
                except _queue.Empty:
                    if proc.poll() is not None and _q.empty():
                        break
                    continue
                if _ln is None:  # reader bitti (stdout kapandı)
                    break
                _lines.append(_ln)
                if not _dbms_seen:
                    _m = _SQLMAP_DBMS_RE.search(_ln)
                    if _m:
                        _dbms_seen = _m.group(1).strip()
                if _echoed < _ECHO_CAP and _sqlmap_echo_line(_ln):
                    print(f"  [sqlmap] {_ln.rstrip()}")
                    _echoed += 1
            try:
                proc.wait(timeout=10)
            except Exception:
                pass
            if _unreg:
                try:
                    _unreg(proc)
                except Exception:
                    pass

            stdout = "".join(_lines)
            stderr = ""
            # Son çalışma meta verisi (run_sqlmap_scan özet için okur).
            self.last_run_meta = {
                "target": target,
                "elapsed_s": round(_subproc_timeout - max(0.0, _deadline - time.monotonic()), 1),
                "dbms": _dbms_seen,
                "timed_out": _timed_out,
                "output_lines": len(_lines),
                "cmd": " ".join(cmd[-12:]),
            }

            # Primary: parse structured CSV written by --results-file
            results = _parse_sqlmap_csv(csv_path, target)

            if not results:
                # Fallback: regex parsing of stdout/stderr
                results = _parse_sqlmap_output(stdout + "\n" + stderr, target)

                # Also check the log file sqlmap writes to out_dir
                for dirpath, _, filenames in os.walk(out_dir):
                    if "log" in filenames:
                        try:
                            with open(os.path.join(dirpath, "log"), encoding="utf-8", errors="replace") as fh:
                                log_text = fh.read()
                            extra = _parse_sqlmap_output(log_text, target)
                            seen = {r.get("parameter") for r in results}
                            for r in extra:
                                if r.get("parameter") not in seen:
                                    results.append(r)
                                    seen.add(r.get("parameter"))
                        except Exception as _fix_e:
                            logger.debug(f"[integrations.sqlmap] {type(_fix_e).__name__}: {_fix_e!r}")

            return results

        except Exception as e:
            logger.error(f"SQLMap binary execution error: {e}")
            return []
        finally:
            try:
                shutil.rmtree(out_dir)
            except Exception:
                pass
            try:
                os.remove(csv_path)
            except Exception:
                pass


def _parse_sqlmap_csv(csv_path: str, target: str) -> List[Dict[str, Any]]:
    """
    Parse sqlmap --results-file CSV output.
    Columns: Target URL, Place, Parameter, Technique(s), Note(s)
    Returns structured finding dicts compatible with _parse_sqlmap_output format.
    """
    results: List[Dict[str, Any]] = []
    try:
        with open(csv_path, newline="", encoding="utf-8", errors="replace") as f:
            reader = csv.DictReader(f)
            for row in reader:
                param = (row.get("Parameter") or row.get("parameter") or "").strip()
                place = (row.get("Place") or row.get("place") or "GET").strip().upper()
                techniques = (row.get("Technique(s)") or row.get("techniques") or "").strip()
                notes = (row.get("Note(s)") or row.get("notes") or "").strip()
                url = (row.get("Target URL") or row.get("target url") or target).strip()

                if not param:
                    continue

                inj_types = [t.strip() for t in techniques.split(",") if t.strip()]
                results.append({
                    "type": "SQL Injection",
                    "url": url,
                    "severity": "Critical",
                    "parameter": param,
                    "method": place,
                    "injections": [{"type": t} for t in inj_types],
                    "evidence": {"notes": notes} if notes else {},
                    "description": (
                        f"SQL injection in parameter '{param}' ({place}) "
                        f"via {techniques or 'unknown technique'}."
                    ),
                })
    except FileNotFoundError as _fix_e:
        logger.debug(f"[integrations.sqlmap] {type(_fix_e).__name__}: {_fix_e!r}")
    except Exception as e:
        logger.debug(f"[SQLMap] CSV parse error: {e}")
    return results


def _parse_sqlmap_output(text: str, target: str) -> List[Dict[str, Any]]:
    """
    Parse sqlmap textual output into structured finding dicts.

    Handles the multi-line block that sqlmap emits for each vulnerable parameter:

        Parameter: id (GET)
            Type: boolean-based blind
            Title: AND boolean-based blind - WHERE or HAVING clause
            Payload: id=1 AND 1=1-- -

    Also extracts: database banner, DBMS type, tables, users, retrieved data.
    """
    results: List[Dict[str, Any]] = []
    current: Optional[Dict[str, Any]] = None

    # Shared metadata extracted from the whole run
    dbms_banner: str = ""
    dbms_type:   str = ""
    databases:   List[str] = []
    db_users:    List[str] = []

    for line in text.splitlines():
        stripped = line.strip()

        # DBMS identification
        m = re.search(r"back-end DBMS:\s*(.+)", stripped, re.I)
        if m:
            dbms_type = m.group(1).strip()

        # Banner
        m = re.search(r"banner:\s*'([^']+)'", stripped, re.I)
        if m and not dbms_banner:
            dbms_banner = m.group(1).strip()

        # Available databases
        m = re.search(r"\[\*\]\s+(\w+)\s*$", stripped)
        if m and "available databases" in text[:text.find(stripped) + 50].lower():
            databases.append(m.group(1))

        # Current user / users
        m = re.search(r"current user is:\s*'([^']+)'", stripped, re.I)
        if m:
            db_users.append(m.group(1).strip())

        # -- Parameter block start -----------------------------------------
        m = re.match(r"Parameter:\s+(.+?)\s+\((\w+)\)", stripped)
        if m:
            if current:
                results.append(current)
            current = {
                "type":        "SQL Injection",
                "url":         target,
                "severity":    "Critical",
                "parameter":   m.group(1).strip(),
                "method":      m.group(2).upper(),
                "injections":  [],
                "evidence":    {},
                "description": "",
            }
            continue

        if current is None:
            continue

        # Injection type
        m = re.match(r"Type:\s+(.+)", stripped)
        if m:
            inj: Dict[str, Any] = {"type": m.group(1).strip()}
            current["injections"].append(inj)
            continue

        # Title
        m = re.match(r"Title:\s+(.+)", stripped)
        if m and current["injections"]:
            current["injections"][-1]["title"] = m.group(1).strip()
            continue

        # Payload
        m = re.match(r"Payload:\s+(.+)", stripped)
        if m and current["injections"]:
            current["injections"][-1]["payload"] = m.group(1).strip()
            continue

        # Retrieved data lines
        m = re.search(r"retrieved:\s+(.+)", stripped, re.I)
        if m:
            current["evidence"].setdefault("retrieved_data", []).append(m.group(1).strip())

    # Flush last block
    if current:
        results.append(current)

    # Annotate all findings with shared metadata
    for r in results:
        if dbms_type:
            r["evidence"]["dbms"] = dbms_type
        if dbms_banner:
            r["evidence"]["banner"] = dbms_banner
        if databases:
            r["evidence"]["databases"] = databases
        if db_users:
            r["evidence"]["db_users"] = db_users
        # Build human-readable description
        inj_types = ", ".join(i.get("type", "") for i in r.get("injections", []))
        r["description"] = (
            f"SQL injection in parameter '{r['parameter']}' ({r['method']}) "
            f"via {inj_types or 'unknown technique'}. "
            + (f"DBMS: {dbms_type}. " if dbms_type else "")
            + (f"Banner: {dbms_banner}." if dbms_banner else "")
        )

    return results
