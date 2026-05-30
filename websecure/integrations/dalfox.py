"""
websecure.integrations.dalfox
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
dalfox — hızlı XSS analiz ve doğrulama aracı entegrasyonu.

Özellikler
----------
* WebSecure XSS bulgularını dalfox ile doğrulama
* Tekil URL / parametre bazlı XSS taraması
* DOM XSS desteği
* Blind XSS (OOB callback ile)
* WAF bypass payload entegrasyonu
* Pipe mode: URL listesi stdin'den işleme
* ToolIntegration arayüzü (SOLID OCP/DIP)
"""
from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional
from websecure.integrations.base import (
    ToolFinding,
    ToolIntegration,
    ToolResult,
    ToolSeverity,
    ToolStatus,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# DalfoxFinding — dalfox ham bulgusu
# ---------------------------------------------------------------------------

@dataclass
class DalfoxFinding:
    """dalfox çıktısından ayrıştırılmış tek XSS bulgusu."""
    url: str
    param: str = ""
    payload: str = ""
    poc: str = ""
    cwe: str = "CWE-79"
    severity: str = "Medium"
    xss_type: str = ""          # "R" (Reflected), "S" (Stored), "D" (DOM)
    evidence: str = ""
    raw: Dict[str, Any] = field(default_factory=dict)

    @property
    def xss_type_full(self) -> str:
        _map = {"R": "Reflected XSS", "S": "Stored XSS", "D": "DOM XSS", "B": "Blind XSS"}
        return _map.get(self.xss_type, f"XSS ({self.xss_type})")


# ---------------------------------------------------------------------------
# DalfoxWrapper
# ---------------------------------------------------------------------------

class DalfoxWrapper(ToolIntegration):
    """
    dalfox XSS tarayıcı entegrasyonu.

    Hem tekil URL taraması hem de WebSecure bulgularını
    doğrulama (verify modu) destekler.
    """

    def __init__(
        self,
        binary_path: Optional[str] = None,
        worker_count: int = 100,
        timeout_s: int = 10,
        blind_callback: str = "",
        waf_evasion: bool = True,
        output_all: bool = False,
        proxy: str = "",
    ) -> None:
        super().__init__(binary_path or "dalfox")
        self.worker_count = worker_count
        self.timeout_s = timeout_s
        self.blind_callback = blind_callback
        self.waf_evasion = waf_evasion
        self.output_all = output_all
        self.proxy = proxy

    # ------------------------------------------------------------------ #
    # ToolIntegration arayüzü
    # ------------------------------------------------------------------ #

    @property
    def tool_name(self) -> str:
        return "dalfox"

    def is_available(self) -> bool:
        return (
            shutil.which(self.binary) is not None
            or (self._binary_path is not None and Path(self._binary_path).exists())
        )

    def version(self) -> Optional[str]:
        if not self.is_available():
            return None
        try:
            proc = subprocess.run(
                [self.binary, "version"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=10, check=False,
            )
            out = (proc.stdout or proc.stderr or b"").decode("utf-8", "ignore")
            return out.strip().splitlines()[0] if out.strip() else None
        except Exception:
            return None

    def run(self, target: str, **kwargs) -> ToolResult:
        """
        Tek URL'yi dalfox ile tara.

        Anahtar argümanlar
        ------------------
        params         : List[str] — test edilecek parametre isimleri
        data           : str — POST body
        cookie         : str — Cookie başlığı
        headers        : Dict[str, str] — Ek başlıklar
        method         : str — "GET" veya "POST"
        blind_callback : str — Blind XSS callback URL
        """
        return self.scan_url(
            url=target,
            params=kwargs.get("params", []),
            data=kwargs.get("data", ""),
            cookie=kwargs.get("cookie", ""),
            headers=kwargs.get("headers", {}),
            method=kwargs.get("method", "GET"),
            blind_callback=kwargs.get("blind_callback", self.blind_callback),
        )

    # ------------------------------------------------------------------ #
    # Tarama metotları
    # ------------------------------------------------------------------ #

    def scan_url(
        self,
        url: str,
        params: Optional[List[str]] = None,
        data: str = "",
        cookie: str = "",
        headers: Optional[Dict[str, str]] = None,
        method: str = "GET",
        blind_callback: str = "",
    ) -> ToolResult:
        """Tekil URL'yi dalfox ile tara."""
        if not self.is_available():
            logger.warning("[dalfox] Binary bulunamadı, atlanıyor.")
            return ToolResult(tool=self.tool_name, target=url, status=ToolStatus.NOT_FOUND)

        start = time.monotonic()
        fd, out_file = tempfile.mkstemp(suffix=".json", prefix="ws_dalfox_")
        os.close(fd)

        try:
            cmd = self._build_url_command(
                url=url,
                out_file=out_file,
                params=params or [],
                data=data,
                cookie=cookie,
                headers=headers or {},
                method=method,
                blind_callback=blind_callback or self.blind_callback,
            )

            logger.info(f"[dalfox] URL taranıyor -> {url}")
            _timeout_df = max(60, self.timeout_s * 30)
            proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            _register_cp = _unregister_cp = None
            try:
                from websecure.core.phases import register_child_proc, unregister_child_proc
                _register_cp, _unregister_cp = register_child_proc, unregister_child_proc
            except Exception as _fix_e:
                logger.debug(f"[integrations.dalfox] {type(_fix_e).__name__}: {_fix_e!r}")
            if _register_cp:
                _register_cp(proc)
            try:
                _, stderr_b = proc.communicate(timeout=_timeout_df)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.communicate()
                logger.warning(f"[dalfox] Timeout ({_timeout_df}s)")
                stderr_b = b""
            finally:
                if _unregister_cp:
                    _unregister_cp(proc)

            if proc.returncode not in (0, 1):
                stderr_out = (stderr_b or b"").decode("utf-8", "ignore")[:300]
                logger.warning(f"[dalfox] Çıkış kodu {proc.returncode}: {stderr_out}")

            dalfox_findings = self._parse_output(out_file)
            findings = self._to_tool_findings(dalfox_findings)
            duration = time.monotonic() - start

            logger.info(f"[dalfox] {url}: {len(findings)} XSS bulgusu  {duration:.1f}s")

            return ToolResult(
                tool=self.tool_name,
                target=url,
                status=ToolStatus.SUCCESS,
                findings=findings,
                duration_s=duration,
                extra={"dalfox_findings": [vars(df) for df in dalfox_findings]},
            )

        except Exception as exc:
            logger.error(f"[dalfox] Hata: {exc!r}", exc_info=True)
            return ToolResult(
                tool=self.tool_name, target=url, status=ToolStatus.ERROR, stderr=str(exc)
            )
        finally:
            try:
                os.unlink(out_file)
            except OSError:
                pass

    def verify_xss_findings(
        self,
        xss_findings: List[Dict[str, Any]],
        cookie: str = "",
    ) -> ToolResult:
        """
        WebSecure XSS bulgularını dalfox ile doğrula.

        XSS bulgularındaki URL + parametre bilgisini kullanarak
        dalfox ile otomatik doğrulama yapar.

        Parametreler
        ------------
        xss_findings : WebSecure native XSS bulgu listesi
        cookie       : Oturum cookie'si

        Döndürür
        --------
        ToolResult — Doğrulanan bulgular
        """
        if not self.is_available():
            return ToolResult(tool=self.tool_name, target="", status=ToolStatus.NOT_FOUND)

        all_findings: List[ToolFinding] = []
        start = time.monotonic()

        for finding in xss_findings:
            url = finding.get("url", "")
            if not url:
                continue

            # Parametreleri çıkart
            params = []
            ev = finding.get("evidence") or {}
            if isinstance(ev, dict) and ev.get("param"):
                params = [ev["param"]]

            result = self.scan_url(url=url, params=params, cookie=cookie)
            all_findings.extend(result.findings)

        return ToolResult(
            tool=self.tool_name,
            target="batch-verify",
            status=ToolStatus.SUCCESS,
            findings=all_findings,
            duration_s=time.monotonic() - start,
        )

    def scan_pipe(
        self,
        urls: List[str],
        cookie: str = "",
        headers: Optional[Dict[str, str]] = None,
    ) -> ToolResult:
        """
        URL listesini dalfox pipe moduyla tara.

        Tüm URL'ler tek bir dalfox pipe süreci üzerinden işlenir
        — toplu tarama için çok daha verimli.
        """
        if not self.is_available() or not urls:
            return ToolResult(tool=self.tool_name, target="", status=ToolStatus.NOT_FOUND)

        start = time.monotonic()
        fd_in, in_file = tempfile.mkstemp(suffix=".txt", prefix="ws_df_in_")
        fd_out, out_file = tempfile.mkstemp(suffix=".json", prefix="ws_df_out_")
        os.close(fd_in)
        os.close(fd_out)

        try:
            with open(in_file, "w", encoding="utf-8") as f:
                f.write("\n".join(urls))

            cmd = [self.binary, "pipe",
                   "--output", out_file, "--format", "json",
                   "--worker", str(self.worker_count),
                   "--timeout", str(self.timeout_s),
                   "--silence"]

            if cookie:
                cmd.extend(["-C", cookie])

            if self.waf_evasion:
                cmd.append("--waf-evasion")

            if self.proxy:
                cmd.extend(["--proxy", self.proxy])

            for h_name, h_val in (headers or {}).items():
                cmd.extend(["-H", f"{h_name}: {h_val}"])

            _pipe_timeout = max(120, len(urls) * 5)
            logger.info(f"[dalfox] pipe mode: {len(urls)} URL (timeout={_pipe_timeout}s)")

            with open(in_file, "rb") as stdin_f:
                proc = subprocess.Popen(
                    cmd,
                    stdin=stdin_f,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.PIPE,
                )
            _unregister_cp = None
            try:
                from websecure.core.phases import register_child_proc, unregister_child_proc
                register_child_proc(proc)
                _unregister_cp = unregister_child_proc
            except Exception as _fix_e:
                logger.debug(f"[integrations.dalfox] {type(_fix_e).__name__}: {_fix_e!r}")
            try:
                _, stderr_b = proc.communicate(timeout=_pipe_timeout)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.communicate()
                logger.warning(f"[dalfox] pipe zaman aşımı ({_pipe_timeout}s) — kısmi sonuçlar ayrıştırılıyor")
            finally:
                if _unregister_cp:
                    _unregister_cp(proc)

            dalfox_findings = self._parse_output(out_file)
            findings = self._to_tool_findings(dalfox_findings)
            duration = time.monotonic() - start

            logger.info(f"[dalfox] pipe: {len(findings)} XSS bulgusu  {duration:.1f}s")

            return ToolResult(
                tool=self.tool_name, target="pipe",
                status=ToolStatus.SUCCESS,
                findings=findings,
                duration_s=duration,
            )
        except Exception as exc:
            logger.error(f"[dalfox] pipe hatası: {exc!r}", exc_info=True)
            return ToolResult(tool=self.tool_name, target="pipe",
                              status=ToolStatus.ERROR, stderr=str(exc))
        finally:
            for p in (in_file, out_file):
                try:
                    os.unlink(p)
                except OSError:
                    pass

    # ------------------------------------------------------------------ #
    # Komut oluşturma
    # ------------------------------------------------------------------ #

    def _build_url_command(
        self,
        url: str,
        out_file: str,
        params: List[str],
        data: str,
        cookie: str,
        headers: Dict[str, str],
        method: str,
        blind_callback: str,
    ) -> List[str]:
        cmd = [
            self.binary, "url", url,
            "--output", out_file, "--format", "json",
            "--worker", str(self.worker_count),
            "--timeout", str(self.timeout_s),
            "--silence",
        ]

        if params:
            cmd.extend(["--only-discovery-param", ",".join(params)])

        if data:
            cmd.extend(["--data", data])

        if cookie:
            cmd.extend(["-C", cookie])

        if method.upper() == "POST":
            cmd.append("--method=POST")

        if blind_callback:
            cmd.extend(["--blind", blind_callback])

        if self.waf_evasion:
            cmd.append("--waf-evasion")

        if self.output_all:
            cmd.append("--output-all")

        if self.proxy:
            cmd.extend(["--proxy", self.proxy])

        for h_name, h_val in headers.items():
            cmd.extend(["-H", f"{h_name}: {h_val}"])

        return cmd

    # ------------------------------------------------------------------ #
    # Çıktı ayrıştırma
    # ------------------------------------------------------------------ #

    def _parse_output(self, out_file: str) -> List[DalfoxFinding]:
        findings: List[DalfoxFinding] = []
        if not os.path.exists(out_file):
            return findings

        try:
            with open(out_file, encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        data = json.loads(line)
                        df = self._parse_finding(data)
                        if df:
                            findings.append(df)
                    except json.JSONDecodeError:
                        # dalfox text çıktı satırı — PoC içeriyorsa kaydet
                        if "POC" in line or "VULN" in line:
                            findings.append(DalfoxFinding(
                                url="", payload=line.strip(),
                                xss_type="R", evidence=line,
                            ))
        except Exception as exc:
            logger.debug(f"[dalfox] Çıktı parse hatası: {exc!r}")

        return findings

    def _parse_finding(self, data: Dict[str, Any]) -> Optional[DalfoxFinding]:
        try:
            return DalfoxFinding(
                url=data.get("query_url") or data.get("url") or "",
                param=data.get("param") or data.get("parameter") or "",
                payload=data.get("payload") or "",
                poc=data.get("poc") or data.get("PoC") or "",
                cwe=data.get("cwe") or "CWE-79",
                severity=data.get("severity") or "Medium",
                xss_type=data.get("type") or data.get("xss_type") or "R",
                evidence=data.get("evidence") or data.get("poc") or "",
                raw=data,
            )
        except Exception:
            return None

    # ------------------------------------------------------------------ #
    # ToolFinding dönüşümü
    # ------------------------------------------------------------------ #

    def _to_tool_findings(
        self, dalfox_findings: List[DalfoxFinding]
    ) -> List[ToolFinding]:
        findings: List[ToolFinding] = []
        for df in dalfox_findings:
            sev_str = df.severity.lower()
            sev = ToolSeverity.from_str(sev_str)

            findings.append(ToolFinding(
                title=df.xss_type_full,
                severity=sev,
                url=df.url,
                tool=self.tool_name,
                description=(
                    f"{df.xss_type_full} doğrulandı. Parametre: {df.param!r}"
                ),
                evidence=df.poc or df.payload or df.evidence,
                cwe_ids=[df.cwe] if df.cwe else ["CWE-79"],
                confidence="high",
                verified=True,
                tags=[t for t in ["xss", df.xss_type.lower(), "dalfox-verified"] if t],
                raw=df.raw,
            ))

        return findings


# ---------------------------------------------------------------------------
# Kısayol fonksiyonlar
# ---------------------------------------------------------------------------

def verify_xss(
    xss_findings: List[Dict[str, Any]],
    cookie: str = "",
    blind_callback: str = "",
) -> List[Dict[str, Any]]:
    """
    WebSecure XSS bulgularını dalfox ile doğrula.

    Döndürür
    --------
    List[Dict] — Doğrulanmış XSS bulguları (native format).
    """
    wrapper = DalfoxWrapper(blind_callback=blind_callback)
    if not wrapper.is_available():
        logger.warning("[Dalfox] verify_xss_findings: binary bulunamadı, atlanıyor.")
        return []
    result = wrapper.verify_xss_findings(xss_findings, cookie=cookie)
    return [f.to_dict() for f in result.findings]


__all__ = [
    "DalfoxFinding",
    "DalfoxWrapper",
    "verify_xss",
]
