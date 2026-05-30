"""
websecure.integrations.httpx_runner
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
httpx — HTTP/2 destekli hızlı prob ve teknoloji tespiti.

Özellikler
----------
* HTTP/1.1 / HTTP/2 / HTTP/3 prob
* Teknoloji tespiti (Wappalyzer tabanlı)
* Status code, content-type, title, server header toplama
* TLS sertifika bilgisi
* CDN, WAF tespiti
* Subdomain listesini toplu prob etme (pipeline)
* ToolIntegration arayüzü (SOLID OCP/DIP)
"""
from __future__ import annotations

import json
import logging
import os
import re
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
# Sabitler
# ---------------------------------------------------------------------------

_INTERESTING_STATUS = {301, 302, 307, 308, 401, 403, 404, 500, 503}
_SECURITY_SEVERITY_BY_STATUS = {
    401: ToolSeverity.LOW,
    403: ToolSeverity.LOW,
    500: ToolSeverity.MEDIUM,
    503: ToolSeverity.INFO,
}


# ---------------------------------------------------------------------------
# ProbeResult — tek URL prob sonucu
# ---------------------------------------------------------------------------

@dataclass
class ProbeResult:
    """httpx tek URL prob sonucu."""
    url: str
    status_code: int = 0
    content_length: int = 0
    title: str = ""
    server: str = ""
    content_type: str = ""
    tech: List[str] = field(default_factory=list)
    tls_cn: str = ""
    tls_expiry: str = ""
    http2: bool = False
    cdn: str = ""
    waf: str = ""
    redirect_location: str = ""
    raw: Dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# HttpxWrapper
# ---------------------------------------------------------------------------

class HttpxWrapper(ToolIntegration):
    """
    httpx (ProjectDiscovery) entegrasyon sarmalayıcısı.

    Hızlı HTTP/2 prob, teknoloji tespiti, toplu URL işleme.
    """

    def __init__(
        self,
        binary_path: Optional[str] = None,
        threads: int = 50,
        rate_limit: int = 150,
        timeout_s: int = 10,
        follow_redirects: bool = True,
        http2: bool = True,
    ) -> None:
        # PATH'ta Python httpx olabilir — tools/ klasöründeki Go httpx'i önceliklendir
        if not binary_path:
            _root = Path(__file__).resolve().parent.parent.parent
            for _candidate in [
                _root / "tools" / "httpx" / "httpx.exe",
                _root / "tools" / "httpx" / "httpx",
                _root / "tools" / "httpx.exe",
                _root / "tools" / "httpx",
            ]:
                if _candidate.exists():
                    binary_path = str(_candidate)
                    logger.debug(f"[httpx] tools/ dizininden Go httpx bulundu: {binary_path}")
                    break
        super().__init__(binary_path or "httpx")
        self.threads = threads
        self.rate_limit = rate_limit
        self.timeout_s = timeout_s
        self.follow_redirects = follow_redirects
        self.http2 = http2

    # ------------------------------------------------------------------ #
    # ToolIntegration arayüzü
    # ------------------------------------------------------------------ #

    @property
    def tool_name(self) -> str:
        return "httpx"

    def _is_go_httpx(self) -> bool:
        """Return True only when the resolved binary is ProjectDiscovery's Go httpx."""
        if hasattr(self, "_go_httpx_cache"):
            return self._go_httpx_cache  # type: ignore[attr-defined]

        result = False
        try:
            proc = subprocess.run(
                [self.binary, "-version"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=8, check=False,
            )
            out = (proc.stdout or proc.stderr or b"").decode("utf-8", "ignore")
            out_lower = out.lower()
            # Python httpx CLI outputs "usage: python -m httpx" or similar
            if "python" in out_lower or ("usage:" in out_lower and "url" in out_lower):
                result = False
            elif re.search(r"v?\d+\.\d+", out):
                # Go httpx emits a version like "vX.Y.Z" or "Current Version: vX.Y.Z"
                result = True
            else:
                # Fallback: check -l flag in help text (Go httpx file-list flag)
                h = subprocess.run(
                    [self.binary, "-help"],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    timeout=8, check=False,
                )
                help_text = (h.stdout or h.stderr or b"").decode("utf-8", "ignore")
                result = ("-l " in help_text or "-list" in help_text)
        except Exception as exc:
            logger.debug(f"[httpx] Go binary detection failed: {exc!r}")
            result = False

        self._go_httpx_cache = result  # type: ignore[attr-defined]
        if not result:
            logger.warning(
                "[httpx] 'httpx' binary, Go/ProjectDiscovery httpx değil — "
                "Python httpx CLI olabilir. Lütfen Go httpx yükleyin: "
                "go install github.com/projectdiscovery/httpx/cmd/httpx@latest"
            )
        return result

    def is_available(self) -> bool:
        binary_found = (
            shutil.which(self.binary) is not None
            or (self._binary_path is not None and Path(self._binary_path).exists())
        )
        if not binary_found:
            return False
        return self._is_go_httpx()

    def version(self) -> Optional[str]:
        if not self.is_available():
            return None
        try:
            proc = subprocess.run(
                [self.binary, "-version"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=10, check=False,
            )
            out = (proc.stdout or proc.stderr or b"").decode("utf-8", "ignore")
            return out.strip().splitlines()[0] if out.strip() else None
        except Exception:
            return None

    def run(self, target: str, **kwargs) -> ToolResult:
        """
        Tek URL'yi veya domain'i prob et.

        Anahtar argümanlar
        ------------------
        urls      : List[str] — Birden fazla URL toplu problamak için
        tech_detect : bool — Teknoloji tespiti (varsayılan True)
        tls_probe   : bool — TLS bilgisi al (varsayılan True)
        """
        urls = kwargs.get("urls") or [target]
        return self.probe_bulk(
            urls=urls,
            tech_detect=kwargs.get("tech_detect", True),
            tls_probe=kwargs.get("tls_probe", True),
        )

    # ------------------------------------------------------------------ #
    # Prob metotları
    # ------------------------------------------------------------------ #

    def probe_bulk(
        self,
        urls: List[str],
        tech_detect: bool = True,
        tls_probe: bool = True,
        custom_headers: Optional[Dict[str, str]] = None,
    ) -> ToolResult:
        """
        URL listesini toplu prob et.

        Parametreler
        ------------
        urls          : Problanacak URL/host listesi
        tech_detect   : Wappalyzer tabanlı teknoloji tespiti
        tls_probe     : TLS sertifika bilgisi al
        custom_headers: İsteğe ek başlıklar
        """
        if not self.is_available():
            logger.warning("[httpx] Binary bulunamadı, atlanıyor.")
            return ToolResult(tool=self.tool_name, target=urls[0] if urls else "",
                              status=ToolStatus.NOT_FOUND)

        start = time.monotonic()
        # URL listesini geçici dosyaya yaz
        fd_in, in_file = tempfile.mkstemp(suffix=".txt", prefix="ws_httpx_in_")
        fd_out, out_file = tempfile.mkstemp(suffix=".json", prefix="ws_httpx_out_")
        os.close(fd_in)
        os.close(fd_out)

        try:
            with open(in_file, "w", encoding="utf-8") as f:
                f.write("\n".join(urls))

            cmd = self._build_command(
                in_file=in_file,
                out_file=out_file,
                tech_detect=tech_detect,
                tls_probe=tls_probe,
                custom_headers=custom_headers or {},
            )

            # Gerçekçi timeout: paralel thread sayısına göre hesapla, max 300s
            _timeout = max(60, min(
                (len(urls) * self.timeout_s) // max(self.threads, 1) + 30,
                300
            ))
            logger.info(f"[httpx] {len(urls)} URL prob ediliyor (timeout={_timeout}s)...")
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
            )
            _unreg = None
            try:
                from websecure.core.phases import register_child_proc, unregister_child_proc
                register_child_proc(proc)
                _unreg = unregister_child_proc
            except Exception:
                pass
            try:
                _, stderr_b = proc.communicate(timeout=_timeout)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.communicate()
                logger.warning(f"[httpx] Zaman aşımı ({_timeout}s) — kısmi sonuçlar ayrıştırılıyor")
            else:
                if proc.returncode not in (0, 1):
                    stderr_out = (stderr_b or b"").decode("utf-8", "ignore")[:300]
                    logger.warning(f"[httpx] Çıkış kodu {proc.returncode}: {stderr_out}")
            finally:
                if _unreg:
                    _unreg(proc)

            probe_results = self._parse_output(out_file)
            findings = self._build_findings(probe_results)
            duration = time.monotonic() - start

            logger.info(
                f"[httpx] {len(probe_results)} URL problandı  "
                f"{len(findings)} bulgu  {duration:.1f}s"
            )

            return ToolResult(
                tool=self.tool_name,
                target=urls[0] if urls else "",
                status=ToolStatus.SUCCESS,
                findings=findings,
                duration_s=duration,
                extra={
                    "probed_count": len(probe_results),
                    "probe_results": [vars(p) for p in probe_results],
                },
            )

        except Exception as exc:
            logger.error(f"[httpx] Hata: {exc!r}", exc_info=True)
            return ToolResult(
                tool=self.tool_name, target=urls[0] if urls else "",
                status=ToolStatus.ERROR, stderr=str(exc),
            )
        finally:
            for p in (in_file, out_file):
                try:
                    os.unlink(p)
                except OSError:
                    pass

    def probe_single(self, url: str, **kwargs) -> Optional[ProbeResult]:
        """Tek URL prob et, ProbeResult döndür."""
        result = self.probe_bulk([url], **kwargs)
        if result.extra.get("probe_results"):
            return ProbeResult(**result.extra["probe_results"][0])
        return None

    # ------------------------------------------------------------------ #
    # Komut oluşturma
    # ------------------------------------------------------------------ #

    def _build_command(
        self,
        in_file: str,
        out_file: str,
        tech_detect: bool,
        tls_probe: bool,
        custom_headers: Dict[str, str],
    ) -> List[str]:
        cmd = [
            self.binary,
            "-l", in_file,
            "-o", out_file,
            "-json",
            "-silent",
            "-threads", str(self.threads),
            "-rate-limit", str(self.rate_limit),
            "-timeout", str(self.timeout_s),
            # Toplanan bilgiler
            "-status-code",
            "-content-length",
            "-title",
            "-server",
            "-content-type",
            "-location",
        ]

        if self.follow_redirects:
            cmd.append("-follow-redirects")

        if self.http2:
            cmd.append("-http2")

        if tech_detect:
            cmd.append("-tech-detect")

        if tls_probe:
            cmd.extend(["-tls-probe", "-tls-grab"])

        for header, value in custom_headers.items():
            cmd.extend(["-H", f"{header}: {value}"])

        return cmd

    # ------------------------------------------------------------------ #
    # Çıktı ayrıştırma
    # ------------------------------------------------------------------ #

    def _parse_output(self, out_file: str) -> List[ProbeResult]:
        results: List[ProbeResult] = []
        if not os.path.exists(out_file):
            return results
        try:
            with open(out_file, encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        data = json.loads(line)
                        pr = self._parse_line(data)
                        if pr:
                            results.append(pr)
                    except json.JSONDecodeError:
                        continue
        except Exception as exc:
            logger.debug(f"[httpx] Çıktı parse hatası: {exc!r}")
        return results

    def _parse_line(self, data: Dict[str, Any]) -> Optional[ProbeResult]:
        try:
            tech_list: List[str] = []
            for tech_entry in (data.get("tech") or data.get("technologies") or []):
                if isinstance(tech_entry, str):
                    tech_list.append(tech_entry)
                elif isinstance(tech_entry, dict):
                    tech_list.append(tech_entry.get("name", ""))

            tls = data.get("tls") or {}

            return ProbeResult(
                url=data.get("url") or data.get("input") or "",
                status_code=data.get("status_code", 0),
                content_length=data.get("content_length", 0),
                title=(data.get("title") or "").strip(),
                server=(data.get("server") or "").strip(),
                content_type=(data.get("content_type") or "").strip(),
                tech=tech_list,
                tls_cn=tls.get("subject_cn", "") if isinstance(tls, dict) else "",
                tls_expiry=tls.get("not_after", "") if isinstance(tls, dict) else "",
                http2=data.get("http2", False),
                cdn=data.get("cdn", ""),
                waf=data.get("waf", ""),
                redirect_location=data.get("location") or "",
                raw=data,
            )
        except Exception as exc:
            logger.debug(f"[httpx] Satır parse hatası: {exc!r}")
            return None

    # ------------------------------------------------------------------ #
    # Finding üretimi
    # ------------------------------------------------------------------ #

    def _build_findings(self, probes: List[ProbeResult]) -> List[ToolFinding]:
        findings: List[ToolFinding] = []

        for pr in probes:
            # Teknoloji tespiti -> bilgi bulgusu
            if pr.tech:
                findings.append(ToolFinding(
                    title=f"Teknoloji Tespiti — {', '.join(pr.tech[:5])}",
                    severity=ToolSeverity.INFO,
                    url=pr.url,
                    tool=self.tool_name,
                    description=f"Tespit edilen teknolojiler: {', '.join(pr.tech)}",
                    evidence=f"Server: {pr.server}  Title: {pr.title}  HTTP2: {pr.http2}",
                    tags=["recon", "tech-detect"],
                    confidence="high",
                    verified=True,
                    raw={"tech": pr.tech, "server": pr.server},
                ))

            # İlginç HTTP durum kodları
            if pr.status_code in _INTERESTING_STATUS:
                sev = _SECURITY_SEVERITY_BY_STATUS.get(pr.status_code, ToolSeverity.INFO)
                findings.append(ToolFinding(
                    title=f"HTTP {pr.status_code} — {pr.url}",
                    severity=sev,
                    url=pr.url,
                    tool=self.tool_name,
                    description=f"URL {pr.status_code} döndürüyor  Size: {pr.content_length}",
                    evidence=f"Status: {pr.status_code}  Title: {pr.title}  Server: {pr.server}",
                    tags=["recon", f"http-{pr.status_code}"],
                    confidence="high",
                    verified=True,
                ))

        return findings


# ---------------------------------------------------------------------------
# Kısayol fonksiyonlar
# ---------------------------------------------------------------------------

def probe_hosts(
    hosts: List[str],
    threads: int = 50,
    tech_detect: bool = True,
) -> List[ProbeResult]:
    """
    Host listesini HTTP prob et.

    Döndürür
    --------
    List[ProbeResult]
    """
    wrapper = HttpxWrapper(threads=threads)
    if not wrapper.is_available():
        logger.warning("[Httpx] probe_bulk_hosts: binary bulunamadı, atlanıyor.")
        return []
    result = wrapper.probe_bulk(hosts, tech_detect=tech_detect)
    return [ProbeResult(**p) for p in result.extra.get("probe_results", [])]


__all__ = [
    "ProbeResult",
    "HttpxWrapper",
    "probe_hosts",
]
