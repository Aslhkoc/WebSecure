"""
websecure.integrations.katana
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
katana — ProjectDiscovery'nin hızlı, kapsamlı web crawler entegrasyonu.

Özellikler
----------
* Headless browser + standart HTTP mod
* JavaScript parser (bundle dosyalarından endpoint çıkarımı)
* Form, API endpoint, parametre keşfi
* Scope kontrolü (in-scope URL filtreleme)
* OpenAPI / Swagger linklerini otomatik takip
* Tüm keşfedilen URL'leri WebSecure'a besleme pipeline
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
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urlparse

from websecure.integrations.base import (
    ToolFinding,
    ToolIntegration,
    ToolResult,
    ToolSeverity,
    ToolStatus,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# KatanaEndpoint — keşfedilen tekil endpoint
# ---------------------------------------------------------------------------

@dataclass
class KatanaEndpoint:
    """katana tarafından keşfedilen bir endpoint."""
    url: str
    method: str = "GET"
    source: str = ""            # "js", "html", "form", "openapi" vb.
    params: List[str] = field(default_factory=list)
    content_type: str = ""
    headers_seen: List[str] = field(default_factory=list)
    depth: int = 0
    raw: Dict[str, Any] = field(default_factory=dict)

    @property
    def domain(self) -> str:
        try:
            return urlparse(self.url).netloc
        except Exception:
            return ""


# ---------------------------------------------------------------------------
# KatanaWrapper
# ---------------------------------------------------------------------------

class KatanaWrapper(ToolIntegration):
    """
    katana web crawler entegrasyon sarmalayıcısı.

    Hızlı JavaScript-aware crawler; form, API, hidden endpoint keşfi.
    """

    def __init__(
        self,
        binary_path: Optional[str] = None,
        depth: int = 3,
        js_crawl: bool = True,
        headless: bool = False,
        threads: int = 10,
        parallelism: int = 10,
        rate_limit: int = 150,
        timeout_s: int = 30,
        crawl_duration_s: int = 300,
        scope_regex: str = "",
    ) -> None:
        super().__init__(binary_path or "katana")
        self.depth = depth
        self.js_crawl = js_crawl
        self.headless = headless
        self.threads = threads
        self.parallelism = parallelism
        self.rate_limit = rate_limit
        self.timeout_s = timeout_s
        self.crawl_duration_s = crawl_duration_s
        self.scope_regex = scope_regex

    # ------------------------------------------------------------------ #
    # ToolIntegration arayüzü
    # ------------------------------------------------------------------ #

    @property
    def tool_name(self) -> str:
        return "katana"

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
        katana çalıştır, keşfedilen endpoint'leri döndür.

        Anahtar argümanlar
        ------------------
        depth            : int — tarama derinliği
        js_crawl         : bool — JS bundle analizi
        headless         : bool — tarayıcısız/başlıklı mod
        form_extraction  : bool — form input analizi
        known_files      : bool — robots.txt, sitemap.xml, vb.
        extensions_match : List[str] — yalnızca bu uzantıları tara
        """
        if not self.is_available():
            logger.warning("[katana] Binary bulunamadı, atlanıyor.")
            return ToolResult(tool=self.tool_name, target=target, status=ToolStatus.NOT_FOUND)

        depth = kwargs.get("depth", self.depth)
        js_crawl = kwargs.get("js_crawl", self.js_crawl)
        headless = kwargs.get("headless", self.headless)
        form_extraction = kwargs.get("form_extraction", True)
        known_files = kwargs.get("known_files", True)

        start = time.monotonic()
        fd, out_file = tempfile.mkstemp(suffix=".json", prefix="ws_katana_")
        os.close(fd)

        try:
            cmd = self._build_command(
                target=target,
                out_file=out_file,
                depth=depth,
                js_crawl=js_crawl,
                headless=headless,
                form_extraction=form_extraction,
                known_files=known_files,
            )

            logger.info(f"[katana] Crawling → {target}  depth={depth}  js={js_crawl}")
            proc = subprocess.run(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                timeout=self.crawl_duration_s,
                check=False,
            )

            if proc.returncode not in (0, 1):
                stderr_out = (proc.stderr or b"").decode("utf-8", "ignore")[:300]
                logger.warning(f"[katana] Çıkış kodu {proc.returncode}: {stderr_out}")

            endpoints = self._parse_output(out_file)
            findings = self._build_findings(target, endpoints)
            duration = time.monotonic() - start

            logger.info(
                f"[katana] {target}: {len(endpoints)} endpoint keşfedildi  "
                f"{duration:.1f}s"
            )

            return ToolResult(
                tool=self.tool_name,
                target=target,
                status=ToolStatus.SUCCESS,
                findings=findings,
                duration_s=duration,
                extra={
                    "endpoint_count": len(endpoints),
                    "endpoints": [vars(e) for e in endpoints],
                    "unique_urls": list({e.url for e in endpoints}),
                },
            )

        except subprocess.TimeoutExpired:
            logger.warning(f"[katana] Zaman aşımı ({self.crawl_duration_s}s)")
            return ToolResult(
                tool=self.tool_name, target=target, status=ToolStatus.TIMEOUT,
                duration_s=time.monotonic() - start,
            )
        except Exception as exc:
            logger.error(f"[katana] Hata: {exc!r}", exc_info=True)
            return ToolResult(
                tool=self.tool_name, target=target, status=ToolStatus.ERROR,
                stderr=str(exc),
            )
        finally:
            try:
                os.unlink(out_file)
            except OSError:
                pass

    # ------------------------------------------------------------------ #
    # Komut oluşturma
    # ------------------------------------------------------------------ #

    def _build_command(
        self,
        target: str,
        out_file: str,
        depth: int,
        js_crawl: bool,
        headless: bool,
        form_extraction: bool,
        known_files: bool,
    ) -> List[str]:
        cmd = [
            self.binary,
            "-u", target,
            "-o", out_file,
            "-json",
            "-silent",
            "-depth", str(depth),
            "-c", str(self.parallelism),
            "-p", str(self.threads),
            "-rate-limit", str(self.rate_limit),
            "-timeout", str(self.timeout_s),
        ]

        if js_crawl:
            cmd.append("-js-crawl")

        if headless:
            cmd.extend(["-headless"])

        if form_extraction:
            cmd.append("-form-extraction")

        if known_files:
            cmd.append("-known-files", "all")

        if self.scope_regex:
            cmd.extend(["-scope-regex", self.scope_regex])

        # Çıktı alanları
        cmd.extend(["-field", "url,method,body,source,tag"])

        return cmd

    # ------------------------------------------------------------------ #
    # Çıktı ayrıştırma
    # ------------------------------------------------------------------ #

    def _parse_output(self, out_file: str) -> List[KatanaEndpoint]:
        endpoints: List[KatanaEndpoint] = []
        seen_urls: Set[str] = set()

        if not os.path.exists(out_file):
            return endpoints

        try:
            with open(out_file, encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        data = json.loads(line)
                        ep = self._parse_endpoint(data)
                        if ep and ep.url not in seen_urls:
                            seen_urls.add(ep.url)
                            endpoints.append(ep)
                    except json.JSONDecodeError:
                        # Plain URL satırı
                        line_clean = line.strip()
                        if line_clean.startswith("http") and line_clean not in seen_urls:
                            seen_urls.add(line_clean)
                            endpoints.append(KatanaEndpoint(url=line_clean))
        except Exception as exc:
            logger.debug(f"[katana] Çıktı parse hatası: {exc!r}")

        return endpoints

    def _parse_endpoint(self, data: Dict[str, Any]) -> Optional[KatanaEndpoint]:
        try:
            req = data.get("request") or {}
            url = req.get("url") or data.get("url") or data.get("endpoint") or ""
            if not url:
                return None

            # Parametreleri çıkart
            params: List[str] = []
            body = req.get("body", "") or ""
            query = urlparse(url).query
            if query:
                params = [p.split("=")[0] for p in query.split("&") if "=" in p]

            return KatanaEndpoint(
                url=url,
                method=req.get("method", "GET").upper(),
                source=data.get("source") or data.get("tag") or "",
                params=params,
                content_type=req.get("headers", {}).get("Content-Type", ""),
                depth=data.get("depth", 0),
                raw=data,
            )
        except Exception as exc:
            logger.debug(f"[katana] Endpoint parse hatası: {exc!r}")
            return None

    # ------------------------------------------------------------------ #
    # Finding üretimi
    # ------------------------------------------------------------------ #

    def _build_findings(
        self, target: str, endpoints: List[KatanaEndpoint]
    ) -> List[ToolFinding]:
        findings: List[ToolFinding] = []
        if not endpoints:
            return findings

        # JS kaynaklı endpoint'ler — yüksek değer (gizli API'lar)
        js_endpoints = [e for e in endpoints if "js" in e.source.lower()]
        form_endpoints = [e for e in endpoints if "form" in e.source.lower()]
        api_endpoints = [
            e for e in endpoints
            if any(seg in e.url for seg in ["/api/", "/v1/", "/v2/", "/graphql", "/rest/"])
        ]

        # Keşif özeti
        findings.append(ToolFinding(
            title=f"Web Crawler — {len(endpoints)} Endpoint Keşfedildi",
            severity=ToolSeverity.INFO,
            url=target,
            tool=self.tool_name,
            description=(
                f"{len(endpoints)} endpoint keşfedildi  "
                f"JS: {len(js_endpoints)}  Form: {len(form_endpoints)}  API: {len(api_endpoints)}"
            ),
            evidence="\n".join(e.url for e in endpoints[:50]),
            tags=["recon", "crawler", "endpoints"],
            confidence="high",
            verified=True,
        ))

        # JS'ten keşfedilen endpoint'ler — orta öncelik
        if js_endpoints:
            findings.append(ToolFinding(
                title=f"JavaScript'ten Endpoint Keşfi — {len(js_endpoints)} URL",
                severity=ToolSeverity.LOW,
                url=target,
                tool=self.tool_name,
                description=(
                    f"JS bundle dosyalarından {len(js_endpoints)} endpoint çıkarıldı. "
                    "Bu endpoint'ler genellikle erişim kontrolü eksik olabilir."
                ),
                evidence="\n".join(e.url for e in js_endpoints[:30]),
                tags=["recon", "js-crawl", "endpoints"],
                confidence="medium",
                verified=False,
            ))

        # Potansiyel API endpoint'ler
        if api_endpoints:
            findings.append(ToolFinding(
                title=f"API Endpoint Keşfi — {len(api_endpoints)} Endpoint",
                severity=ToolSeverity.INFO,
                url=target,
                tool=self.tool_name,
                description=f"{len(api_endpoints)} API endpoint tespit edildi.",
                evidence="\n".join(e.url for e in api_endpoints[:30]),
                tags=["recon", "api", "endpoints"],
                confidence="high",
                verified=True,
            ))

        return findings


# ---------------------------------------------------------------------------
# Kısayol fonksiyonlar
# ---------------------------------------------------------------------------

def crawl_target(
    target: str,
    depth: int = 3,
    js_crawl: bool = True,
) -> List[str]:
    """
    Hedefi katana ile crawl et, keşfedilen URL listesini döndür.

    Döndürür
    --------
    List[str] — Keşfedilen URL'ler.
    """
    wrapper = KatanaWrapper(depth=depth, js_crawl=js_crawl)
    if not wrapper.is_available():
        return []
    result = wrapper.run(target)
    return result.extra.get("unique_urls", [])


__all__ = [
    "KatanaEndpoint",
    "KatanaWrapper",
    "crawl_target",
]
