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
import re
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
    effective_timeout,
    no_timeout_mode,
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
        depth: int = 2,             # 3'ten düşürüldü — exponential büyüme önlenir
        js_crawl: bool = True,
        headless: bool = False,
        threads: int = 10,
        parallelism: int = 10,
        rate_limit: int = 50,       # 150'den düşürüldü — WAF tetiklemez, timeout azalır
        timeout_s: int = 10,        # 30'dan düşürüldü — istek başına zaman aşımı
        crawl_duration_s: int = 120,  # 300'den düşürüldü — toplam 2 dakika yeterli
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
        # Binary keşfi — tools/ klasörüne de bak
        self._check_binary()

    def _check_binary(self) -> None:
        """Binary yolunu çöz: PATH → tools/ klasörü."""
        if shutil.which(self.binary):
            return
        from websecure.core.paths import writable_root as _ws_root
        root = _ws_root()
        for candidate in [
            root / "tools" / "katana" / "katana.exe",
            root / "tools" / "katana" / "katana",
            root / "tools" / "katana.exe",
        ]:
            if candidate.exists():
                self._binary_path = str(candidate)
                logger.info(f"[katana] Binary bulundu: {candidate}")
                return
        logger.warning("[katana] Binary bulunamadı — crawling devre dışı.")

    # ------------------------------------------------------------------ #
    # ToolIntegration arayüzü
    # ------------------------------------------------------------------ #

    @property
    def tool_name(self) -> str:
        return "katana"

    def is_available(self) -> bool:
        if shutil.which(self.binary) is not None:
            return True
        if self._binary_path and Path(self._binary_path).exists():
            return True
        return False

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

        Timeout davranışı
        -----------------
        1. Katana'ya -ct flag ile kendi süre limitini ver (crawl_duration_s - 5s).
           Katana graceful exit yapar, çıktı dosyası tamamdır.
        2. Python tarafı Popen + communicate(timeout) kullanır.
           Timeout'da proc.kill() çağrılır — Windows'ta da process gerçekten ölür.
        3. Timeout'da bile o ana kadar yazılan kısmi çıktı parse edilir,
           bulgu listesi döndürülür (TIMEOUT yerine SUCCESS, timed_out=True).

        Gizlilik
        ---------
        proxy kwarg: "socks5h://..." veya "http://..." — katana bu proxy üzerinden çalışır.
        """
        if not self.is_available():
            logger.warning("[katana] Binary bulunamadı, atlanıyor.")
            return ToolResult(tool=self.tool_name, target=target, status=ToolStatus.NOT_FOUND)

        depth = kwargs.get("depth", self.depth)
        js_crawl = kwargs.get("js_crawl", self.js_crawl)
        headless = kwargs.get("headless", self.headless)
        form_extraction = kwargs.get("form_extraction", True)
        known_files = kwargs.get("known_files", True)
        proxy = kwargs.get("proxy")

        start = time.monotonic()
        fd, out_file = tempfile.mkstemp(suffix=".jsonl", prefix="ws_katana_")
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
                proxy=proxy,
            )

            logger.info(
                f"[katana] Crawling → {target}  depth={depth}  js={js_crawl}  "
                f"rate={self.rate_limit}/s  timeout={self.crawl_duration_s}s"
                f"{'  proxy=' + proxy if proxy else ''}"
            )

            # Popen kullan — subprocess.run Windows'ta TimeoutExpired'da prosesi öldürmüyor
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
            )

            # Child process kaydı (signal handler desteği)
            _unreg = None
            try:
                from websecure.core.phases import register_child_proc, unregister_child_proc
                register_child_proc(proc)
                _unreg = unregister_child_proc
            except Exception as _fix_e:
                logger.debug(f"[integrations.katana] {type(_fix_e).__name__}: {_fix_e!r}")

            timed_out = False
            stderr_b = b""
            try:
                _, stderr_b = proc.communicate(timeout=effective_timeout(self.crawl_duration_s))
            except subprocess.TimeoutExpired:
                timed_out = True
                logger.warning(
                    f"[katana] Subprocess zaman aşımı ({self.crawl_duration_s}s) — "
                    "process öldürülüyor, kısmi sonuçlar kullanılacak"
                )
                proc.kill()
                try:
                    proc.communicate(timeout=5)
                except Exception:
                    pass
            finally:
                if _unreg:
                    _unreg(proc)

            if not timed_out and proc.returncode not in (0, 1):
                stderr_out = (stderr_b or b"").decode("utf-8", "ignore")[:400]
                logger.warning(f"[katana] Çıkış kodu {proc.returncode}: {stderr_out}")

            endpoints = self._parse_output(out_file)
            findings = self._build_findings(target, endpoints)
            duration = time.monotonic() - start

            logger.info(
                f"[katana] {target}: {len(endpoints)} endpoint keşfedildi  "
                f"{duration:.1f}s{'  [kısmi-timeout]' if timed_out else ''}"
            )

            return ToolResult(
                tool=self.tool_name,
                target=target,
                status=ToolStatus.SUCCESS,   # kısmi sonuçlar da kullanılabilir
                findings=findings,
                duration_s=duration,
                extra={
                    "endpoint_count": len(endpoints),
                    "endpoints": [vars(e) for e in endpoints],
                    "unique_urls": list({e.url for e in endpoints}),
                    "timed_out": timed_out,
                },
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
        proxy: Optional[str] = None,
    ) -> List[str]:
        # Ensure URL has a protocol prefix — katana rejects bare hostnames
        if target and not target.startswith(("http://", "https://")):
            target = "https://" + target
            logger.info(f"[katana] URL'ye protokol eklendi → {target}")

        cmd = [
            self.binary,
            "-u", target,
            "-o", out_file,
            "-jsonl",           # katana v1.6+ JSONL çıktı
            "-silent",
            "-no-color",
            "-depth", str(depth),
            "-c", str(self.parallelism),
            "-p", str(self.threads),
            "-rl", str(self.rate_limit),
            "-timeout", str(self.timeout_s),
        ]

        # Katana'nın kendi toplam süre limitini ekle — graceful exit sağlar
        # subprocess timeout'dan 5s önce katana'nın kendisi durur.
        # Max-power modunda crawl süresi sınırı kaldırılır (24s = effektif sınırsız);
        # katana site keşfini tamamen tüketene kadar tarar, süreyle kesilmez.
        ct_seconds = 86400 if no_timeout_mode() else max(10, self.crawl_duration_s - 5)
        _supported = self._get_supported_flags()

        # -ct / -crawl-duration — toplam tarama süresi sınırı (en kritik fix)
        if "-ct" in _supported:
            cmd.extend(["-ct", f"{ct_seconds}s"])
        elif "-crawl-duration" in _supported:
            cmd.extend(["-crawl-duration", f"{ct_seconds}s"])

        if js_crawl and "-js-crawl" in _supported:
            cmd.append("-js-crawl")

        if headless and "-headless" in _supported:
            cmd.append("-headless")

        if form_extraction and "-form-extraction" in _supported:
            cmd.append("-form-extraction")

        # -known-files flag syntax varies across katana versions
        if known_files:
            if "-known-files" in _supported:
                cmd.extend(["-known-files", "all"])
            elif "-kf" in _supported:
                cmd.extend(["-kf", "all"])

        if self.scope_regex and "-scope-regex" in _supported:
            cmd.extend(["-scope-regex", self.scope_regex])

        # Proxy desteği — socks5h:// katana'da desteklenmez, socks5:// olarak geçirilir
        # (katana kendi DNS çözümlemesi yapar — Tor için sadece socks5:// geçerli)
        if proxy:
            proxy_for_katana = proxy.replace("socks5h://", "socks5://")
            cmd.extend(["-proxy", proxy_for_katana])
            logger.info(f"[katana] Proxy aktif: {proxy_for_katana}")

        return cmd

    def _get_supported_flags(self) -> Set[str]:
        """
        Parse katana --help to discover available flags.
        Cached per instance to avoid repeated subprocess calls.
        """
        if hasattr(self, "_supported_flags_cache"):
            return self._supported_flags_cache  # type: ignore[attr-defined]

        supported: Set[str] = set()
        try:
            proc = subprocess.run(
                [self.binary, "-help"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=8,
                check=False,
            )
            help_text = (proc.stdout or proc.stderr or b"").decode("utf-8", "ignore")
            for m in re.finditer(r"\s(-{1,2}[\w-]+)", help_text):
                supported.add(m.group(1))
        except Exception as exc:
            logger.debug(f"[katana] Flag discovery failed: {exc!r}")
            # Conservative defaults — en yaygın katana flag'leri
            supported = {
                "-js-crawl", "-headless", "-form-extraction",
                "-known-files", "-silent", "-no-color", "-jsonl",
                "-depth", "-c", "-p", "-rl", "-timeout",
                "-ct", "-u", "-o", "-scope-regex",
            }

        self._supported_flags_cache = supported  # type: ignore[attr-defined]
        return supported

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
            url = (
                req.get("endpoint")
                or req.get("url")
                or data.get("url")
                or data.get("endpoint")
                or ""
            )
            if not url:
                return None

            params: List[str] = []
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

        js_endpoints = [e for e in endpoints if "js" in e.source.lower()]
        form_endpoints = [e for e in endpoints if "form" in e.source.lower()]
        api_endpoints = [
            e for e in endpoints
            if any(seg in e.url for seg in ["/api/", "/v1/", "/v2/", "/graphql", "/rest/"])
        ]

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
    depth: int = 2,
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
        logger.warning("[Katana] crawl_site: binary bulunamadı, atlanıyor.")
        return []
    result = wrapper.run(target)
    return result.extra.get("unique_urls", [])


__all__ = [
    "KatanaEndpoint",
    "KatanaWrapper",
    "crawl_target",
]
