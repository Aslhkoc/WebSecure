"""
websecure.integrations.amass
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Amass subdomain + ASN keşif entegrasyonu.

Özellikler
----------
* Pasif subdomain enumeration (API kaynakları: Shodan, Censys, VirusTotal vb.)
* Aktif DNS brute-force (opsiyonel)
* ASN / CIDR keşfi
* Amass DB'den geçmiş tarama verisi okuma
* ToolIntegration arayüzü (base.py) — SOLID OCP/DIP uyumlu
"""
from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import tempfile
import time
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
# AmassWrapper
# ---------------------------------------------------------------------------

class AmassWrapper(ToolIntegration):
    """
    Amass subdomain + ASN enumeration aracı entegrasyonu.

    Parametreler
    ------------
    binary_path  : Amass binary yolu (None → otomatik keşif)
    passive_only : True → sadece pasif kaynaklar (aktif DNS yok)
    timeout_s    : Maksimum tarama süresi (saniye)
    """

    def __init__(
        self,
        binary_path: Optional[str] = None,
        passive_only: bool = True,
        timeout_s: int = 300,
        resolvers: Optional[List[str]] = None,
        wordlist: Optional[str] = None,
        max_dns_queries: int = 20000,
    ) -> None:
        super().__init__(binary_path or "amass")
        self.passive_only = passive_only
        self.timeout_s = timeout_s
        self.resolvers = resolvers or []
        self.wordlist = wordlist
        self.max_dns_queries = max_dns_queries

    # ------------------------------------------------------------------ #
    # ToolIntegration arayüzü
    # ------------------------------------------------------------------ #

    @property
    def tool_name(self) -> str:
        return "amass"

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
        Amass enum çalıştır.

        Parametreler
        ------------
        target : Hedef URL veya domain (örn. "https://example.com" veya "example.com")

        Anahtar argümanlar
        ------------------
        passive_only  : bool (override)
        timeout_s     : int (override)
        include_asn   : bool (ASN keşfi de yap)
        config_path   : str (Amass config dosyası)
        """
        domain = _extract_domain(target)
        if not domain:
            return ToolResult(
                tool=self.tool_name, target=target,
                status=ToolStatus.ERROR,
                stderr=f"Geçersiz hedef domain: {target!r}",
            )

        if not self.is_available():
            logger.warning("[Amass] Binary bulunamadı, atlanıyor.")
            return ToolResult(tool=self.tool_name, target=target, status=ToolStatus.NOT_FOUND)

        passive = kwargs.get("passive_only", self.passive_only)
        timeout_s = kwargs.get("timeout_s", self.timeout_s)
        include_asn = kwargs.get("include_asn", False)
        config_path = kwargs.get("config_path")

        start = time.monotonic()

        # Sonuç dosyası
        fd, out_file = tempfile.mkstemp(suffix=".json")
        os.close(fd)

        try:
            subdomains = self._run_enum(
                domain=domain,
                out_file=out_file,
                passive=passive,
                timeout_s=timeout_s,
                config_path=config_path,
            )

            asn_data: List[Dict[str, Any]] = []
            if include_asn:
                asn_data = self._run_intel(domain, timeout_s=min(timeout_s, 60))

            findings = self._build_findings(domain, subdomains, asn_data)
            duration = time.monotonic() - start

            logger.info(
                f"[Amass] {domain}: {len(subdomains)} subdomain  "
                f"{len(asn_data)} ASN  {duration:.1f}s"
            )

            return ToolResult(
                tool=self.tool_name,
                target=target,
                status=ToolStatus.SUCCESS,
                findings=findings,
                duration_s=duration,
                extra={
                    "domain": domain,
                    "subdomains": list(subdomains),
                    "asn_data": asn_data,
                },
            )

        except subprocess.TimeoutExpired:
            logger.warning(f"[Amass] Zaman aşımı ({timeout_s}s)")
            return ToolResult(
                tool=self.tool_name, target=target,
                status=ToolStatus.TIMEOUT,
                duration_s=time.monotonic() - start,
            )
        except Exception as exc:
            logger.error(f"[Amass] Hata: {exc!r}", exc_info=True)
            return ToolResult(
                tool=self.tool_name, target=target,
                status=ToolStatus.ERROR,
                stderr=str(exc),
            )
        finally:
            try:
                os.unlink(out_file)
            except OSError:
                pass

    # ------------------------------------------------------------------ #
    # Amass komutları
    # ------------------------------------------------------------------ #

    def _run_enum(
        self,
        domain: str,
        out_file: str,
        passive: bool,
        timeout_s: int,
        config_path: Optional[str],
    ) -> Set[str]:
        """Amass enum çalıştır, subdomain setini döndür."""
        cmd = [self.binary, "enum", "-d", domain, "-json", out_file]

        if passive:
            cmd.append("-passive")
        else:
            cmd.extend(["-active", "-brute"])
            if self.wordlist and Path(self.wordlist).exists():
                cmd.extend(["-wl", self.wordlist])

        if self.resolvers:
            cmd.extend(["-rf", ",".join(self.resolvers)])

        cmd.extend(["-max-dns-queries", str(self.max_dns_queries)])

        if config_path and Path(config_path).exists():
            cmd.extend(["-config", config_path])

        logger.info(f"[Amass] enum başlatılıyor → domain={domain}  passive={passive}")
        proc = subprocess.run(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            timeout=timeout_s,
            check=False,
        )

        if proc.returncode not in (0, 1):
            stderr_out = (proc.stderr or b"").decode("utf-8", "ignore")[:300]
            logger.warning(f"[Amass] enum çıkış kodu {proc.returncode}: {stderr_out}")

        return self._parse_json_output(out_file)

    def _run_intel(self, domain: str, timeout_s: int = 60) -> List[Dict[str, Any]]:
        """Amass intel ile ASN/CIDR bilgisi al."""
        cmd = [self.binary, "intel", "-whois", "-d", domain]
        try:
            proc = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                timeout=timeout_s,
                check=False,
            )
            out = (proc.stdout or b"").decode("utf-8", "ignore")
            return self._parse_intel_output(out)
        except subprocess.TimeoutExpired:
            logger.debug(f"[Amass] intel zaman aşımı ({timeout_s}s)")
            return []
        except Exception as exc:
            logger.debug(f"[Amass] intel hatası: {exc!r}")
            return []

    # ------------------------------------------------------------------ #
    # Çıktı ayrıştırma
    # ------------------------------------------------------------------ #

    def _parse_json_output(self, file_path: str) -> Set[str]:
        """Amass JSON satır çıktısından subdomain'leri çıkart."""
        subdomains: Set[str] = set()
        if not os.path.exists(file_path):
            return subdomains
        try:
            with open(file_path, encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        data = json.loads(line)
                        # Amass JSON formatı: {"name": "sub.example.com", ...}
                        name = data.get("name") or data.get("hostname") or ""
                        if name:
                            subdomains.add(name.lower().rstrip("."))
                    except json.JSONDecodeError:
                        # Plain text satır da olabilir
                        if "." in line and " " not in line:
                            subdomains.add(line.lower())
        except Exception as exc:
            logger.debug(f"[Amass] JSON çıktı parse hatası: {exc!r}")
        return subdomains

    def _parse_intel_output(self, output: str) -> List[Dict[str, Any]]:
        """Amass intel metin çıktısından ASN/CIDR verisini çıkart."""
        results = []
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            # Örn: "AS12345 - EXAMPLE-NET, Example Corp\n  192.0.2.0/24"
            if line.startswith("AS"):
                parts = line.split(" - ", 1)
                asn = parts[0].strip()
                org = parts[1].strip() if len(parts) > 1 else ""
                results.append({"asn": asn, "org": org, "cidrs": []})
            elif "/" in line and results:
                results[-1]["cidrs"].append(line)
        return results

    # ------------------------------------------------------------------ #
    # Finding üretimi
    # ------------------------------------------------------------------ #

    def _build_findings(
        self,
        domain: str,
        subdomains: Set[str],
        asn_data: List[Dict[str, Any]],
    ) -> List[ToolFinding]:
        findings: List[ToolFinding] = []

        # Keşfedilen subdomain'ler → tek bir bilgi bulgusu
        if subdomains:
            findings.append(ToolFinding(
                title=f"Subdomain Keşfi — {len(subdomains)} subdomain",
                severity=ToolSeverity.INFO,
                url=f"https://{domain}",
                tool=self.tool_name,
                description=(
                    f"{len(subdomains)} subdomain keşfedildi: "
                    + ", ".join(sorted(subdomains)[:10])
                    + ("..." if len(subdomains) > 10 else "")
                ),
                evidence="\n".join(sorted(subdomains)),
                tags=["recon", "subdomain"],
                confidence="high",
                verified=True,
            ))

        # ASN verisi
        for asn in asn_data:
            if asn.get("asn"):
                findings.append(ToolFinding(
                    title=f"ASN Keşfi — {asn['asn']}",
                    severity=ToolSeverity.INFO,
                    url=f"https://{domain}",
                    tool=self.tool_name,
                    description=f"ASN: {asn['asn']}  Org: {asn.get('org', 'N/A')}  CIDRs: {asn.get('cidrs', [])}",
                    evidence=json.dumps(asn, ensure_ascii=False),
                    tags=["recon", "asn", "network"],
                    confidence="high",
                    verified=True,
                    raw=asn,
                ))

        return findings


# ---------------------------------------------------------------------------
# Yardımcı fonksiyonlar
# ---------------------------------------------------------------------------

def _extract_domain(target: str) -> str:
    """URL veya domain string'inden ana domain çıkart."""
    if target.startswith(("http://", "https://")):
        parsed = urlparse(target)
        return parsed.hostname or ""
    return target.strip().lstrip("*.")


def run_amass(
    target: str,
    passive_only: bool = True,
    timeout_s: int = 300,
    include_asn: bool = False,
) -> List[str]:
    """
    Amass'ı çalıştır, subdomain listesi döndür.

    Döndürür
    --------
    List[str] — Keşfedilen subdomain'ler.
    """
    wrapper = AmassWrapper(passive_only=passive_only, timeout_s=timeout_s)
    if not wrapper.is_available():
        return []
    result = wrapper.run(target, include_asn=include_asn)
    return result.extra.get("subdomains", [])


__all__ = [
    "AmassWrapper",
    "run_amass",
]
