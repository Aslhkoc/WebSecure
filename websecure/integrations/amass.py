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
import re
import shutil
import subprocess
import tempfile
import time
import uuid
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
    binary_path  : Amass binary yolu (None -> otomatik keşif)
    passive_only : True -> sadece pasif kaynaklar (aktif DNS yok)
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
            # Amass v5'te "version" subcommand yok; -h içindeki başlıktan versiyon çıkar
            proc = subprocess.run(
                [self.binary, "-h"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=10, check=False,
            )
            out = (proc.stdout or proc.stderr or b"").decode("utf-8", "ignore")
            for line in out.splitlines():
                if "v" in line and any(c.isdigit() for c in line):
                    stripped = line.strip()
                    if stripped:
                        return stripped
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

        # Amass v5 -oA flag'i ile prefix-based dosya üretir: prefix.json, prefix.txt
        out_prefix = os.path.join(tempfile.gettempdir(), f"ws_amass_{uuid.uuid4().hex[:12]}")

        try:
            subdomains = self._run_enum(
                domain=domain,
                out_prefix=out_prefix,
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
            # Amass -oA prefix.json, prefix.txt ve diğer dosyaları temizle
            for _ext in (".json", ".txt"):
                _p = out_prefix + _ext
                try:
                    os.unlink(_p)
                except OSError:
                    pass

    # ------------------------------------------------------------------ #
    # Amass komutları
    # ------------------------------------------------------------------ #

    def _run_enum(
        self,
        domain: str,
        out_prefix: str,
        passive: bool,
        timeout_s: int,
        config_path: Optional[str],
    ) -> Set[str]:
        """Amass enum çalıştır, subdomain setini döndür."""
        # Amass v5: -oA ile prefix.json + prefix.txt üretir; -json flag'i yok
        cmd = [self.binary, "enum", "-d", domain, "-oA", out_prefix, "-silent"]

        if not passive:
            cmd.extend(["-active", "-brute"])
            if self.wordlist and Path(self.wordlist).exists():
                cmd.extend(["-w", self.wordlist])   # -wl → -w (v5 flag adı)

        rf_file: Optional[str] = None
        if self.resolvers:
            # -rf dosya yolu bekliyor; IP listesini geçici dosyaya yaz
            fd_r, rf_file = tempfile.mkstemp(suffix=".txt", prefix="ws_amass_rf_")
            try:
                with os.fdopen(fd_r, "w") as _f:
                    _f.write("\n".join(self.resolvers))
                cmd.extend(["-rf", rf_file])
            except Exception as exc:
                logger.debug(f"[Amass] Resolver dosyası oluşturulamadı: {exc!r}")
                try:
                    os.close(fd_r)
                except OSError:
                    pass

        # -max-dns-queries v5'te yok — kaldırıldı

        if config_path and Path(config_path).exists():
            cmd.extend(["-config", config_path])

        logger.info(f"[Amass] enum başlatılıyor -> domain={domain}  passive={passive}")
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
        try:
            _, stderr_b = proc.communicate(timeout=effective_timeout(timeout_s))
        except subprocess.TimeoutExpired:
            proc.kill()
            try:
                proc.communicate(timeout=10)
            except subprocess.TimeoutExpired:
                pass
            logger.warning(f"[Amass] enum zaman aşımı ({timeout_s}s) — kısmi sonuçlar ayrıştırılıyor")
        else:
            if proc.returncode not in (0, 1):
                stderr_out = (stderr_b or b"").decode("utf-8", "ignore")[:300]
                logger.warning(f"[Amass] enum çıkış kodu {proc.returncode}: {stderr_out}")
        finally:
            if rf_file:
                try:
                    os.unlink(rf_file)
                except OSError:
                    pass

        return self._parse_json_output(out_prefix + ".json")

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

        # Keşfedilen subdomain'ler -> tek bir bilgi bulgusu
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
        logger.warning("[Amass] get_subdomains: binary bulunamadı, atlanıyor.")
        return []
    result = wrapper.run(target, include_asn=include_asn)
    return result.extra.get("subdomains", [])


# ---------------------------------------------------------------------------
# SubfinderIntegration — Pasif subdomain OSINT
# ---------------------------------------------------------------------------

class SubfinderIntegration(ToolIntegration):
    """
    subfinder pasif subdomain enumeration entegrasyonu.

    ProjectDiscovery'nin subfinder aracını kullanarak çok sayıda
    pasif DNS kaynağından (Shodan, Censys, VirusTotal vb.) subdomain toplar.
    """

    def __init__(
        self,
        binary_path: Optional[str] = None,
        timeout_s: int = 120,
        all_sources: bool = True,
    ) -> None:
        super().__init__(binary_path or "subfinder")
        self.timeout_s = timeout_s
        self.all_sources = all_sources

    @property
    def tool_name(self) -> str:
        return "subfinder"

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
        Subfinder ile pasif subdomain enumeration.

        Anahtar argümanlar
        ------------------
        timeout_s     : int — maksimum süre (saniye)
        all_sources   : bool — tüm pasif kaynakları kullan
        """
        domain = _extract_domain(target)
        if not domain:
            return ToolResult(tool=self.tool_name, target=target,
                              status=ToolStatus.ERROR, stderr="Invalid domain")

        if not self.is_available():
            logger.warning("[subfinder] Binary bulunamadı, atlanıyor.")
            return ToolResult(tool=self.tool_name, target=target, status=ToolStatus.NOT_FOUND)

        timeout_s = kwargs.get("timeout_s", self.timeout_s)
        start = time.monotonic()

        fd, out_file = tempfile.mkstemp(suffix=".txt", prefix="ws_subfinder_")
        os.close(fd)

        try:
            cmd = [self.binary, "-d", domain, "-o", out_file, "-silent"]
            if kwargs.get("all_sources", self.all_sources):
                cmd.append("-all")

            logger.info(f"[subfinder] Pasif enum başlıyor: {domain}")
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
            )
            try:
                _, stderr_b = proc.communicate(timeout=effective_timeout(timeout_s))
            except subprocess.TimeoutExpired:
                proc.kill()
                try:
                    proc.communicate(timeout=10)
                except subprocess.TimeoutExpired:
                    pass
                logger.warning(f"[subfinder] Zaman aşımı ({timeout_s}s) — kısmi sonuçlar ayrıştırılıyor")
            else:
                if proc.returncode not in (0, 1):
                    stderr_out = (stderr_b or b"").decode("utf-8", "ignore")[:300]
                    logger.warning(f"[subfinder] Çıkış kodu {proc.returncode}: {stderr_out}")

            subdomains = self._parse_output(out_file)
            findings = self._build_findings(domain, subdomains)
            duration = time.monotonic() - start

            logger.info(f"[subfinder] {domain}: {len(subdomains)} subdomain  {duration:.1f}s")

            return ToolResult(
                tool=self.tool_name,
                target=target,
                status=ToolStatus.SUCCESS,
                findings=findings,
                duration_s=duration,
                extra={"domain": domain, "subdomains": list(subdomains)},
            )

        except Exception as exc:
            logger.error(f"[subfinder] Hata: {exc!r}", exc_info=True)
            return ToolResult(tool=self.tool_name, target=target,
                              status=ToolStatus.ERROR, stderr=str(exc))
        finally:
            try:
                os.unlink(out_file)
            except OSError:
                pass

    def _parse_output(self, out_file: str) -> Set[str]:
        subdomains: Set[str] = set()
        if not os.path.exists(out_file):
            return subdomains
        try:
            with open(out_file, encoding="utf-8", errors="ignore") as f:
                for line in f:
                    sub = line.strip().lower()
                    if sub:
                        subdomains.add(sub)
        except Exception as exc:
            logger.debug(f"[subfinder] Çıktı parse hatası: {exc!r}")
        return subdomains

    def _build_findings(self, domain: str, subdomains: Set[str]) -> List[ToolFinding]:
        if not subdomains:
            return []
        return [ToolFinding(
            title=f"Subfinder — {len(subdomains)} Subdomain Keşfedildi",
            severity=ToolSeverity.INFO,
            url=f"https://{domain}",
            tool=self.tool_name,
            description=(
                f"Pasif OSINT ile {len(subdomains)} subdomain keşfedildi: "
                + ", ".join(sorted(subdomains)[:10])
                + ("..." if len(subdomains) > 10 else "")
            ),
            evidence="\n".join(sorted(subdomains)),
            tags=["recon", "subdomain", "passive"],
            confidence="high",
            verified=True,
        )]


# ---------------------------------------------------------------------------
# InteractshIntegration — OAST/OOB callback server
# ---------------------------------------------------------------------------

class InteractshIntegration(ToolIntegration):
    """
    interactsh-client OAST (Out-of-Band Application Security Testing) entegrasyonu.

    interactsh-client binary'sini çalıştırarak out-of-band callback kanalı sağlar.
    DNS, HTTP, SMTP protokollerinde gelen callback'leri dinler ve raporlar.

    Binary: tools/interactsh/interactsh-client.exe veya drivers/interactsh-client.exe
    """

    def __init__(
        self,
        binary_path: Optional[str] = None,
        server: str = "https://oast.me",
        timeout_s: int = 30,
    ) -> None:
        # Binary keşif: önce tools/, sonra drivers/, son olarak PATH
        if not binary_path:
            from websecure.core.paths import writable_root as _ws_root
            _root = _ws_root()
            for _candidate in [
                _root / "tools" / "interactsh" / "interactsh-client.exe",
                _root / "tools" / "interactsh" / "interactsh-client",
                _root / "drivers" / "interactsh-client.exe",
                _root / "drivers" / "interactsh-client",
            ]:
                if _candidate.exists():
                    binary_path = str(_candidate)
                    logger.debug(f"[interactsh] Binary bulundu: {binary_path}")
                    break
        super().__init__(binary_path or "interactsh-client")
        self.server = server
        self.timeout_s = timeout_s

    @property
    def tool_name(self) -> str:
        return "interactsh"

    def is_available(self) -> bool:
        bp = self._binary_path
        if bp and Path(bp).exists():
            return True
        return shutil.which("interactsh-client") is not None

    def version(self) -> Optional[str]:
        if not self.is_available():
            return None
        try:
            proc = subprocess.run(
                [self.binary, "-version"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=8, check=False,
            )
            out = (proc.stdout or proc.stderr or b"").decode("utf-8", "ignore")
            return out.strip().splitlines()[0] if out.strip() else None
        except Exception:
            return None

    def run(self, target: str, **kwargs) -> ToolResult:
        """
        interactsh-client'i kısa süreliğine başlatır, kayıt doğrulaması yapar
        ve gelen etkileşimleri ToolFinding olarak döndürür.

        Anahtar argümanlar
        ------------------
        timeout_s : int — kaç saniye dinlenecek (varsayılan 20)
        server    : str — interactsh sunucusu
        """
        if not self.is_available():
            logger.warning("[interactsh] Binary bulunamadı, atlanıyor.")
            return ToolResult(tool=self.tool_name, target=target, status=ToolStatus.NOT_FOUND)

        start = time.monotonic()
        timeout_s = int(kwargs.get("timeout_s", min(self.timeout_s, 20)))
        server = kwargs.get("server", self.server)

        fd, out_file = tempfile.mkstemp(suffix=".json", prefix="ws_interactsh_")
        os.close(fd)

        try:
            cmd = [
                self.binary,
                "-server", server,
                "-json",
                "-o", out_file,
            ]

            logger.info(f"[interactsh] Başlatılıyor: server={server} timeout={timeout_s}s")
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            # Kısa süre çalıştır → kayıt doğrula + gelen eventleri al
            try:
                _, stderr_b = proc.communicate(timeout=timeout_s)
            except subprocess.TimeoutExpired:
                proc.kill()
                try:
                    _, stderr_b = proc.communicate(timeout=10)
                except subprocess.TimeoutExpired:
                    stderr_b = b""

            # Kayıtlı domain'i stderr'den çıkart
            domain = ""
            stderr_text = (stderr_b or b"").decode("utf-8", "ignore")
            for pattern in (
                r"([a-z0-9]+\.oast\.[a-z]+)",
                r"([a-z0-9]+\.interact\.sh)",
                r"([a-z0-9]{8,}\.[a-z0-9]+\.[a-z]{2,})",
            ):
                m = re.search(pattern, stderr_text, re.I)
                if m:
                    domain = m.group(1)
                    break

            # Çıktı dosyasından event'leri ayrıştır
            interactions: List[Dict[str, Any]] = []
            if os.path.exists(out_file):
                try:
                    with open(out_file, encoding="utf-8", errors="ignore") as f:
                        for line in f:
                            line = line.strip()
                            if not line:
                                continue
                            try:
                                interactions.append(json.loads(line))
                            except json.JSONDecodeError as _fix_e:
                                logger.debug(f"[integrations.amass] {type(_fix_e).__name__}: {_fix_e!r}")
                except Exception as exc:
                    logger.debug(f"[interactsh] Çıktı parse hatası: {exc!r}")

            # Bulgular oluştur
            findings: List[ToolFinding] = []

            # Her etkileşim için bir bulgu
            for ix in interactions:
                protocol = str(ix.get("protocol") or ix.get("type") or "unknown").upper()
                findings.append(ToolFinding(
                    title=f"OAST Callback — {protocol}",
                    severity=ToolSeverity.HIGH,
                    url=target,
                    tool=self.tool_name,
                    description=(
                        f"Out-of-band {protocol} etkileşimi alındı. "
                        f"Kaynak: {ix.get('remote-address', ix.get('remote_address', 'unknown'))}"
                    ),
                    evidence=json.dumps(ix, ensure_ascii=False)[:400],
                    tags=["oast", "oob", protocol.lower(), "interactsh"],
                    confidence="high",
                    verified=True,
                    raw=ix,
                ))

            # Servis durum bulgusu
            findings.append(ToolFinding(
                title="interactsh OAST Server — Hazır",
                severity=ToolSeverity.INFO,
                url=target,
                tool=self.tool_name,
                description=(
                    f"interactsh-client mevcut ve çalışıyor. "
                    f"Server: {server}. "
                    f"Domain: {domain or 'kayıt edilmedi'}. "
                    f"Etkileşim: {len(interactions)}"
                ),
                evidence=f"Binary: {self.binary}",
                tags=["oast", "interactsh", "info"],
                confidence="high",
                verified=True,
            ))

            duration = time.monotonic() - start
            logger.info(
                f"[interactsh] Tamamlandı — domain={domain or 'N/A'}  "
                f"etkileşim={len(interactions)}  {duration:.1f}s"
            )

            return ToolResult(
                tool=self.tool_name,
                target=target,
                status=ToolStatus.SUCCESS,
                findings=findings,
                duration_s=duration,
                extra={"domain": domain, "interactions": interactions, "server": server},
            )

        except Exception as exc:
            logger.error(f"[interactsh] Hata: {exc!r}", exc_info=True)
            return ToolResult(
                tool=self.tool_name, target=target,
                status=ToolStatus.ERROR, stderr=str(exc),
                duration_s=time.monotonic() - start,
            )
        finally:
            try:
                os.unlink(out_file)
            except OSError:
                pass


__all__ = [
    "AmassWrapper",
    "SubfinderIntegration",
    "InteractshIntegration",
    "run_amass",
]
