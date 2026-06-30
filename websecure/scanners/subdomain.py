"""
websecure.scanners.subdomain
-----------------------------
Subdomain enumeration:
  1. DNS brute-force (kelime listesi bazlı, threadli)
  2. Subfinder binary entegrasyonu (kuruluysa)
  3. Amass binary entegrasyonu (kuruluysa)
  4. Sertifika şeffaflık logu (crt.sh)

Bulunan subdomainler phases.py'deki 'subdomains' bucket'ına yazılır.
"""
from __future__ import annotations

import concurrent.futures
import logging
import os
import random
import re
import shutil
import socket
import subprocess
import tempfile
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urlparse

try:
    import requests as _requests
except ImportError:
    _requests = None  # type: ignore

from websecure.scanners.base import BaseScanner

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Yardımcılar
# ---------------------------------------------------------------------------

# PSL (private-section dahil) çözücü — eTLD+1 tabanını DOĞRU çıkarır.
# Offline gömülü snapshot (suffix_list_urls=()) → tarama sırasında ağ isteği
# yapmaz (air-gapped / Tor güvenli). Başarısızsa utils.net.registrable_domain
# sezgiseline düşülür.
try:
    import tldextract as _tldextract_mod
    _PSL_EXTRACT = _tldextract_mod.TLDExtract(
        suffix_list_urls=(), include_psl_private_domains=True
    )
except Exception:  # pragma: no cover - tldextract yoksa
    _PSL_EXTRACT = None


def _extract_domain(target: str) -> str:
    """
    URL veya hostname'den KAYIT-EDİLEBİLİR kök domain'i (eTLD+1) çıkarır.

    Subdomain enumerasyonu hedefin TÜM kardeş alt-alanlarını keşfetmelidir;
    bu yüzden taban apex olmalı: 'https://www.atlassian.com' -> 'atlassian.com',
    'shop.example.co.uk' -> 'example.co.uk'. Eskiden ham hostname (www.atlassian.com)
    döndürülüyordu → crt.sh/HackerTarget/amass '%.www.atlassian.com' ve DNS-brute
    '{word}.www.atlassian.com' sorgulardı → her zaman ~0 sonuç (hedef bir alt-alan
    önekiyle verildiğinde keşif RAPORA HİÇ düşmüyordu). PSL birincil, sezgisel yedek.
    """
    if "://" in target:
        host = urlparse(target).hostname or target
    else:
        host = target
    # Strip port
    host = host.split(":")[0].strip().lower().strip(".")
    if not host:
        return ""
    # Salt IP ise (subdomain anlamsız) olduğu gibi döndür.
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
        return host
    # 1) PSL (private section dahil) — en doğru eTLD+1 kaynağı
    if _PSL_EXTRACT is not None:
        try:
            ext = _PSL_EXTRACT(host)
            base = (
                getattr(ext, "top_domain_under_public_suffix", "")
                or getattr(ext, "registered_domain", "")
            )
            if base:
                return base
        except Exception as _psl_e:  # pragma: no cover
            logger.debug("[Subdomain] PSL extract başarısız: %r", _psl_e)
    # 2) Sezgisel yedek (utils.net.registrable_domain — eTLD+1, çok-parçalı ccTLD)
    try:
        from websecure.core.utils.net import registrable_domain as _rd
        base = _rd(host)
        if base:
            return base
    except Exception as _rd_e:  # pragma: no cover
        logger.debug("[Subdomain] registrable_domain yedeği başarısız: %r", _rd_e)
    return host


def _resolve(fqdn: str, timeout: float = 1.5) -> Optional[str]:
    """DNS A kaydı çözer. Başarısızsa None döner."""
    try:
        return socket.gethostbyname(fqdn)
    except (socket.gaierror, OSError):
        return None


# ---------------------------------------------------------------------------
# 1. DNS Brute-force
# ---------------------------------------------------------------------------

class DNSBruteForce:
    """
    Wordlist bazlı subdomain brute-force.
    Varsayılan: SecLists DNS listesi kullanılır. Yoksa dahili liste devreye girer.
    """

    # Minimal dahili liste — SecLists kurulu değilse fallback
    _BUILTIN = [
        "www", "mail", "ftp", "admin", "api", "dev", "staging", "test",
        "app", "blog", "shop", "store", "portal", "vpn", "remote", "m",
        "mobile", "ns1", "ns2", "smtp", "pop", "imap", "webmail", "cdn",
        "static", "assets", "media", "img", "images", "upload", "uploads",
        "dashboard", "panel", "cpanel", "whm", "webdisk", "autodiscover",
        "autoconfig", "mx", "relay", "beta", "preview", "demo", "sandbox",
        "internal", "intranet", "corp", "office", "git", "gitlab", "github",
        "ci", "jenkins", "jira", "confluence", "wiki", "docs", "help",
        "support", "status", "monitor", "metrics", "grafana", "kibana",
        "elastic", "db", "database", "mysql", "postgres", "redis", "mongo",
        "backup", "files", "download", "downloads", "secure", "ssl",
        "login", "auth", "sso", "oauth", "account", "accounts", "user",
        "users", "profile", "profiles", "search", "pay", "payment",
        "payments", "checkout", "cart", "order", "orders", "invoice",
        "old", "new", "v1", "v2", "v3", "stage", "uat", "qa", "prod",
    ]

    def __init__(self, wordlist_path: Optional[str] = None, threads: int = 50):
        self.wordlist_path = wordlist_path
        self.threads = threads

    def _load_words(self) -> List[str]:
        if self.wordlist_path and os.path.isfile(self.wordlist_path):
            try:
                with open(self.wordlist_path, encoding="utf-8", errors="ignore") as f:
                    words = [line.strip() for line in f if line.strip() and not line.startswith("#")]
                logger.info(f"[Subdomain] Wordlist yüklendi: {len(words)} kelime — {self.wordlist_path}")
                return words
            except Exception as e:
                logger.warning(f"[Subdomain] Wordlist yüklenemedi: {e}")

        # WebSecure bundled subdomains.txt — packaged with the tool
        _here = os.path.dirname(__file__)
        bundled = os.path.normpath(os.path.join(_here, "..", "wordlists", "subdomains.txt"))
        if os.path.isfile(bundled):
            try:
                with open(bundled, encoding="utf-8", errors="ignore") as f:
                    words = [line.strip() for line in f if line.strip() and not line.startswith("#")]
                if words:
                    logger.info(f"[Subdomain] Bundled subdomains.txt yüklendi: {len(words)} kelime")
                    return words
            except Exception as exc:
                logger.debug(f"[Subdomain] subdomains.txt okunamadı: {exc!r}")

        # SecLists otomatik tespit (priority over built-in if available)
        seclists_candidates = [
            "/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt",
            "/usr/share/SecLists/Discovery/DNS/subdomains-top1million-20000.txt",
            "/opt/SecLists/Discovery/DNS/subdomains-top1million-20000.txt",
            r"C:\tools\SecLists\Discovery\DNS\subdomains-top1million-20000.txt",
        ]
        for p in seclists_candidates:
            if os.path.isfile(p):
                try:
                    with open(p, encoding="utf-8", errors="ignore") as f:
                        words = [line.strip() for line in f if line.strip()]
                    logger.info(f"[Subdomain] SecLists DNS listesi bulundu: {len(words)} kelime")
                    return words
                except Exception as exc:
                    logger.debug("[DNSBruteForce] SecLists read error for %s: %s", p, exc)

        logger.info(f"[Subdomain] Dahili liste kullanılıyor ({len(self._BUILTIN)} kelime)")
        return list(self._BUILTIN)

    def run(self, domain: str) -> List[Dict[str, Any]]:
        words = self._load_words()
        found: List[Dict[str, Any]] = []

        _canary = f"nonexistent-canary-{random.randint(100000, 999999)}.{domain}"
        _wildcard_ip = _resolve(_canary)

        def check(word: str):
            fqdn = f"{word}.{domain}"
            ip = _resolve(fqdn)
            if ip and ip != _wildcard_ip:
                return {"subdomain": fqdn, "ip": ip, "method": "dns_brute"}
            return None

        logger.info(f"[Subdomain] DNS brute-force başlıyor: {domain} ({len(words)} kelime, {self.threads} thread)")
        # OVERALL DEADLINE — socket.gethostbyname has NO per-lookup timeout and is
        # uninterruptible (it ignores socket.setdefaulttimeout), so a slow/black-holed
        # resolver could keep a worker stuck indefinitely. The 'subdomain' phase runs
        # under an UNBOUNDED watchdog (no_timeout), so without this bound a single
        # stuck lookup + the old un-timed as_completed() froze the entire scan until
        # Ctrl+C. Budget ~ words/threads × 2.5s of resolution, clamped [60s, 1800s].
        _budget = max(60.0, min(1800.0, (len(words) / max(1, self.threads)) * 2.5 + 30.0))
        exe = concurrent.futures.ThreadPoolExecutor(max_workers=self.threads)
        try:
            futures = {exe.submit(check, w): w for w in words}
            try:
                for fut in concurrent.futures.as_completed(futures, timeout=_budget):
                    try:
                        res = fut.result()
                        if res:
                            found.append(res)
                            logger.debug(f"[Subdomain] Bulundu: {res['subdomain']} -> {res['ip']}")
                    except Exception as exc:
                        logger.debug("[DNSBruteForce] Future error: %s", exc)
            except concurrent.futures.TimeoutError:
                logger.warning(
                    "[Subdomain] DNS brute-force bütçesi (%ds) doldu — kısmi sonuç (%d/%d kelime işlendi)",
                    int(_budget), len(found), len(words),
                )
        finally:
            # Drop pending lookups and DON'T block on stuck gethostbyname threads
            # (wait=False). Leaked running resolver threads are bounded (== threads)
            # and harmless — the process reaps them at exit. Without wait=False the
            # ThreadPoolExecutor context-exit would re-introduce the very hang above.
            exe.shutdown(wait=False, cancel_futures=True)

        logger.info(f"[Subdomain] DNS brute-force tamamlandı: {len(found)} subdomain")
        return found


# ---------------------------------------------------------------------------
# 2. Subfinder entegrasyonu
# ---------------------------------------------------------------------------

# Subfinder: güçlü integration (effective_timeout/TAM GUC, kısmi-sonuç, ToolResult)
# tek kaynaktır. Bu sınıf yalnızca arayüz uyarlar (ToolResult → List[Dict]) ve her
# subdomain için IP çözer — tıpkı aşağıdaki AmassWrapper adapter'ı gibi. Eski yerel
# subprocess kopyası (sabit timeout=120, no_timeout'a uymuyordu) integration yoksa
# devreye giren ImportError fallback'ına indirildi.
try:
    from websecure.integrations.amass import SubfinderIntegration as _SubfinderIntegration

    class SubfinderWrapper:
        """
        Adapter: integrations/amass.SubfinderIntegration'ı subdomain tarayıcısının
        beklediği List[Dict] arayüzüne dönüştürür (ToolResult → List[Dict], IP çözümü dahil).
        """

        def __init__(self, binary: str = "subfinder"):
            self._impl = _SubfinderIntegration(
                binary_path=binary if binary != "subfinder" else None
            )

        def is_available(self) -> bool:
            return self._impl.is_available()

        def run(self, domain: str, timeout: int = 120) -> List[Dict[str, Any]]:
            result = self._impl.run(domain, timeout_s=timeout)
            # ToolResult.extra["subdomains"] -> List[str] (lowercase, dedup)
            extra = getattr(result, "extra", None) or {}
            subdomains: List[str] = extra.get("subdomains") or []
            out: List[Dict[str, Any]] = []
            for sub in subdomains:
                if sub:
                    ip = _resolve(str(sub))
                    out.append({"subdomain": str(sub), "ip": ip or "", "method": "subfinder"})
            logger.info(f"[Subfinder] {len(out)} subdomain bulundu (integration adapter)")
            return out

except ImportError:
    class SubfinderWrapper:  # type: ignore[no-redef]
        """Subfinder binary wrapper (passive OSINT) — integration yoksa fallback."""

        def __init__(self, binary: str = "subfinder"):
            self.binary = binary
            self._find_binary()

        def _find_binary(self):
            if shutil.which(self.binary):
                return
            from websecure.core.platform_compat import binary_candidates as _bc
            from websecure.core.paths import writable_root as _ws_root
            root = _ws_root()
            for _cand in _bc(root, "subfinder"):
                if _cand.exists():
                    self.binary = str(_cand)
                    return

        def is_available(self) -> bool:
            return bool(shutil.which(self.binary) or os.path.isfile(self.binary))

        def run(self, domain: str, timeout: int = 120) -> List[Dict[str, Any]]:
            if not self.is_available():
                logger.debug("[Subfinder] Binary bulunamadı, atlanıyor.")
                return []

            fd, tmp = tempfile.mkstemp(suffix=".txt")
            os.close(fd)
            try:
                cmd = [self.binary, "-d", domain, "-o", tmp, "-silent", "-all"]
                logger.info(f"[Subfinder] Pasif OSINT başlıyor: {domain}")
                subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                               check=False, timeout=timeout)
                results = []
                if os.path.isfile(tmp):
                    with open(tmp, encoding="utf-8", errors="ignore") as f:
                        for line in f:
                            sub = line.strip()
                            if sub:
                                ip = _resolve(sub)
                                results.append({"subdomain": sub, "ip": ip or "", "method": "subfinder"})
                logger.info(f"[Subfinder] {len(results)} subdomain bulundu")
                return results
            except subprocess.TimeoutExpired:
                logger.warning("[Subfinder] Zaman aşımı")
                return []
            except Exception as e:
                logger.error(f"[Subfinder] Hata: {e}")
                return []
            finally:
                try:
                    os.remove(tmp)
                except OSError:
                    pass


# ---------------------------------------------------------------------------
# 3. Amass entegrasyonu
# ---------------------------------------------------------------------------

try:
    from websecure.integrations.amass import AmassWrapper as _AmassIntegration

    class AmassWrapper:
        """
        Adapter: integrations/amass.AmassWrapper'ı subdomain tarayıcısının
        beklediği List[Dict] arayüzüne dönüştürür (ToolResult → List[Dict]).
        """

        def __init__(self, binary: str = "amass"):
            self._impl = _AmassIntegration(
                binary_path=binary if binary != "amass" else None
            )

        def is_available(self) -> bool:
            return self._impl.is_available()

        def run(
            self, domain: str, passive: bool = True, timeout: int = 180
        ) -> List[Dict[str, Any]]:
            result = self._impl.run(domain, passive_only=passive, timeout_s=timeout)
            # ToolResult.extra["subdomains"] -> List[str]
            extra = getattr(result, "extra", None) or {}
            subdomains: List[str] = extra.get("subdomains") or []
            out: List[Dict[str, Any]] = []
            for sub in subdomains:
                if sub:
                    ip = _resolve(str(sub))
                    out.append({"subdomain": str(sub), "ip": ip or "", "method": "amass"})
            logger.info(f"[Amass] {len(out)} subdomain bulundu (integration adapter)")
            return out

except ImportError:
    class AmassWrapper:  # type: ignore[no-redef]
        """Amass binary wrapper (pasif + aktif enum) — integration yoksa fallback."""

        def __init__(self, binary: str = "amass"):
            self.binary = binary
            self._find_binary()

        def _find_binary(self):
            if shutil.which(self.binary):
                return
            from websecure.core.platform_compat import binary_candidates as _bc
            from websecure.core.paths import writable_root as _ws_root
            root = _ws_root()
            for _cand in _bc(root, "amass"):
                if _cand.exists():
                    self.binary = str(_cand)
                    return

        def is_available(self) -> bool:
            return bool(shutil.which(self.binary) or os.path.isfile(self.binary))

        def run(
            self, domain: str, passive: bool = True, timeout: int = 180
        ) -> List[Dict[str, Any]]:
            if not self.is_available():
                logger.debug("[Amass] Binary bulunamadı, atlanıyor.")
                return []

            fd, tmp = tempfile.mkstemp(suffix=".txt")
            os.close(fd)
            try:
                cmd = [self.binary, "enum", "-d", domain, "-o", tmp]
                if passive:
                    cmd.append("-passive")
                logger.info(
                    f"[Amass] {'Pasif' if passive else 'Aktif'} enum başlıyor: {domain}"
                )
                subprocess.run(
                    cmd,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    check=False,
                    timeout=timeout,
                )
                results: List[Dict[str, Any]] = []
                if os.path.isfile(tmp):
                    with open(tmp, encoding="utf-8", errors="ignore") as f:
                        for line in f:
                            sub = line.strip()
                            if sub and domain in sub:
                                ip = _resolve(sub)
                                results.append(
                                    {"subdomain": sub, "ip": ip or "", "method": "amass"}
                                )
                logger.info(f"[Amass] {len(results)} subdomain bulundu")
                return results
            except subprocess.TimeoutExpired:
                logger.warning("[Amass] Zaman aşımı")
                return []
            except Exception as e:
                logger.error(f"[Amass] Hata: {e}")
                return []
            finally:
                try:
                    os.remove(tmp)
                except OSError:
                    pass


# ---------------------------------------------------------------------------
# 4. crt.sh Sertifika Şeffaflık Logu
# ---------------------------------------------------------------------------

def _crtsh_enum(domain: str, timeout: int = 30) -> List[Dict[str, Any]]:
    """
    crt.sh üzerinden sertifika şeffaflık loglarını sorgular.
    Harici araç gerekmez — saf HTTP isteği.
    """
    if _requests is None:
        return []
    results = []
    try:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        resp = _requests.get(url, timeout=timeout, headers={"User-Agent": "Mozilla/5.0"})
        if resp.status_code != 200:
            return []
        data = resp.json()
        seen: Set[str] = set()
        for entry in data:
            name_value = entry.get("name_value", "")
            for sub in name_value.split("\n"):
                sub = sub.strip().lower().lstrip("*.")
                if sub and domain in sub and sub not in seen:
                    seen.add(sub)
                    ip = _resolve(sub)
                    results.append({"subdomain": sub, "ip": ip or "", "method": "crt.sh"})
        logger.info(f"[crt.sh] {len(results)} subdomain bulundu")
    except Exception as e:
        logger.debug(f"[crt.sh] Sorgu hatası: {e}")
    return results


# ---------------------------------------------------------------------------
# 5. HackerTarget API — ücretsiz pasif subdomain keşfi
# ---------------------------------------------------------------------------

class HackerTargetWrapper:
    """
    HackerTarget API ile subdomain enumeration.
    Ücretsiz, auth gerektirmez (günlük rate limit var).
    """
    _URL = "https://api.hackertarget.com/hostsearch/?q={domain}"

    def is_available(self) -> bool:
        return True  # HTTP tabanlı, her zaman dene

    def run(self, domain: str) -> List[Dict[str, Any]]:
        if _requests is None:
            return []
        results_list: List[Dict[str, Any]] = []
        try:
            url = self._URL.format(domain=domain)
            resp = _requests.get(url, timeout=20, headers={"User-Agent": "Mozilla/5.0"})
            if resp.status_code != 200:
                return []
            text = resp.text.strip()
            if "error" in text[:100].lower() or "API count exceeded" in text:
                logger.debug("[HackerTarget] Rate limit aşıldı.")
                return []
            for line in text.split("\n"):
                if "," in line:
                    parts = line.strip().split(",")
                    sub = parts[0].strip()
                    ip = parts[1].strip() if len(parts) > 1 else ""
                    if sub and domain in sub:
                        results_list.append({"subdomain": sub, "ip": ip, "method": "hackertarget"})
            logger.info(f"[HackerTarget] {len(results_list)} subdomain bulundu")
        except Exception as e:
            logger.debug(f"[HackerTarget] Hata: {e}")
        return results_list


# ---------------------------------------------------------------------------
# 6. SecurityTrails API — API key gerektiren premium enum
# ---------------------------------------------------------------------------

class SecurityTrailsWrapper:
    """
    SecurityTrails API ile kapsamlı subdomain keşfi.
    SECURITYTRAILS_API_KEY ortam değişkeni veya cfg parametresi gerektirir.
    """
    _BASE = "https://api.securitytrails.com/v1"

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.environ.get("SECURITYTRAILS_API_KEY", "")

    def is_available(self) -> bool:
        return bool(self.api_key)

    def run(self, domain: str) -> List[Dict[str, Any]]:
        if not self.api_key:
            logger.debug("[SecurityTrails] API key yok, atlanıyor.")
            return []
        results_list: List[Dict[str, Any]] = []
        try:
            headers = {"APIKEY": self.api_key, "Content-Type": "application/json"}
            url = f"{self._BASE}/domain/{domain}/subdomains?children_only=false&include_inactive=false"
            resp = _requests.get(url, headers=headers, timeout=20)
            if resp.status_code != 200:
                logger.debug(f"[SecurityTrails] HTTP {resp.status_code}")
                return []
            data = resp.json()
            for sub in data.get("subdomains", []):
                fqdn = f"{sub}.{domain}"
                ip = _resolve(fqdn)
                results_list.append({"subdomain": fqdn, "ip": ip or "", "method": "securitytrails"})
            logger.info(f"[SecurityTrails] {len(results_list)} subdomain bulundu")
        except Exception as e:
            logger.debug(f"[SecurityTrails] Hata: {e}")
        return results_list


# ---------------------------------------------------------------------------
# 7. DNS Zone Transfer — kritik güvenlik açığı tespiti
# ---------------------------------------------------------------------------

class DNSZoneTransfer:
    """
    Hedef domain'in nameserver'larına AXFR (DNS zone transfer) isteği gönderir.
    Başarılı olursa tüm DNS kayıtları açığa çıkar — kritik keşif vektörü.
    Raw TCP AXFR: dnspython gerektirmez.
    """

    def _get_nameservers(self, domain: str) -> List[str]:
        """Domain NS IP adreslerini toplar."""
        ns_ips: List[str] = []
        # Yöntem 1: nslookup / dig ile NS kayıtlarını al
        for cmd in [
            ["nslookup", "-type=NS", domain],
            ["dig", "NS", domain, "+short"],
        ]:
            try:
                result = subprocess.run(
                    cmd, capture_output=True, text=True, timeout=8, errors="replace",
                )
                output = result.stdout or ""
                # NS host adlarını çıkar
                for line in output.split("\n"):
                    line = line.strip().rstrip(".")
                    if "." in line and not line.startswith(";"):
                        # Sadece NS gibi görünen satırları al
                        parts = line.split()
                        for part in parts:
                            part = part.rstrip(".")
                            if "." in part and not part.startswith("Server") and len(part) > 4:
                                ip = _resolve(part)
                                if ip and ip not in ns_ips:
                                    ns_ips.append(ip)
            except Exception as _fix_e:
                logger.debug(f"[scanners.subdomain] {type(_fix_e).__name__}: {_fix_e!r}")

        # Yöntem 2: Yaygın NS prefix'leri dene
        if not ns_ips:
            for prefix in ["ns1", "ns2", "ns3", "ns4", "dns", "dns1", "dns2"]:
                fqdn = f"{prefix}.{domain}"
                ip = _resolve(fqdn)
                if ip and ip not in ns_ips:
                    ns_ips.append(ip)

        return ns_ips[:4]  # En fazla 4 NS

    def _axfr_raw(self, ns_ip: str, domain: str, timeout: int = 8) -> List[str]:
        """
        Raw TCP AXFR isteği gönderir ve yanıttaki domain adlarını çıkarır.
        """
        import struct
        records: List[str] = []
        try:
            def _encode_name(name: str) -> bytes:
                encoded = b""
                for label in name.rstrip(".").split("."):
                    lbl = label.encode("ascii", errors="replace")
                    encoded += bytes([len(lbl)]) + lbl
                return encoded + b"\x00"

            qname = _encode_name(domain)
            # AXFR type=252, class=IN=1
            question = qname + struct.pack(">HH", 252, 1)
            # DNS header: TxID=0xABCD, flags=0, qdcount=1
            header = struct.pack(">HHHHHH", 0xABCD, 0x0000, 1, 0, 0, 0)
            message = header + question
            tcp_msg = struct.pack(">H", len(message)) + message

            with socket.create_connection((ns_ip, 53), timeout=timeout) as s:
                s.sendall(tcp_msg)
                data = b""
                while True:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                    if len(data) > 131072:  # 128 KB limit
                        break

            # Domain adlarını ham yanıttan çıkar
            pattern = re.compile(
                r"([a-zA-Z0-9\-_]{1,63}(?:\.[a-zA-Z0-9\-_]{1,63})*\." + re.escape(domain) + r")"
            )
            text = data.decode("latin-1", errors="replace")
            found = set(pattern.findall(text))
            records.extend(found)
        except Exception as e:
            logger.debug(f"[ZoneTransfer] Raw AXFR hatası {ns_ip}: {e}")
        return list(set(records))

    def run(self, domain: str) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        ns_ips = self._get_nameservers(domain)
        if not ns_ips:
            logger.debug(f"[ZoneTransfer] {domain} için NS bulunamadı")
            return findings

        for ns_ip in ns_ips:
            logger.debug(f"[ZoneTransfer] AXFR deneniyor: {ns_ip} -> {domain}")
            records = self._axfr_raw(ns_ip, domain)
            # Zone transfer başarılıysa genellikle 10+ kayıt döner
            if len(records) >= 5:
                findings.append({
                    "type": "DNS Zone Transfer Açığı",
                    "severity": "Critical",
                    "url": f"dns://{domain}",
                    "title": f"DNS Zone Transfer Başarılı: NS={ns_ip}",
                    "message": (
                        f"Nameserver {ns_ip} AXFR isteğine izin veriyor. "
                        f"{len(records)} DNS kaydı açığa çıktı — saldırgan tüm altyapıyı haritalayabilir."
                    ),
                    "evidence": {"nameserver": ns_ip, "record_count": len(records), "records": records[:50]},
                })
                logger.warning(f"[ZoneTransfer] KRİTİK: {domain} @ {ns_ip} zone transfer'a açık!")
        return findings


# ---------------------------------------------------------------------------
# 8. ASNMapper — BGPView API ile ASN / IP blok haritalama
# ---------------------------------------------------------------------------

class ASNMapper:
    """
    BGPView API aracılığıyla hedef organizasyonun ASN'ini ve IP bloklarını tespit eder.
    Ücretsiz, auth gerektirmez.
    """
    _BGPVIEW = "https://api.bgpview.io"

    def run(self, domain: str) -> List[Dict[str, Any]]:
        if _requests is None:
            return []
        findings: List[Dict[str, Any]] = []
        try:
            ip = _resolve(domain)
            if not ip:
                return findings

            hdrs = {"User-Agent": "Mozilla/5.0 (WebSecure Scanner)"}

            # 1. IP -> ASN + prefix bilgisi
            r = _requests.get(f"{self._BGPVIEW}/ip/{ip}", timeout=15, headers=hdrs)
            asn_list: List[str] = []
            prefix_list: List[str] = []
            country: str = ""

            if r.status_code == 200:
                data = r.json().get("data", {})
                # Prefix listesi
                for pfx in data.get("prefixes", []):
                    asn_obj = pfx.get("asn") or {}
                    asn_num = asn_obj.get("asn", "")
                    asn_name = asn_obj.get("name", "")
                    if asn_num:
                        entry = f"AS{asn_num} ({asn_name})"
                        if entry not in asn_list:
                            asn_list.append(entry)
                    pfx_cidr = pfx.get("prefix")
                    if pfx_cidr and pfx_cidr not in prefix_list:
                        prefix_list.append(pfx_cidr)
                country = (data.get("rir_allocation") or {}).get("country_code", "")

            # 2. Org arama (domain prefix -> company adı ile)
            org = domain.split(".")[0]
            r2 = _requests.get(
                f"{self._BGPVIEW}/search", params={"query_term": org},
                timeout=15, headers=hdrs,
            )
            if r2.status_code == 200:
                search_data = r2.json().get("data", {})
                for asn_obj in search_data.get("asns", [])[:5]:
                    entry = f"AS{asn_obj.get('asn', '')} ({asn_obj.get('name', '')})"
                    if entry not in asn_list:
                        asn_list.append(entry)

            if asn_list or prefix_list:
                findings.append({
                    "type": "ASN / IP Blok Haritalaması",
                    "severity": "Info",
                    "url": f"https://{domain}",
                    "title": f"ASN Tespiti: {domain} ({ip})",
                    "message": f"{len(asn_list)} ASN, {len(prefix_list)} IP bloğu tespit edildi",
                    "evidence": {
                        "ip": ip,
                        "country": country,
                        "asns": asn_list[:10],
                        "ip_prefixes": prefix_list[:20],
                    },
                })
                logger.info(f"[ASNMapper] {domain}: {asn_list[:2]}, {len(prefix_list)} prefix")
        except Exception as e:
            logger.debug(f"[ASNMapper] Hata: {e}")
        return findings


# ---------------------------------------------------------------------------
# Ana Scanner sınıfı
# ---------------------------------------------------------------------------

class SubdomainScanner(BaseScanner):
    """
    Tüm subdomain enumeration yöntemlerini birleştirir:
    crt.sh + HackerTarget + Subfinder + Amass + SecurityTrails + DNS brute-force
    + DNS Zone Transfer + ASN Mapping
    """
    name: str = "subdomain"

    def __init__(
        self,
        session=None,
        results=None,
        debug=False,
        wordlist_path: Optional[str] = None,
        threads: int = 50,
        use_subfinder: bool = True,
        use_amass: bool = True,
        use_crtsh: bool = True,
        passive_only: bool = True,
        securitytrails_key: Optional[str] = None,
    ):
        super().__init__(session=session, results=results, debug=debug)
        self.wordlist_path = wordlist_path
        self.threads = threads
        self.use_subfinder = use_subfinder
        self.use_amass = use_amass
        self.use_crtsh = use_crtsh
        self.passive_only = passive_only
        self.securitytrails_key = securitytrails_key or os.environ.get("SECURITYTRAILS_API_KEY", "")

    @staticmethod
    def _enrich(item: Dict[str, Any], domain: str) -> Dict[str, Any]:
        """Fill the display fields a single subdomain record needs in the report."""
        sub = item.get("subdomain", "")
        item.setdefault("severity", "info")
        item.setdefault("title", f"Subdomain: {sub}")
        item.setdefault("domain", domain)
        item.setdefault("url", f"https://{sub}")
        item.setdefault("message", f"{sub} ({item.get('ip', '')}) [{item.get('method', '')}]")
        return item

    def run(self, target: str, **kwargs) -> List[Dict[str, Any]]:
        """BaseScanner interface — delegates to scan."""
        return self.scan(target, stream=bool(kwargs.get("stream", False)))

    def scan(self, target: str, stream: bool = False) -> List[Dict[str, Any]]:
        """Enumerate subdomains from every available source.

        When ``stream=True`` each newly discovered subdomain (and the
        zone-transfer / ASN findings) is written to the central report bucket the
        MOMENT its source finishes — instead of only after the whole scan returns.
        This is critical because active ``amass`` (passive_only=False) under
        no_timeout can run for many minutes; with the old all-or-nothing return,
        if that long tail was abandoned or the scan ended first, even the instant
        crt.sh / HackerTarget hits were silently lost (no ``subdomains`` bucket in
        the report at all). Streaming makes partial results always survive.
        """
        domain = _extract_domain(target)
        if not domain:
            logger.warning("[Subdomain] Geçerli domain çıkarılamadı.")
            return []

        # Lazy import so standalone use (stream=False) keeps zero reporting coupling.
        _emit = None
        if stream:
            try:
                from websecure.core.reporting import add_result as _emit
            except Exception as _imp_exc:  # pragma: no cover
                logger.debug(f"[Subdomain] streaming devre dışı (import): {_imp_exc!r}")
                _emit = None

        logger.info(f"[Subdomain] Hedef domain: {domain}")
        all_results: List[Dict[str, Any]] = []
        seen_subs: Set[str] = set()

        def _add(items: List[Dict[str, Any]]):
            for item in items:
                sub = item.get("subdomain", "")
                if sub and sub not in seen_subs:
                    seen_subs.add(sub)
                    self._enrich(item, domain)
                    all_results.append(item)
                    if _emit:                      # persist immediately — survive abandonment
                        try:
                            _emit("subdomains", item)
                        except Exception as _e:
                            logger.debug(f"[Subdomain] stream emit hatası: {_e!r}")

        # 1. crt.sh — hızlı, pasif, araç gerektirmez
        if self.use_crtsh:
            _add(_crtsh_enum(domain))

        # 2. HackerTarget — ücretsiz API
        _add(HackerTargetWrapper().run(domain))

        # 3. Subfinder — harici araç (kuruluysa)
        if self.use_subfinder:
            _add(SubfinderWrapper().run(domain))

        # 5. SecurityTrails — key varsa (hızlı API, amass'tan ÖNCE)
        if self.securitytrails_key:
            _add(SecurityTrailsWrapper(api_key=self.securitytrails_key).run(domain))

        # 6. DNS brute-force — her zaman çalışır (kendi bütçesiyle sınırlı)
        brute = DNSBruteForce(wordlist_path=self.wordlist_path, threads=self.threads)
        _add(brute.run(domain))

        # 4. Amass — harici araç (kuruluysa). EN SONA alındı: aktif enum (passive_only
        #    False) çok uzun sürebilir; yukarıdaki hızlı kaynaklar artık çoktan
        #    rapora yazıldığı için amass uzasa/terk edilse bile sonuç KAYBOLMAZ.
        if self.use_amass:
            # Aktif modda bile sonlu tut: no_timeout watchdog bütçesi (~600s) ile
            # hizalı — aksi halde tek bir hedef için amass faz join'ini saatlerce
            # bloklayabilir.
            _amass_timeout = 600 if not self.passive_only else 240
            _add(AmassWrapper().run(domain, passive=self.passive_only, timeout=_amass_timeout))

        logger.info(f"[Subdomain] Toplam {len(all_results)} benzersiz subdomain bulundu")

        # 7. DNS Zone Transfer — kritik güvenlik testi. Bulgular ARTIK merkezî rapora
        #    akar (eskiden run() taze bir {} verdiğinden self.results'a yazılıp KAYBOLUYORDU).
        zone_findings = DNSZoneTransfer().run(domain)
        for zf in zone_findings:
            if isinstance(self.results, dict):
                self.results.setdefault("passive", []).append(zf)
            if _emit:
                try:
                    _emit("offensive", zf)   # Critical bulgu — bulgu kovasına
                except Exception:
                    pass

        # 8. ASN / IP Blok haritalama
        asn_findings = ASNMapper().run(domain)
        for af in asn_findings:
            if isinstance(self.results, dict):
                self.results.setdefault("passive", []).append(af)
            if _emit:
                try:
                    _emit("passive", af)
                except Exception:
                    pass

        return all_results


# ---------------------------------------------------------------------------
# Plugin API (phases.py tarafından çağrılır)
# ---------------------------------------------------------------------------

def run(target: str, cfg: Optional[Dict[str, Any]] = None, session=None) -> List[Dict[str, Any]]:
    """
    Plugin entry point.
    cfg anahtarları:
      subdomain.wordlist              — özel wordlist yolu
      subdomain.threads               — brute-force thread sayısı (varsayılan: 50)
      subdomain.use_subfinder         — subfinder kullan (varsayılan: True)
      subdomain.use_amass             — amass kullan (varsayılan: True)
      subdomain.use_crtsh             — crt.sh sorgula (varsayılan: True)
      subdomain.passive_only          — sadece passive tarama (varsayılan: True)
      subdomain.securitytrails_key    — SecurityTrails API key (opsiyonel)
    """
    cfg = cfg or {}
    sub_cfg = cfg.get("subdomain", {}) if isinstance(cfg, dict) else {}

    scanner = SubdomainScanner(
        wordlist_path=sub_cfg.get("wordlist"),
        threads=int(sub_cfg.get("threads", 50)),
        use_subfinder=bool(sub_cfg.get("use_subfinder", True)),
        use_amass=bool(sub_cfg.get("use_amass", True)),
        use_crtsh=bool(sub_cfg.get("use_crtsh", True)),
        passive_only=bool(sub_cfg.get("passive_only", True)),
        securitytrails_key=sub_cfg.get("securitytrails_key"),
    )

    # stream=True → her kaynak biter bitmez merkezî 'subdomains' kovasına yaz
    # (yavaş/aktif amass terk edilse bile hızlı kaynakların sonucu rapora düşer).
    return scanner.scan(target, stream=True)
