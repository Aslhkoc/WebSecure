"""
websecure.integrations.nuclei
------------------------------
Nuclei vulnerability scanner — full integration.

Özellikler:
  - tools/nuclei/nuclei.exe otomatik keşif (PATH gerekmez)
  - Nuclei v2 + v3 uyumlu flag'ler
  - Tech-aware template seçimi: tespit edilen teknolojilere göre tag'ler
  - OAST/interactsh entegrasyonu: kör SSRF/XXE/RCE tespiti
  - Stealth / Agresif profil: rate-limit ve concurrency otomatik ayarı
  - Custom templates: proje içi templates/nuclei/ dizini
  - Deduplication: mevcut WebSecure bulgularıyla fingerprint karşılaştırması
  - Bulgu zenginleştirme: CVE ID, CVSS, CWE, referanslar
  - Şablon yaşlanma kontrolü: 24 saatte bir otomatik güncelleme
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

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
# Sabitler
# ---------------------------------------------------------------------------

# 24 saatte bir güncelleme tetiklenir
_TEMPLATE_STALENESS_SECONDS: int = 86_400

# Son güncelleme zaman damgası dosyası
_LAST_UPDATE_FILE: Path = Path.home() / ".nuclei" / ".ws_last_update"

# Severity eşlemesi
_SEV_MAP: Dict[str, str] = {
    "critical": "Critical",
    "high":     "High",
    "medium":   "Medium",
    "low":      "Low",
    "info":     "Info",
    "unknown":  "Info",
}

# Varsayılan Nuclei tag'leri: kapsamlı kapsam
_DEFAULT_TAGS: str = (
    "cve,default-logins,exposed-panels,misconfig,takeover,tech,"
    "xss,sqli,ssrf,rce,lfi,xxe,ssti,idor,redirect,auth-bypass,"
    "injection,traversal,disclosure,exposure,intrusive"
)

# Teknoloji → Nuclei tag eşlemesi
_TECH_TAG_MAP: Dict[str, str] = {
    "wordpress":   "wordpress",
    "drupal":      "drupal",
    "joomla":      "joomla",
    "apache":      "apache",
    "nginx":       "nginx",
    "iis":         "iis",
    "php":         "php",
    "java":        "java,spring",
    "tomcat":      "apache,tomcat",
    "nodejs":      "node",
    "django":      "django",
    "flask":       "flask",
    "aspnet":      "asp,iis",
    "graphql":     "graphql",
    "jenkins":     "jenkins",
    "gitlab":      "gitlab",
    "github":      "github",
    "jira":        "jira",
    "confluence":  "confluence",
    "sonarqube":   "sonarqube",
    "elasticsearch": "elasticsearch",
    "kibana":      "kibana",
    "redis":       "redis",
    "mongodb":     "mongodb",
    "mysql":       "mysql",
    "postgresql":  "postgresql",
    "laravel":     "laravel",
    "symfony":     "symfony",
    "kubernetes":  "kubernetes,k8s",
    "docker":      "docker",
    "prometheus":  "prometheus",
    "grafana":     "grafana",
    "swagger":     "swagger",
    "spring":      "spring,springboot",
    "struts":      "struts",
    "coldfusion":  "coldfusion",
    "websphere":   "websphere",
    "weblogic":    "weblogic",
    "sharepoint":  "sharepoint",
    "exchange":    "exchange",
    "citrix":      "citrix",
    "f5":          "f5",
    "fortinet":    "fortinet",
}

# Nuclei v3'te değiştirilen flag'ler (eski → yeni)
_V3_FLAG_CHANGES: Dict[str, str] = {
    "-update-templates": "-ut",
    "-json":             "-je",        # v3'te -je <file> formatına geçti
}

# Rate limit profil ayarları
_RATE_LIMIT_BY_PROFILE: Dict[str, int] = {
    "stealth":    10,
    "normal":     75,
    "aggressive": 200,
}

# Concurrency profil ayarları
_CONCURRENCY_BY_PROFILE: Dict[str, int] = {
    "stealth":    5,
    "normal":     25,
    "aggressive": 50,
}


# ---------------------------------------------------------------------------
# NucleiWrapper
# ---------------------------------------------------------------------------

class NucleiWrapper(ToolIntegration):
    """
    Nuclei vulnerability scanner wrapper.
    https://github.com/projectdiscovery/nuclei

    Thread-safe değil — her tarama için yeni instance oluşturun.
    """

    def __init__(self, binary_path: str = "nuclei") -> None:
        # ToolIntegration.__init__ → _resolve_binary(binary_path) çağırır.
        # Bu, tools/nuclei/nuclei.exe → PATH sırasıyla binary'yi bulur.
        super().__init__(binary_path)
        self._version_major: Optional[int] = None   # 2 veya 3
        self._custom_templates_dir: Optional[str] = self._find_project_templates()

    # ------------------------------------------------------------------
    # ToolIntegration arayüzü
    # ------------------------------------------------------------------

    @property
    def tool_name(self) -> str:
        return "nuclei"

    def is_available(self) -> bool:
        """Binary keşfedildiyse True döner."""
        # ToolIntegration._resolve_binary() self._binary_path'i set eder.
        # self.binary → self._binary_path or self._binary_name
        bp = self._binary_path
        if bp and Path(bp).exists():
            return True
        # Fallback: PATH kontrolü
        return shutil.which("nuclei") is not None

    def run(self, target: str, **kwargs) -> ToolResult:
        """ToolIntegration arayüzü — tarama yap ve ToolResult döndür."""
        start = time.monotonic()
        raw = self.scan(
            target,
            tags=kwargs.get("tags"),
            severity=kwargs.get("severity", "low,medium,high,critical"),
            rate_limit=kwargs.get("rate_limit"),
            concurrency=kwargs.get("concurrency"),
            timeout=kwargs.get("timeout", 300),
            proxy=kwargs.get("proxy"),
            tech_stack=kwargs.get("tech_stack"),
            profile_cfg=kwargs.get("profile_cfg"),
            profile=kwargs.get("profile", "normal"),
            interactsh_url=kwargs.get("interactsh_url"),
            custom_templates=kwargs.get("custom_templates"),
        )
        findings = [self._raw_to_tool_finding(f) for f in raw]
        return ToolResult(
            tool=self.tool_name,
            target=target,
            status=ToolStatus.SUCCESS,
            findings=findings,
            duration_s=time.monotonic() - start,
        )

    # ------------------------------------------------------------------
    # Versiyon tespiti
    # ------------------------------------------------------------------

    def get_version_major(self) -> int:
        """Nuclei ana versiyonu döndürür (2 veya 3). Bilinmiyorsa 3."""
        if self._version_major is not None:
            return self._version_major
        if not self.is_available():
            self._version_major = 3
            return 3
        try:
            proc = subprocess.run(
                [self.binary, "-version"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=10,
                check=False,
            )
            out = _strip_ansi(
                (proc.stdout or proc.stderr or b"").decode("utf-8", "ignore")
            )
            # "Nuclei Engine Version: v3.x.x"
            for line in out.splitlines():
                if "version" in line.lower():
                    for token in line.split():
                        if token.startswith("v") and "." in token:
                            major = token.lstrip("v").split(".")[0]
                            if major.isdigit():
                                self._version_major = int(major)
                                return self._version_major
        except Exception as exc:
            logger.debug(f"[Nuclei] Versiyon tespiti başarısız: {exc!r}")
        self._version_major = 3
        return 3

    def get_template_version(self) -> Optional[str]:
        """Şablon versiyonunu döndürür (ANSI kodları temizlenmiş)."""
        if not self.is_available():
            return None
        try:
            proc = subprocess.run(
                [self.binary, "-version"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=10,
                check=False,
            )
            out = (proc.stdout or proc.stderr or b"").decode("utf-8", "ignore")
            out = _strip_ansi(out)
            for line in out.splitlines():
                line_l = line.lower()
                if "template" in line_l and "version" in line_l:
                    return line.strip()
            # Engine versiyonunu döndür
            for line in out.splitlines():
                if "version" in line.lower() and "v" in line.lower():
                    return line.strip()
            return out.strip().splitlines()[0] if out.strip() else None
        except Exception as exc:
            logger.debug(f"[Nuclei] Şablon versiyon kontrolü başarısız: {exc!r}")
            return None

    # ------------------------------------------------------------------
    # Şablon yönetimi
    # ------------------------------------------------------------------

    def _find_project_templates(self) -> Optional[str]:
        """Proje içi özel Nuclei şablon dizinini arar."""
        from websecure.core.paths import writable_root as _ws_root
        root = _ws_root()
        for candidate in [
            root / "templates" / "nuclei",
            root / "tools" / "nuclei-templates",
            root / "nuclei-templates",
        ]:
            if candidate.is_dir() and any(candidate.glob("**/*.yaml")):
                logger.debug(f"[Nuclei] Proje şablon dizini: {candidate}")
                return str(candidate)
        return None

    def _templates_are_stale(self) -> bool:
        """Şablonlar 24 saatten eski mi?"""
        try:
            if _LAST_UPDATE_FILE.exists():
                last = float(_LAST_UPDATE_FILE.read_text(encoding="utf-8").strip())
                return (time.time() - last) > _TEMPLATE_STALENESS_SECONDS
        except Exception as _fix_e:
            logger.debug(f"[integrations.nuclei] {type(_fix_e).__name__}: {_fix_e!r}")
        return True

    def _mark_updated(self) -> None:
        try:
            _LAST_UPDATE_FILE.parent.mkdir(parents=True, exist_ok=True)
            _LAST_UPDATE_FILE.write_text(str(time.time()), encoding="utf-8")
        except Exception as exc:
            logger.debug(f"[Nuclei] Güncelleme işaretçisi yazılamadı: {exc!r}")

    def update_templates(self, force: bool = False, timeout: int = 120) -> bool:
        """
        Nuclei şablonlarını günceller.
        v2: -update-templates   v3: -ut   (her ikisi de denenecek)
        """
        if not self.is_available():
            logger.warning("[Nuclei] Binary yok — şablon güncelleme atlandı")
            return False

        if not force and not self._templates_are_stale():
            logger.debug("[Nuclei] Şablonlar güncel (< 24s), atlandı")
            return True

        logger.info("[Nuclei] Şablonlar güncelleniyor...")

        # v3 önce, yoksa v2 flag dene
        for update_flag in ["-ut", "-update-templates"]:
            try:
                proc = subprocess.run(
                    [self.binary, update_flag, "-silent"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=timeout,
                    check=False,
                )
                if proc.returncode == 0:
                    self._mark_updated()
                    logger.info("[Nuclei] Şablonlar başarıyla güncellendi")
                    return True
                stderr_out = (proc.stderr or b"").decode("utf-8", "ignore")[:200]
                # "unknown flag" hatası değilse gerçek hata
                if "unknown" not in stderr_out.lower() and "flag" not in stderr_out.lower():
                    logger.warning(
                        f"[Nuclei] Güncelleme başarısız (rc={proc.returncode}): {stderr_out}"
                    )
                    return False
                # Bilinmeyen flag → diğer flag'i dene
                logger.debug(f"[Nuclei] Flag '{update_flag}' tanınmadı, alternatif deneniyor")
            except subprocess.TimeoutExpired:
                logger.warning(f"[Nuclei] Güncelleme {timeout}s içinde tamamlanamadı")
                return False
            except Exception as exc:
                logger.error(f"[Nuclei] Güncelleme hatası ({update_flag}): {exc!r}")

        return False

    def ensure_templates_fresh(self, timeout: int = 120) -> None:
        """Eski şablonları sessizce günceller."""
        if self._templates_are_stale():
            self.update_templates(timeout=timeout)

    # ------------------------------------------------------------------
    # Ana tarama
    # ------------------------------------------------------------------

    def scan(
        self,
        target: str,
        tags: Optional[str] = None,
        templates: Optional[str] = None,
        severity: str = "low,medium,high,critical",
        rate_limit: Optional[int] = None,
        concurrency: Optional[int] = None,
        timeout: int = 300,
        proxy: Optional[str] = None,
        extra_args: Optional[List[str]] = None,
        tech_stack: Optional[List[str]] = None,
        profile_cfg: Optional[Dict] = None,
        profile: str = "normal",
        interactsh_url: Optional[str] = None,
        custom_templates: Optional[str] = None,
        auto_update: bool = False,
        deduplicate_fps: Optional[Set[str]] = None,
    ) -> List[Dict[str, Any]]:
        """
        Nuclei ile hedefi tara, WebSecure native bulgu listesi döndür.

        Parametreler
        ------------
        target           : Taranacak URL
        tags             : Virgülle ayrılmış tag listesi (None → otomatik seçim)
        templates        : Özel şablon dizini / dosyası
        severity         : Minimum severity filtresi
        rate_limit       : Saniyedeki istek sayısı (None → profile'a göre)
        concurrency      : Eşzamanlı template sayısı (None → profile'a göre)
        timeout          : Toplam tarama timeout (saniye)
        proxy            : HTTP/SOCKS proxy URL'si
        tech_stack       : Tespit edilen teknoloji listesi (tag genişletme için)
        profile_cfg      : Config dict'ten alınan ek nuclei ayarları
        profile          : "stealth" | "normal" | "aggressive"
        interactsh_url   : OAST callback URL'si (kör vuln tespiti için)
        custom_templates : Proje özel şablon dizini
        auto_update      : Başlamadan önce şablonları güncelle
        deduplicate_fps  : Çıkarılacak mevcut bulgu fingerprint seti
        """
        if not self.is_available():
            logger.warning("[Nuclei] Binary bulunamadı, tarama atlandı")
            return []

        # Şablon güncelleme (sadece serbest çalışmada, stealth'te atla)
        if auto_update and profile != "stealth":
            self.ensure_templates_fresh(timeout=60)

        # Profile bazlı rate limit / concurrency
        _profile_key = profile.lower() if profile.lower() in _RATE_LIMIT_BY_PROFILE else "normal"
        _rl  = rate_limit  if rate_limit  is not None else _RATE_LIMIT_BY_PROFILE[_profile_key]
        _con = concurrency if concurrency is not None else _CONCURRENCY_BY_PROFILE[_profile_key]

        # Config override
        if profile_cfg:
            _rl  = int(profile_cfg.get("rate_limit",   _rl))
            _con = int(profile_cfg.get("concurrency",  _con))

        # Geçici JSONL çıktı dosyası
        fd, output_file = tempfile.mkstemp(suffix=".jsonl")
        os.close(fd)

        try:
            cmd = self._build_cmd(
                target=target,
                output_file=output_file,
                tags=tags,
                templates=templates or custom_templates or self._custom_templates_dir,
                severity=severity,
                rate_limit=_rl,
                concurrency=_con,
                proxy=proxy,
                tech_stack=tech_stack,
                interactsh_url=interactsh_url,
                extra_args=extra_args,
                profile=_profile_key,
            )

            logger.info(
                f"[Nuclei] Tarama başlıyor → {target} "
                f"(profile={_profile_key}, rl={_rl}, c={_con})"
            )
            logger.debug(f"[Nuclei] cmd: {' '.join(cmd)}")

            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
            )

            # Child process kaydı (faz yönetici sinyal gönderirse temizlenir)
            _unreg = None
            try:
                from websecure.core.phases import register_child_proc, unregister_child_proc
                register_child_proc(proc)
                _unreg = unregister_child_proc
            except Exception as _fix_e:
                logger.debug(f"[integrations.nuclei] {type(_fix_e).__name__}: {_fix_e!r}")

            timed_out = False
            stderr_b = b""
            try:
                _, stderr_b = proc.communicate(timeout=effective_timeout(timeout))
            except subprocess.TimeoutExpired:
                timed_out = True
                proc.kill()
                try:
                    proc.communicate(timeout=10)
                except subprocess.TimeoutExpired:
                    pass
                logger.warning(
                    f"[Nuclei] Tarama {timeout}s içinde bitmedi — kısmi sonuçlar kullanılıyor"
                )
            finally:
                if _unreg:
                    _unreg(proc)

            # rc=0 → bulgu yok, rc=1 → bulgu var; diğerleri hata (timeout'ta atla)
            if not timed_out and proc.returncode not in (0, 1):
                stderr_out = (stderr_b or b"").decode("utf-8", "ignore")[:500]
                logger.warning(
                    f"[Nuclei] Hatalı çıkış kodu {proc.returncode} — "
                    f"çıktı ayrıştırılmıyor. stderr={stderr_out!r}"
                )
                return []

            findings = self._parse_output(output_file)

            # Deduplication
            if deduplicate_fps and findings:
                before = len(findings)
                findings = [
                    f for f in findings
                    if _finding_fingerprint(f) not in deduplicate_fps
                ]
                removed = before - len(findings)
                if removed:
                    logger.info(f"[Nuclei] {removed} tekrar bulgu çıkarıldı")

            logger.info(f"[Nuclei] Tamamlandı: {len(findings)} bulgu")
            return findings

        except FileNotFoundError:
            logger.error(
                f"[Nuclei] Binary çalıştırılamadı: {self.binary!r} — "
                "PATH veya tools/nuclei/ dizinini kontrol edin"
            )
            return []
        except Exception as exc:
            logger.error(f"[Nuclei] Beklenmedik hata: {exc!r}")
            return []
        finally:
            try:
                os.remove(output_file)
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Komut oluşturucu
    # ------------------------------------------------------------------

    def _build_cmd(
        self,
        target: str,
        output_file: str,
        tags: Optional[str],
        templates: Optional[str],
        severity: str,
        rate_limit: int,
        concurrency: int,
        proxy: Optional[str],
        tech_stack: Optional[List[str]],
        interactsh_url: Optional[str],
        extra_args: Optional[List[str]],
        profile: str,
    ) -> List[str]:
        """Nuclei komut satırını oluşturur (v2/v3 uyumlu)."""
        v3 = self.get_version_major() >= 3

        # v3: -j (jsonl format) -o <file>
        # v2: -jle <file>
        if v3:
            output_flags = ["-j", "-o", output_file]
        else:
            output_flags = ["-jle", output_file]

        # Stealth'te istek başına daha uzun timeout — tek sefer ayarla
        _req_timeout = "15" if profile == "stealth" else "10"

        cmd: List[str] = [
            self.binary,
            "-u", target,
            *output_flags,
            "-silent",
            "-nc",                                  # renkli çıktı kapalı
            "-rate-limit", str(rate_limit),
            "-c", str(concurrency),                 # template concurrency
            "-severity", severity,
            "-timeout", _req_timeout,               # istek başına timeout (saniye)
            "-retries", "1",
            "-mhe", "50",                           # max host errors
        ]

        # Şablon seçimi: custom dizin veya tag bazlı
        if templates and Path(templates).exists():
            cmd.extend(["-t", templates])
        else:
            active_tags: Set[str] = set((tags or _DEFAULT_TAGS).split(","))
            if tech_stack:
                for tech in tech_stack:
                    mapped = _TECH_TAG_MAP.get(tech.lower())
                    if mapped:
                        active_tags.update(mapped.split(","))
            # Boş tag'leri temizle
            active_tags = {t.strip() for t in active_tags if t.strip()}
            cmd.extend(["-tags", ",".join(sorted(active_tags))])

        # OAST / interactsh entegrasyonu
        if interactsh_url:
            # -iserver / -interactsh-server: kendi sunucumuzu belirt
            iserver_flag = "-iserver" if v3 else "-interactsh-url"
            cmd.extend([iserver_flag, interactsh_url])
            logger.info(f"[Nuclei] OAST server: {interactsh_url}")
        elif profile == "stealth":
            # Stealth modda varsayılan OAST sunucularına da bağlanma
            cmd.append("-no-interactsh")

        # Proxy
        if proxy:
            _proxy = proxy.replace("socks5h://", "socks5://")
            cmd.extend(["-proxy", _proxy])

        if extra_args:
            cmd.extend(extra_args)

        return cmd

    # ------------------------------------------------------------------
    # Çıktı ayrıştırma
    # ------------------------------------------------------------------

    def _parse_output(self, file_path: str) -> List[Dict[str, Any]]:
        """Nuclei JSONL çıktısını WebSecure finding listesine dönüştürür."""
        findings: List[Dict[str, Any]] = []
        if not os.path.exists(file_path):
            return findings
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        data = json.loads(line)
                        finding = self._normalize_finding(data)
                        if finding:
                            findings.append(finding)
                    except json.JSONDecodeError:
                        continue
        except Exception as exc:
            logger.error(f"[Nuclei] Çıktı ayrıştırma hatası: {exc!r}")
        return findings

    def _normalize_finding(self, data: Dict) -> Optional[Dict[str, Any]]:
        """Ham Nuclei JSON → WebSecure standart bulgu formatı."""
        try:
            info        = data.get("info", {}) or {}
            sev_raw     = (info.get("severity") or "info").lower()
            severity    = _SEV_MAP.get(sev_raw, "Info")

            matched_at  = data.get("matched-at") or data.get("host") or ""
            template_id = data.get("template-id") or data.get("templateID") or ""
            template_nm = info.get("name") or template_id
            description = info.get("description") or f"Nuclei şablonu eşleşti: {template_id}"

            # CVE / CVSS / CWE
            classif     = info.get("classification") or {}
            cve_ids: List[str] = []
            raw_cve = classif.get("cve-id") or []
            if isinstance(raw_cve, str):
                cve_ids = [raw_cve] if raw_cve else []
            elif isinstance(raw_cve, list):
                cve_ids = [c for c in raw_cve if c]

            cvss_score  = classif.get("cvss-score")
            cvss_vec    = classif.get("cvss-metrics") or classif.get("cvss-vector") or ""
            cwe_ids: List[str] = []
            raw_cwe = classif.get("cwe-id") or []
            if isinstance(raw_cwe, str):
                cwe_ids = [raw_cwe] if raw_cwe else []
            elif isinstance(raw_cwe, list):
                cwe_ids = [c for c in raw_cwe if c]

            # Curl / request kanıtı
            curl_cmd    = data.get("curl-command") or ""
            matcher_nm  = data.get("matcher-name") or ""
            extracted   = data.get("extracted-results") or []

            # Tags
            tags_raw    = info.get("tags") or []
            tags: List[str] = tags_raw if isinstance(tags_raw, list) else str(tags_raw).split(",")

            # Referanslar
            refs        = info.get("reference") or []

            # Teknoloji tespiti mi?
            is_tech     = "tech" in tags

            return {
                "type":       f"Nuclei: {template_nm}",
                "vuln_type":  template_nm,
                "severity":   severity,
                "url":        matched_at,
                "method":     "GET",
                "source":     "nuclei",
                "template_id": template_id,
                "verified":   True,
                "confidence": "high",
                "is_tech_detection": is_tech,
                "description": description,
                "cve_ids":    cve_ids,
                "cvss_score": float(cvss_score) if cvss_score else None,
                "cvss_vector": cvss_vec,
                "cwe_ids":    cwe_ids,
                "detail": description,
                "evidence": {
                    "template_id":  template_id,
                    "matched_at":   matched_at,
                    "matcher":      matcher_nm,
                    "extracted":    extracted[:5] if extracted else [],
                    "curl":         curl_cmd[:600] if curl_cmd else "",
                    "tags":         tags,
                    "references":   refs[:5],
                    "cve_id":       cve_ids,
                    "cwe":          cwe_ids,
                    "cvss_score":   float(cvss_score) if cvss_score else None,
                    "cvss_vector":  cvss_vec,
                },
            }
        except Exception as exc:
            logger.debug(f"[Nuclei] Bulgu normalleştirme hatası: {exc!r}")
            return None

    def _raw_to_tool_finding(self, f: Dict[str, Any]) -> ToolFinding:
        """WebSecure native dict → ToolFinding dönüşümü."""
        ev = f.get("evidence") or {}
        cve = ev.get("cve_id", []) if isinstance(ev, dict) else []
        if isinstance(cve, str):
            cve = [cve] if cve else []
        return ToolFinding(
            title=f.get("type", "Nuclei Finding"),
            severity=ToolSeverity.from_str(f.get("severity", "info")),
            url=f.get("url", ""),
            tool=self.tool_name,
            description=f.get("description", ""),
            evidence=str(ev.get("curl", ""))[:300] if isinstance(ev, dict) else "",
            cve_ids=list(cve),
            cvss_score=f.get("cvss_score"),
            confidence=f.get("confidence", "high"),
            verified=f.get("verified", True),
            tags=list(ev.get("tags", [])) if isinstance(ev, dict) else [],
            raw=f,
        )


# ---------------------------------------------------------------------------
# Yardımcılar
# ---------------------------------------------------------------------------

def _strip_ansi(text: str) -> str:
    """ANSI renk/biçim kaçış kodlarını ve nuclei log prefix'lerini temizler."""
    # ANSI escape: \x1b[...m
    text = re.sub(r"\x1b\[[0-9;]*[mGKHFABCDEJ]", "", text)
    # nuclei v3 log prefix: [INF] [WRN] [ERR] [DBG]
    text = re.sub(r"\[(?:INF|WRN|ERR|DBG|VER)\]\s*", "", text)
    # Kalan bracket-number: [34m gibi artık kodlar
    text = re.sub(r"\[\d+m", "", text)
    return text


# ---------------------------------------------------------------------------
# Yardımcı: fingerprint
# ---------------------------------------------------------------------------

def _finding_fingerprint(finding: Dict[str, Any]) -> str:
    """Bulgu için benzersiz string anahtarı (dedup için)."""
    key = f"{finding.get('template_id','')}{finding.get('url','')}{finding.get('severity','')}"
    return hashlib.md5(key.encode(), usedforsecurity=False).hexdigest()


# ---------------------------------------------------------------------------
# Teknoloji çıkarma (ctx.technologies güncelleme için)
# ---------------------------------------------------------------------------

def extract_technologies_from_findings(
    findings: List[Dict[str, Any]],
) -> List[str]:
    """
    Nuclei bulgularındaki tech-detection sonuçlarını çıkarır.
    phases/__init__.py tarafından ctx.technologies'i güncellemek için kullanılır.
    """
    techs: List[str] = []
    for f in findings:
        if not f.get("is_tech_detection"):
            continue
        # Template ID genellikle "detect-wordpress", "nginx-version" şeklinde
        tid = (f.get("template_id") or "").lower()
        nm  = (f.get("vuln_type") or "").lower()
        for tech in _TECH_TAG_MAP:
            if tech in tid or tech in nm:
                techs.append(tech)
    return list(set(techs))


# ---------------------------------------------------------------------------
# Bağımsız kullanım kolaylığı fonksiyonları
# ---------------------------------------------------------------------------

def run_nuclei_scan(
    target: str,
    tech_stack: Optional[List[str]] = None,
    proxy: Optional[str] = None,
    rate_limit: int = 75,
    profile: str = "normal",
    interactsh_url: Optional[str] = None,
    auto_update: bool = True,
    deduplicate_fps: Optional[Set[str]] = None,
) -> List[Dict[str, Any]]:
    """Hedefi Nuclei ile tara. Binary yoksa boş liste döner."""
    wrapper = NucleiWrapper()
    if not wrapper.is_available():
        logger.info("[Nuclei] Binary bulunamadı — tarama atlandı")
        return []
    return wrapper.scan(
        target,
        tech_stack=tech_stack,
        proxy=proxy,
        rate_limit=rate_limit,
        profile=profile,
        interactsh_url=interactsh_url,
        auto_update=auto_update,
        deduplicate_fps=deduplicate_fps,
    )


def update_nuclei_templates(force: bool = False, timeout: int = 120) -> bool:
    """Nuclei şablonlarını günceller. Başarılıysa True döner."""
    wrapper = NucleiWrapper()
    return wrapper.update_templates(force=force, timeout=timeout)


def run_nuclei_with_correlation(
    target: str,
    existing_fingerprints: Optional[Set[str]] = None,
    tech_stack: Optional[List[str]] = None,
    rate_limit: int = 75,
    profile: str = "normal",
    interactsh_url: Optional[str] = None,
    sarif_output: Optional[str] = None,
) -> Tuple[List[Dict[str, Any]], List[str]]:
    """
    Nuclei taraması + WebSecure bulguları ile korelasyon + teknoloji çıkarma.

    Döndürür
    --------
    (yeni_bulgular, tespit_edilen_teknolojiler)
    """
    wrapper = NucleiWrapper()
    if not wrapper.is_available():
        logger.warning("[Nuclei] run_nuclei: binary bulunamadı, atlanıyor.")
        return [], []

    fps = frozenset(existing_fingerprints or set())
    raw = wrapper.scan(
        target,
        tech_stack=tech_stack,
        rate_limit=rate_limit,
        profile=profile,
        interactsh_url=interactsh_url,
        deduplicate_fps=set(fps),
    )

    new_techs = extract_technologies_from_findings(raw)

    if sarif_output:
        try:
            from websecure.integrations.sarif import SARIFNormalizer
            norm = SARIFNormalizer()
            for f in raw:
                ev = f.get("evidence") or {}
                tf = ToolFinding(
                    title=f.get("type", "Nuclei"),
                    severity=ToolSeverity.from_str(f.get("severity", "info")),
                    url=f.get("url", target),
                    tool="nuclei",
                    description=f.get("description", ""),
                    evidence=str(ev.get("curl", ""))[:300] if isinstance(ev, dict) else "",
                    cve_ids=ev.get("cve_id", []) if isinstance(ev, dict) else [],
                    cvss_score=f.get("cvss_score"),
                    confidence="high",
                    verified=True,
                    tags=ev.get("tags", []) if isinstance(ev, dict) else [],
                    raw=f,
                )
                norm.ingest_findings([tf])
            norm.save(sarif_output)
        except Exception as exc:
            logger.debug(f"[Nuclei] SARIF yazma hatası: {exc!r}")

    return raw, new_techs
