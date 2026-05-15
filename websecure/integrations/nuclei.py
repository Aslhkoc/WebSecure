"""
websecure.integrations.nuclei
------------------------------
Nuclei vulnerability scanner wrapper.
Nuclei uses community YAML templates to detect thousands of CVEs, misconfigs,
exposed panels, default creds, and more.
"""
import json
import logging
import os
import shutil
import subprocess
import tempfile
import time
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

# How old (in seconds) templates must be before auto-update triggers (default: 24h)
_TEMPLATE_STALENESS_SECONDS = 86_400   # 24 hours
# Marker file storing last successful update timestamp
_LAST_UPDATE_FILE = Path.home() / ".nuclei" / ".ws_last_update"

# Severity mapping from nuclei to WebSecure standard
_SEV_MAP = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "info": "Info",
    "unknown": "Info",
}

# Default template categories to run (fast + impactful)
_DEFAULT_TAGS = "cve,default-logins,exposed-panels,misconfig,takeover,tech"

# Template categories that match detected technologies
_TECH_TEMPLATE_MAP = {
    "wordpress": "wordpress",
    "drupal": "drupal",
    "joomla": "joomla",
    "apache": "apache",
    "nginx": "nginx",
    "iis": "iis",
    "php": "php",
    "java": "java",
    "tomcat": "apache,tomcat",
    "nodejs": "node",
    "django": "django",
    "aspnet": "asp,iis",
    "graphql": "graphql",
    "rest_api": "api",
    "cloudflare": "cloudflare",
}


class NucleiWrapper(ToolIntegration):
    """
    Wrapper for the Nuclei vulnerability scanner.
    https://github.com/projectdiscovery/nuclei
    """

    def __init__(self, binary_path: str = "nuclei"):
        super().__init__("")
        self._binary_name = binary_path
        self._check_binary()

    @property
    def tool_name(self) -> str:
        return "nuclei"

    def _check_binary(self) -> None:
        if shutil.which(self.binary):
            return
        # Check project tools folder
        root = Path(__file__).resolve().parent.parent.parent
        for candidate in [
            root / "tools" / "nuclei" / "nuclei.exe",
            root / "tools" / "nuclei.exe",
            root / "tools" / "nuclei" / "nuclei",
            root / "tools" / "nuclei",
        ]:
            if candidate.exists():
                self._binary_path = str(candidate)
                return
        logger.warning("[Nuclei] Binary bulunamadi. Program baslarken otomatik indirilecek.")

    def is_available(self) -> bool:
        return shutil.which(self.binary) is not None or Path(self.binary).exists()

    def run(self, target: str, **kwargs) -> ToolResult:
        """ToolIntegration interface — scan target and return ToolResult."""
        start = time.monotonic()
        raw = self.scan(
            target,
            tags=kwargs.get("tags"),
            severity=kwargs.get("severity", "low,medium,high,critical"),
            rate_limit=kwargs.get("rate_limit", 150),
            timeout=kwargs.get("timeout", 300),
            proxy=kwargs.get("proxy"),
            tech_stack=kwargs.get("tech_stack"),
            profile_cfg=kwargs.get("profile_cfg"),
        )
        findings = [self._raw_to_tool_finding(f) for f in raw]
        return ToolResult(
            tool=self.tool_name,
            target=target,
            status=ToolStatus.SUCCESS,
            findings=findings,
            duration_s=time.monotonic() - start,
        )

    def _raw_to_tool_finding(self, f: Dict[str, Any]) -> ToolFinding:
        ev = f.get("evidence") or {}
        cve = ev.get("cve_id", []) if isinstance(ev, dict) else []
        if isinstance(cve, str):
            cve = [cve] if cve else []
        return ToolFinding(
            title=f.get("type", "Nuclei Finding"),
            severity=ToolSeverity.from_str(f.get("severity", "info")),
            url=f.get("url", ""),
            tool=self.tool_name,
            description=f.get("detail", ""),
            evidence=str(ev.get("curl", ""))[:300] if isinstance(ev, dict) else "",
            cve_ids=list(cve),
            cvss_score=ev.get("cvss_score") if isinstance(ev, dict) else None,
            confidence=f.get("confidence", "high"),
            verified=f.get("verified", True),
            tags=list(ev.get("tags", [])) if isinstance(ev, dict) else [],
            raw=f,
        )

    # -------------------------------------------------------------------------
    # Template update management
    # -------------------------------------------------------------------------

    def _templates_are_stale(self) -> bool:
        """Return True if templates haven't been updated within staleness window."""
        try:
            if _LAST_UPDATE_FILE.exists():
                last = float(_LAST_UPDATE_FILE.read_text().strip())
                return (time.time() - last) > _TEMPLATE_STALENESS_SECONDS
        except Exception:
            pass
        return True  # No marker -> assume stale

    def _mark_updated(self) -> None:
        """Write current timestamp to the last-update marker file."""
        try:
            _LAST_UPDATE_FILE.parent.mkdir(parents=True, exist_ok=True)
            _LAST_UPDATE_FILE.write_text(str(time.time()))
        except Exception as exc:
            logger.debug(f"[Nuclei] Could not write update marker: {exc!r}")

    def update_templates(self, force: bool = False, timeout: int = 120) -> bool:
        """
        Update Nuclei templates via `nuclei -update-templates`.

        Args:
            force: Update even if templates were recently updated.
            timeout: Max seconds to wait for update to complete.

        Returns:
            True if update succeeded or was skipped (not stale), False on failure.
        """
        if not self.is_available():
            logger.warning("[Nuclei] Cannot update templates — binary not available")
            return False

        if not force and not self._templates_are_stale():
            logger.debug("[Nuclei] Templates are up-to-date (updated < 24h ago), skipping")
            return True

        logger.info("[Nuclei] Updating templates...")
        try:
            proc = subprocess.run(
                [self.binary, "-update-templates", "-silent"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout,
                check=False,
            )
            if proc.returncode == 0:
                self._mark_updated()
                logger.info("[Nuclei] Templates updated successfully")
                return True
            else:
                stderr_out = (proc.stderr or b"").decode("utf-8", "ignore")[:300]
                logger.warning(f"[Nuclei] Template update failed (rc={proc.returncode}): {stderr_out}")
                return False
        except subprocess.TimeoutExpired:
            logger.warning(f"[Nuclei] Template update timed out after {timeout}s")
            return False
        except Exception as exc:
            logger.error(f"[Nuclei] Template update error: {exc!r}")
            return False

    def ensure_templates_fresh(self, timeout: int = 120) -> None:
        """
        Convenience: silently update templates if stale.
        Call this before .scan() to ensure templates are current.
        """
        if self._templates_are_stale():
            self.update_templates(timeout=timeout)

    def get_template_version(self) -> Optional[str]:
        """Return current template version string, or None if unavailable."""
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
            # nuclei -version output: "Nuclei Engine Version: v3.x.x\nNuclei Templates Version: v9.x.x"
            for line in out.splitlines():
                if "template" in line.lower() and "version" in line.lower():
                    return line.strip()
            return out.strip().splitlines()[0] if out.strip() else None
        except Exception as exc:
            logger.debug(f"[Nuclei] Version check failed: {exc!r}")
            return None

    def scan(
        self,
        target: str,
        tags: Optional[str] = None,
        templates: Optional[str] = None,
        severity: str = "low,medium,high,critical",
        rate_limit: int = 150,
        timeout: int = 300,
        proxy: Optional[str] = None,
        extra_args: Optional[List[str]] = None,
        tech_stack: Optional[List[str]] = None,
        profile_cfg: dict = None,
        auto_update: bool = True,
    ) -> List[Dict[str, Any]]:
        """
        Run nuclei against target. Returns list of findings dicts.

        Args:
            target: URL to scan
            tags: Comma-separated template tags (e.g. "cve,misconfig")
            templates: Path to custom templates directory
            severity: Minimum severity filter
            rate_limit: Requests per second
            timeout: Total scan timeout in seconds
            proxy: HTTP proxy URL
            tech_stack: Detected technologies — auto-selects relevant templates
            auto_update: Automatically update templates if stale (>24h old)
        """
        if not self.is_available():
            logger.warning("[Nuclei] Binary not available, skipping")
            return []

        # Auto-update templates if stale (non-blocking best-effort)
        if auto_update:
            self.ensure_templates_fresh(timeout=60)

        fd, output_file = tempfile.mkstemp(suffix=".jsonl")
        os.close(fd)

        try:
            _p = profile_cfg or {}
            _rate = _p.get("rate_limit", rate_limit)

            cmd = [
                self.binary,
                "-u", target,
                "-jle", output_file,  # JSONL export: -je file_path (json-export) yerine -jle (jsonl-export)
                "-silent",
                "-nc",
                "-rate-limit", str(_rate),
                "-severity", severity,
                "-timeout", "10",
            ]

            # Template selection: tech-aware or default tags
            if templates:
                cmd.extend(["-t", templates])
            else:
                # Build tag list from tech stack
                active_tags = set((tags or _DEFAULT_TAGS).split(","))
                if tech_stack:
                    for tech in tech_stack:
                        mapped = _TECH_TEMPLATE_MAP.get(tech.lower())
                        if mapped:
                            active_tags.update(mapped.split(","))
                cmd.extend(["-tags", ",".join(active_tags)])

            if proxy:
                cmd.extend(["-proxy", proxy.replace("socks5h://", "socks5://")])

            if extra_args:
                cmd.extend(extra_args)

            logger.info(f"[Nuclei] Scanning {target} ...")
            proc = subprocess.run(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                timeout=timeout,
                check=False,
            )

            # 0 = no findings, 1 = findings found, diğerleri hata
            if proc.returncode not in (0, 1):
                stderr_out = (proc.stderr or b"").decode("utf-8", "ignore")[:500]
                logger.warning(f"[Nuclei] Exit kodu {proc.returncode} — hata olabilir: {stderr_out}")
                if proc.returncode >= 2 and not stderr_out:
                    # Binary crash veya permission hatası — çıktı bekleme
                    return []

            return self._parse_output(output_file)

        except subprocess.TimeoutExpired:
            logger.warning(f"[Nuclei] Scan timed out after {timeout}s")
            return []
        except Exception as e:
            logger.error(f"[Nuclei] Error: {e}")
            return []
        finally:
            try:
                os.remove(output_file)
            except Exception as exc:
                pass

    def _parse_output(self, file_path: str) -> List[Dict[str, Any]]:
        """Parse nuclei JSONL output into WebSecure finding dicts."""
        findings = []
        if not os.path.exists(file_path):
            return findings

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
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
        except Exception as e:
            logger.error(f"[Nuclei] Output parse error: {e}")

        logger.info(f"[Nuclei] Found {len(findings)} issues")
        return findings

    def _normalize_finding(self, data: Dict) -> Optional[Dict[str, Any]]:
        """Convert nuclei JSON finding to WebSecure standard format."""
        try:
            info = data.get("info", {}) or {}
            sev_raw = (info.get("severity") or "info").lower()
            severity = _SEV_MAP.get(sev_raw, "Info")

            matched_at = data.get("matched-at") or data.get("host") or ""
            template_id = data.get("template-id") or data.get("templateID") or ""
            template_name = info.get("name") or template_id

            # Extract request/response proof
            curl_cmd = data.get("curl-command", "")
            matched_line = data.get("matcher-name") or data.get("extracted-results", [])

            return {
                "type": f"Nuclei: {template_name}",
                "severity": severity,
                "url": matched_at,
                "detail": info.get("description") or f"Template {template_id} matched",
                "evidence": {
                    "template_id": template_id,
                    "matched_at": matched_at,
                    "matcher": matched_line,
                    "curl": curl_cmd[:500] if curl_cmd else "",
                    "tags": info.get("tags", []),
                    "references": info.get("reference", []),
                    "cvss_score": info.get("classification", {}).get("cvss-score"),
                    "cve_id": info.get("classification", {}).get("cve-id"),
                },
                "verified": True,
                "confidence": "high",
                "source": "nuclei",
            }
        except Exception as exc:
            return None


def run_nuclei_scan(
    target: str,
    tech_stack: Optional[List[str]] = None,
    proxy: Optional[str] = None,
    rate_limit: int = 150,
    auto_update: bool = True,
) -> List[Dict[str, Any]]:
    """Convenience function: scan target with nuclei, return findings."""
    wrapper = NucleiWrapper()
    if not wrapper.is_available():
        return []
    return wrapper.scan(
        target,
        tech_stack=tech_stack,
        proxy=proxy,
        rate_limit=rate_limit,
        auto_update=auto_update,
    )


def update_nuclei_templates(force: bool = False) -> bool:
    """Standalone helper: update Nuclei templates. Returns True on success."""
    wrapper = NucleiWrapper()
    return wrapper.update_templates(force=force)


def run_nuclei_with_correlation(
    target: str,
    existing_fingerprints: Optional[set] = None,
    tech_stack: Optional[List[str]] = None,
    rate_limit: int = 150,
    sarif_output: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """
    Nuclei taraması yap + WebSecure bulguları ile çakışma kontrolü yap.

    Parametreler
    ------------
    existing_fingerprints : Mevcut WebSecure bulgu parmak izleri (set)
    sarif_output          : SARIF dosya yolu (belirtilirse SARIF de yazar)

    Döndürür
    --------
    List[Dict] — Yeni (çakışmayan) Nuclei bulgularının native formatı.
    """
    try:
        from websecure.integrations.base import FindingCorrelator, ToolFinding, ToolSeverity
        from websecure.integrations.sarif import SARIFNormalizer

        wrapper = NucleiWrapper()
        if not wrapper.is_available():
            return []

        raw_findings = wrapper.scan(target, tech_stack=tech_stack, rate_limit=rate_limit)

        # ToolFinding'e dönüştür
        tool_findings = []
        for f in raw_findings:
            ev = f.get("evidence") or {}
            tf = ToolFinding(
                title=f.get("type", "Nuclei Finding"),
                severity=ToolSeverity.from_str(f.get("severity", "info")),
                url=f.get("url", target),
                tool="nuclei",
                description=f.get("detail", ""),
                evidence=str(ev.get("curl", ""))[:300] if isinstance(ev, dict) else "",
                cve_ids=ev.get("cve_id", []) if isinstance(ev, dict) and ev.get("cve_id") else [],
                cvss_score=ev.get("cvss_score") if isinstance(ev, dict) else None,
                confidence=f.get("confidence", "high"),
                verified=f.get("verified", True),
                tags=ev.get("tags", []) if isinstance(ev, dict) else [],
                raw=f,
            )
            tool_findings.append(tf)

        # Deduplication
        fps = frozenset(existing_fingerprints or set())
        new_findings = [f for f in tool_findings if f.fingerprint() not in fps]

        deduped = len(tool_findings) - len(new_findings)
        if deduped:
            logger.info(f"[Nuclei] Korelasyon: {deduped} çakışan bulgu çıkarıldı")

        # SARIF çıktı
        if sarif_output:
            try:
                norm = SARIFNormalizer()
                for tf in new_findings:
                    norm._report.add_findings([tf])
                norm.save(sarif_output)
            except Exception as exc:
                logger.debug(f"[Nuclei] SARIF yazma hatası: {exc!r}")

        return [f.raw for f in new_findings]

    except ImportError:
        # base.py yoksa klasik yola dön
        return run_nuclei_scan(target, tech_stack=tech_stack, rate_limit=rate_limit)
