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
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

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


class NucleiWrapper:
    """
    Wrapper for the Nuclei vulnerability scanner.
    https://github.com/projectdiscovery/nuclei
    """

    def __init__(self, binary_path: str = "nuclei"):
        self.binary = binary_path
        self._check_binary()

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
                self.binary = str(candidate)
                return
        logger.warning("[Nuclei] Binary bulunamadi. Program baslarken otomatik indirilecek.")

    def is_available(self) -> bool:
        return shutil.which(self.binary) is not None or Path(self.binary).exists()

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
        """
        if not self.is_available():
            logger.warning("[Nuclei] Binary not available, skipping")
            return []

        fd, output_file = tempfile.mkstemp(suffix=".jsonl")
        os.close(fd)

        try:
            cmd = [
                self.binary,
                "-u", target,
                "-o", output_file,
                "-je",          # JSON output per-finding
                "-silent",
                "-nc",          # No color
                "-rate-limit", str(rate_limit),
                "-severity", severity,
                "-timeout", "10",  # Per-request timeout (seconds)
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
                cmd.extend(["-proxy", proxy])

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

            if proc.returncode not in (0, 1):  # 1 = findings found
                stderr_out = (proc.stderr or b"").decode("utf-8", "ignore")[:500]
                logger.warning(f"[Nuclei] Exit {proc.returncode}: {stderr_out}")

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
    )
