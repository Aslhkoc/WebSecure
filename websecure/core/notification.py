"""
websecure.core.notification
----------------------------
Harici bildirim entegrasyonlari: JIRA, GitHub Issues, Slack, Teams, PagerDuty.

Adim 13 — Siniflar:
  NotificationConfig     — ortak yapılandırma dataclass
  BaseNotifier           — soyut interface (SOLID/LSP)
  JIRANotifier           — REST API ile JIRA ticket oluşturma
  GitHubIssueNotifier    — GitHub Issues API per-finding ticket
  SlackNotifier          — Slack Incoming Webhook mesajı
  TeamsNotifier          — Microsoft Teams Adaptive Card webhook
  PagerDutyNotifier      — PagerDuty Events API v2
  NotificationDispatcher — tüm notifier'ları yöneten orkestratör
"""
from __future__ import annotations

import json
import logging
import re
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import requests

_logger = logging.getLogger(__name__)

_SEV_EMOJI = {
    "Critical": "[Critical]", "critical": "[Critical]",
    "High": "[High]", "high": "[High]",
    "Medium": "[Medium]", "medium": "[Medium]",
    "Low": "[Info]", "low": "[Info]",
    "Informational": "[o]", "info": "[o]",
}

_SEV_PD_PRIORITY = {
    "Critical": "P1", "critical": "P1",
    "High": "P2", "high": "P2",
    "Medium": "P3", "medium": "P3",
    "Low": "P4", "low": "P4",
    "Informational": "P5", "info": "P5",
}

_TIMEOUT = 12


def _sev_lower(finding: Dict[str, Any]) -> str:
    return str(finding.get("severity") or "info").lower().strip()


def _finding_title(finding: Dict[str, Any]) -> str:
    t = finding.get("type") or finding.get("title") or finding.get("vulnerability") or "Security Finding"
    url = finding.get("url") or finding.get("endpoint") or ""
    return f"[WebSecure] {t} — {url}" if url else f"[WebSecure] {t}"


def _finding_body(finding: Dict[str, Any]) -> str:
    lines = []
    for key in ("type", "severity", "url", "param", "description", "details", "remediation"):
        val = finding.get(key)
        if val:
            lines.append(f"**{key.capitalize()}**: {val}")
    cwe = finding.get("cwe")
    if cwe:
        lines.append(f"**CWE**: {cwe}")
    cvss = finding.get("cvss_score")
    if cvss:
        lines.append(f"**CVSS**: {cvss}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

@dataclass
class NotificationConfig:
    """Central notification configuration. All fields are optional."""
    # JIRA
    jira_url: str = ""
    jira_user: str = ""
    jira_token: str = ""
    jira_project: str = ""
    jira_issue_type: str = "Bug"
    jira_min_severity: str = "medium"
    # GitHub
    github_token: str = ""
    github_repo: str = ""           # "owner/repo"
    github_min_severity: str = "high"
    github_labels: List[str] = field(default_factory=lambda: ["security", "websecure"])
    # Slack
    slack_webhook_url: str = ""
    slack_channel: str = ""
    slack_min_severity: str = "medium"
    # Teams
    teams_webhook_url: str = ""
    teams_min_severity: str = "medium"
    # PagerDuty
    pagerduty_routing_key: str = ""
    pagerduty_min_severity: str = "high"

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "NotificationConfig":
        n = d.get("notification") or d.get("notifications") or d
        cfg = cls()
        for key in (
            "jira_url", "jira_user", "jira_token", "jira_project",
            "jira_issue_type", "jira_min_severity",
            "github_token", "github_repo", "github_min_severity", "github_labels",
            "slack_webhook_url", "slack_channel", "slack_min_severity",
            "teams_webhook_url", "teams_min_severity",
            "pagerduty_routing_key", "pagerduty_min_severity",
        ):
            if key in n:
                setattr(cfg, key, n[key])
        return cfg


# ---------------------------------------------------------------------------
# Severity filter helper
# ---------------------------------------------------------------------------

_SEV_RANK = {"Critical": 5, "critical": 5, "High": 4, "high": 4,
              "Medium": 3, "medium": 3, "Low": 2, "low": 2,
              "Informational": 1, "info": 1}


def _sev_passes(finding: Dict, min_severity: str) -> bool:
    sev = _sev_lower(finding)
    return _SEV_RANK.get(sev, 1) >= _SEV_RANK.get(min_severity.lower(), 1)


# ---------------------------------------------------------------------------
# BaseNotifier
# ---------------------------------------------------------------------------

class BaseNotifier(ABC):
    """Abstract base for all notification targets. SOLID/LSP."""

    def __init__(self, config: NotificationConfig):
        self.config = config

    @abstractmethod
    def send(self, finding: Dict[str, Any]) -> bool:
        """Send notification for a single finding. Returns True on success."""
        ...

    def send_batch(self, findings: List[Dict[str, Any]]) -> int:
        """Send all findings. Returns count of successful sends."""
        ok = 0
        for f in findings:
            try:
                if self.send(f):
                    ok += 1
            except Exception as e:
                _logger.debug(f"[{self.__class__.__name__}] batch send error: {e}")
        return ok


# ---------------------------------------------------------------------------
# JIRANotifier
# ---------------------------------------------------------------------------

class JIRANotifier(BaseNotifier):
    """
    Creates JIRA issues via REST API v3.
    Requires: jira_url, jira_user, jira_token, jira_project.
    """

    def send(self, finding: Dict[str, Any]) -> bool:
        cfg = self.config
        if not all([cfg.jira_url, cfg.jira_user, cfg.jira_token, cfg.jira_project]):
            return False
        if not _sev_passes(finding, cfg.jira_min_severity):
            return False

        sev = _sev_lower(finding)
        priority_map = {"Critical": "Highest", "critical": "Highest",
                        "High": "High", "high": "High",
                        "Medium": "Medium", "medium": "Medium",
                        "Low": "Low", "low": "Low"}
        priority = priority_map.get(sev, "Medium")

        payload = {
            "fields": {
                "project": {"key": cfg.jira_project},
                "summary": _finding_title(finding)[:255],
                "description": {
                    "type": "doc",
                    "version": 1,
                    "content": [
                        {"type": "paragraph", "content": [
                            {"type": "text", "text": _finding_body(finding)}
                        ]}
                    ],
                },
                "issuetype": {"name": cfg.jira_issue_type},
                "priority": {"name": priority},
                "labels": ["security", "websecure-scan"],
            }
        }

        url = cfg.jira_url.rstrip("/") + "/rest/api/3/issue"
        try:
            r = requests.post(
                url, json=payload, timeout=_TIMEOUT,
                auth=(cfg.jira_user, cfg.jira_token),
                headers={"Accept": "application/json"},
            )
            if r.status_code in (200, 201):
                issue_key = r.json().get("key", "?")
                _logger.info(f"[JIRA] Created: {issue_key} — {_finding_title(finding)[:60]}")
                return True
            else:
                _logger.warning(f"[JIRA] Failed {r.status_code}: {r.text[:200]}")
        except Exception as e:
            _logger.debug(f"[JIRA] Error: {e}")
        return False


# ---------------------------------------------------------------------------
# GitHubIssueNotifier
# ---------------------------------------------------------------------------

class GitHubIssueNotifier(BaseNotifier):
    """
    Creates GitHub Issues via REST API.
    Requires: github_token, github_repo ("owner/repo").
    """

    def send(self, finding: Dict[str, Any]) -> bool:
        cfg = self.config
        if not all([cfg.github_token, cfg.github_repo]):
            return False
        if not _sev_passes(finding, cfg.github_min_severity):
            return False

        sev = _sev_lower(finding)
        emoji = _SEV_EMOJI.get(sev, "[o]")
        title = f"{emoji} {_finding_title(finding)}"[:255]
        body = _finding_body(finding)
        body += f"\n\n---\n*Auto-created by [WebSecure](https://github.com/Aslhkoc/WebSecure)*"

        payload = {
            "title": title,
            "body": body,
            "labels": cfg.github_labels + [sev],
        }

        url = f"https://api.github.com/repos/{cfg.github_repo}/issues"
        try:
            r = requests.post(
                url, json=payload, timeout=_TIMEOUT,
                headers={
                    "Authorization": f"token {cfg.github_token}",
                    "Accept": "application/vnd.github+json",
                },
            )
            if r.status_code == 201:
                issue_url = r.json().get("html_url", "?")
                _logger.info(f"[GitHub] Created: {issue_url}")
                return True
            else:
                _logger.warning(f"[GitHub] Failed {r.status_code}: {r.text[:200]}")
        except Exception as e:
            _logger.debug(f"[GitHub] Error: {e}")
        return False


# ---------------------------------------------------------------------------
# SlackNotifier
# ---------------------------------------------------------------------------

class SlackNotifier(BaseNotifier):
    """
    Sends formatted Slack messages via Incoming Webhook.
    Requires: slack_webhook_url.
    """

    def send(self, finding: Dict[str, Any]) -> bool:
        cfg = self.config
        if not cfg.slack_webhook_url:
            return False
        if not _sev_passes(finding, cfg.slack_min_severity):
            return False

        sev = _sev_lower(finding)
        emoji = _SEV_EMOJI.get(sev, "[o]")
        color_map = {"Critical": "#FF0000", "critical": "#FF0000",
                     "High": "#FF6600", "high": "#FF6600",
                     "Medium": "#FFCC00", "medium": "#FFCC00",
                     "Low": "#00AA00", "low": "#00AA00"}
        color = color_map.get(sev, "#AAAAAA")
        title = _finding_title(finding)
        fields_list = []
        for key in ("severity", "url", "param", "cwe", "cvss_score"):
            val = finding.get(key)
            if val:
                fields_list.append({"title": key.capitalize(), "value": str(val), "short": True})

        payload: Dict[str, Any] = {
            "attachments": [{
                "color": color,
                "title": f"{emoji} {title}",
                "text": finding.get("description") or finding.get("details") or "",
                "fields": fields_list,
                "footer": "WebSecure Scanner",
                "ts": int(time.time()),
            }]
        }
        if cfg.slack_channel:
            payload["channel"] = cfg.slack_channel

        try:
            r = requests.post(cfg.slack_webhook_url, json=payload, timeout=_TIMEOUT)
            if r.status_code == 200 and r.text == "ok":
                _logger.info(f"[Slack] Sent: {title[:60]}")
                return True
            else:
                _logger.warning(f"[Slack] Failed {r.status_code}: {r.text[:100]}")
        except Exception as e:
            _logger.debug(f"[Slack] Error: {e}")
        return False


# ---------------------------------------------------------------------------
# TeamsNotifier
# ---------------------------------------------------------------------------

class TeamsNotifier(BaseNotifier):
    """
    Sends Microsoft Teams messages via Incoming Webhook (Adaptive Card).
    Requires: teams_webhook_url.
    """

    def send(self, finding: Dict[str, Any]) -> bool:
        cfg = self.config
        if not cfg.teams_webhook_url:
            return False
        if not _sev_passes(finding, cfg.teams_min_severity):
            return False

        sev = _sev_lower(finding)
        emoji = _SEV_EMOJI.get(sev, "[o]")
        title = f"{emoji} {_finding_title(finding)}"
        facts = []
        for key in ("severity", "url", "param", "description", "cwe", "cvss_score", "remediation"):
            val = finding.get(key)
            if val:
                facts.append({"name": key.capitalize(), "value": str(val)[:500]})

        payload = {
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "themeColor": "FF6600" if sev in ("High", "high", "Critical", "critical") else "FFCC00",
            "summary": title[:128],
            "sections": [{
                "activityTitle": title,
                "facts": facts,
                "markdown": True,
            }],
            "potentialAction": [{
                "@type": "OpenUri",
                "name": "View Finding",
                "targets": [{"os": "default", "uri": finding.get("url") or "#"}],
            }],
        }

        try:
            r = requests.post(cfg.teams_webhook_url, json=payload, timeout=_TIMEOUT)
            if r.status_code == 200:
                _logger.info(f"[Teams] Sent: {title[:60]}")
                return True
            else:
                _logger.warning(f"[Teams] Failed {r.status_code}: {r.text[:100]}")
        except Exception as e:
            _logger.debug(f"[Teams] Error: {e}")
        return False


# ---------------------------------------------------------------------------
# PagerDutyNotifier
# ---------------------------------------------------------------------------

class PagerDutyNotifier(BaseNotifier):
    """
    Creates PagerDuty incidents via Events API v2.
    Requires: pagerduty_routing_key.
    """

    _API_URL = "https://events.pagerduty.com/v2/enqueue"

    def send(self, finding: Dict[str, Any]) -> bool:
        cfg = self.config
        if not cfg.pagerduty_routing_key:
            return False
        if not _sev_passes(finding, cfg.pagerduty_min_severity):
            return False

        sev = _sev_lower(finding)
        pd_severity_map = {"Critical": "critical", "critical": "critical",
                           "High": "error", "high": "error",
                           "Medium": "warning", "medium": "warning",
                           "Low": "info", "low": "info",
                           "Informational": "info", "info": "info"}

        summary = _finding_title(finding)[:256]
        payload = {
            "routing_key": cfg.pagerduty_routing_key,
            "event_action": "trigger",
            "payload": {
                "summary": summary,
                "severity": pd_severity_map.get(sev, "warning"),
                "source": finding.get("url") or "websecure-scan",
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "custom_details": {
                    k: str(finding.get(k))
                    for k in ("type", "severity", "url", "param", "description",
                              "cwe", "cvss_score", "remediation")
                    if finding.get(k)
                },
            },
            "links": [{"href": finding.get("url") or "#", "text": "Target URL"}],
        }

        try:
            r = requests.post(self._API_URL, json=payload, timeout=_TIMEOUT)
            if r.status_code == 202:
                dedup_key = r.json().get("dedup_key", "?")
                _logger.info(f"[PagerDuty] Triggered: {dedup_key} — {summary[:60]}")
                return True
            else:
                _logger.warning(f"[PagerDuty] Failed {r.status_code}: {r.text[:200]}")
        except Exception as e:
            _logger.debug(f"[PagerDuty] Error: {e}")
        return False


# ---------------------------------------------------------------------------
# NotificationDispatcher
# ---------------------------------------------------------------------------

class NotificationDispatcher:
    """
    Routes security findings to all configured notification targets.

    SOLID/OCP: Add new notifier types without modifying existing dispatcher.
    SOLID/DIP: Depends on BaseNotifier abstraction, not concrete classes.
    """

    def __init__(self, config: NotificationConfig):
        self.config = config
        self._notifiers: List[BaseNotifier] = self._build_notifiers()

    def _build_notifiers(self) -> List[BaseNotifier]:
        cfg = self.config
        notifiers: List[BaseNotifier] = []
        if cfg.jira_url and cfg.jira_token:
            notifiers.append(JIRANotifier(cfg))
        if cfg.github_token and cfg.github_repo:
            notifiers.append(GitHubIssueNotifier(cfg))
        if cfg.slack_webhook_url:
            notifiers.append(SlackNotifier(cfg))
        if cfg.teams_webhook_url:
            notifiers.append(TeamsNotifier(cfg))
        if cfg.pagerduty_routing_key:
            notifiers.append(PagerDutyNotifier(cfg))
        return notifiers

    def notify(self, finding: Dict[str, Any]) -> Dict[str, bool]:
        """Send finding to all notifiers. Returns {notifier_name: success}."""
        results: Dict[str, bool] = {}
        for notifier in self._notifiers:
            name = notifier.__class__.__name__
            try:
                results[name] = notifier.send(finding)
            except Exception as e:
                _logger.debug(f"[Dispatcher] {name} error: {e}")
                results[name] = False
        return results

    def notify_batch(
        self,
        findings: List[Dict[str, Any]],
        deduplicate: bool = True,
    ) -> Dict[str, int]:
        """
        Send all findings to all notifiers.
        deduplicate=True: same (type+url) pair sent only once.
        Returns {notifier_name: success_count}.
        """
        seen: set = set()
        totals: Dict[str, int] = {}
        for finding in findings:
            if deduplicate:
                key = f"{finding.get('type')}|{finding.get('url')}"
                if key in seen:
                    continue
                seen.add(key)
            for name, ok in self.notify(finding).items():
                totals[name] = totals.get(name, 0) + (1 if ok else 0)
        return totals

    def add_notifier(self, notifier: BaseNotifier) -> None:
        """Register a custom notifier (SOLID/OCP)."""
        self._notifiers.append(notifier)

    @classmethod
    def from_config_dict(cls, cfg_dict: Dict[str, Any]) -> "NotificationDispatcher":
        """Build dispatcher from raw config dict."""
        return cls(NotificationConfig.from_dict(cfg_dict))


__all__ = [
    'NotificationConfig',
    'BaseNotifier',
    'JIRANotifier',
    'GitHubIssueNotifier',
    'SlackNotifier',
    'TeamsNotifier',
    'PagerDutyNotifier',
    'NotificationDispatcher',
]
