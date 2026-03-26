"""
websecure.core.phases._hprofile
--------------------------------
Adaptive HTTP profile manager.

HProfilePolicy   — immutable policy config (rps, concurrency, categories, …)
HProfileManager  — runtime manager with adaptive profile switching based on
                   observed HTTP 429/403 block rates.

Public singletons and helpers:
  hpm()                   — get/create the global HProfileManager
  hpm_init_from_config()  — initialise from a config dict
  hpm_bootstrap_from_file()
  hpm_record_status()
  hpm_current_policy()
"""
from __future__ import annotations

import inspect as _inspect
import json
import os
import re
import threading
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Set

from websecure.core.reporting import add_result

_logger = None  # lazy — avoids circular import on early load


def _get_logger():
    global _logger
    if _logger is None:
        import logging
        _logger = logging.getLogger(__name__)
    return _logger


# ---------------------------------------------------------------------------
# Policy dataclass
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class HProfilePolicy:
    name: str
    rps: float
    concurrency: int
    allow_categories: Set[str]
    idempotent_only: bool
    oast: bool
    heavy_modules: bool
    robots_respect: bool
    politeness_ms: int
    # Transition thresholds
    obs_seconds: int
    min_req: int
    up_when_block_rate_below: float
    down_when_block_rate_above: float


# ---------------------------------------------------------------------------
# Manager
# ---------------------------------------------------------------------------

class HProfileManager:

    def __init__(self, profiles: Dict[str, Any] | None = None, active: str = "normal"):
        self._policies: Dict[str, HProfilePolicy] = self._load_policies(profiles or {})
        act = str(active or "normal").strip().lower()
        self._active: str = act if act in self._policies else "normal"
        self._timeline: List[Dict[str, Any]] = []
        self._req_count: int = 0
        self._blocked_count: int = 0
        self._window_start: float = time.monotonic()

    @staticmethod
    def _as_bool(x: Any, default: bool) -> bool:
        if isinstance(x, bool):
            return x
        if isinstance(x, str):
            lx = x.strip().lower()
            if lx in ('1', 'true', 'yes', 'on'):
                return True
            if lx in ('0', 'false', 'no', 'off'):
                return False
        return default

    @staticmethod
    def _as_set(xs: Any) -> Set[str]:
        if isinstance(xs, (list, tuple, set)):
            return {str(x).strip().lower() for x in xs if str(x).strip()}
        return set()

    @staticmethod
    def _num(x, default: float) -> float:
        if isinstance(x, (int, float)):
            return float(x)
        if isinstance(x, str):
            s = x.strip()
            if re.fullmatch(r'[+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?', s):
                return float(s)
        return float(default)

    def _load_policies(self, cfg: Dict[str, Any]) -> Dict[str, HProfilePolicy]:
        pols: Dict[str, HProfilePolicy] = {}
        _FULL_SCOPE = {'aggressive', 'deep', 'nightmare', 'safe_full', 'smart'}
        _ALL_CATS = [
            'xss', 'sqli', 'ssrf', 'xxe', 'rce', 'nosqli', 'ssti',
            'open_redirect', 'prototype_pollution', 'deserialization',
            'ldap', 'xpath', 'crlf',
        ]

        def build(name: str, node: Dict[str, Any]) -> HProfilePolicy:
            is_full = name in _FULL_SCOPE or '*' in (node.get('modules') or [])
            is_stealth = name in ('stealth', 'safe_full')
            def_rps = 2.0 if is_stealth else (60.0 if name in ('aggressive', 'nightmare') else 15.0)
            rps = self._num(node.get('rps'), def_rps)
            def_conc = 5 if is_stealth else (60 if name in ('aggressive', 'nightmare') else 25)
            conc = int(node.get('concurrency') or def_conc)
            if node.get('allow_categories'):
                allow_cats = self._as_set(node.get('allow_categories'))
            else:
                allow_cats = set(_ALL_CATS) if is_full else {'xss', 'sqli', 'ssrf', 'ssti', 'open_redirect'}
            idem = self._as_bool(node.get('idempotent_only'), is_stealth and name != 'safe_full')
            oast = self._as_bool(node.get('oast', node.get('oast_enabled', False)), is_full)
            heavy = self._as_bool(node.get('heavy_modules'), is_full)
            def_robots = name not in ('aggressive', 'nightmare')
            robots = self._as_bool(node.get('robots_respect'), def_robots)
            def_polite = (1500 if name == 'safe_full' else
                          800 if name == 'stealth' else
                          0 if name in ('aggressive', 'nightmare') else 300)
            polite = int(node.get('politeness_ms') or def_polite)
            obs = int(node.get('obs_seconds') or 60)
            min_req = int(node.get('min_req') or 40)
            up_below = self._num(node.get('up_when_block_rate_below'), 0.01 if is_stealth else 0.005)
            down_above = self._num(node.get('down_when_block_rate_above'),
                                   0.05 if name in ('aggressive', 'nightmare') else 0.03)
            return HProfilePolicy(name, rps, conc, allow_cats, idem, oast, heavy, robots,
                                  polite, obs, min_req, up_below, down_above)

        for k, node in cfg.items():
            if isinstance(node, dict):
                pols[k] = build(k, node)
        if 'normal' not in pols:
            pols['normal'] = build('normal', {})
        return pols

    def _emit_event(self, etype: str, data: Dict[str, Any]) -> None:
        evt = {'t': time.time(), 'type': etype, **data}
        self._timeline.append(evt)
        add_result('profile_event', evt)

    def policy(self) -> HProfilePolicy:
        return self._policies[self._active]

    def name(self) -> str:
        return self._active

    def record_status(self, status_code: int) -> None:
        self._req_count += 1
        if status_code in (429, 403):
            self._blocked_count += 1
        self._maybe_rotate()

    def _reset_window(self) -> None:
        self._req_count = 0
        self._blocked_count = 0
        self._window_start = time.monotonic()

    def _maybe_rotate(self) -> None:
        now = time.monotonic()
        elapsed = now - self._window_start
        pol = self.policy()
        if elapsed < float(pol.obs_seconds):
            return
        if self._req_count < pol.min_req:
            self._reset_window()
            return
        rate = 0.0 if self._req_count <= 0 else (self._blocked_count / float(self._req_count))
        cur = self._active
        nxt = cur
        if cur == 'aggressive' and rate >= pol.down_when_block_rate_above:
            nxt = 'normal'
        elif cur == 'normal' and rate >= pol.down_when_block_rate_above:
            nxt = 'stealth'
        elif cur == 'stealth' and rate <= pol.up_when_block_rate_below:
            nxt = 'normal'
        elif cur == 'normal' and rate <= pol.up_when_block_rate_below:
            nxt = 'aggressive'

        if nxt != cur:
            old_pol = self.policy()
            self._active = nxt
            new_pol = self.policy()
            self._emit_event('profile_switch', {
                'from': cur,
                'to': nxt,
                'window_seconds': pol.obs_seconds,
                'req': self._req_count,
                'blocked': self._blocked_count,
                'block_rate': rate,
                'old_rps': old_pol.rps,
                'new_rps': new_pol.rps,
                'old_conc': old_pol.concurrency,
                'new_conc': new_pol.concurrency,
            })
        self._reset_window()


# ---------------------------------------------------------------------------
# Global singleton helpers
# ---------------------------------------------------------------------------

_HPM: HProfileManager | None = None
_HPM_LOCK = threading.Lock()


def hpm_bootstrap_from_file(path: str) -> None:
    with open(path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    hpm_init_from_config(data)


def hpm() -> HProfileManager:
    global _HPM
    if _HPM is None:
        with _HPM_LOCK:
            if _HPM is None:
                hpm_init_from_config({'settings': {'profiles': {}, 'scan_profile': 'normal'}})
    return _HPM  # type: ignore[return-value]


def _set_attr_if_present(obj, name: str, value) -> None:
    if hasattr(obj, name):
        setattr(obj, name, value)


def hpm_init_from_config(cfg: Dict[str, Any] | None) -> None:
    global _HPM
    with _HPM_LOCK:
        settings = (cfg or {}).get("settings") or {}
        profiles = settings.get("profiles") or {}
        initial = str(settings.get("scan_profile") or "normal")

        sig = _inspect.signature(HProfileManager)
        params = [p for p in sig.parameters.values() if p.name != "self"]
        names = [p.name for p in params]

        if len(params) >= 2 or ({"profiles", "active"} <= set(names)):
            _HPM = HProfileManager(profiles, initial)
            return

        if len(params) == 1 or ("profiles" in names and "active" not in names):
            _HPM = HProfileManager(profiles)
            if hasattr(_HPM, "set_active") and callable(getattr(_HPM, "set_active")):
                _HPM.set_active(initial)
            else:
                _set_attr_if_present(_HPM, "active", initial)
                _set_attr_if_present(_HPM, "_active", initial)
            return

        _HPM = HProfileManager()
        if hasattr(_HPM, "load_profiles") and callable(getattr(_HPM, "load_profiles")):
            _HPM.load_profiles(profiles)
        else:
            _set_attr_if_present(_HPM, "_policies", profiles)
            _set_attr_if_present(_HPM, "policies", profiles)
        if hasattr(_HPM, "set_active") and callable(getattr(_HPM, "set_active")):
            _HPM.set_active(initial)
        else:
            _set_attr_if_present(_HPM, "_active", initial)
            _set_attr_if_present(_HPM, "active", initial)


def hpm_record_status(status_code: int) -> None:
    mgr = hpm()
    if hasattr(mgr, "record_status") and callable(getattr(mgr, "record_status")):
        mgr.record_status(int(status_code))


def hpm_current_policy() -> Dict[str, Any]:
    mgr = hpm()
    pol = None
    if hasattr(mgr, "policy") and callable(getattr(mgr, "policy")):
        pol = mgr.policy()

    def _get(obj, name: str, default):
        if obj is None:
            return default
        if isinstance(obj, dict):
            return obj.get(name, default)
        return getattr(obj, name, default)

    allow = _get(pol, "allow_categories", []) or []
    if not isinstance(allow, list):
        allow = list(allow)

    return {
        "name": _get(pol, "name", "normal"),
        "rps": _get(pol, "rps", 10.0),
        "concurrency": _get(pol, "concurrency", 10),
        "allow_categories": sorted(set(allow)),
        "idempotent_only": bool(_get(pol, "idempotent_only", True)),
        "oast": bool(_get(pol, "oast", False)),
        "heavy_modules": bool(_get(pol, "heavy_modules", False)),
        "robots_respect": bool(_get(pol, "robots_respect", True)),
        "politeness_ms": int(_get(pol, "politeness_ms", 300)),
    }
