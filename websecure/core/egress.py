"""
websecure.core.egress
~~~~~~~~~~~~~~~~~~~~~~
Egress policy ve egress health-check yardımcıları.
main.py'den taşındı (FAZ-EK).
"""
from __future__ import annotations

import logging

_logger = logging.getLogger(__name__)


def _enforce_egress_policy(cfg) -> None:
    pr = (cfg.get('privacy') or {}).get('egress') if isinstance(cfg, dict) else None
    if not isinstance(pr, dict):
        return
    if pr.get('kill_switch'):
        raise SystemExit('Egress kill-switch aktif. Ağ çıkışı engellendi.')
    if pr.get('required'):
        proxies = ((cfg.get('http') or {}).get('proxies') or {})
        if not isinstance(proxies, dict):
            proxies = {}
        from websecure.core.utils import current_identity

        px = (current_identity(cfg) or {}).get('proxy_url')
        if not proxies and not px:
            raise SystemExit('Egress proxy zorunlu ancak configte yok ve identity proxy de boş.')


def _egress_health_check(session, cfg: dict, results: dict) -> None:
    from websecure.core.session_factory import _proxy_alive
    from websecure.core.http import verify_for_phase

    privacy = (cfg.get("privacy") or {}) if isinstance(cfg, dict) else {}
    egress = (privacy.get("egress") or {}) if isinstance(privacy, dict) else {}
    eps_cfg = list((egress.get("ip_echo_endpoints") or [])) if isinstance(egress, dict) else []

    defaults = [
        "https://api.ipify.org?format=text",
        "https://checkip.amazonaws.com/",
        "https://www.cloudflare.com/cdn-cgi/trace",
        "https://check.torproject.org/api/ip",
    ]
    eps = eps_cfg if eps_cfg else defaults

    eps = eps[:3]

    proxies_in_sess = getattr(session, "proxies", {}) or {}
    unique_proxies = {str(v) for v in proxies_in_sess.values() if v}
    any_proxy = bool(unique_proxies)

    proxy_alive = False
    if any_proxy:
        for purl in unique_proxies:
            if _proxy_alive(purl):
                proxy_alive = True
                break

    observations = []
    for u in eps:
        # verify bayrağını faz bağlamına göre hesapla
        ver = verify_for_phase(cfg, 'egress', u)

        # Proxy BYPASS gerekiyorsa call-level override yap
        call_kwargs = dict(timeout=6, allow_redirects=True, verify=ver)
        if any_proxy and not proxy_alive:
            # Proxy configured fakat **up değil** → bypass
            call_kwargs['proxies'] = {}

        try:
            r = session.get(u, **call_kwargs)
            txt = (getattr(r, "text", "") or "").strip()
            ip = txt
            # cloudflare trace: "ip=1.2.3.4" biçimini ayrıştır
            if "ip=" in txt:
                for line in txt.splitlines():
                    if line.startswith("ip="):
                        ip = line.split("=", 1)[1].strip()
                        break
            code = int(getattr(r, "status_code", 0) or 0)
            observations.append({
                "endpoint": u,
                "code": code,
                "ip": (ip or "")[:128],
                "used_proxy": (any_proxy and proxy_alive)
            })
        except Exception as e:
            _logger.error('phase error [egress_health_check]', exc_info=True)
            observations.append({
                "endpoint": u,
                "error": f"{e.__class__.__name__}: {e}",
                "used_proxy": (any_proxy and proxy_alive)
            })

    if "sections" not in results or not isinstance(results.get("sections"), list):
        results["sections"] = []
    results["egress_health"] = {
        "observations": observations,
        "proxy_configured": any_proxy,
        "proxy_alive": proxy_alive,
    }


__all__ = [
    "_enforce_egress_policy",
    "_egress_health_check",
]
