"""
websecure.core.egress
~~~~~~~~~~~~~~~~~~~~~~
Egress policy, IP gizleme ve Tor/proxy yönetimi.
main.py'den taşındı (FAZ-EK).
"""
from __future__ import annotations

import logging
import os
import socket
import subprocess
import shutil
import time
from typing import Optional, Dict, Any

_logger = logging.getLogger(__name__)


# --- Tor / SOCKS5 proxy desteği ---

TOR_SOCKS_DEFAULT = "socks5h://127.0.0.1:9050"
TOR_CONTROL_PORT = 9051


# ---------------------------------------------------------------------------
# Global socket-level Tor enforcement (kills raw-socket / direct-request IP leaks)
# ---------------------------------------------------------------------------
# PROBLEM: only the proxied requests.Session goes through Tor. Raw
# socket.create_connection() (TLS scanner's ~12 probes, ws_fuzz, port checks) and
# direct module-level requests.* calls (utils/net, analysis) connect with the REAL
# IP even when Tor is on. And socket.create_connection resolves DNS LOCALLY → DNS
# leak. This forces EVERY socket in the Python process through Tor with remote DNS,
# EXCEPT localhost/private destinations (Tor SOCKS port itself, SQLMap API,
# interactsh, Tor control) which must stay direct or everything deadlocks.
import ipaddress as _ipaddress

_TOR_SOCKET_STATE: Dict[str, Any] = {
    "patched": False, "orig_socket": None, "orig_getaddrinfo": None,
}


def _ws_is_local_host(host) -> bool:
    """localhost / private / link-local → bypass Tor (stay direct)."""
    try:
        h = str(host).strip("[]").lower()
        if h in ("localhost", "localhost.localdomain", ""):
            return True
        try:
            ip = _ipaddress.ip_address(h)
            return ip.is_loopback or ip.is_private or ip.is_link_local
        except ValueError:
            return False  # hostname → treat as remote, route via Tor (rdns)
    except Exception:
        return False


def enable_global_tor_socket(host: str = "127.0.0.1", port: int = 9050) -> bool:
    """
    Route ALL process sockets through Tor (raw TLS sockets included) with remote
    DNS, bypassing only localhost/private. Reversible + idempotent + guarded.
    Returns True if enforcement is active.
    """
    try:
        import socks  # PySocks
    except ImportError:
        _logger.warning(
            "[egress] PySocks yok — socket seviyesi Tor zorlaması YAPILAMADI; "
            "ham socket'ler (TLS/ws_fuzz) ve proxy'siz requests GERÇEK IP ile bağlanır."
        )
        return False
    import socket as _socket
    if _TOR_SOCKET_STATE["patched"]:
        return True

    orig_socket = _socket.socket
    orig_gai = _socket.getaddrinfo

    class _WSTorSocket(socks.socksocket):  # type: ignore[misc]
        def connect(self, address):
            try:
                if address and _ws_is_local_host(address[0]):
                    self.set_proxy(None)  # localhost/private → direct (no Tor)
            except Exception:
                pass
            return super().connect(address)

    def _ws_getaddrinfo(host_, *a, **kw):
        # Remote host → defer resolution to the SOCKS proxy (rdns) by returning the
        # hostname unresolved → no DNS leak to ISP. Local host → resolve normally.
        try:
            if host_ is not None and not _ws_is_local_host(host_):
                _port = a[0] if a else (kw.get("port") or 0)
                return [(_socket.AF_INET, _socket.SOCK_STREAM, 6, "", (host_, _port))]
        except Exception:
            pass
        return orig_gai(host_, *a, **kw)

    try:
        socks.set_default_proxy(socks.SOCKS5, host, int(port), rdns=True)
        _socket.socket = _WSTorSocket
        _socket.getaddrinfo = _ws_getaddrinfo
        _TOR_SOCKET_STATE.update(patched=True, orig_socket=orig_socket, orig_getaddrinfo=orig_gai)
        _logger.info(
            "[egress] Global Tor socket yönlendirmesi AKTİF — ham socket + DNS Tor'dan "
            "geçer (localhost bypass)."
        )
        return True
    except Exception as exc:
        _logger.warning(f"[egress] Global Tor socket zorlaması kurulamadı: {exc!r}")
        return False


def disable_global_tor_socket() -> None:
    """Restore the original socket / getaddrinfo (e.g. at scan end)."""
    if not _TOR_SOCKET_STATE["patched"]:
        return
    import socket as _socket
    try:
        if _TOR_SOCKET_STATE["orig_socket"] is not None:
            _socket.socket = _TOR_SOCKET_STATE["orig_socket"]
        if _TOR_SOCKET_STATE["orig_getaddrinfo"] is not None:
            _socket.getaddrinfo = _TOR_SOCKET_STATE["orig_getaddrinfo"]
    finally:
        _TOR_SOCKET_STATE.update(patched=False, orig_socket=None, orig_getaddrinfo=None)


def _tor_is_running() -> bool:
    """Tor SOCKS5 proxy'nin dinlediğini kontrol et."""
    try:
        s = socket.create_connection(("127.0.0.1", 9050), timeout=2)
        s.close()
        return True
    except Exception:
        return False


def _start_tor_if_needed() -> bool:
    """Tor çalışmıyorsa başlatmaya çalış (Kali/Linux)."""
    if _tor_is_running():
        return True
    tor_bin = shutil.which("tor")
    if not tor_bin:
        _logger.warning("[egress] tor binary bulunamadı. sudo apt install tor")
        return False
    try:
        subprocess.Popen(
            ["tor", "--quiet"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        for _ in range(15):
            time.sleep(1)
            if _tor_is_running():
                _logger.info("[egress] Tor başlatıldı ve hazır.")
                return True
        _logger.warning("[egress] Tor başlatıldı ama bağlantı kurulamadı.")
        return False
    except Exception as e:
        _logger.error(f"[egress] Tor başlatma hatası: {e}")
        return False


def _tor_cookie_auth() -> Optional[bytes]:
    """
    Tor'un CookieAuthentication dosyasını oku.
    Tor varsayılan olarak cookie auth kullanır — boş şifre çalışmayabilir.
    """
    cookie_paths = [
        # Linux/Mac standart
        os.path.expanduser("~/.tor/control_auth_cookie"),
        "/var/run/tor/control.authcookie",
        "/var/lib/tor/control_auth_cookie",
        # Windows Tor Browser (use env vars — never hardcode username)
        os.path.expandvars(r"%APPDATA%\tor\control_auth_cookie"),
        os.path.expandvars(r"%LOCALAPPDATA%\Tor Browser\Browser\TorBrowser\Data\Tor\control_auth_cookie"),
        os.path.expandvars(r"%APPDATA%\Tor Browser\Browser\TorBrowser\Data\Tor\control_auth_cookie"),
    ]
    for path in cookie_paths:
        try:
            if os.path.exists(path):
                with open(path, "rb") as f:
                    return f.read()
        except Exception:
            continue
    return None


def new_tor_identity() -> bool:
    """
    Tor NEWNYM komutu ile yeni kimlik al (yeni IP).

    Auth sırası:
    1. Boş şifre (CookieAuthentication 0 veya HashedControlPassword "")
    2. Cookie dosyası (varsayılan Tor kurulumu — en yaygın)
    """
    def _send_newnym(auth_cmd: bytes) -> bool:
        try:
            # P3/P11 fix: original code called s.close() only on the happy path;
            # any exception from s.recv() left the socket open. Use context manager.
            with socket.create_connection(("127.0.0.1", TOR_CONTROL_PORT), timeout=5) as s:
                s.sendall(auth_cmd + b"\r\nSIGNAL NEWNYM\r\nQUIT\r\n")
                resp = s.recv(1024)
            # P7 fix: QUIT always responds with "250 closing connection", so the
            # naive `b"250" in resp` returned True even when AUTH failed (515) and
            # NEWNYM was rejected (514). Explicitly reject known error codes.
            return b"250" in resp and not any(
                err in resp for err in (b"514", b"515", b"552")
            )
        except Exception as e:
            _logger.debug(f"[egress] NEWNYM sendall hatası: {e}")
            return False

    # P8 fix: cb_reset() try/except block was copy-pasted identically into both
    # success paths. Restructured to a single success exit point.
    auth_label = ""

    # 1. Boş şifre dene
    if _send_newnym(b'AUTHENTICATE ""'):
        auth_label = "boş auth"
    else:
        # 2. Cookie auth dene
        cookie = _tor_cookie_auth()
        if cookie:
            if _send_newnym(f'AUTHENTICATE {cookie.hex()}'.encode()):
                auth_label = "cookie auth"
            else:
                _logger.warning("[egress] Cookie auth da başarısız. Tor control port erişilemiyor.")
        else:
            _logger.warning(
                "[egress] NEWNYM başarısız — Tor cookie dosyası bulunamadı. "
                "torrc'ye 'CookieAuthentication 0' ekleyin veya control port şifresi ayarlayın."
            )

    if auth_label:
        _logger.info(f"[egress] Yeni Tor kimliği alındı ({auth_label}).")
        time.sleep(2)
        try:
            from websecure.core.circuit_breaker import cb_reset as _cb_reset
            _cb_reset()
        except Exception as _fix_e:
            _logger.debug(f"[core.egress] {type(_fix_e).__name__}: {_fix_e!r}")
        return True
    return False


def get_tor_proxies() -> Dict[str, str]:
    """requests için Tor proxy dict döner."""
    return {
        "http":  TOR_SOCKS_DEFAULT,
        "https": TOR_SOCKS_DEFAULT,
    }


def get_current_ip(proxies: Optional[Dict] = None, timeout: int = 8) -> Optional[str]:
    """
    Mevcut çıkış IP'sini tespit et.
    proxies verilmişse proxy üzerinden kontrol et.
    """
    endpoints = [
        "https://api.ipify.org?format=text",
        "https://checkip.amazonaws.com/",
        "https://icanhazip.com",
        "https://ifconfig.me/ip",
    ]
    try:
        import requests
        for ep in endpoints:
            try:
                r = requests.get(ep, proxies=proxies, timeout=timeout)
                ip = r.text.strip()
                if ip and len(ip) < 50:
                    return ip
            except Exception:
                continue
    except ImportError:
        pass
    return None


def verify_anonymity(proxies: Dict[str, str], cfg: dict) -> Dict[str, Any]:
    """
    Proxy/Tor üzerinden bağlantının gerçekten anonim olduğunu doğrula.
    Returns: {"anonymous": bool, "real_ip_leaked": bool, "exit_ip": str, "issues": [str]}
    """
    result: Dict[str, Any] = {
        "anonymous": False,
        "real_ip_leaked": False,
        "exit_ip": None,
        "direct_ip": None,
        "issues": [],
    }

    # Direkt IP (proxy olmadan)
    direct_ip = get_current_ip(proxies=None, timeout=5)
    result["direct_ip"] = direct_ip

    # Proxy üzerinden IP
    proxy_ip = get_current_ip(proxies=proxies, timeout=10)
    result["exit_ip"] = proxy_ip

    if not proxy_ip:
        result["issues"].append("Proxy üzerinden IP alınamadı — proxy çalışmıyor olabilir")
        return result

    if direct_ip and proxy_ip == direct_ip:
        result["real_ip_leaked"] = True
        result["issues"].append(f"UYARI: Gerçek IP sızdı! Proxy bypassed. IP: {direct_ip}")
    elif direct_ip is None:
        # P7 fix: when direct_ip could not be determined we have no baseline to
        # compare against, so anonymity cannot actually be verified. The original
        # code fell into the else branch and set anonymous=True regardless.
        result["issues"].append(
            "Gerçek IP alınamadı — anonimlik karşılaştırması yapılamıyor"
        )
        _logger.warning("[egress] Anonimlik doğrulanamadı: direkt IP tespiti başarısız.")
    else:
        result["anonymous"] = True
        _logger.info(f"[egress] Anonimlik doğrulandı. Çıkış IP: {proxy_ip}")

    return result


def setup_privacy(cfg: dict) -> Optional[Dict[str, str]]:
    """
    Config'e göre gizlilik proxy'sini kur.
    Returns: proxies dict (requests için) veya None

    Config örneği:
    {
        "privacy": {
            "mode": "tor",          # "tor", "socks5", "http", "none"
            "socks5_url": "socks5h://127.0.0.1:9050",
            "http_proxy": "http://user:pass@proxy:8080",
            "auto_start_tor": true,
            "verify_anonymity": true,
            "rotate_identity": true,
            "rotate_every": 50      # N istek sonra NEWNYM
        }
    }
    """
    privacy = (cfg.get("privacy") or {}) if isinstance(cfg, dict) else {}
    mode = (privacy.get("mode") or "none").lower().strip()

    if mode == "none" or not mode:
        return None

    proxies: Optional[Dict[str, str]] = None

    if mode == "tor":
        auto_start = privacy.get("auto_start_tor", True)
        if auto_start:
            ok = _start_tor_if_needed()
            if not ok:
                _logger.warning("[egress] Tor başlatılamadı, proxy olmadan devam ediliyor.")
                return None
        proxies = get_tor_proxies()
        _logger.info(f"[egress] Tor proxy aktif: {TOR_SOCKS_DEFAULT}")

    elif mode in ("socks5", "socks5h"):
        socks_url = privacy.get("socks5_url") or TOR_SOCKS_DEFAULT
        proxies = {"http": socks_url, "https": socks_url}
        _logger.info(f"[egress] SOCKS5 proxy: {socks_url}")

    elif mode in ("http", "https"):
        http_proxy = privacy.get("http_proxy") or privacy.get("proxy_url")
        if not http_proxy:
            _logger.warning("[egress] http_proxy URL belirtilmemiş.")
            return None
        proxies = {"http": http_proxy, "https": http_proxy}
        _logger.info(f"[egress] HTTP proxy: {http_proxy}")

    # Anonimlik doğrulama
    if proxies and privacy.get("verify_anonymity", True):
        anon = verify_anonymity(proxies, cfg)
        if not anon["anonymous"]:
            _logger.error(f"[egress] Anonimlik DOĞRULANAMADI: {anon['issues']}")
            if privacy.get("abort_if_not_anonymous", False):
                raise RuntimeError(f"Anonimlik sağlanamadı: {anon['issues']}")
        else:
            _logger.info(f"[egress] Anonim çıkış IP: {anon['exit_ip']}")

    return proxies


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

        # Proxy configured ama cevap vermiyorsa — bypass ETMEYİZ, uyarı ver
        # Bypass edilirse gerçek IP sızar (privacy leak).
        call_kwargs = dict(timeout=6, allow_redirects=True, verify=ver)
        if any_proxy and not proxy_alive:
            _logger.error(
                "[egress] UYARI: Proxy yapılandırıldı ama canlı değil! "
                "Gerçek IP sızmasını önlemek için egress health check isteği ATLANACAK."
            )
            observations.append({
                "endpoint": u,
                "error": "proxy_down:skipped_to_prevent_ip_leak",
                "used_proxy": False,
                "ip_leaked": True,
            })
            continue

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
    "TOR_SOCKS_DEFAULT",
    "TOR_CONTROL_PORT",
    "_tor_is_running",
    "_start_tor_if_needed",
    "new_tor_identity",
    "get_tor_proxies",
    "get_current_ip",
    "verify_anonymity",
    "setup_privacy",
]
