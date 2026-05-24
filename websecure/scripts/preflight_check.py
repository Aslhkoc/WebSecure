"""
WebSecure Preflight Check
Programın başlangıcında tüm araçların gerçekten bulunup çalıştırılabilir
olduğunu doğrular. Entegrasyon sınıflarının is_available() metodlarını
kullanır — PATH'e değil, base._resolve_binary() mantığına dayanır.
"""
import os
import sys
import socket
import logging

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
log = logging.getLogger(__name__)


def _check_tool(label, cls_import_fn):
    try:
        wrapper = cls_import_fn()
        ok = wrapper.is_available()
        binary = getattr(wrapper, 'binary', '?')
        if ok:
            log.info(f"[OK] {label:15s} -> {binary}")
        else:
            log.error(f"[FAIL] {label:15s} -> binary bulunamadi")
        return ok
    except Exception as e:
        log.error(f"[ERR] {label:15s} -> {e}")
        return False


def _check_port(host, port, label):
    try:
        with socket.create_connection((host, port), timeout=2):
            log.info(f"[OK] {label:15s} -> {host}:{port} dinleniyor")
            return True
    except Exception:
        log.warning(f"[WARN] {label:15s} -> {host}:{port} kapali")
        return False


def _check_playwright():
    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as p:
            b = p.chromium.launch(headless=True)
            ver = b.version
            b.close()
        log.info(f"[OK] {'chromium':15s} -> playwright chromium v{ver}")
        return True
    except Exception as e:
        log.error(f"[FAIL] {'chromium':15s} -> {e}")
        return False


def _check_wordlists():
    from pathlib import Path
    base = Path(__file__).resolve().parent.parent / "wordlists"
    required = ["dirs.txt", "files.txt", "params.txt", "subdomains.txt"]
    all_ok = True
    for f in required:
        p = base / f
        if p.exists():
            log.info(f"[OK] wordlist/{f}")
        else:
            log.error(f"[FAIL] wordlist/{f} eksik")
            all_ok = False
    return all_ok


def main():
    print("\n=== WebSecure Preflight Check ===\n")

    results = {}

    # Harici araclar (entegrasyon siniflari uzerinden)
    print("[+] Harici Araclar:")
    from websecure.integrations.nmap import NmapWrapper
    from websecure.integrations.amass import AmassWrapper, SubfinderIntegration
    from websecure.integrations.ffuf import FFUFWrapper, FeroxbusterWrapper
    from websecure.integrations.httpx_runner import HttpxWrapper
    from websecure.integrations.katana import KatanaWrapper
    from websecure.integrations.nuclei import NucleiWrapper
    from websecure.integrations.dalfox import DalfoxWrapper
    from websecure.integrations.sqlmap import SQLMapWrapper

    results['nmap']        = _check_tool('nmap',        NmapWrapper)
    results['amass']       = _check_tool('amass',       AmassWrapper)
    results['subfinder']   = _check_tool('subfinder',   SubfinderIntegration)
    results['ffuf']        = _check_tool('ffuf',        FFUFWrapper)
    results['feroxbuster'] = _check_tool('feroxbuster', FeroxbusterWrapper)
    results['httpx']       = _check_tool('httpx',       HttpxWrapper)
    results['katana']      = _check_tool('katana',      KatanaWrapper)
    results['nuclei']      = _check_tool('nuclei',      NucleiWrapper)
    results['dalfox']      = _check_tool('dalfox',      DalfoxWrapper)
    results['sqlmap']      = _check_tool('sqlmap',      SQLMapWrapper)

    # Playwright / Chromium
    print("\n[+] Tarayici (DOM XSS / JS tarama):")
    results['chromium'] = _check_playwright()

    # Tor
    print("\n[+] Tor / Proxy:")
    tor_ok = (
        _check_port("127.0.0.1", 9050, "tor(socks5)") or
        _check_port("127.0.0.1", 9150, "tor-browser") or
        _check_port("127.0.0.1", 9151, "tor-control")
    )
    results['tor'] = tor_ok
    if not tor_ok:
        log.warning("  Tor servisi calismiyor — Tor gerektiren taramalar atlanacak.")

    # Wordlist'ler
    print("\n[+] Wordlistler:")
    results['wordlists'] = _check_wordlists()

    # Ozet
    print("\n=== OZET ===")
    ok_count  = sum(1 for v in results.values() if v)
    fail_count = len(results) - ok_count
    for name, ok in results.items():
        status = "OK  " if ok else "FAIL"
        print(f"  [{status}] {name}")
    print(f"\n{ok_count}/{len(results)} hazir", end="")
    if fail_count:
        print(f", {fail_count} eksik/calismiyor")
    else:
        print(" -- tumü hazir!")
    print()
    return fail_count == 0


if __name__ == "__main__":
    ok = main()
    sys.exit(0 if ok else 1)
