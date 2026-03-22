
import os
import shutil
import subprocess
import socket
import logging

# Setup basic logging
logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")

def check_binary(name):
    path = shutil.which(name)
    if path:
        logging.info(f"[OK] {name} found at: {path}")
        return True
    else:
        logging.error(f"[FAIL] {name} NOT found in PATH.")
        return False

def check_port(host, port, name):
    try:
        with socket.create_connection((host, port), timeout=2):
            logging.info(f"[OK] {name} is listening on {host}:{port}")
            return True
    except (socket.timeout, ConnectionRefusedError):
        logging.warning(f"[WARN] {name} not reachable on {host}:{port} (Is it running?)")
        return False

def main():
    print("=== WebSecure Deep System Verification ===")
    
    # 1. External Tools
    tools = ["nmap", "ffuf", "feroxbuster", "sqlmap", "python"]
    print("\n[+] Checking External Tools:")
    for t in tools:
        check_binary(t)

    # 2. Tor / Proxy
    print("\n[+] Checking Tor/Proxy:")
    check_port("127.0.0.1", 9050, "Tor SOCKS5 (Default)")
    check_port("127.0.0.1", 9150, "Tor Browser SOCKS5")

    # 3. Wordlists
    print("\n[+] Checking Critical Wordlists:")
    base = os.path.join(os.getcwd(), "websecure", "wordlists")
    files = ["dirs.txt", "files.txt", "seclists"]
    for f in files:
        p = os.path.join(base, f)
        if os.path.exists(p):
             logging.info(f"[OK] Wordlist found: {p}")
        else:
             logging.error(f"[FAIL] Wordlist missing: {p}")

    print("\n=== Verification Complete ===")

if __name__ == "__main__":
    main()
