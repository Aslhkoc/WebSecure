import socket
from urllib.parse import urlparse
import logging

logger = logging.getLogger(__name__)

def discovery_enrich(url: str, results: dict, open_ports: dict = None, detailed: bool = False, debug: bool = False):
    """
    Performs basic enrichment: DNS resolution and service banner grabbing.
    """
    domain = urlparse(url).netloc.split(':')[0]
    
    # DNS
    dns_info = {}
    try:
        ip = socket.gethostbyname(domain)
        dns_info['ip'] = ip
        print(f"[+] Hedef IP: \033[92m{ip}\033[0m")  # Green color for visibility
        # Could add more DNS records here if needed
    except Exception as e:
        print(f"[-] DNS Çözümleme Hatası ({domain}): {e}")
        if debug:
            logger.debug(f"DNS resolution failed: {e}")
        
    results.setdefault('discovery', {})['dns'] = dns_info
    
    # Service Banners
    if open_ports:
        services = {}
        # Handle both list (e.g. [80, 443]) and dict (e.g. {80: True})
        ports_to_scan = []
        if isinstance(open_ports, dict):
            ports_to_scan = [p for p, open in open_ports.items() if open]
        elif isinstance(open_ports, (list, tuple)):
            ports_to_scan = open_ports
            
        for port in ports_to_scan:
            try:
                # Very basic banner grab
                with socket.create_connection((domain, int(port)), timeout=1.5) as s:
                    # Send a generic payload depending on port? 
                    # For now just connect. HTTP ports might need HTTP request.
                    if int(port) in [80, 443, 8080, 8443]:
                        s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                    else:
                        s.sendall(b"\r\n") 
                    
                    banner = s.recv(1024).decode('utf-8', 'ignore').strip()
                    services[port] = banner[:50] if banner else "Open (no banner)"
            except Exception:
                services[port] = "Open"
        results['discovery']['services'] = services
