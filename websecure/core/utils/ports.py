
import socket
import threading
import concurrent.futures
from typing import Dict, List, Any, Optional

def tcp_connect_scan(host: str, ports: List[int]) -> Dict[int, bool]:
    """Basic TCP Connect Scan."""
    results = {}
    
    def scan_one(h, p):
        try:
            with socket.create_connection((h, p), timeout=2.0) as s:
                return (p, True)
        except (socket.timeout, ConnectionRefusedError, OSError):
            return (p, False)

    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        futures = {executor.submit(scan_one, host, p): p for p in ports}
        for future in concurrent.futures.as_completed(futures):
            p, is_open = future.result()
            results[p] = is_open
            
    return results

def scan_ports(target: str, results: Dict[str, Any], detailed: bool = False, debug: bool = False, protocol: str = "tcp") -> List[int]:
    """
    Scans common ports on top of 'target' and populates 'results'.
    Returns list of open ports.
    """
    from urllib.parse import urlparse
    if "://" in target:
        parsed = urlparse(target)
        host = parsed.hostname or target
    else:
        host = target.split(":")[0]

    # TOP 50 ports
    COMMON_PORTS = [
        21, 22, 23, 25, 53, 80, 81, 110, 111, 135, 139, 143, 443, 445, 465, 587, 993, 995, 
        1433, 1521, 3000, 3306, 3389, 5000, 5432, 5900, 6379, 8000, 8008, 8080, 8081, 8443, 
        8888, 9000, 9090, 9200, 27017
    ]
    
    if detailed:
        # Extend to TOP 1000ish or just more common ones if detailed
        COMMON_PORTS.extend([
            8082, 8083, 8084, 8085, 8086, 8087, 8088, 8089, 8090,
            7000, 7001, 7002, 
            # ... add more as needed
        ])

    open_ports = []
    scan_res = tcp_connect_scan(host, COMMON_PORTS)
    
    port_records = []
    
    for p, is_open in scan_res.items():
        if is_open:
            open_ports.append(p)
            port_records.append({
                "host": host,
                "port": p,
                "proto": "tcp",
                "state": "open",
                "service": "unknown" 
            })
            
    # Populate results for reporting
    results["port_scan"] = port_records # Legacy key support
    results["nmap"] = port_records      # Legacy key support
    results["open_ports"] = open_ports
    
    # Also add summary for top-level report
    results["port_scan_summary"] = {
        "scanned": len(COMMON_PORTS),
        "open": len(open_ports),
        "details": port_records
    }
    
    return open_ports
