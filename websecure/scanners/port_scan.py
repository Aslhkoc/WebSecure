
import logging
from typing import Dict, List, Any
from websecure.integrations.nmap import NmapWrapper

logger = logging.getLogger(__name__)

def run(target: str, cfg: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Executes Nmap scan using the centralized integration wrapper.
    """
    ps_cfg = cfg.get("port_scan", {}) if isinstance(cfg, dict) else {}
    if not ps_cfg.get("enabled", True):
        logger.info("[PortScan] Disabled in config.")
        return []

    wrapper = NmapWrapper()
    if not wrapper.is_available():
        logger.warning("[PortScan] Nmap binary not found via integration wrapper.")
        return [{
            "type": "Config Warning",
            "severity": "Info",
            "url": target,
            "title": "Nmap Not Found",
            "description": "Nmap scanning skipped (binary missing).",
        }]
    
    # Map config to wrapper arguments
    # wrapper.scan(target, ports="-F" etc)
    
    # Determine ports
    c_ports = ps_cfg.get("ports", [])
    ports_arg = "-F"
    if ps_cfg.get("detailed"):
        ports_arg = "-p-"
    elif c_ports:
        ports_arg = "-p" + ",".join(map(str, c_ports))
        
    extra = []
    if ps_cfg.get("detailed"):
        extra.append("-sV")
        extra.append("-T4") # default aggressive
        if ps_cfg.get("os_detection"):
             extra.append("-O")

    # Arguments from config
    user_args = ps_cfg.get("arguments", [])
    if user_args:
        extra.extend(user_args)

    logger.info(f"[PortScan] Starting scan on {target} (ports={ports_arg})")
    
    # Wrapper returns raw list, we format to findings
    # Extract host from target url if needed, but wrapper handles it?
    # Wrapper.scan expects 'host'.
    from urllib.parse import urlparse
    host = target
    if "://" in target:
        host = urlparse(target).hostname or target
    
    scan_res = wrapper.scan(host, ports=ports_arg, extra_args=extra)
    
    # Remap to 'finding' format expect by reporting
    # Scanner convention returns list of dicts.
    results = []
    for item in scan_res:
        results.append({
            "port": item.get("port"),
            "proto": item.get("protocol"),
            "state": "open",
            "service": item.get("service"),
            "product": item.get("product"),
            "version": item.get("version"),
            "scanned": True
        })
        
    if results:
        logger.info(f"[PortScan] Found {len(results)} open ports.")
        
    return results
