import logging
import xml.etree.ElementTree as ET
from typing import List, Dict, Optional, Any

logger = logging.getLogger(__name__)

class NmapParser:
    """
    Nmap XML Reader (-oX format).
    Parses open ports and service details to feed into WebSecure scope.
    """
    
    @staticmethod
    def parse_xml(file_path: str) -> List[Dict[str, Any]]:
        """
        Parses Nmap XML file and returns a list of open services.
        Structure:
        [
            {
                "ip": "192.168.1.1",
                "hostname": "example.com",
                "port": 80,
                "protocol": "tcp",
                "service": "http",
                "product": "Apache",
                "version": "2.4.41"
            }, ...
        ]
        """
        results = []
        try:
            tree = ET.parse(file_path)
            root = tree.getroot()
            
            for host in root.findall("host"):
                # Host Status Check
                status = host.find("status")
                if status is not None and status.get("state") != "up":
                    continue
                
                # IP Address
                address = host.find("address")
                ip = address.get("addr") if address is not None else "unknown"
                
                # Hostname
                hostname = ""
                hostnames = host.find("hostnames")
                if hostnames is not None:
                    hn = hostnames.find("hostname")
                    if hn is not None:
                        hostname = hn.get("name", "")

                # Ports
                ports = host.find("ports")
                if ports is None:
                    continue
                
                for port in ports.findall("port"):
                    state = port.find("state")
                    if state is None or state.get("state") != "open":
                        continue
                        
                    port_id = int(port.get("portid"))
                    protocol = port.get("protocol")
                    
                    service = port.find("service")
                    service_name = "unknown"
                    product = ""
                    version = ""
                    
                    if service is not None:
                        service_name = service.get("name", "unknown")
                        product = service.get("product", "")
                        version = service.get("version", "")
                    
                    results.append({
                        "ip": ip,
                        "hostname": hostname,
                        "port": port_id,
                        "protocol": protocol,
                        "service": service_name,
                        "product": product,
                        "version": version
                    })
                    
        except ET.ParseError as e:
            logger.error(f"Nmap XML parse error ({file_path}): {e}")
        except FileNotFoundError:
            logger.error(f"Nmap file not found: {file_path}")
        except Exception as e:
            logger.error(f"Unexpected Nmap parse error: {e}")
            
        logger.info(f"Nmap ingest: {len(results)} open ports found in {file_path}")
        return results
