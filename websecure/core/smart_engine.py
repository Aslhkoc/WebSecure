
import re
from typing import List, Dict, Set

class TechDetector:
    """
    Analyzes HTTP headers and URL patterns to detect the technology stack.
    Result examples: ['php', 'linux', 'nginx', 'aspnet', 'java']
    """
    def __init__(self):
        self.signatures = {
            "php": [r"PHP/", r"PHPSESSID", r"\.php$"],
            "aspnet": [r"ASP.NET", r"ASPSESSION", r"\.aspx?$", r"__VIEWSTATE"],
            "java": [r"JSESSIONID", r"Apache-Coyote", r"Tomcat", r"Jetty", r"\.jsp$"],
            "nginx": [r"nginx"],
            "apache": [r"Apache/"],
            "linux": [r"Ubuntu", r"Debian", r"CentOS"],
            "windows": [r"Windows", r"IIS/"],
        }

    def detect(self, headers: Dict[str, str], url: str) -> Set[str]:
        tags = set()
        
        # 1. Header Analysis
        combined_headers = " ".join([f"{k}: {v}" for k, v in headers.items()])
        for tech, patterns in self.signatures.items():
            for pat in patterns:
                if re.search(pat, combined_headers, re.IGNORECASE):
                    tags.add(tech)
                    break
        
        # 2. URL Analysis
        for tech, patterns in self.signatures.items():
            for pat in patterns:
                if re.search(pat, url, re.IGNORECASE):
                    tags.add(tech)
                    break
                    
        return tags

class ParamAnalyzer:
    """
    Analyzes parameter names and values to prioritize specific exploit types.
    """
    def __init__(self):
        self.priorities = {
            "sqli": [r"id", r"num", r"user", r"item", r"account", r"view", r"sort", r"order"],
            "xss": [r"q", r"s", r"search", r"query", r"name", r"title", r"comment", r"msg"],
            "ssrf": [r"url", r"link", r"src", r"dest", r"redirect", r"uri", r"path"],
            "lfi": [r"file", r"doc", r"page", r"include", r"cat", r"dir"],
            "rce": [r"cmd", r"exec", r"command", r"ping", r"query", r"code"]
        }

    def analyze(self, param_name: str) -> List[str]:
        vulns = []
        for vuln_type, patterns in self.priorities.items():
            for pat in patterns:
                if re.search(pat, param_name, re.IGNORECASE):
                    vulns.append(vuln_type)
                    break
        return vulns

# Global Instances
_tech_detector = TechDetector()
_param_analyzer = ParamAnalyzer()

def analyze_target_context(url: str, headers: Dict[str, str], params: List[str]) -> Dict:
    """
    Returns a 'Smart Context' dictionary to guide scanners.
    """
    tech_tags = _tech_detector.detect(headers, url)
    
    param_priorities = {}
    for p in params:
        vulns = _param_analyzer.analyze(p)
        if vulns:
            param_priorities[p] = vulns
            
    return {
        "tech_stack": list(tech_tags),
        "param_risks": param_priorities,
        "is_api": "/api/" in url or "json" in str(headers).lower()
    }
