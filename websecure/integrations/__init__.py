"""
websecure.integrations
~~~~~~~~~~~~~~~~~~~~~~~
Harici araç entegrasyonları paketi.

Tüm entegrasyonlar `ToolIntegration` (base.py) soyut sınıfından türer.
Her araç bağımsız olarak import edilebilir veya `ToolRegistry` üzerinden kullanılabilir.

Hızlı Kullanım
--------------
```python
from websecure.integrations import ToolRegistry, FindingCorrelator

registry = ToolRegistry.instance()
correlator = FindingCorrelator()

# Tüm mevcut araçları çalıştır
results = registry.run_all("https://example.com", correlator=correlator)
new_findings = correlator.all_findings()
```

Araçlar
-------
- nuclei    : CVE, misconfiguration, exposure taraması
- ffuf      : Directory/endpoint/parametre fuzzing
- nmap      : Port ve servis tespiti
- sqlmap    : SQL injection doğrulama
- amass     : Subdomain + ASN enumeration    [YENİ]
- httpx     : HTTP/2 hızlı prob + tech detect [YENİ]
- katana    : JS-aware web crawler            [YENİ]
- dalfox    : XSS doğrulama                  [YENİ]
- metasploit: CVE exploit doğrulama (check)  [YENİ]
- burp      : Burp Suite Pro API import       [YENİ]

SARIF
-----
```python
from websecure.integrations import merge_tool_results_to_sarif
merge_tool_results_to_sarif(results.values(), output_path="report.sarif.json")
```
"""
from __future__ import annotations

# ---------------------------------------------------------------------------
# Base sınıflar (her zaman kullanılabilir)
# ---------------------------------------------------------------------------
from websecure.integrations.base import (
    FindingCorrelator,
    ToolFinding,
    ToolIntegration,
    ToolRegistry,
    ToolResult,
    ToolSeverity,
    ToolStatus,
)

# ---------------------------------------------------------------------------
# SARIF normalizasyon
# ---------------------------------------------------------------------------
from websecure.integrations.sarif import (
    SARIFNormalizer,
    SARIFReport,
    findings_to_sarif,
    merge_tool_results_to_sarif,
)

# ---------------------------------------------------------------------------
# Araç entegrasyonları — lazy import hatalarını yakala
# ---------------------------------------------------------------------------

def _safe_import(module_path: str, names: list) -> dict:
    """Araç modülünü güvenli şekilde import et."""
    result = {}
    try:
        import importlib
        mod = importlib.import_module(module_path)
        for name in names:
            obj = getattr(mod, name, None)
            if obj:
                result[name] = obj
    except ImportError as exc:
        import logging
        logging.getLogger(__name__).debug(
            f"[integrations] {module_path} import atlandı: {exc!r}"
        )
    return result


# Nuclei
_nuclei = _safe_import("websecure.integrations.nuclei", [
    "NucleiWrapper", "run_nuclei_scan", "update_nuclei_templates",
    "run_nuclei_with_correlation",
])
NucleiWrapper = _nuclei.get("NucleiWrapper")
run_nuclei_scan = _nuclei.get("run_nuclei_scan")
update_nuclei_templates = _nuclei.get("update_nuclei_templates")
run_nuclei_with_correlation = _nuclei.get("run_nuclei_with_correlation")

# FFUF + ParamDiscovery
_ffuf = _safe_import("websecure.integrations.ffuf", [
    "FFUFWrapper", "FeroxbusterWrapper",
    "ParamDiscoveryPipeline", "ParamDiscoveryResult",
])
FFUFWrapper = _ffuf.get("FFUFWrapper")
FeroxbusterWrapper = _ffuf.get("FeroxbusterWrapper")
ParamDiscoveryPipeline = _ffuf.get("ParamDiscoveryPipeline")
ParamDiscoveryResult = _ffuf.get("ParamDiscoveryResult")

# Nmap
_nmap = _safe_import("websecure.integrations.nmap", ["NmapWrapper"])
NmapWrapper = _nmap.get("NmapWrapper")

# SQLMap
_sqlmap = _safe_import("websecure.integrations.sqlmap", ["SQLMapClient", "SQLMapWrapper"])
SQLMapClient = _sqlmap.get("SQLMapClient")
SQLMapWrapper = _sqlmap.get("SQLMapWrapper")

# Amass + Subfinder (recon)
_amass = _safe_import("websecure.integrations.amass", [
    "AmassWrapper", "SubfinderIntegration", "run_amass",
])
AmassWrapper = _amass.get("AmassWrapper")
SubfinderIntegration = _amass.get("SubfinderIntegration")
run_amass = _amass.get("run_amass")

# httpx (YENİ)
_httpx = _safe_import("websecure.integrations.httpx_runner", [
    "HttpxWrapper", "ProbeResult", "probe_hosts",
])
HttpxWrapper = _httpx.get("HttpxWrapper")
ProbeResult = _httpx.get("ProbeResult")
probe_hosts = _httpx.get("probe_hosts")

# katana (YENİ)
_katana = _safe_import("websecure.integrations.katana", [
    "KatanaWrapper", "KatanaEndpoint", "crawl_target",
])
KatanaWrapper = _katana.get("KatanaWrapper")
KatanaEndpoint = _katana.get("KatanaEndpoint")
crawl_target = _katana.get("crawl_target")

# dalfox (YENİ)
_dalfox = _safe_import("websecure.integrations.dalfox", [
    "DalfoxWrapper", "DalfoxFinding", "verify_xss",
])
DalfoxWrapper = _dalfox.get("DalfoxWrapper")
DalfoxFinding = _dalfox.get("DalfoxFinding")
verify_xss = _dalfox.get("verify_xss")

# Metasploit (YENİ)
_msf = _safe_import("websecure.integrations.metasploit", [
    "MetasploitIntegration", "MetasploitRPCClient",
    "check_cves_with_metasploit", "_CVE_TO_MODULE",
])
MetasploitIntegration = _msf.get("MetasploitIntegration")
MetasploitRPCClient = _msf.get("MetasploitRPCClient")
check_cves_with_metasploit = _msf.get("check_cves_with_metasploit")

# Burp Suite (YENİ)
_burp = _safe_import("websecure.integrations.burp", [
    "BurpIntegration", "BurpSuiteAPIClient", "import_burp_findings",
])
BurpIntegration = _burp.get("BurpIntegration")
BurpSuiteAPIClient = _burp.get("BurpSuiteAPIClient")
import_burp_findings = _burp.get("import_burp_findings")


# ---------------------------------------------------------------------------
# ToolRegistry otomatik doldurma
# ---------------------------------------------------------------------------

def _auto_register_tools() -> ToolRegistry:
    """
    Mevcut tüm araçları ToolRegistry'e otomatik kaydet.

    Araç sınıfları lazy import edilir — binary yoksa sessizce atlanır.
    """
    registry = ToolRegistry.instance()

    _tool_classes = [
        # Subdomain / recon
        ("amass",        AmassWrapper),
        ("subfinder",    SubfinderIntegration),
        # HTTP / crawl
        ("httpx",        HttpxWrapper),
        ("katana",       KatanaWrapper),
        # Fuzzing / discovery
        ("ffuf",         FFUFWrapper),
        ("feroxbuster",  FeroxbusterWrapper),
        # Vulnerability scanning
        ("nuclei",       NucleiWrapper),
        ("dalfox",       DalfoxWrapper),
        ("sqlmap",       SQLMapWrapper),
        # Port scanning
        ("nmap",         NmapWrapper),
        # Enterprise (optional)
        ("metasploit",   MetasploitIntegration),
        ("burp",         BurpIntegration),
    ]

    for name, cls in _tool_classes:
        if cls is not None:
            try:
                tool = cls()
                registry.register(tool)
            except Exception:
                pass

    return registry


# Modül yüklendiğinde otomatik kayıt
try:
    _auto_register_tools()
except Exception:
    pass


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

__all__ = [
    # Base
    "ToolIntegration",
    "ToolFinding",
    "ToolResult",
    "ToolSeverity",
    "ToolStatus",
    "FindingCorrelator",
    "ToolRegistry",
    # SARIF
    "SARIFReport",
    "SARIFNormalizer",
    "findings_to_sarif",
    "merge_tool_results_to_sarif",
    # Araçlar
    "NucleiWrapper",
    "FFUFWrapper",
    "FeroxbusterWrapper",
    "NmapWrapper",
    "SQLMapClient",
    "SQLMapWrapper",
    "AmassWrapper",
    "SubfinderIntegration",
    "HttpxWrapper",
    "KatanaWrapper",
    "DalfoxWrapper",
    "MetasploitIntegration",
    "BurpIntegration",
    # Kısayol fonksiyonlar
    "run_nuclei_scan",
    "run_nuclei_with_correlation",
    "update_nuclei_templates",
    "run_amass",
    "probe_hosts",
    "crawl_target",
    "verify_xss",
    "check_cves_with_metasploit",
    "import_burp_findings",
    # ParamDiscovery
    "ParamDiscoveryPipeline",
    "ParamDiscoveryResult",
]
