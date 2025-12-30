import logging
from typing import Dict, Any, List

logger = logging.getLogger(__name__)

def should_fail_ci(cfg: Dict[str, Any], results: Dict[str, Any]) -> bool:
    """
    CI Quality Gate Logic.
    Determines if the scan should fail based on configuration and results.
    
    cfg: Full configuration dictionary.
    results: Final results dictionary (may contain 'stats', 'findings', or be a summary dict).
    """
    ci_cfg = cfg.get("ci") or {}
    fail_on = ci_cfg.get("fail_on") or []
    
    if not fail_on:
        return False
        
    normalized_fail = [s.strip().lower() for s in fail_on if isinstance(s, str)]
    if not normalized_fail:
        return False

    # Extract counts (support multiple result structures)
    counts = {}
    
    # Structure 1: results['summary']['counts'] (from export_json)
    if "summary" in results and "counts" in results["summary"]:
        counts = results["summary"]["counts"]
    
    # Structure 2: Direct buckets/findings walk
    elif "findings" in results:
        # Calculate manually
        counts = {"kritik": 0, "yüksek": 0, "orta": 0, "düşük": 0, "bilgi": 0}
        for sev in ["kritik", "yüksek", "orta", "düşük", "bilgi"]:
             counts[sev] = 0 # init
             
        for cat, items in results["findings"].items():
            for item in items:
                s = str(item.get("severity") or "Bilgi").lower()
                # Turkish/English mapping
                if s in ["critical", "severe"]: s = "kritik"
                elif s in ["high"]: s = "yüksek"
                elif s in ["medium"]: s = "orta"
                elif s in ["low"]: s = "düşük"
                elif s in ["info"]: s = "bilgi"
                
                if s in counts:
                    counts[s] += 1
                else:
                    counts[s] = 1 # unknown severity

    # Check conditions
    for severity, count in counts.items():
        if count > 0:
            # Check exact match or "any"
            if "any" in normalized_fail:
                logger.error(f"CI Failure: Found {count} issues (Rule: 'any')")
                return True
            if severity.lower() in normalized_fail:
                logger.error(f"CI Failure: Found {count} issues with severity '{severity}'")
                return True
                
    return False
