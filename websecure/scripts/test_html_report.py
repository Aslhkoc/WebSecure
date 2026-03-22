
import sys
import os
from pathlib import Path

# Fix path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from websecure.core.reporting import perform_reporting

def test_html_render():
    print("Testing HTML Report Generation...")
    
    results = {
        "final": [
            {
                "type": "XSS",
                "severity": "High",
                "url": "http://test.com",
                "param": "id",
                "poc": "<script>alert(1)</script>",
                "description": "Reflected XSS",
                "recommendation": "Encode output"
            },
            {
                "type": "SQLi",
                "severity": "Critical",
                "url": "http://test.com/login",
                "param": "user",
                "poc": "' OR 1=1--",
                "description": "SQL Injection",
                "recommendation": "Use parameterized queries"
            }
        ],
        "meta": {"target": "http://test.com"},
        "http_timing": [{"status": 200}, {"status": 404}],
        "rate_limit_obs": [],
        "anti_block_event": [],
        "input_coverage": [],
        "payload_metrics": {}
    }
    
    cfg = {
        "reporting": {
            "formats": ["json", "md", "html"],
            "output_dir": "output/test_gen"
        }
    }
    
    try:
        perform_reporting(None, cfg, results)
        print("Reporting executed.")
    except Exception as e:
        print(f"Reporting crashed: {e}")
        import traceback
        traceback.print_exc()

    # Verify
    p = Path("output/test_gen/report.html")
    if p.exists():
        print(f"SUCCESS: {p} created. Size: {p.stat().st_size}")
    else:
        print(f"FAILURE: {p} NOT created.")

if __name__ == "__main__":
    test_html_render()
