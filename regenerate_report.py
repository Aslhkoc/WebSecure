
import json
import io
from websecure.reporters import html, markdown
import os

OUT_DIR = r"c:\Users\Acer\PycharmProjects\WebSecure\output"
RESULTS_FILE = os.path.join(OUT_DIR, "report.json") # usually contains the full report structure

def main():
    print("--- Manual Report Regeneration ---")
    if not os.path.exists(RESULTS_FILE):
        print(f"❌ report.json not found at {RESULTS_FILE}")
        # Try metadata + results
        return
        
    with open(RESULTS_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)
        
    print(f"✅ Loaded report data: {len(data.get('final', []))} findings.")
    
    # 1. HTML
    try:
        print("Generating HTML...")
        html_content = html.render(data)
        out_path = os.path.join(OUT_DIR, "report_report.html")
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(html_content)
        print(f"✅ Wrote HTML to {out_path}")
    except Exception as e:
        print(f"❌ HTML Gen Failed: {e}")
        import traceback
        traceback.print_exc()

    # 2. Markdown (Verify)
    try:
        print("Generating Markdown...")
        md_content = markdown.render(data)
        out_path = os.path.join(OUT_DIR, "report_report_manual.md")
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(md_content)
        print(f"✅ Wrote Markdown to {out_path}")
    except Exception as e:
        print(f"❌ MD Gen Failed: {e}")

if __name__ == "__main__":
    main()
