
import sys
try:
    import websecure.scanners.ssrf_xxe
    print("Success")
except ImportError as e:
    with open("FATAL.txt", "w", encoding="utf-8") as f:
        f.write(str(e))
except Exception as e:
    with open("FATAL.txt", "w", encoding="utf-8") as f:
        f.write(f"{type(e).__name__}: {e}")
