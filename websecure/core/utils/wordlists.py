import os
import pathlib
from typing import List, Dict

def collect_all_wordlists(base_dirs: List[str] = None) -> Dict[str, object]:
    """
    Belirtilen dizinler altındaki tüm .txt dosyalarını (wordlist) recursive olarak bulur.
    
    Args:
        base_dirs: Taranacak kök dizinlerin listesi. Varsayılan: otomatik tespit.
    
    Returns:
        Dict: {"all": [path1, path2...], "count": int, "total_lines_est": int}
    """
    if base_dirs is None:
        # Resolve paths relative to this file so the project is portable
        _here = pathlib.Path(__file__).resolve().parent.parent.parent  # websecure/
        base_dirs = [
            str(_here / "wordlists"),
            str(_here / "wordlists_custom"),
        ]

    found_files = []
    total_size = 0
    
    for d in base_dirs:
        p = pathlib.Path(d)
        if not p.exists():
            continue
            
        for f in p.rglob("*.txt"):
            if f.is_file():
                found_files.append(str(f.resolve()))
                total_size += f.stat().st_size

    # Basit satır tahmini (ortalama 10 byte/satır)
    estimated_lines = total_size // 10
    
    return {
        "all": found_files,
        "count": len(found_files),
        "total_lines_est": estimated_lines
    }
