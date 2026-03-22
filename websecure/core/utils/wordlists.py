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
            
        # [UPDATE] Artık sadece .txt değil, uzantısız ve diğer wordlist uzantılarını da alıyoruz.
        # İstenmeyen uzantılar (binary, script, resim vb.) filtrelenir.
        ALLOWED_EXTENSIONS = {'.txt', '.lst', '.fuzz', '.list', '.dict', '.csv', '.json'}
        IGNORED_EXTENSIONS = {
            '.py', '.pyc', '.md', '.zip', '.tar', '.gz', '.png', '.jpg', '.jpeg', '.gif',
            '.svg', '.xml', '.xsl', '.sh', '.yml', '.yaml', '.php', '.bin', '.exe', '.dll',
            '.git', '.gitignore', '.gitattributes'
        }

        for f in p.rglob("*"):
            if f.is_file():
                suffix = f.suffix.lower()
                
                # 1. Uzantısız dosyaları kabul et (Linux wordlist'leri genelde uzantısızdır)
                if not suffix:
                    found_files.append(str(f.resolve()))
                    total_size += f.stat().st_size
                    continue
                
                # 2. İzin verilen uzantıları kabul et
                if suffix in ALLOWED_EXTENSIONS:
                    found_files.append(str(f.resolve()))
                    total_size += f.stat().st_size
                    continue

                # 3. Geriye kalanları (bilinmeyen ama potansiyel text) analiz etmek riskli olabilir,
                # şimdilik sadece ALLOWED veya (NOT IGNORED) mantığı denenebilir.
                # Ancak güvenli olması için whitelist + empty extension en temizidir.


    # Basit satır tahmini (ortalama 10 byte/satır)
    estimated_lines = total_size // 10
    
    return {
        "all": found_files,
        "count": len(found_files),
        "total_lines_est": estimated_lines
    }
