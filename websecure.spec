# -*- mode: python ; coding: utf-8 -*-
"""
WebSecure — PyInstaller onefile spec (cross-platform: Windows / Linux / macOS).

Build
-----
    python build_exe.py
veya doğrudan:
    pyinstaller websecure.spec --clean --noconfirm

Çıktı: ``dist/websecure`` (Linux/macOS) veya ``dist/websecure.exe`` (Windows).

Notlar
------
- Salt-okunur kaynaklar (config.json, wordlists, profiller, playbook'lar,
  rapor şablonları) ``datas`` ile paketlenir; layout ``websecure.core.paths``
  ve ``__file__``-göreli okumalarla birebir uyumludur (``_MEIPASS/websecure/...``).
- Harici binary araçlar (nuclei, ffuf, sqlmap, nmap…) PAKETLENMEZ; ilk
  çalıştırmada ``websecure.core.startup`` tarafından kullanıcı veri dizinine
  (``user_data_dir``) indirilir.
- ``playwright`` ve ``weasyprint`` bilerek HARİÇ tutulur: tarayıcı binary'leri
  runtime'da indirilir / GTK native bağımlılıkları taşınamaz. İlgili kod
  yolları (DOM XSS, PDF) bunlar yoksa zarifçe devre dışı kalır.
"""
from pathlib import Path

from PyInstaller.utils.hooks import collect_submodules

ROOT = Path(".").resolve()


def _collect(rel: str):
    """`rel` (dosya veya dizin) için (kaynak, hedef_dizin) tuple listesi üret.

    Hedef dizin, kaynağın proje köküne göreli üst dizinidir; böylece
    paketlenmiş layout (``_MEIPASS/<rel>``) korunur.
    """
    src = ROOT / rel
    if not src.exists():
        return []
    if src.is_file():
        parent = Path(rel).parent
        return [(str(src), str(parent) if str(parent) != "." else ".")]
    out = []
    for p in src.rglob("*"):
        if p.is_file():
            out.append((str(p), str(p.relative_to(ROOT).parent)))
    return out


datas = []
for _rel in [
    "config.json",
    "config.schema.json",
    "websecure/wordlists",
    "websecure/config",            # YAML profiller + exploit playbook'ları
    "websecure/reporters/templates",
]:
    datas += _collect(_rel)

# Dinamik yüklenen websecure alt modülleri (scanner/integration/plugin) —
# PyInstaller statik analizinin kaçırabileceklerini garanti altına al.
hiddenimports = [
    m for m in collect_submodules("websecure")
    if ".tests" not in m and not m.endswith(".tests")
]
# Lazy / try-except ile içe aktarılan opsiyonel 3. taraf kütüphaneler.
#  - h2       : httpx[http2] HTTP/2 desteğini lazy yükler (waf_bypass HTTP2Mux,
#               race_condition, oast) → frozen'da statik analiz kaçırabilir.
#  - reportlab: frozen'da TEK PDF backend'i (weasyprint native GTK nedeniyle
#               hariç) — reporting._try_reportlab lazy import; bundle EDİLMEZSE
#               exe hiç PDF üretemez, yalnız HTML'e düşer.
hiddenimports += [
    "curl_cffi", "tls_client", "cloudscraper", "socks",
    "bs4", "lxml", "tldextract", "cryptography", "jinja2",
    "cvss", "regex", "Levenshtein", "httpx", "h2", "yaml", "rich",
    "jsonschema", "reportlab",
]

# Native/ağır veya runtime'da indirilen — bilerek hariç (kod zarifçe degrade eder).
#  - playwright/weasyprint: tarayıcı runtime'da iner / GTK native taşınamaz.
#  - torch & ML yığını: yalnızca opsiyonel sentence_transformers (semantic_ratio)
#    tarafından transitif çekilir; websecure hiçbir yerde doğrudan import etmez.
#    Hariç tutmak exe'yi ~200MB küçültür ve frozen torch/CUDA init çökmesini önler.
excludes = [
    "playwright", "weasyprint", "tkinter",
    "torch", "torchvision", "torchaudio",
    "sentence_transformers", "transformers", "sklearn", "scipy", "pandas",
]

block_cipher = None

a = Analysis(
    ["run_websecure.py"],
    pathex=[str(ROOT)],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=excludes,
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name="websecure",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
