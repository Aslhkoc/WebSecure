# WebSecure

Python ile yazılmış, sektör seviyesi bir **web güvenlik tarama çerçevesi**. 36 zafiyet
kategorisini otomatik tarar, saldırı zinciri kurar, exploit eder ve raporlar
(SQLi, XSS, SSRF/XXE, SSTI, LFI, CMDi, GraphQL, JWT, Auth/IDOR, TLS, Request
Smuggling, Race Condition ve daha fazlası).

> ⚠️ **Yasal uyarı:** WebSecure yalnızca **sahibi olduğunuz veya açık yazılı
> izniniz olan** sistemlerde kullanılmalıdır. İzinsiz tarama çoğu ülkede suçtur.
> Sorumluluk tamamen kullanıcıya aittir.

---

## Kurulum

Üç yol var — ihtiyacınıza göre seçin.

### A) Hazır çalıştırılabilir (en kolay — Python gerekmez)

[Releases](../../releases) sayfasından işletim sisteminize uygun dosyayı indirin:

| OS | Dosya | Çalıştırma |
|----|-------|------------|
| Windows | `websecure.exe` | `websecure.exe --help` (veya çift tıkla) |
| Linux | `websecure-linux` | `chmod +x websecure-linux && ./websecure-linux --help` |
| macOS | `websecure-macos` | `chmod +x websecure-macos && ./websecure-macos --help` |

İlk çalıştırmada harici araçlar (nuclei, ffuf, sqlmap…) otomatik olarak
kullanıcı veri dizinine indirilir:
- Windows: `%LOCALAPPDATA%\WebSecure`
- Linux: `~/.local/share/websecure`
- macOS: `~/Library/Application Support/WebSecure`

### B) Kaynak koddan (Python 3.10+)

```bash
git clone https://github.com/Aslhkoc/WebSecure.git
cd WebSecure
pip install -r requirements.txt
python install.py            # opsiyonel: Playwright tarayıcısı + bağımlılık kontrolü
python -m websecure --setup  # harici binary araçları indirir
python -m websecure --help
```

### C) Docker (en tekrarlanabilir — tüm araçlar dahil)

```bash
docker build -t websecure .
docker run --rm websecure scan --target https://hedef.com --profile cicd
```

---

## Hızlı başlangıç

```bash
# Temel tarama
python -m websecure scan --target https://hedef.com

# Profil ile (stealth = yavaş + WAF bypass, aggressive = hızlı + tam kapsam)
python -m websecure scan --target https://hedef.com --profile stealth

# Rapor formatı
python -m websecure scan --target https://hedef.com --format html
```

Çıktılar varsayılan olarak `output/` (kaynak mod) veya kullanıcı veri dizini
(donmuş `.exe`) altına yazılır: `results.json`, `report.html`, SARIF, JUnit, kanıtlar.

---

## Yapılandırma

- `config.json` — tüm tarayıcı parametreleri, WAF bypass, OAST, rate limiting, auth.
- Kendi config'inizi kullanmak için: çalıştırma dizinine `config.json` koyun,
  veya `WEBSECURE_CONFIG=/yol/config.json` ortam değişkenini ayarlayın.
- Veri/çıktı dizinini taşımak için: `WEBSECURE_HOME=/yol` ayarlayın.

---

## Opsiyonel özellikler

| Özellik | Gereksinim | Yoksa ne olur |
|---------|-----------|---------------|
| DOM XSS (gerçek tarayıcı) | Playwright + `playwright install chromium` | DOM XSS taraması atlanır |
| PDF raporu | weasyprint (+ Windows'ta GTK) | HTML raporu kullanılır |
| Cloudflare/Akamai bypass | `curl-cffi` | Standart TLS ile denenir (daha zayıf) |

---

## Geliştirme

```bash
pip install -r requirements.txt
python -m pytest                 # test paketi
python build_exe.py              # bu OS için standalone binary üret (dist/)
```
