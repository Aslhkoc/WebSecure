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

İki yol var — ihtiyacınıza göre seçin.

### A) Hazır çalıştırılabilir (en kolay — Python gerekmez)

[Releases](../../releases) sayfasından işletim sisteminize uygun dosyayı indirip
**çift tıklayın** veya terminalden argümansız çalıştırın — karşınıza interaktif
ZEMSEC ekranı gelir (aşağıdaki "Çalıştırma"ya bakın):

| OS | Dosya | Çalıştırma |
|----|-------|------------|
| Windows | `websecure.exe` | `websecure.exe` (veya çift tıkla) |
| Linux | `websecure-linux` | `chmod +x websecure-linux && ./websecure-linux` |
| macOS (Apple Silicon) | `websecure-macos-arm64` | `chmod +x websecure-macos-arm64 && ./websecure-macos-arm64` |
| macOS (Intel) | `websecure-macos-intel` | `chmod +x websecure-macos-intel && ./websecure-macos-intel` |

### B) Kaynak koddan (Python 3.10+)

```bash
git clone https://github.com/Aslhkoc/WebSecure.git
cd WebSecure
pip install -r requirements.txt
python install.py            # opsiyonel: Playwright tarayıcısı + bağımlılık kontrolü
python -m websecure          # ÇALIŞTIR — interaktif ZEMSEC ekranı açılır
```

Harici güvenlik araçları (nuclei, ffuf, sqlmap…) **ilk çalıştırmada** interaktif
olarak kullanıcı veri dizinine indirilir — elle kurulum gerekmez:
- Windows: `%LOCALAPPDATA%\WebSecure`
- Linux: `~/.local/share/websecure`
- macOS: `~/Library/Application Support/WebSecure`

---

## Çalıştırma

**Önerilen kullanım — argüman vermeden çalıştırın:**

```bash
python -m websecure
```

(eşdeğeri: `python websecure/main.py` veya hazır dosyada `websecure.exe`)

Program sizi adım adım yönlendiren **interaktif ZEMSEC ekranıyla** karşılar:

1. **ZEMSEC banner**
2. **Araç kurulumu** — eksik harici araçları (nmap/nuclei/ffuf/sqlmap…) indirme onayı
3. **Hedef** — `Hedef (domain veya URL) gir:` sorusu
4. **Tor / kimlik doğrulama / proxy** — anonimlik ve oturum seçenekleri
5. **Tarama profili** — aşağıdaki 7 profilden biri:

| # | Profil | Açıklama |
|---|--------|----------|
| 1 | **Agresif** | Tam kapsam + maksimum hız (~30 dk) |
| 2 | **Stealth** | Tam kapsam + yavaş + WAF bypass + Tor (~4 saat) |
| 3 | **CI/CD Pipeline** | Hızlı kritik tarama (sadece Critical/High) |
| 4 | **Bug Bounty** | Min. false positive, OOB/OAST, WAF bypass (~90 dk) |
| 5 | **Uyumluluk Denetimi** | OWASP Top 10 + PCI-DSS/HIPAA/ISO27001 raporu (~60 dk) |
| 6 | **API-Only** | Sadece REST/GraphQL/gRPC yüzey (~25 dk) |
| 7 | **Kimlik Doğrulamalı** | Login → token → tam tarama (~60 dk) |

Hedef, profil veya `--help` yazmanıza gerek yoktur; her şey ekrandan seçilir.

**İleri / otomasyon kullanımı (interaktif değil):**

```bash
# Hedefi ve profili doğrudan ver (soru sormaz)
python -m websecure --target https://hedef.com --profile stealth

# Tüm soruları atla, varsayılanlarla çalış (CI için)
python -m websecure --target https://hedef.com --batch

# Tüm seçenekler
python -m websecure --help
```

Çıktılar varsayılan olarak `output/` (kaynak mod) veya kullanıcı veri dizini
(donmuş `.exe`) altına yazılır: `results.json`, `report.html`, SARIF, JUnit,
`compliance_report.md` (uyumluluk profilinde) ve kanıtlar.

---

## Kullanılan araçlar

WebSecure aşağıdaki sektör-standardı araçları orkestre eder. **Harici binary
araçlar ilk çalıştırmada otomatik indirilir** (kullanıcı veri dizinine; sistemde
ayrıca kurulu olmaları gerekmez).

**Harici güvenlik araçları:**

| Araç | Görev |
|------|-------|
| **nmap** | Port / servis / zafiyet-script taraması |
| **nuclei** | CVE & şablon tabanlı zafiyet tarayıcı (ProjectDiscovery) |
| **sqlmap** | SQL enjeksiyon keşfi + sömürü |
| **dalfox** | XSS doğrulama |
| **ffuf** + **feroxbuster** | İçerik / dizin / dosya fuzzing |
| **katana** | JS-farkında web crawler (endpoint keşfi) |
| **amass** + **subfinder** | Subdomain enumerasyonu |
| **httpx** | Toplu HTTP probe / parmak izi |
| **interactsh** | OAST / OOB callback (kör SSRF / XXE / RCE doğrulama) |

**Tarayıcı motorları:**

- **Playwright (Chromium)** — DOM XSS, SPA / JS-render form ve endpoint keşfi
- **Selenium (Chrome)** — dinamik gezinme

**Gizlilik:**

- **Tor** — SOCKS5 üzerinden anonim çıkış (interaktif Tor ekranından etkinleştirilir)

**Çekirdek Python kütüphaneleri** (`requirements.txt`): requests, beautifulsoup4,
lxml, cryptography, jinja2, cvss, `httpx[http2]`, curl-cffi / tls-client /
cloudscraper (WAF/TLS bypass), PySocks (Tor), rich. Opsiyonel: playwright (DOM XSS),
weasyprint / reportlab (PDF raporu).

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
| PDF raporu | weasyprint (+ Windows'ta GTK) veya reportlab | HTML raporu kullanılır |
| Cloudflare/Akamai bypass | `curl-cffi` | Standart TLS ile denenir (daha zayıf) |
