# WebSecure — Temizlik / Konsolidasyon Değişiklik Günlüğü

> Amaç: Tüm projede fonksiyonel tekrarları güçlü olanda birleştirmek. Bu dosya, programı
> çalıştırınca hata çıkarsa **"eksik aktarım mı (merge eksik) / yarım silme mi (dangling
> referans)"** ayrımını yapabilmek için her değişikliği iki ayrı eksende kayıt altına alır:
> - **AKTARILAN** = güçsüzden güçlüye taşınan benzersiz yetenekler (eksik aktarım buradan izlenir)
> - **SİLİNEN/YÖNLENDİRİLEN** = kaldırılan kod + yeniden bağlanan her referans (yarım silme buradan izlenir)
>
> Plan: `memory/plan_dedup_konsolidasyon.md`. Her aday = atomik commit. Benchmark FP=0/Recall=100% kapısı.

---

## YEŞİL TABAN (2026-06-11, değişiklik öncesi)

- **Benchmark:** TP=5 FP=0 FN=0 TN=5 · Precision=100% Recall=100% F1=1.00 (32.5s)
- **Testler:** `tests/integration/test_scanner_chain.py` + `tests/unit` → **296 passed** (25.6s)
- **pyflakes (websecure/):** 69 uyarı — hepsi MEVCUT/kasıtlı re-export "imported but unused"
  (örn. `payloads.py:799` payload_engine yeniden-ihraç, `phases/__init__.py:5` _hprofile).
  İzlenen regresyon sinyali: **yeni "undefined name"** veya sayının değişiklikle ARTMASI.
- **Kaynak envanteri:** websecure/ 147 .py (core 72, scanners 37, integrations 11, cli 10,
  root 5, reporters 4, db 3, scripts 3, api 2).

---

## DEĞİŞİKLİK KAYITLARI

> Format her aday için:
> ### [Faz][Madde] #N — <kısa başlık>
> - **KAZANAN (korunan):** dosya:sınıf/fonksiyon
> - **KAYBEDEN (kaldırılan):** dosya:sınıf/fonksiyon
> - **AKTARILAN (merge manifest):** güçsüzden güçlüye taşınan benzersiz yetenekler (yoksa "yok")
> - **SİLİNEN/YÖNLENDİRİLEN referanslar:** import / phase / registry / config / test / PROJECT_MAP
> - **Doğrulama:** pyflakes / benchmark / test sonucu
> - **Commit:** hash

### [Ön-inceleme] report_generator.py finalize_reports/export_sarif/export_junit — TEKRAR DEĞİL
- **Sonuç:** KORUNDU. `report_generator.py` gerçek bir rakip implementasyon değil; hepsi
  `reporting.py` / `integrations/sarif.py` gerçek implementasyonuna **delege eden facade**
  (+ import başarısızsa minimal fallback). Körü körüne silinseydi facade'ı import eden
  çağıranlar kırılırdı. Tekrar olarak işaretlenmedi.

---

### [T10/T1][Madde 4] #1 — subfinder: iki ayrı binary-wrapper → tek güçlü integration
- **KAZANAN (korunan):** `integrations/amass.py:SubfinderIntegration` (ToolIntegration tabanı;
  `effective_timeout`/TAM GUC uyumlu, Popen+kill+kısmi-sonuç, ToolResult/findings/version,
  base `_resolve_binary` ile tools/ dizini + PATH keşfi).
- **KAYBEDEN (kaldırılan aktif yol):** `scanners/subdomain.py:SubfinderWrapper`'ın kendi
  subprocess kopyası — sabit `timeout=120` (no_timeout/TAM GUC'a UYMUYORDU), ToolResult yok.
- **AKTARILAN (merge manifest):**
  1. Her subdomain için **IP çözümü** (`_resolve(sub)`) + `{"subdomain","ip","method":"subfinder"}`
     dict şekli → yeni adapter `run()` içine taşındı (yanındaki AmassWrapper adapter'ı ile birebir).
  2. Paketlenmiş binary keşfi (platform_compat tools/) → ToolIntegration tabanı ZATEN yapıyor
     (base.py:313 `_resolve_binary`), aktarım GEREKMEDİ (fazlalıktı).
  3. `-all` (tüm kaynaklar) → SubfinderIntegration `all_sources=True` default ile karşılanıyor.
- **SİLİNEN/YÖNLENDİRİLEN:** `SubfinderWrapper` sınıf ADI ve `run(domain,timeout)` imzası AYNI
  kaldı → çağıran `SubdomainScanner` (subdomain.py:704 `SubfinderWrapper().run(domain)`)
  DEĞİŞMEDİ. Eski subprocess impl silinmedi, `except ImportError` fallback'ına indirildi
  (AmassWrapper paritesi + frozen/import-hatası dayanıklılığı). PROJECT_MAP: sınıf adı
  korunduğu için entry değişmedi.
- **Doğrulama:** pyflakes temiz (paket 69→69, yeni undefined yok) · import smoke
  (SubfinderWrapper→SubfinderIntegration, is_available=True) · `test_subdomain_scanner.py` 9/9 ·
  benchmark TP=5 FP=0 FN=0 Recall=100% Precision=100%.
- **Commit:** c5dc7facb

---

### [Ön-inceleme] tls.py: TLSAdim9Scanner + TLSDeepScanner — TEKRAR DEĞİL (tamamlayıcı)
- **Sonuç:** KORUNDU. `scan_tls()` (tek orkestratör giriş, tls.py:104) İKİSİNİ DE çağırır;
  farklı prober grupları: TLSAdim9Scanner = BEAST/POODLE/CRIME/ROBOT/HTTP2/HTTP3/CDN,
  TLSDeepScanner = WeakCipher/HSTS/ProtocolDowngrade/CertValidation/Compression. Rakip değil.
- **AÇIK FLAG (derin TLS fazına):** scan_tls 2-3. adım `check_protocol_support`/`check_weak_ciphers`
  ile TLSDeepScanner'ın WeakCipherSuiteProber/TLSProtocolDowngradeProber ve infrastructure
  cert kontrolü (PySSLCertChecker) ↔ TLSDeepScanner.CertificateValidationProber arasında
  OLASI mükerrer-bulgu örtüşmesi var → ileride mükerrer-finding kontrolü gerek (Madde 2/3).

### [Ön-inceleme] scanners/headers.py — TEKRAR DEĞİL (legacy compat stub)
- **Sonuç:** KORUNDU. `infrastructure.get_security_headers`'a delege eden 25-satırlık stub;
  config `modules: ['headers']` dinamik importu için duruyor. Rakip logic yok. (Config'den
  'headers' modülü kalkarsa ölü-kod olur → o zaman kaldırılabilir; şimdilik bağlı.)

---

### [T2/T1][Madde 1] #2 — XSS→ATO: orchestrator'ın zayıf simülasyonu → güçlü scanner motoruna delege
- **KAZANAN (korunan):** `scanners/xss.py:XSSToATOChain` — gerçek ATO motoru: XSSCallbackServer
  (127.0.0.1) + 3 PoC payload (cookie_steal / localstorage_steal / email-change ATO CSRF) +
  Playwright/Selenium/requests sürüş + callback doğrulama. (chain_reactor:2307 zaten buna
  delege ediyordu — şimdi exploit_orchestrator da ediyor.)
- **KAYBEDEN (kaldırılan aktif logic):** `core/exploit_orchestrator.py:XSSToATOStrategy`'nin
  kendi tek `_COOKIE_STEALER_TEMPLATE`'i + yansıma-only simülasyonu (gerçek callback yok).
- **AKTARILAN (merge manifest — güçsüzde olup korunması gerekenler):**
  1. **ExploitStrategy arayüzü** (can_handle/name/ExploitResult) → sınıf wrapper KORUNDU,
     sadece execute() içi delegasyona çevrildi (SQLiExploitStrategy deseniyle birebir).
  2. **cvss_amplification** skorları (stored=2.0, reflected/dom=1.5) → KORUNDU.
  3. **stored XSS yansıma-doğrulama** sinyali (sayfada payload hâlâ yansıyor mu) → KORUNDU.
  4. **reflected crafted-URL doğrulama** → KORUNDU; ama artık güçlü `cookie_steal` (img/onerror)
     payload'unu enjekte ediyor → regex `<script>`'ten `onerror=|<script>`'e genişletildi
     (yoksa güçlü payload yansıması asla eşleşmezdi — payload swap'ı kırmamak için kritik düzeltme).
  5. **DOM impact dokümantasyonu** + **OOB host** (ctx.extra oob_host/lhost) → KORUNDU,
     oob_host artık generate_poc'a attacker_host olarak geçiyor.
  6. `_COOKIE_STEALER_TEMPLATE` SİLİNMEDİ → yalnız motor import'u başarısızsa fallback'e indirildi.
- **SİLİNEN/YÖNLENDİRİLEN:** XSSToATOStrategy sınıf adı + strateji kaydı (orchestrator:2135) +
  __all__ AYNI kaldı. Yeni bağ: `from websecure.scanners.xss import XSSToATOChain` (method-içi
  lazy, cycle yok — SQLi stratejisi de aynısını yapıyor). PROJECT_MAP entry değişmedi (sınıf adı sabit).
- **Doğrulama:** pyflakes temiz (paket 69→69) · offline execute smoke (reflected graceful-fail,
  DOM güçlü PoC'u evidence'a koyuyor) · `test_chaining.py`+`test_xss_scanner.py`+`test_dom_xss.py`
  40/40 · benchmark TP=5 FP=0 FN=0 Recall=100% Precision=100%.
- **Commit:** (aşağıdaki)
