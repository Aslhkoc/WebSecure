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
- **Commit:** 30a94717b

---

### [T1/T2][Madde 1] Denetim — exploit_orchestrator tüm *Strategy delegasyon analizi (TAMAMLANDI)
- **Yöntem:** 13 ExploitStrategy sınıfının her birinin execute()'u, karşılık gelen scanner'da
  yeniden-kullanılır **exploiter** sınıfına delege mi ediyor yoksa kendi kopyasını mı çalıştırıyor.
- **Zaten delege eden (güçlü, dokunulmadı):** SQLiExploitStrategy→`scanners.sqli.SQLiExploiter`,
  SSTIExploitStrategy→`scanners.ssti.SSTIAutoExploiter`, CMDiExploitStrategy→`scanners.cmdi.CMDIRCEChain`,
  FileUploadExploitStrategy→`scanners.file_upload.PolyglotFileUploader`.
- **Düzeltildi:** XSSToATOStrategy→`scanners.xss.XSSToATOChain` (yukarıdaki #2).
- **Ayrı ROL — tekrar DEĞİL, KORUNDU (8):** LFI, SSRF, JWT, GraphQL, XXE, CORS, IDOR, Deserialization
  stratejileri. Gerekçe: ilgili scanner sınıfları **BaseScanner tespit** prober'ları (`run→List[Dict]`
  bulgu üretir), strateji ise **post-tespit sömürü** (LFI log-poison/PHP-filter RCE+loot+shell;
  JWT alg:none/RS256→HS256/kid forge→hedefe gönder→ExploitResult). Delege edilebilir hazır exploiter
  YOK. Teknik/payload ÖRTÜŞMESİ var ama birleştirme = tespit+sömürü ortak-primitif çıkarma refactor'ü.
- **AÇIK FLAG (ileride, dikkatli, ayrı iş):** (a) JWT forge primitifleri (alg:none/key-confusion/
  weak-secret) hem `scanners.jwt` prober'larında hem JWTExploitStrategy'de — scanner 12 alg:none
  case-variant'ı daha zengin; ortak `jwt_forge` util'e çıkarılabilir. (b) LFI log-poison/filter-chain
  payload mantığı LFIExploitStrategy ↔ scanners.lfi.LFILogPoisoningChain/LFIPHPFilterChain. **LFI
  benchmark'ta → bu refactor benchmark-LFI recall'ı riske atar, ÖZEL dikkat gerekir.** Şimdi YAPILMADI.
- **Sonuç:** Strateji-delegasyon dedup partisi #2 ile KAPANDI (1 gerçek düzeltme; 4 zaten doğru;
  8 ayrı-rol korundu). Körü körüne hiçbir sömürü kodu silinmedi.

---

### [T1][Madde 3] #3 — JS sır-tarama: iki pattern havuzu → tek kaynak (js_analyzer)
- **KAZANAN (korunan):** `scanners/js_analyzer.py:_SECRET_PATTERNS` (31 compiled pattern, capture-group
  destekli, Shannon-entropy FP filtresi). Tek sır-pattern kaynağı.
- **KAYBEDEN (aktif yoldan çıkarılan):** `scanners/passive_recon.py:PassiveJSScanner.SECRET_PATTERNS`
  (18 pattern alt-küme — JSAnalyzer'ın subseti). İki fazda (run_js_analysis + passive_recon) iki
  ayrı sır-tarayıcı çalışıyordu.
- **AKTARILAN (merge manifest):**
  1. Shannon-entropy FP filtresi (`_is_false_positive`) → PassiveJSScanner'da KORUNDU (zaten js_analyzer'
     da da var, benzersiz değildi). 2. BaseScanner finding şekli (`create_finding`) → KORUNDU.
  3. capture-group desteği → eklendi (`match.lastindex` ile bare-secret çıkarımı).
  4. Endpoint çıkarımı (`_find_endpoints`) → ayrı sorumluluk, DOKUNULMADI.
- **SİLİNEN/YÖNLENDİRİLEN:** PassiveJSScanner aktif yolu artık `_JS_SECRET_PATTERNS` (js_analyzer'dan
  import) kullanıyor → sır havuzu TEK yerde bakımlanıyor; passive tarama 18→31 pattern'e yükseldi.
  Yerel `SECRET_PATTERNS` dict SİLİNMEDİ, ImportError fallback'ine indirildi (house-style). Sınıf adı/
  imza/BaseScanner mirası AYNI → test_passive_recon (BaseScanner+run callable) bozulmadı.
- **Doğrulama:** pyflakes temiz (paket 69→69) · smoke (31 pattern yüklü, AWS key tespiti) ·
  `test_passive_recon.py`+`test_js_analyzer.py` 8/8 · benchmark TP=5 FP=0 FN=0 Recall=100% Precision=100%.
- **Commit:** e0c6d98cc

---

## ═══ T1 (scanners/ — 37 dosya) KAPANIŞ ÖZETİ ═══

**Gerçek konsolidasyonlar (3):**
- #1 subfinder wrapper → SubfinderIntegration (c5dc7facb)
- #2 XSS→ATO orchestrator → scanners.xss.XSSToATOChain (30a94717b)
- #3 JS sır-pattern havuzu → tek kaynak js_analyzer (e0c6d98cc)

**Denetlendi — TEKRAR DEĞİL, korundu:**
- report_generator.py (facade/delege), tls.py TLSAdim9+TLSDeepScanner (tamamlayıcı prober grupları),
  headers.py (legacy stub→infrastructure), 8 ExploitStrategy (LFI/SSRF/JWT/GraphQL/XXE/CORS/IDOR/Deser
  = post-tespit sömürü, scanner tespitinden ayrı rol).
- **OOB/OAST ortak altyapı:** cmdi/ssrf_xxe/sqli/xss hepsi `core/oast.py` (get_oast_poller/OASTClient/
  OASTScannerMixin) paylaşıyor → callback tekrarı YOK, zaten konsolide.
- **BaseScanner:** 36 scanner tek `scanners/base.py` abstract'ını implement ediyor → arayüz tek.

**FLAG — gerçek tekrar ama YÜKSEK RİSK, ayrı dikkatli pas (körü körüne yapılmadı):**
- **TLS/cert (Madde 2):** `scan_tls` İKİ dosyada (tls.py:104 derin ↔ infrastructure.py:1220 hafif),
  cert-çıkarımı da iki yerde (tls._get_cert_details ↔ infrastructure.check_ssl_certificate/
  _extract_cert_details). public API (`scanners/__init__` ihraç) + çok faz-çağıranı + 2 büyük dosya.
  Ayrıca scan_tls cipher/protokol ↔ TLSDeepScanner WeakCipher/Downgrade prober mükerrer-bulgu olası.
- **JWT forge primitifleri (Madde 1):** scanners.jwt prober'ları (12 alg:none variant) ↔
  JWTExploitStrategy (kendi forge'u) — ortak `jwt_forge` util'e çıkarılabilir.
- **LFI RCE primitifleri (Madde 1):** LFIExploitStrategy log-poison/PHP-filter ↔ scanners.lfi
  LFILogPoisoningChain/LFIPHPFilterChain. **LFI benchmark'ta → recall riski, özel dikkat.**

**Scanner↔core tekrarları (T1 değil, kaynak fazında işlenecek):** baseline/response analizi
(→T5 response_analyzer), payload/encoding (→T3), HTTP/session (→T6). Kazanan core'da olduğu için
ilgili çekirdek fazında konsolide edilecek — T1'de değil.

**⚠️ ÖNCEDEN VAR OLAN FLAKY TEST (dedup DEĞİL — T1 sırasında keşfedildi):**
`tests/unit/test_xss_scanner.py::test_reflected_xss_detected` 5'te ~1 düşüyor. Kök neden:
`scanners/xss.py:scan_url` payload seçiminde rastgelelik — `random.sample(rest_pool)` (612) +
`if random.random()<0.2: mutate` (617) — minimal echo-mock'a karşı bazen executable XSS üretmiyor.
KANIT bu BENİM değişikliğim DEĞİL: izole test_xss çalıştırmasında passive_recon (#3) hiç import
edilmiyor, #2 xss.py'ye dokunmadı, başlangıç tabanı da bu flaky'nin şanslı geçişiydi. Benchmark
(gerçek vulnapp, 25 XSS TP) etkilenmiyor — orada çok payload + gerçek yansıma var. **XSS
benchmark-kritik olduğu için dedup işi içinde reaktif düzeltilmedi**; ayrı görev olarak flag'lendi
(deterministik test: mutasyonu patch'le / seed'le, scanner mantığına dokunmadan).

**T1 SONUÇ:** Saf scanner↔scanner temiz tekrarları konsolide edildi; ortak altyapı (OAST/BaseScanner)
doğrulandı; yüksek-riskli yapısal örtüşmeler özgül kanıtla flag'lendi. Üç dedup değişikliğinin HİÇBİRİ
test kırmadı (295 deterministik geçiyor + 1 önceden-flaky XSS). Benchmark FP=0/Recall=100% korundu.
**T1 TAMAM.** ➜ Sıradaki: T3 (WAF/payload/encoding — Madde-4 yoğun) ya da flag'li TLS/JWT/LFI özel pasları.

---

## ═══ T3 (core WAF/payload/encoding — 7 dosya) ═══

### [T3][Madde 4] #4 — fullwidth encoding: 2 byte-identical implementasyon → tek kaynak
- **KAZANAN (tek kaynak):** `core/mutator.py:to_fullwidth()` (yeni module-level fonksiyon, algoritmik
  +0xFEE0). `Mutator._to_fullwidth` artık buna delege eder.
- **KAYBEDEN (kaldırılan):** `core/evasion.py:UnicodeConfuser._FULLWIDTH` dict
  (`chr(i+0xFF00-0x20) for i in range(0x21,0x7F)`) — mutator'ın +0xFEE0'i ile **BYTE-IDENTICAL**
  (kanıt: smoke'ta module==static==evasion). UnicodeConfuser.fullwidth() artık mutator.to_fullwidth'a delege.
- **AKTARILAN:** yok (birebir aynı, kayıp yetenek yok). **SİLİNEN:** `_FULLWIDTH` dict + dict-lookup gövdesi.
- **Doğrulama:** byte-identical kanıtlandı (A→0xff21, non-ASCII korunur) · pyflakes 69→69 · benchmark
  TP=5 FP=0 Recall=100% · 296 test. **Saf refactor — davranış değişmedi (benchmark-güvenli).**
- **Commit:** (aşağıdaki)

### T3 HARİTA + FLAG'ler (kanıta dayalı)
- **evasion.py — TEKRAR DEĞİL (farklı SEVİYE), KORUNDU:** REQUEST/transport-seviyesi WAF-bypass
  toolkit'i (ChunkedBodyBuilder/OverlongUTF8Encoder/CRLFInjector/EncodingChain/PathMutator/
  ParamFragmentor/JSONUnicodeEscaper/HTTP2EvasionHelper). `waf_bypass.WAFBypassAdapter` çıkan HTTP
  isteğini (path/body/header/chunk/HTTP2) `_evasion_*` flag'leriyle dönüştürür. mutator/payload_engine
  PAYLOAD-string seviyesi; evasion onların tekrarı değil.
- **WAF tespiti — TEKRAR DEĞİL (katmanlı), KORUNDU:** `waf_fingerprint.WAFFingerprinter` zaten
  `waf_bypass.WAFDetector`'a delege ediyor + davranış-probları ekliyor; `analysis.detect_waf_from_response`
  passive fallback. (Küçük yerel `_detect_waf`: param_pollution + tech_fingerprint — başka faz dosyaları,
  dar yerel ihtiyaç; T3 değil.)
- **payloads.py — FACADE, KORUNDU:** payload_engine'i re-export eden hub (pyflakes "imported but unused"
  satırları kasıtlı). report_generator gibi.
- **🚩 FLAG — ASIL T3 TEKRARI (Madde 4, YÜKSEK RİSK, ayrı benchmark-validated pas):** payload
  encoding/mutation **5 implementasyona dağılmış**: `mutator.Mutator` (base primitifler) ↔
  `waf_bypass.AdaptiveMutationEngine` (Mutator'ı sarar + confusable) ↔ `payload_engine.EncodingVariantGenerator`
  (_enc_url/double/html/base64/hex/unicode) ↔ `payload_engine.PayloadMutationEngine` (strateji) ↔
  `human_adapter._mutate_payload` (mini). **İKİ PARALEL YIĞIN base.get_smart_payloads'ta BİRLİKTE CANLI:**
  `get_payloads_v2`(PayloadEngine→EncodingVariantGenerator) + `_apply_creative_waf_bypass`(AdaptiveMutationEngine→
  Mutator) — aynı payload'a örtüşen URL/double-url/hex/html encoding uygulayıp dedup ediyor. **SQLi/XSS
  BENCHMARK-KRİTİK + implementasyonlar byte-identical DEĞİL → birleştirme variant-set'i değiştirir = recall
  riski.** Doğru yol: kanonik encoding-primitif modülü çıkar, tüm motorları ona bağla, HER primitiften sonra
  benchmark (SQLi/XSS recall=100%) doğrula. Aceleyle YAPILMADI ("çöp olur" riski).
- **T3 SONUÇ:** 1 güvenli konsolidasyon (#4 fullwidth, byte-identical); evasion/WAF-detect/payloads
  facade KORUNDU (tekrar değil); asıl encoding-motor tekrarı kanıtla FLAG'lendi (dedicated pas gerek).

---

## ═══ T6 (core HTTP/session/rate/concurrency — 10 dosya) ═══

### [T6][Madde 4] #5 — token-bucket: 2 implementasyon → tek kaynak (rate_controller)
- **KAZANAN (tek kaynak):** `core/rate_controller.py:_TokenBucket` (public alias `TokenBucket` eklendi).
  DAHA GÜÇLÜ: adaptif `set_rate()`, `block` param, capped-sleep `min(wait,0.5)` (daha responsive).
- **KAYBEDEN (algoritması kaldırılan):** `core/http.py:RateLimiter`'ın kendi kopyalanmış bucket'ı
  (`_add_tokens` + acquire döngüsü) — `_TokenBucket` ile algoritmik AYNI (tokens=min(cap,tokens+
  elapsed*rate), consume-or-wait).
- **AKTARILAN (merge manifest):** RateLimiter'a özgü clamp'ler → KORUNDU (rps `max(0.1,..)`,
  capacity `max(1,..)`); `acquire()->None` imzası + `rps`/`capacity` attribute'ları KORUNDU.
  RateLimiter artık TokenBucket'ı sarıyor → capped-sleep responsiveness'ı da kazandı (aynı efektif rate).
- **SİLİNEN/YÖNLENDİRİLEN:** `RateLimiter._add_tokens` + manuel bucket döngüsü silindi; AntiBlockingHTTP
  (`self.rl.acquire()`, http.py:1626/2432) DEĞİŞMEDİ (yalnız .acquire() kullanıyordu). `bl_concurrency.
  RateGate` (interval-gate + inflight semaphore, race/concurrency) FARKLI mekanizma → tekrar değil, dokunulmadı.
- **Doğrulama:** pyflakes 69→69 · smoke (TokenBucket delegasyon, clamp'ler, 4 hızlı acquire, AdaptiveRateController
  bozulmadı) · benchmark TP=5 FP=0 Recall=100% (17.8s) · 296 test. (rate-limiting timing'i, tespiti değil → benchmark-güvenli.)
- **Commit:** (aşağıdaki)

### T6 HARİTA (devam ediyor)
- **Session builder'lar — TEKRAR DEĞİL (layered), KORUNDU:** `http.hardened_session` = TABAN;
  `session_factory.ensure_session` onu sarıp instrument ekler; `waf_bypass.build_bypass_session`/
  `human_adapter.make_human_session` üstüne katman; `scan_runner.make_human_session` zaten human_adapter'a
  delege (ince shim). `ensure_session` auth_flow↔session_factory = isim-çakışması, FARKLI anlam (canlı-mı? vs inşa-et).
- **Concurrency havuzları — TEKRAR DEĞİL (farklı bağlam), KORUNDU:** `concurrency.AdaptiveThreadPool`
  (genel adaptif scan pool + PriorityTaskQueue) ↔ `bl_concurrency` (RaceEngine/ThreadEngine/AsyncioEngine =
  race-condition eşzamanlı burst) ↔ `async_runner.AsyncScanRunner` (aiohttp async). Hepsi stdlib
  ThreadPoolExecutor'ı FARKLI amaçla kullanıyor (genel/race/async) → ortak primitif zaten stdlib, dup değil.
- **Circuit breaker — TEK KAYNAK, KORUNDU:** `circuit_breaker.py` (ScanCircuitBreaker + cb_check/cb_record);
  `http.py:271` onu import edip kullanıyor (reimplement etmiyor). Zaten konsolide.

**T6 SONUÇ:** 1 gerçek konsolidasyon (#5 token-bucket, rate_controller tek kaynak); session-builder'lar
(layered), RateGate (farklı mekanizma), concurrency havuzları (farklı bağlam), circuit-breaker (tek kaynak)
= tekrar DEĞİL, KORUNDU. Benchmark FP=0/Recall=100%, 296 test. **T6 TAMAM.** ➜ Sıradaki: T8 (rapor/skor —
CVSS/scoring tekrarı) ya da batch-FLAG dedicated risky pas (T3-encoding/TLS/JWT/LFI).

---

## ═══ T8 (core rapor/skor — 8 dosya) ═══

### [T8][Madde 4] #6 — CVSS score→severity band: 3 kopya → tek kaynak (cvss)
- **KAZANAN (tek kaynak):** `core/cvss.py:cvss_to_severity()` (yeni public; standart CVSS v3.1 bandı
  >=9 Critical / >=7 High / >=4 Medium / >=0.1 Low / else Info). `_severity_label` artık buna alias.
- **KAYBEDEN (kaldırılan kopyalar):** `chain_reactor.py:_cvss_to_severity` (>0.0→Low) +
  `evidence_chain.py:_score_to_sev` (>=1.0→Low) — ikisi de aynı band'ı kopyalıyordu, low-bound TUTARSIZdı.
- **AKTARILAN:** yok (high-CVSS bandlar zaten aynıydı). **DÜZELTME:** low-bound (0.1–1.0 aralığı) artık
  3 yerde de standart CVSS v3.1 (>=0.1→Low) — önceki off-by-boundary tutarsızlık giderildi.
- **SİLİNEN/YÖNLENDİRİLEN:** `_cvss_to_severity`/`_score_to_sev` fonksiyon ADLARI + tüm çağıranları
  (chain_reactor 203/1360/1370 vb.) AYNI kaldı, gövdeleri cvss.cvss_to_severity'e delege (lazy import,
  cvss saf leaf → cycle yok). `_SEV_SCORES` (evidence_chain, severity→float) FARKLI ölçek, DOKUNULMADI.
- **Doğrulama:** pyflakes 69→69 · smoke (3 yol+alias tam aralıkta kanonikle BİREBİR aynı; high-CVSS
  değişmedi) · benchmark TP=5 FP=0 Recall=100% · 325 test (chaining dahil). (Benchmark high-CVSS →
  low-bound farkı tetiklenmez = güvenli; üstelik standarda hizalandı.)
- **Commit:** (aşağıdaki)
