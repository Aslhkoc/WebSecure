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
- **Commit:** 19936bdc7

### T8 HARİTA + KAPANIŞ
- **CVSS scoring SINIFLARI — TEKRAR DEĞİL (farklı amaç), KORUNDU:** `cvss.CVSSScorer` (per-finding CVSS
  v3 base score) ↔ `chain_reactor.CVSSChainCalculator` (exploit-zinciri aggregate CVSS) ↔
  `score_tracker.ScoreCalculator` (tüm-tarama risk grade'i 0-100, "1 Critical→62/100"). Farklı hesap,
  farklı girdi/çıktı. (Ortak primitif = score→severity band → #6'da tekilleşti.)
- **Bildirim 3 MODALİTE — TEKRAR DEĞİL, KORUNDU:** `notification.py` (HARİCİ servisler: Slack/Jira/
  Teams/PagerDuty/GitHub webhook) ↔ `alerts.py:AlertManager` (AUDIO: winsound beep, severity'e göre
  siren/machine-gun) ↔ `live_monitor.py` (TERMİNAL canlı gösterim). Üç ayrı çıktı kanalı, örtüşme yok.
- **`finalize_reports`** reporting↔report_generator = facade (T1'de incelendi, korundu). **`redaction.py`**
  = PII maskeleme, benzersiz.

**T8 SONUÇ:** 1 gerçek konsolidasyon (#6 CVSS band, 3→1, low-bound standarda hizalandı); CVSS scoring
sınıfları (farklı amaç), bildirim 3-modalite, finalize facade, redaction = tekrar DEĞİL, KORUNDU.
Benchmark FP=0/Recall=100%, 325 test. **T8 TAMAM.**

---

## ═══ T5 (core analiz/FP — 5 dosya) ═══

> Kapsam: response_analyzer, fp_reducer, fp_learner, correlation_engine, timing_analyzer (Madde 3 = analiz).
> ADIM 0/1 sonucu: katman İYİ AYRIŞIK — 3 farklı baseline (içerik-diff / timing / soft-404), 3 farklı
> FP/dedup ölçeği (oturum-içi exact dedup / öğrenilmiş-regex kural / çapraz-tarama korelasyon), her biri
> AYRI amaç. Tek gerçek Madde-3 tekrarı: **SQL/DB hata-pattern kütüphanesi**.

### [T5][Madde 3] #7 — SQL/DB hata-pattern kütüphanesi: sqli kopyası → tek kaynak (SQLErrorDetector)
- **KAZANAN (tek kaynak):** `core/response_analyzer.py:SQLErrorDetector` (16-DB, ~70 pattern, compile+cache,
  thread-safe, 64KB ReDoS-cap, `extract_fingerprints`→stabil `"<DB>:<idx>"` etiketleri). Zaten
  `ResponseBehaviorAnalyzer`'ın motoru; sqli onu (RBA üzerinden) zaten import ediyordu.
- **KAYBEDEN (kaldırılan kopya):** `scanners/sqli.py:ERRORS` dict (13-DB, ~45 pattern) — `SQLErrorDetector`'ın
  ALT KÜMESİ. `_extract_error_fingerprints` artık SQLErrorDetector'a delege.
- **AKTARILAN (ADIM 2 merge manifest — sqli'de olup canonical'da OLMAYAN):** `MariaDB: "valid MariaDB result"`
  TEK benzersiz pattern → `SQLErrorDetector._RAW["MariaDB"]`'e eklendi (2→3 pattern). Geri kalan tüm sqli
  pattern'leri canonical'da zaten vardı (canonical superset).
- **DAVRANIŞ KORUNDU:** `_extract_error_fingerprints` dönüş şekli `(db, label)` tuple kaldı → 5 tüketici
  (`db = next(iter(new_errors))[0]`) AYNEN çalışır. label artık stabil `idx` tabanlı → injected−baseline
  set-farkı tutarlı (eskiden ham regex string'iydi, yine stabildi). KAZANÇ: 13→16 DB (Redis/Cassandra/
  ElasticSearch + her DB'de daha fazla pattern); baseline-diff + reproducibility gate FP'yi tutar.
- **SİLİNEN/YÖNLENDİRİLEN:** `ERRORS` class-attr (60 satır) silindi. `_extract_error_fingerprints` gövdesi
  delegasyona indi. `import` satırına `SQLErrorDetector` eklendi. `sqli._ERROR_PATTERNS` (7-pattern, ayrı
  LOAD_FILE okuma-prober'ı, bool döner) DOKUNULMADI — farklı dar amaç, recall-kritik değil (not edildi).
- **Doğrulama:** pyflakes temiz (sqli+response_analyzer) · import smoke OK (MariaDB=3 pattern) · **benchmark
  TP=5 FP=0 FN=0 Recall=100% Precision=100%, SQLi=3 (baseline'la BİREBİR aynı)** · integration 13/13 + sqli
  unit (25 passed).
- **Commit:** b24fc46b7

### T5 HARİTA + KAPANIŞ
- **3 BASELINE — TEKRAR DEĞİL (farklı ölçüm), KORUNDU:** `response_analyzer.BaselineCapture` (içerik
  fingerprint: hash/uzunluk/başlık/hata-fp → differential) ↔ `timing_analyzer.TimingBaseline` (istatistik
  zamanlama profili: mean/stdev/dinamik-eşik) ↔ `fp_reducer.SoftNotFoundBaseline` (soft-404/catch-all). Üçü
  farklı şey ölçer, farklı algoritma tüketir.
- **FP/DEDUP/KORELASYON — TEKRAR DEĞİL (farklı kapsam), KORUNDU:** `fp_reducer._GlobalFindingRegistry`
  (oturum-içi exact-key dedup + reproducibility) ↔ `fp_learner.FPLearner` (kalıcı öğrenilmiş regex-kural FP
  filtresi, API-only) ↔ `correlation_engine` (çapraz-tarama ilişki tespiti: repeat/escalation/chain/
  persistence, API-only). Üç ayrı mekanizma/kapsam. Hash key'leri (fp_reducer vuln|url|param|payload,
  fp_learner title|url|sev|tool) FARKLI alan setleri → tekrar değil.
- **anomaly_score (T4 analysis.py) ↔ ResponseDifferential (T5):** FARKLI seviye/sinyal — anomaly_score
  jenerik BaseScanner sinyali (semantic/levenshtein, `base.check_anomaly`), RBA SQLi-özel hata-fp
  differential. Tamamlayıcı, tekrar değil. (analysis.py zaten T4 dosyası → cross-layer, kaynak T4'te.)
- **correlation_engine._CHAIN_PAIRS ↔ chain_reactor zincirleri (T2):** FARKLI amaç — _CHAIN_PAIRS post-hoc
  anahtar-kelime ÇİFTİ tespiti (raporlanan bulgularda potansiyel zincir işaretle), chain_reactor AKTİF
  çok-adımlı sömürü. Tekrar değil.
- **🚩 AÇIK FLAG (recall-kritik, gerekirse ileride):** `graphql._ERROR_SIGS` (Mongo/BSON/$-operatör, dar
  GraphQL-enjeksiyon seti) + `ws_fuzz` çok-vuln marker tablosu + `sqli._ERROR_PATTERNS` (LFI-via-SQLi okuma
  prober'ı) = küçük domain-özel setler; SQLErrorDetector'a zorla taşımak YANLIŞ olur (farklı seviye/amaç).

**T5 SONUÇ:** 1 gerçek konsolidasyon (#7 SQL/DB hata kütüphanesi, sqli→SQLErrorDetector tek kaynak,
"valid MariaDB result" aktarıldı, 13→16 DB kazanç); 3 baseline + FP/dedup/korelasyon üçlüsü +
anomaly/RBA + chain-pair = tekrar DEĞİL, KORUNDU. Benchmark FP=0/Recall=100%, SQLi=3 birebir, 25 test.
**T5 TAMAM.** ➜ Sıradaki: T4 (crawl) ya da T2 (exploit core kalan) ya da batch-FLAG (T3-encoding/TLS/JWT/LFI).

---

## ═══ T4 (core crawl/analiz — 6 dosya) ═══

> Kapsam: crawler, browser_crawler, form_parser, analysis, endpoint_prioritizer, tech_fingerprint (Madde 2 tarama + 3 analiz).
> ADIM 0/1: 3 crawler WIRED + FARKLI rol (root `crawler.py:WebCrawler` üretim HTTP+browser [main.py];
> `core/crawler.py:CrawlerOrchestrator` API/şema keşfi fazı [phases:1674]; `browser_crawler.BrowserCrawler`
> Playwright SPA fazı) — PROJECT_MAP "farklı roller" doğrulandı, körü körüne BİRLEŞTİRİLMEZ. Extraction
> primitifleri (link/form/JS) bağlam-özel (kırık-HTML fuzz regex / static BS4 / SPA DOM), farklı sonuç
> şekline besler. `infer_form_method` ZATEN tek kaynak (analysis.py, commit 948b9406d).

### [T4][Madde 3] #8 — Sır (secret) pattern havuzu: browser_crawler kopyası → tek kaynak (js_analyzer)
- **KAZANAN (tek kaynak):** `scanners/js_analyzer.py:_SECRET_PATTERNS` (derlenmiş, capture-grup'lu; T1 #3'te
  passive_recon da buna bağlanmıştı). 31→**32** pattern.
- **KAYBEDEN (fallback'e indirildi):** `core/browser_crawler.py:_SECRET_PATTERNS` (5-pattern dict) →
  `_scan_for_secrets` artık canonical `_JS_SECRET_PATTERNS`'i kullanır (modül yoksa yerel dict fallback —
  passive_recon ile birebir aynı desen). Sır taraması 5→32 pattern'e yükseldi.
- **AKTARILAN (ADIM 2 merge manifest):** browser_crawler-benzersiz TEK pattern `"Bearer Token"`
  (`[Bb]earer\s+(...)` inline form; js_analyzer'da yalnız `bearer_token` key=value vardı) → canonical'e
  eklendi. Diğer 4 (API Key/JWT/AWS Key/Private Key) canonical'da zaten daha geniş haliyle vardı.
- **DAVRANIŞ:** finding şekli (`type/url/value_preview[:20]/severity:High`) korundu; canonical capture-grup
  varsa onu (`match.lastindex`) alır → gerçek sır değeri (eskisi tam-eşleşme alıyordu, iyileşme).
- **İmport güvenliği:** core→scanners import'u modül-seviyesi `try/except` ile (cycle olursa ImportError
  yakalanır → fallback). js_analyzer yalnız `core.reporting` (leaf) import eder → cycle yok; smoke doğruladı.
- **SİLİNEN/YÖNLENDİRİLEN:** hiçbir şey silinmedi (5-pattern dict bilinçli fallback olarak kaldı, passive_recon
  precedent'i). Canlı yol artık TEK kaynak. PROJECT_MAP browser_crawler deps += js_analyzer.
- **Doğrulama:** pyflakes temiz (browser_crawler+js_analyzer) · import/cycle smoke OK (canonical=32, görünür) ·
  fonksiyonel (AWS Key + Bearer canonical yoldan tespit) · benchmark TP=5 FP=0 Recall=100% · integration 13/13 ·
  passive_recon 17 + js_analyzer 6 unit yeşil (canonical'in diğer tüketicileri Bearer eklemesinden bozulmadı).
- **Commit:** 984db648c

### T4 HARİTA + KAPANIŞ
- **3 CRAWLER — TEKRAR DEĞİL (farklı rol, hepsi WIRED), KORUNDU:** root `crawler.py:WebCrawler`+
  `discover_dynamic_endpoints` (üretim HTTP+browser keşfi, main.py) ↔ `core/crawler.py:CrawlerOrchestrator`
  (API/şema keşif fazı: OpenAPI/GraphQL/gRPC/APIVersion/ParameterMiner/Sitemap, phases:1674) ↔
  `browser_crawler.BrowserCrawler` (Playwright SPA fazı). PROJECT_MAP "farklı roller" doğrulandı.
- **EXTRACTION primitifleri (link/form/JS) — TEKRAR DEĞİL (bağlam-özel), KORUNDU:** `form_parser.extract_all_forms`
  (kırık-HTML fuzz için regex, virtual-form/script-input çıkarımı) ↔ `core/crawler._extract_forms` (BFS-crawl,
  `infer_form_method`'a delege) ↔ `analysis.detect_get_parameters_and_forms` (driver/fetcher + BS4) ↔
  browser_crawler SPA DOM. Farklı girdi/çıktı şekli, farklı pipeline. `infer_form_method` ZATEN tek kaynak
  (analysis.py, 948b9406d) — 4 keşif noktası ona delege ediyor (dedup zaten yapılmış).
- **tech_fingerprint — KENDİ KENDİNE YETER (canonical), KORUNDU:** Wappalyzer-tarzı (header/body/cookie/db sig
  + `_detect_waf`), pre-scan TechProfile. WAF tespiti katmanlı (analysis.detect_waf_from_response fallback +
  tech_fingerprint._detect_waf tag + T3 waf_fingerprint/waf_bypass) — farklı seviye, T3'te korundu.
- **endpoint_prioritizer — TEK IMPL (wired), KORUNDU:** `EndpointPrioritizer.rank` (main.py:1896). payload_engine
  `.rank` FARKLI (payload skorlama). Tekrar yok.
- **ParameterMiner ↔ ffuf ParamDiscoveryPipeline — FARKLI TEKNİK, KORUNDU:** arjun-tarzı differential param
  madenciliği (core/crawler) ↔ wordlist-fuzz (ffuf, T10). İkisi de ayrı fazda wired. Cross-layer.
- **🚩 B3-FLAG (ölü-kod, dedup değil):** `analysis.cloud_hints(headers)` ORPHAN (0 çağıran; sadece tanım).
  Wired `passive_recon.CloudDetector` (11 sağlayıcı header-sig + CNAME takeover) çok daha güçlü → cloud_hints
  benzersiz değer taşımıyor, tamamen subsumed. **Körü körüne SİLİNMEDİ** (orphan = 6boyut B3'ün işi); B3 pasında
  kaldırılmalı. [[plan_6boyut_tam_denetim]]

**T4 SONUÇ:** 1 gerçek konsolidasyon (#8 sır pattern havuzu, browser_crawler→js_analyzer tek kaynak,
5→32 pattern, "Bearer Token" aktarıldı); 3 crawler (farklı rol) + extraction primitifleri (bağlam-özel) +
tech_fingerprint (canonical) + endpoint_prioritizer + ParameterMiner = tekrar DEĞİL, KORUNDU. cloud_hints
orphan → B3-flag. Benchmark FP=0/Recall=100%, integration 13/13 + passive_recon 17 + js_analyzer 6.
**T4 TAMAM.** ➜ Sıradaki: T2 (exploit core kalan) / T7 (auth) / T9-T15 ya da batch-FLAG (T3-encoding/TLS/JWT/LFI).

---

## ═══ T2 (core exploit — 6 dosya) ═══

> Kapsam: chain_reactor, exploit_orchestrator, post_exploit, evidence_chain, oast, xss_callback (Madde 1 saldırı + 2 tarama).
> **SONUÇ: 0 YENİ konsolidasyon — katman ZATEN tekilleşmiş** (T1 strateji-denetimi + T8 severity + iyi DIP mimarisi).
> Doğrulama-only faz: kod değişmedi, benchmark FP=0/Recall=100% (T4'ten beri sabit), tüm T2 modülleri import OK.

### T2 HARİTA + ZATEN-KONSOLİDE / KORUNDU (her biri kanıtla)
- **Exploit STRATEJİLERİ (exploit_orchestrator 13 *Strategy) — ZATEN T1-DENETLENDİ (8ee390ec4):** 4 zaten
  delege (SQLi/SSTI/CMDi/FileUpload→scanner zincirleri), 1 düzeltildi (#2 XSSToATO→xss.XSSToATOChain, 30a94717b),
  8 ayrı-rol sömürü KORUNDU (LFI/SSRF/JWT/GraphQL/XXE/CORS/IDOR/Deser = tespit-vs-sömürü). Re-litigate YOK.
- **POST-EXPLOIT komut çalıştırıcılar — ZATEN TEK KAYNAK (DIP), KORUNDU:** `post_exploit.CommandRunner` (+ SSTI/
  CMDi/WebShell alt sınıfları, yalnız `_build_payload` farklı) + `PostExploitChain` TEK kaynak. chain_reactor
  (ChainExploitRunner 1921/2502) VE exploit_orchestrator stratejileri (215/307/402/584/762/877) hepsi buna
  DELEGE eder — reimplement YOK. Bölüm-C "post-exploit runner tekrarı" zaten çözülmüş.
- **OAST/OOB — ZATEN MERKEZİ (oast.py), KORUNDU:** `oast.py` tam OOB altyapısı (token gen, Interactsh/Generic
  client, poller, SMTP/FTP/LDAP/log4shell kanalları, korelasyon). Scanner OOB prober'ları (CMDiOOBDNSProber/
  BlindXXEErrorProber/SSRFScanner) `oast.OASTScannerMixin`'i import eder + `config.oast.dns_domain`/global poller
  kullanır — token/polling reimplement YOK (cmdi/sqli/ssrf_xxe oast'tan import). T1 "OAST ortak" doğrulaması geçerli.
  (`uuid4().hex[:8]` canary'leri trivial stdlib idiom — dedup hedefi değil.)
- **CVSS/severity yardımcıları — ZATEN T8-DELEGE:** `chain_reactor._cvss_to_severity` + `evidence_chain._score_to_sev`
  → `cvss.cvss_to_severity` tek kaynak (19936bdc7). `CVSSChainCalculator` (zincir-aggregate) farklı amaç, KORUNDU.
- **3 ZİNCİR-BİLGİSİ ENCODER'ı — FARKLI AMAÇ/YAPI/TÜKETİCİ, KORUNDU:** `correlation_engine._CHAIN_PAIRS` (15 tuple,
  ÇAPRAZ-tarama keyword korelasyonu, API-only) ↔ `chain_reactor` ChainRule sınıfları (10, AKTİF exploit-graph +
  ChainExploitRunner, phase_chain_reactor) ↔ `evidence_chain._CHAIN_RULES` (10 tuple, TEK-tarama rapor narrative +
  CVSS escalation, annotate_results). Aynı domain bilgisini (XSS→ATO, SQLi→exfil…) 3 UYUMSUZ şemada 3 farklı
  algoritma için kodlar; birleştirmek 3'ünün de DAVRANIŞINI değiştirir → "davranış değişmez" ihlali olurdu. KORUNDU.
- **3 HTTP SERVER — FARKLI AMAÇ, KORUNDU:** `xss_callback.XSSCallbackServer` (blind-XSS cookie/storage yakalama,
  xss.py kullanır) ↔ `api/server.py` (REST API) ↔ `cli/web_ui.py` (dashboard). BaseHTTPRequestHandler ortak ama
  3 ayrı amaç. xss_callback (in-browser JS exfil) ↔ oast (protokol-seviyesi OOB) de farklı yakalama mekanizması.
- **🚩 B3-FLAG (ölü-kod, dedup değil):** `chain_reactor.analyze_chains` (1535, public facade `ChainReactor().analyze`)
  CANLI ÇAĞIRANI YOK — main.py phase_chain_reactor'ı kullanıyor (yorum 2399: "analyze_chains sadece detection,
  exploit pipeline çalışmıyordu"). `__all__`'da public API olduğu için körü körüne SİLİNMEDİ; 6boyut B3 değerlendirsin.

**T2 SONUÇ:** 0 yeni konsolidasyon. Exploit-core katmanı T1 (strateji denetimi + XSS→ATO) + T8 (severity) +
iyi DIP (post-exploit tek kaynak, OAST merkezi) ile ZATEN tekilleşmiş. 3 zincir-encoder + 3 HTTP-server =
farklı amaç, KORUNDU. analyze_chains orphan → B3-flag. Kod değişmedi, benchmark FP=0/Recall=100%.
**T2 TAMAM.** ➜ Sıradaki: T7 (auth) / T9-T15 ya da batch-FLAG (T3-encoding/TLS-cert/JWT-forge/LFI-RCE).

---

## ═══ T7 (core auth/profil/akış — 14 dosya) ═══

> Kapsam: auth_flow, auth_manager, flows, auth/(__init__,flows,providers,totp), profiles, scan_profile,
> scan_runner, checkpoint, phases/(_context,_hprofile) (Madde 2 tarama + 4 diğer).
> ADIM 0/1: Bölüm-C "4 login akışı" kısmen yanlış-gruplama: `core/flows.py` = business-logic-flow DSL (login DEĞİL),
> `core/auth/flows.py` = EmailOTP/DeviceCode 2FA sağlayıcıları (login DEĞİL). Gerçek login-primitifi tekrarı:
> **auth_flow ↔ auth_manager** (iki paralel auth sistemi: main.py→auth_flow.run_auth_flow, phases.run→AuthManager).

### [T7][Madde 4] #9 — CSRF token çıkarımı: auth_manager kopyası → tek kaynak (auth_flow.extract_csrf)
- **KAZANAN (tek kaynak):** `auth_flow.extract_csrf` (en sağlam: boş-guard + `analysis.extract_csrf` delegasyonu
  + DOM selectolax/lxml + regex fallback). main.py login yolu + test_auth_flow ile kaplı.
- **KAYBEDEN (fallback'e indirildi):** `auth_manager._extract_csrf` (bağımsız 8-isim regex kopyası) →
  artık `auth_flow.extract_csrf`'e delege (lazy import; yerel regex yalnız o modül yoksa fallback).
- **AKTARILAN (ADIM 2 merge manifest — auth_manager'da olup auth_flow'da OLMAYAN):** (a) field adları
  `xsrf_token` + `__RequestVerificationToken` (ASP.NET) → `_CSRF_NAMES`'e eklendi (DOM + regex ikisi de görür);
  (b) value→name sırası (eskiden yalnız name→value); (c) `<meta name="csrf*" content>` etiketi; (d) esnek value
  pozisyonu (`name="csrf" type="hidden" value="x"` — name/value arası attribute). Hepsi `_extract_csrf_regex`'te
  birleşti → auth_flow'un TÜM çağıranları da kazandı.
- **DAVRANIŞ:** sadece tekilleşme + additive kapsam artışı (auth_manager hiçbir şey kaybetmedi, DOM+analysis+meta
  KAZANDI; auth_flow daha çok token yakalıyor). Cycle yok (auth_flow auth_manager'ı import etmez; dep zaten vardı).
- **Doğrulama:** pyflakes temiz · fonksiyonel 5/5 (meta/value-first/aspnet/attr-between/classic — HEM canonical
  HEM consumer) · test_auth_flow + test_csrf + integration 27 passed · benchmark TP=5 FP=0 Recall=100% (auth
  benchmark-dışı ama çalıştırıldı).
- **Commit:** f80e108dc

### T7 HARİTA + KAPANIŞ
- **İKİ AUTH SİSTEMİ — paralel ama WIRED, farklı runner, KORUNDU:** `auth_flow` (session+cfg, Requests/WebDriver/
  Playwright stratejileri + signup/device-code/mailbox/LoginAuditor; main.py pipeline) ↔ `auth_manager.AuthManager`
  (ctx-tabanlı çok-metot: form/basic/bearer/cookie/apikey/jwt; phases.run). Tüm sistemleri birleştirmek = 2 runner'ı
  riske atar; bunun yerine PAYLAŞILAN primitifler tekilleşti (CSRF #9). `_looks_authenticated` (auth_flow resp+hints
  + Set-Cookie ↔ auth_manager indicator-substring + farklı hint seti) + form-alan tespiti (auth_manager._detect_form_fields
  extract-all ↔ auth_flow._infer_login_fields login-özel) = FARKLI imza/amaç → birleştirmek davranış değiştirir, KORUNDU.
- **core/flows.py — TEKRAR DEĞİL (login değil):** business-logic-flow DSL (run_business_logic_flows/idempotency,
  store/assert/extractor). Auth ile alakasız.
- **core/auth/flows.py + providers + totp — TEKRAR DEĞİL (2FA):** EmailOtpProvider (IMAP) / DeviceCodeAuth (OAuth) /
  Totp2FA/EmailOtp2FA/Null2FA / TOTP. 2FA sağlayıcıları, login-orkestrasyonu değil.
- **profiles.py ↔ scan_profile.py — TAMAMLAYICI (delege), KORUNDU:** scan_profile (etkileşimli CLI sihirbazı +
  süre tahmini, `_offer_scan_profile_and_confirm`) `profiles.get_registry/apply_profile`'a DELEGE eder (OOP
  ScanProfile hiyerarşisi: Aggressive/Stealth/CICD/BugBounty/...). Tekrar değil, katmanlı.
- **scan_runner / checkpoint / phases/_context,_hprofile — denetlendi, tekrar yok:** scan-state/checkpoint/host-profile
  bağlam yardımcıları, ayrı sorumluluk.

**T7 SONUÇ:** 1 gerçek konsolidasyon (#9 CSRF çıkarımı, auth_manager→auth_flow tek kaynak, meta/iki-sıra/ASP.NET-
token/esnek-pozisyon aktarıldı). 2 auth sistemi (paralel/wired/farklı-runner) + _looks_authenticated/form-alan
(farklı imza) + flows(business-logic) + auth/(2FA) + profiles↔scan_profile(delege) = tekrar DEĞİL, KORUNDU.
Benchmark FP=0/Recall=100%, 27 test. **T7 TAMAM.** ➜ Sıradaki: T9 (altyapı/util) / T10-T15 ya da batch-FLAG.

---

## ═══ T9 (core altyapı/util — 16 dosya) ═══

> Kapsam: paths, platform_compat, startup, tool_manager, plugin_registry, plugin_marketplace, exceptions,
> __init__, utils/(__init__,config,helpers,net,system,wordlists), cli/__init__ (Madde 4 diğer/sistem).
> **SONUÇ: 0 YENİ canlı konsolidasyon — katman İYİ KATMANLI** (T2 gibi). Doğrulama-only faz, kod değişmedi,
> benchmark FP=0/Recall=100% (T7'den sabit), tüm T9 modülleri import OK.

### T9 HARİTA + ZATEN-KATMANLI / KORUNDU (her biri kanıtla)
- **BINARY KEŞFİ — KATMANLI, FARKLI KONVANSİYON, KORUNDU:** `paths.py` (TÜM yolların tek kaynağı, frozen-aware:
  tools_dir/drivers_dir/...) ↔ `platform_compat.py` (exe_suffix/binary_name/**binary_candidates** = canonical
  tools/-aday üreteci, archive extraction) ↔ `tool_manager.py` (runtime ToolManager: _find_binary + sqlmap API +
  Go/pdtm dir search) ↔ `startup.py` (_GO_TOOLS install-spec, ensure_* indirme). **binary_candidates ZATEN canonical:**
  integrations/base._resolve_binary + sqlmap/nmap/ffuf ona DELEGE eder. tool_manager._find_binary FARKLI konvansiyon
  (`tools/{tool_name}/{binary}` + _KNOWN_TOOLS alias'ları [sqlmap→sqlmapapi.py, interactsh→interactsh-client] +
  capitalize variant + Go-dir search); binary_candidates `tools/{tool}/{tool}` + exe_suffix. Birleştirmek konvansiyon
  çakışması + tool-tespiti riski (benchmark-dışı) → KORUNDU. tool.path zaten paths.tools_dir() kullanıyor (path tek kaynak).
- **PLUGIN — FARKLI AMAÇ, ikisi de WIRED, KORUNDU:** `plugin_registry.PluginRegistry` (İÇ scanner kaydı:
  built-in BaseScanner sınıfları → fazlar, entry-point/dizin keşfi; phases.get_registry) ↔ `plugin_marketplace`
  (HARİCİ 3.parti plugin yaşam-döngüsü: BasePlugin ABC, git/local install, enable/disable/uninstall/run;
  api/server get_marketplace). Farklı arayüz, farklı amaç. Tekrar değil.
- **profiles ↔ scan_profile (T7'de de geçti):** scan_profile DELEGE eder. utils/* (config/helpers/net/wordlists/
  system) tekil-amaç yardımcılar; net.is_junk_url/same_site vb. tek kaynak (T4'te de doğrulandı).
- **🚩 B3-FLAG (ölü-kod, dedup değil):** dizin-oluşturma üçlüsü `paths.ensure` (canonical, CANLI) ↔
  `utils/system.ensure_dir` (0 çağıran, yalnız `__all__` export — orphan) ↔ `reporting._ensure_dir` (0 çağıran,
  private orphan). İkincil ikisi paths.ensure kopyası; CANLI çağıranı yok → körü körüne SİLİNMEDİ, 6boyut B3
  değerlendirsin (ensure_dir public export olduğu için harici-kullanıcı riski var). [[plan_6boyut_tam_denetim]]

**T9 SONUÇ:** 0 yeni canlı konsolidasyon. Altyapı/util katmanı iyi-katmanlı: binary-keşif (paths/platform_compat/
tool_manager/startup farklı konvansiyon+amaç, binary_candidates zaten canonical) + plugin (iç-registry vs harici-
marketplace farklı amaç) + utils tekil-amaç = tekrar DEĞİL, KORUNDU. ensure_dir/reporting._ensure_dir orphan →
B3-flag. Kod değişmedi, benchmark FP=0/Recall=100%. **T9 TAMAM.** ➜ Sıradaki: T10 (integrations) / T11-T15 ya da
batch-FLAG (T3-encoding/TLS-cert/JWT-forge/LFI-RCE).

---

## ═══ T10 (integrations/ — 11 dosya) ═══

> Kapsam: __init__, base, amass, dalfox, ffuf, httpx_runner, katana, nmap, nuclei, sarif, sqlmap (Madde 2,4).
> Hepsi `base.ToolIntegration` türevi araç wrapper'ları.

### [T10][Madde 4] #10 — is_available() boilerplate: 7 birebir kopya → tek kaynak (base default)
- **KAZANAN (tek kaynak):** `base.ToolIntegration.is_available()` artık CONCRETE varsayılan (eskiden abstract):
  `shutil.which(self.binary) is not None or (self._binary_path and Path(self._binary_path).exists())`.
- **KAYBEDEN (kaldırılan 7 birebir override):** amass.AmassWrapper, amass.SubfinderIntegration,
  amass.InteractshIntegration, dalfox.DalfoxWrapper, katana.KatanaWrapper, nuclei.NucleiWrapper,
  ffuf.FeroxbusterWrapper — hepsi bu birebir aynı kontrolü (veya denkini: nuclei/interactsh hardcoded ad)
  tekrar ediyordu. Artık base'den miras alır.
- **AKTARILAN (ADIM 2):** yok (7 override base default'a denk; nuclei/interactsh'in hardcoded adı
  self._binary_name ile aynı → fark yok). 4 dosyada artık kullanılmayan import temizlendi (shutil/Path).
- **KORUNAN (özel, override KALDI):** sqlmap (.py script + binary_candidates), ffuf.FFUFWrapper (.py launcher
  sys.executable kontrolü), httpx (_is_go_httpx Go-vs-Python ayrımı). nmap (kendi _find_binary).
- **DAVRANIŞ:** birebir aynı — 10 wrapper is_available() çıktısı baseline'la BİREBİR eşleşti (hepsi True,
  binary mevcut). base hâlâ abstract (tool_name/run). abstractmethod yalnız is_available'dan kalktı.
- **Doğrulama:** pyflakes temiz (4 unused import temizlendi) · is_available baseline 10/10 BİREBİR ·
  base instantiate-edilemez (abstract korundu) · benchmark TP=5 FP=0 Recall=100% · integration 13/13.
  PROJECT_MAP base.py entry güncellendi (ortak is_available + classes/funcs/deps).
- **Commit:** bb4d76a70

### T10 HARİTA + KAPANIŞ
- **binary çözümleme — ZATEN canonical:** `platform_compat.binary_candidates` tek kaynak; `base._resolve_binary`
  + sqlmap/nmap/ffuf ona DELEGE eder (T9'da da doğrulandı). katana/ffuf'un __init__'teki ekstra _check_binary'si
  süper sonrası REDUNDANT re-resolution (base zaten çözüyor) ama her birinde ufak fark var (katana hardcoded aday,
  uyarı log'u) → davranış-değişmez riski, NOT edildi (düşük öncelik), KORUNDU.
- **subdomain Amass/Subfinder — ZATEN DELEGE (adapter+fallback):** `scanners/subdomain.py` AmassWrapper/Subfinder
  birer adapter, `integrations.amass.AmassWrapper`/`SubfinderIntegration`'a delege eder (T1 #1 + mevcut). Tekrar değil.
- **SARIF — ZATEN DELEGE:** `report_generator.export_sarif` → `integrations/sarif.findings_to_sarif` (canonical;
  fingerprint/CWE/dedup). integrations/sarif.py tek SARIF kaynağı. Tekrar değil.
- **subprocess/parse — FARKLI CLI başına özel, KORUNDU:** her aracın run/_build_command/_parse_output'u kendi
  CLI'sine özgü (nuclei templates, amass enum/intel, httpx probe, katana crawl…). effective_timeout/no_timeout
  base'den (tek kaynak). Tekrar değil.

**T10 SONUÇ:** 1 gerçek konsolidasyon (#10 is_available 7→1 base default, davranış birebir). binary_candidates/
SARIF/subdomain-adapter ZATEN canonical-delege; subprocess/parse CLI-başına özel = tekrar DEĞİL, KORUNDU.
_check_binary redundancy NOT edildi (düşük öncelik). Benchmark FP=0/Recall=100%, integration 13/13.
**T10 TAMAM.** ➜ Sıradaki: T11 (reporters) / T12 (cli) / T13 (db+api) / T14 (root) / T15 (kod-dışı) ya da batch-FLAG.

---

## ═══ T11 (reporters/ — 4 dosya) ═══

> Kapsam: __init__, html_dashboard, markdown, pdf (Madde 4 diğer). Rapor format renderer'ları.

### [T11][Madde 4] #11 — severity normalize/rank: format'lar arası 6 kopya → tek kaynak (reporters/__init__)
- **KAZANAN (yeni tek kaynak):** `reporters/__init__.py` (eskiden boş) → `normalize_severity(s)` (TR/EN varyant →
  kanonik etiket) + `severity_rank(s)` (Critical=4..Info=0, normalize-ederek-sıralar).
- **KAYBEDEN (kaldırılan/delege edilen kopyalar):**
  - `markdown._norm_sev_tr` + `_norm_sev_en` (~aynı TR/EN normalizasyonu) → normalize_severity'e delege.
  - `markdown._sev_rank` → severity_rank'e delege. `markdown` render_risk_matrix yerel `_SEV_ORDER` haritası → kaldırıldı.
  - `html_dashboard` İKİ ayrı yerel `{Critical:4..Info:0}` haritası (`_sev_ranks` satır 323 + `_SEV_ORDER` satır 636) →
    severity_rank() çağrısına indirildi.
- **AKTARILAN (ADIM 2):** TR varyant supersetı (`düsük`/`düşük`/`dusuk`→Low, `kritik`/`yüksek`/`orta`/`bilgi` …)
  canonical normalize'a toplandı (markdown'ın iki normalize fonksiyonunun birleşimi).
- **🐞 LATENT BUG DÜZELTİLDİ (dedup yan-ürünü):** `markdown._sev_rank` büyük-harf normalize çıktısını ("Critical")
  küçük-harf anahtarlı haritada arıyordu → **her severity için DAİMA 0** döndürüyordu. Sonuç: markdown dedup
  severity-escalation (aynı bulgu farklı bucket'ta Low+High → High'a yükseltme) ve severity-sıralaması fiilen
  çalışmıyordu. severity_rank'e delege ile düzeldi (render smoke: Low+High duplike → "High" gösteriliyor).
- **DAVRANIŞ:** normalize/html-rank BİREBİR korundu (13/13 severity vakası eşleşti); yalnız markdown'ın bozuk
  _sev_rank'ı DÜZELDİ (kasıtlı, doğru davranış). pdf/html severity RENK paletleri FARKLI (#dc3545 vs #da3633) →
  kasıtlı ayrı tasarım, tekrar değil, KORUNDU.
- **Doğrulama:** pyflakes temiz · severity eşdeğerlik 13/13 · markdown+html render crash'siz (911/58199 char) ·
  test_reporting + integration 31 passed · benchmark TP=5 FP=0 Recall=100%. PROJECT_MAP reporters/__init__ güncellendi.
- **Commit:** 422491a3f

### T11 HARİTA + KAPANIŞ
- **finding extraction/dedup — FARKLI YAKLAŞIM, KORUNDU:** `markdown._coerce_final` (results["final"] veya generic
  merge) ↔ `markdown._dedupe_findings` (gelişmiş merge: payload/evidence/poc birleştirme) ↔ `pdf._flatten_findings`
  (hardcoded bucket listesi + basit seen-set) ↔ html_dashboard inline. Farklı sofistikelik/amaç, format-özel.
- **severity RENK/İKON — FORMAT-ÖZEL, KORUNDU:** `markdown._SEV_ICON` (emoji) ↔ `pdf._severity_color` (#dc3545…) ↔
  `html_dashboard` renk (#da3633…). Her format kendi sunumu; renkler bilinçli farklı palet.
- **pdf — kendi _count_by_severity/_render:** PDF-özel (reportlab/weasyprint + j2 template), ayrı sorumluluk.

**T11 SONUÇ:** 1 gerçek konsolidasyon (#11 severity normalize/rank 6 kopya→tek kaynak reporters/__init__,
+ latent markdown._sev_rank daima-0 bug'ı düzeltildi). finding-extraction (farklı yaklaşım) + severity renk/ikon
(format-özel) = tekrar DEĞİL, KORUNDU. Benchmark FP=0/Recall=100%, 31 test. **T11 TAMAM.** ➜ Sıradaki: T12 (cli) /
T13 (db+api) / T14 (root websecure/*.py) / T15 (kod-dışı+mutabakat) ya da batch-FLAG (T3-encoding/TLS/JWT/LFI).

---

## ═══ T12 (cli/ — 10 dosya) ═══

> Kapsam: __init__, autocomplete, commands, diff, queue_manager, scheduler, tui, web_ui, webhook, wizard (Madde 4).

### [T12][Madde 4] #12 — _make_websecure_runner: 2 birebir kopya → tek kaynak (commands)
- **KAZANAN (yeni tek kaynak):** `cli/commands.py:make_websecure_runner(log_label="CLI")` — `python -m websecure
  <target>` subprocess runner factory. commands.py modül-yükünde yalnız stdlib import eder (cli alt-modülleri lazy) →
  cycle-güvenli home. (`cli/__init__` re-export hub olduğu için home OLAMAZDI — scheduler/queue'yu import ediyor.)
- **KAYBEDEN (kaldırılan kopyalar):** `scheduler._make_websecure_runner` + `queue_manager._make_websecure_runner` —
  BİREBİR aynıydı (tek fark: log etiketi `[Scheduler]`/`[Queue]` + bir docstring kelimesi). İkisi de lazy import ile
  `make_websecure_runner("Scheduler")` / `("Queue")` çağırır.
- **AKTARILAN (ADIM 2):** log etiketi parametreye (`log_label`) çıkarıldı; gövde birebir korundu.
- **Doğrulama:** pyflakes temiz · cli paketi import OK (cycle yok) · runner uçtan-uca çalıştı (sonuç şekli
  {success,finding_count,duration_s,error}) · benchmark TP=5 FP=0 Recall=100% · integration 13/13.
- **Commit:** 1ff7c8ffd

### [T12][Madde 4] #13 — diff severity rank: yerel kopya → tek kaynak (reporters.severity_rank)
- **KAZANAN (tek kaynak):** `reporters.severity_rank` (T11'de kurulan canonical; normalize-ederek-sıralar).
- **KAYBEDEN (kaldırılan kopya):** `cli/diff.py:_SEVERITY_ORDER` ({Critical:4..Info:0}) — T11'de markdown/html'den
  kaldırılan haritanın aynısı. 8 çağrı yeri (`_SEVERITY_ORDER.get(sev, 0)` skorlama/sıralama/regression) →
  `severity_rank(...)`. `_SEVERITY_EMOJI` (terminal etiketi `[Critical]`) format-özel → KORUNDU.
- **DAVRANIŞ:** birebir aynı — diff'in severity değerleri zaten büyük-harf İngilizce, severity_rank normalize
  ederek aynı rütbeyi döndürür (T11'de 13/13 eşdeğerlik kanıtlandı). cycle yok (reporters/__init__ leaf).
- **Doğrulama:** pyflakes temiz · ScanDiff.compare crash'siz (8 severity_rank yeri yürüdü) · benchmark
  TP=5 FP=0 Recall=100% · integration 13/13.
- **Commit:** b9fdf3101

### T12 HARİTA + KAPANIŞ
- **severity RENK/EMOJİ — FORMAT-ÖZEL, KORUNDU:** `tui._SEVERITY_COLORS`/`_SEVERITY_EMOJI` (Rich renk + emoji) ↔
  `diff._SEVERITY_EMOJI` (`[Critical]` terminal etiketi) ↔ `web_ui` CSS `.sev-Critical`. Her UI kendi sunumu
  (T11 deseni: renk/ikon format-özel). Tekrar değil.
- **run_*_cli — FARKLI ARGÜMAN, KORUNDU:** run_serve_cli/run_scheduler_cli/run_queue_cli/run_diff_cli/
  run_completion_cli/run_wizard_cli — her biri kendi argparse alt-komutunu parse eder, ortak boilerplate değil.
- **webhook ↔ notification (T8) — FARKLI AMAÇ:** `cli/webhook` jenerik outbound HTTP webhook dispatcher (Webhook
  Event/Endpoint, tarama-olayı tetikleme) ↔ `notification.py` belirli servis entegrasyonları (Slack/Jira/Teams/
  PagerDuty). Farklı katman/amaç, KORUNDU.
- **web_ui._DashboardHandler (BaseHTTPRequestHandler) — 3 HTTP-server'dan biri** (api/web_ui/xss_callback, T2'de
  farklı amaç olarak korundu). KORUNDU.

**T12 SONUÇ:** 2 gerçek konsolidasyon (#12 _make_websecure_runner 2→1 commands; #13 diff severity rank →
reporters.severity_rank, T11 canonical'ine bağlandı). severity renk/emoji (format-özel) + run_*_cli (farklı arg) +
webhook (farklı amaç) = tekrar DEĞİL, KORUNDU. Benchmark FP=0/Recall=100%, integration 13/13.
**T12 TAMAM.** ➜ Sıradaki: T13 (db+api) / T14 (root websecure/*.py) / T15 (kod-dışı+mutabakat) ya da batch-FLAG.

---

## ═══ T13 (db/ + api/ — 5 dosya) ═══

> Kapsam: db/(__init__, database, repository) + api/(__init__, server) (Madde 4 = diğer/sistem).
> ADIM 0/1: Katman İYİ DELEGE EDİLMİŞ — db/ tek kanonik kalıcılık katmanı; tüketiciler doğru bağlı:
> `score_tracker._db_record`→ScoreRepository, `correlation_engine.correlate_from_db`→FindingRepository,
> `api/server` 13 endpoint hepsi db.repository + core servislerine (score_tracker/fp_learner/
> plugin_marketplace/correlation_engine) DELEGE eder (reimplement yok). 3 saf intra-katman tekrar bulundu.

### [T13][Madde 4] #14 — api/server serileştirme: 2 birebir static method → tek kaynak (_to_dict)
- **KAZANAN (tek kaynak):** `api/server.py:APIServer._to_dict(obj)` — `dataclasses.asdict` + `vars()` fallback.
- **KAYBEDEN (kaldırılan):** `_scan_to_dict(scan)` + `_finding_to_dict(finding)` — BİREBİR aynıydı (yalnız param
  adı farklı). 6 çağrı yeri (`_list_scans`/`_create_scan`/`_get_scan`/`_scan_findings`/`_scan_score`/
  `_search_findings`) `_to_dict`'e güncellendi.
- **AKTARILAN:** yok (birebir aynı). **SİLİNEN:** `_scan_to_dict`+`_finding_to_dict` gövdeleri (biri kaldı, adı genelleşti).
- **KORUNDU (cross-layer, dokunulmadı):** `correlation_engine._finding_to_dict` (T5/core, aynı trivial stdlib
  idiom AMA core→api ters bağımlılık yaratmamak için ayrı bırakıldı); `chain_reactor._chain_finding_to_dict`
  (asdict değil, ChainFinding'den manuel dict kurar — farklı iş).
- **Doğrulama:** pyflakes 69→69 · `_to_dict` smoke (dataclass Scan/Finding + non-dataclass vars fallback) ·
  api/server'da eski ad kalıntısı yok · benchmark TP=5 FP=0 Recall=100% · integration 13/13.
- **Commit:** 760b9cddb

### [T13][Madde 4] #15 — FindingRepository INSERT: create+bulk_create birebir kopya → tek kaynak
- **KAZANAN (tek kaynak):** `repository.py:FindingRepository._INSERT_SQL` (class-constant, 20-kolon INSERT OR IGNORE)
  + `_insert_params(f)` static helper (Finding→20'li param demeti).
- **KAYBEDEN (kaldırılan kopya):** `create()` ve `bulk_create()` AYNI INSERT SQL string'i + AYNI param tuple
  builder'ı tekrar ediyordu (yalnız girinti farkı, SQL'de anlamsız). İkisi de artık `self._INSERT_SQL,
  self._insert_params(...)` kullanır.
- **AKTARILAN (ADIM 2 — bulk_create'in BENZERSİZ faydası):** `bulk_create` TEK `with connection()` içinde N satır
  (tek transaction/bağlantı) + per-row try/except + warn → KORUNDU. create()'e DELEGE EDİLMEDİ (o N bağlantı
  açıp bulk faydasını yok ederdi). Yalnız SQL+param inşası tekilleşti, döngü/transaction yapısı aynen kaldı.
- **Doğrulama:** pyflakes 69→69 · round-trip smoke (temp db: create+bulk_create+list_by_scan+get; json tags/extra
  roundtrip; severity sıralaması Critical→Info; count_by_severity) BİREBİR · benchmark FP=0/Recall=100% · integration 13/13.
- **Commit:** ff704d0cd

### [T13][Madde 4] #16 — repository __init__: 6 birebir kopya → tek kaynak (_BaseRepository)
- **KAZANAN (yeni tek kaynak):** `repository.py:_BaseRepository` — concrete taban, `__init__(db)→self._db = db or
  get_db()` (T10 `base.ToolIntegration.is_available` concrete-default deseni). SRP=yalnız bağlantı kökü, OCP=alt
  sınıf tabloya-özgü CRUD ekler.
- **KAYBEDEN (kaldırılan kopyalar):** 6 repository (Tenant/Project/Scan/Finding/FPRule/Score) hepsi BİREBİR aynı
  2-satır `__init__`'i tekrar ediyordu → 6 override kaldırıldı, hepsi `_BaseRepository`'den miras alır.
- **AKTARILAN:** yok (birebir aynı boilerplate). FindingRepository'nin `_INSERT_SQL`/`_insert_params`'ı (#15)
  korundu — yalnız `__init__` tabana taşındı.
- **SİLİNEN/YÖNLENDİRİLEN:** Tek kalan `def __init__` = `_BaseRepository`'nin kendisi (tek kaynak). Sınıf adları +
  CRUD imzaları + `__all__` AYNI kaldı → tüm tüketiciler (api/server, score_tracker, fp_learner,
  correlation_engine, cli/commands) DEĞİŞMEDİ.
- **Doğrulama:** pyflakes 69→69 · `def __init__` artık YALNIZ 1 (base) · 6/6 repo `issubclass(_BaseRepository)` +
  tam CRUD round-trip (explicit db + get_db() default branch) BİREBİR · benchmark FP=0/Recall=100% · integration 13/13.
- **Commit:** 499340d29

### T13 HARİTA + KAPANIŞ
- **db/ KANONİK KALICILIK — TEK KAYNAK, KORUNDU:** `database.Database`/`get_db` (bağlantı/şema/migration singleton)
  + `repository` 6 model+6 repo. Paralel persistence YOK: tüketiciler db'ye delege eder.
- **score_tracker / correlation_engine — DOĞRU TÜKETİCİ (db'ye delege), KORUNDU:** `score_tracker._db_record`→
  ScoreRepository, `correlation_engine`→FindingRepository (`correlate_from_db`). Kendi tablosunu kurmaz.
- **fp_learner ÇİFT-YAZIM (JSON + db mirror) — T5'TE KORUNDU, dokunulmadı:** `fp_learner` kendi `FPRule`
  (regex-matching model, from_dict/to_dict/eşleştirme) + `fp_rules.json` öğrenilmiş-kural store'u tutar, AYRICA
  `_db_save` ile `db.FPRuleRepository`'ye opsiyonel mirror'lar. İki `FPRule` FARKLI rol (matching-engine modeli vs
  DB-satırı dataclass'ı) → T5 "fp_learner ayrı kapsam, API-only" kararı geçerli; T13'te birleştirilmez (yüksek risk,
  cross-layer, davranış değişir).
- **api/server HTTP-server — 3'ten biri (T2'de FARKLI AMAÇ), KORUNDU:** `api/server` (REST) ↔ `cli/web_ui`
  (dashboard) ↔ `xss_callback` (blind-XSS yakalama). BaseHTTPRequestHandler ortak ama 3 ayrı amaç.
- **api/server endpoint DB-hata boilerplate — KORUNDU (bilinçli):** ~10 handler `except Exception as exc: return
  _err(503, f"... {exc}")` deseni paylaşır AMA her biri FARKLI etiket ("DB hatası"/"Skor hatası"/"Trend hatası"/
  "FP hatası"/"Plugin hatası"/"Korelasyon hatası"). Decorator'a çıkarmak etiketleri parametrize zorunluluğu + hata
  semantiğini değiştirme riski → düşük değer, dokunulmadı (byte-identical değil).
- **PROJECT_MAP:** api/server.py + db/repository.py entry'leri `classes:[]`/`funcs:[]` zaten boş (dosyaların 12+
  sınıfı hiç listelenmemiş — özet alanlar enumere edilmiyor); `_BaseRepository`/`_to_dict` iç-helper, dosya
  amacı/deps değişmedi → harita güncellemesi gerekmedi (mevcut boş-alan konvansiyonuyla tutarlı).

**T13 SONUÇ:** 3 gerçek konsolidasyon (#14 api/server _to_dict 2→1; #15 FindingRepository INSERT create+bulk
paylaşır; #16 6 repository __init__ → _BaseRepository tabanı). db/ kanonik kalıcılık + doğru-delege tüketiciler +
fp_learner çift-yazım (T5 korundu) + 3 HTTP-server (T2 korundu) + endpoint hata-etiketleri = tekrar DEĞİL, KORUNDU.
Benchmark FP=0/Recall=100%, integration 13/13, pyflakes 69. **T13 TAMAM.** ➜ Sıradaki: T14 (root websecure/*.py:
main/crawler/__init__/__main__/setup) / T15 (kod-dışı+mutabakat) ya da batch-FLAG (T3-encoding/TLS-cert/JWT-forge/LFI-RCE).

---

## ═══ T14 (root websecure/*.py — 5 dosya) ═══

> Kapsam: main, crawler, __init__, __main__, setup (Madde 1 saldırı + 2 tarama + 3 analiz + 4 diğer).
> ADIM 0/1: main.py = ORKESTRATÖR — saldırı/tarama/analizi scanner/phase'lere delege eder (fonksiyonların
> çoğu graceful-degradation fallback stub'ı). Tek gerçek tekrar: crawler'ın kendi sır-tarama pattern kopyası (Madde 3).

### [T14][Madde 3] #17 — crawler sır-tarama: yerel 6-pattern kopya → tek kaynak (js_analyzer)
- **KAZANAN (tek kaynak):** `scanners/js_analyzer.py:_SECRET_PATTERNS` (32→**34**, capture-grup'lu; passive_recon
  [T1#3] + browser_crawler [T4#8] de buna bağlı). crawler artık **4. tüketici**.
- **KAYBEDEN (fallback'e indirildi):** `crawler.py:_JS_KEY_PATTERNS` (6-pattern: AWS/GoogleAPI/Mapbox/StripePub/
  SentryDSN/Algolia) — `harvest_js_keys` artık kanonik `_CANON_SECRET_PATTERNS` kullanır; yerel dict yalnız
  ImportError fallback (passive_recon/browser_crawler precedent'i).
- **AKTARILAN (ADIM 2 merge manifest — crawler'da olup canonical'da OLMAYAN):**
  - **Mapbox Token** (`sk\.[0-9a-zA-Z]{60,}`) + **Sentry DSN** (`https://…@o\d+\.ingest\.sentry\.io/\d+`) → canonical'e
    EKLENDİ (4 tüketici de kazandı). AWS/GoogleAPI canonical'da zaten vardı (birebir).
  - **BİLİNÇLİ PROMOTE EDİLMEDİ (anti-feature, precision koruması):** Algolia `[A-Z0-9]{32}` (herhangi 32-char
    hash/CSS-hash'i yakalar → FP seli) + Stripe `pk_` (publishable = public-by-design, sır DEĞİL). Canonical'a
    taşımak 4 tüketicinin de precision'ını bozardı. Normal yolda (canonical) artık çalışmazlar = precision iyileşmesi.
- **crawler-BENZERSİZ KORUNDU:** `_mask_secret` maskeleme (`val[:6]+…+val[-4:]`) + `{provider,value,source}` çıktı
  şekli (`_finalize_results` `(value,provider)` dedup'u + `results["secrets"]` tüketicisi) + kendi fetch/400/size-guard
  döngüsü. capture-grup çıkarımı eklendi (`m.group(m.lastindex)` → gerçek sır, eskiden `group(0)` tam-eşleşme).
- **SİLİNEN/YÖNLENDİRİLEN:** hiçbir şey silinmedi (yerel 6-pattern bilinçli fallback). Eski kısa provider adları
  ("AWS"/"Algolia") hiçbir yerde literal tüketilmiyordu (grep doğrulandı) → ad değişimi (kanonik "AWS Access Key")
  güvenli. Cycle yok (js_analyzer leaf, yalnız core.reporting). PROJECT_MAP crawler deps += scanners/js_analyzer.
- **Doğrulama:** pyflakes 69→69 · 34-pattern wired smoke (Mapbox/Sentry mevcut, capture-grup+mask+shape) · consumer
  testleri js_analyzer+passive_recon 8/8 + dom_xss 5/5 · benchmark TP=5 FP=0 Recall=100% (sır benchmark-dışı) · integration 13/13.
- **Commit:** 76541f480

### T14 HARİTA + KAPANIŞ (kanıtla korunanlar)
- **main.py ORKESTRATÖR — ZATEN DELEGE, KORUNDU:** `_sig_params`/`_kw_filter` (960-980) try-dalı `core.utils.
  sig_params/kw_filter` kanoniğine delege + except fallback (T1#3 deseni, zaten tekil). `_get_resolve_canonical_base`
  (424) kanonik resolve + fallback. egress helpers `core/egress`'e taşınmış (yorum 995). Saldırı/tarama fazları
  phases/scanner'lara delege; main-içi `def run_mode/graphql_scan/ssrf_xxe_scan…` = import başarısızsa fallback STUB.
- **İKİ `_to_bool` (main.py 869 + 1041) — FARKLI KONTRAT, KORUNDU:** #1 (`_off_enabled`) `enabled/disabled` token'ları
  tanır, `default=False` (feature-flag bool); #2 (`_normalize_webdriver_cfg`) bu token'ları tanımaz, `default=None`
  TRI-STATE (`headless is None` config-cascade'i buna bağlı). Birleştirmek webdriver config-parse davranışını değiştirir
  (T13 endpoint-etiketleri / `_sig_params` fallback deseni: farklı-ama-ikisi-de-geçerli yerel helper).
- **`_build_auth_ctx` (796) — FARKLI KONU, KORUNDU:** statik config→headers/cookies (Bearer/api-key/cookie injection
  ctx-dict'i). T7 auth (auth_flow/auth_manager) = interaktif LOGIN akışı (form/CSRF). Farklı sorumluluk.
- **crawler.py — T4-KORUNANLAR geçerli:** WebCrawler farklı-rol (üretim HTTP+browser, main.py); `_extract_links`/
  `_analyze_content` form-parse = bağlam-özel extraction (analiz kısmını `core.analysis.analyze_form_inputs`
  kanoniğine zaten delege eder); `_parse_sitemap_xml`/`_parse_robots` = crawl-URL keşfi (≠ `passive_recon._check_sitemap`
  SUBDOMAIN çıkarımı, farklı amaç/çıktı). Browser strateji'leri (_Playwright/_UC) crawler-özel.
- **__init__.py / __main__.py / setup.py — KORUNDU:** __init__ = graceful-degradation re-export (her try/except farklı
  modül, desen değil tekrar); __main__ = 4-satır entry; setup.py `full` extras = bireysel extras'ların toplamı
  (standart setuptools konvansiyonu, kasıtlı).

**T14 SONUÇ:** 1 gerçek konsolidasyon (#17 crawler sır-tarama → kanonik js_analyzer, 6→34 pattern, Mapbox+Sentry
aktarıldı, Algolia/pk_ FP-koruması için bilinçli dışlandı). main.py orkestratör (zaten delege) + 2 _to_bool (farklı
kontrat) + _build_auth_ctx (farklı konu) + crawler extraction (T4 bağlam-özel) + root küçük dosyalar = tekrar DEĞİL,
KORUNDU. Benchmark FP=0/Recall=100%, integration 13/13, pyflakes 69. **T14 TAMAM.** ➜ Sıradaki: **T15** (kod-dışı +
MUTABAKAT: wordlists/config/playbooks/templates + PROJECT_MAP tam doğrulama + ölü-referans son tarama + tam test+benchmark)
ya da batch-FLAG (T3-encoding/TLS-cert/JWT-forge/LFI-RCE).

---

## ═══ T15 (kod-dışı + MUTABAKAT — 3 .py + ~33 varlık) — SON FAZ ═══

> Kapsam: scripts/(__init__, preflight_check, validate_config) + wordlists/*.txt(22) + config/profiles(5)/
> playbooks(4)*.yml + reporters/templates/report.html.j2 + config.json/schema (final = mutabakat/doğrulama).
> **SONUÇ: 0 konsolidasyon — doğrulama-only faz** (T2/T9 gibi). Kod-dışı varlık SİLİNMEZ (kırmızı çizgi);
> tekrar eden *yükleyici* kodu zaten T3'te tekilleşti. scripts/*.py = bağımsız CLI, kanonik API tüketir.

### scripts/*.py — TEKRAR DEĞİL (bağımsız CLI, kanonik tüketici), KORUNDU
- **`preflight_check.py`** (standalone tanı CLI `python -m …preflight_check`): 10 entegrasyon wrapper'ının
  `is_available()`'ını çağırır → **kanonik (T10 `base.ToolIntegration.is_available`) tüketir**, reimplement YOK.
  `_check_port` (Tor socket), `_check_playwright` (chromium launch), `_check_wordlists` (varlık kontrolü) =
  tanı-özel. startup.py (T9 install-spec) / tool_manager (T9 farklı konvansiyon) ile FARKLI amaç (tanı vs kurulum).
- **`validate_config.py`** (standalone CI/dev CLI): jsonschema ile config.json↔schema doğrular + opsiyonel --prune.
  Runtime config yükleme (core/utils/config) = farklı amaç (hafif yükleme vs şema-doğrulama). Tekrar değil.
- **`__init__.py`** = boş paket işaretçisi.

### MUTABAKAT (reconciliation) — programatik doğrulama sonuçları
- **PROJECT_MAP ↔ gerçek dosyalar:** `websecure/` altındaki **150 .py'nin TAMAMI** PROJECT_MAP FILES'da mevcut
  (eksik=0). Disk'te olmayan 4 path = `websecure/output/*` (report.md/junit.xml/sarif = runtime-üretilen
  artefakt, temiz ağaçta yok — kasıtlı örnek girdileri, kaynak değil). tests/*, tools/*, root scriptleri repo
  kökünde mevcut. **PROJECT_MAP GÜNCEL — stale kaynak entry'si YOK.**
- **Ölü-referans son tarama (pyflakes):** paket geneli **69 uyarı** (taban ile AYNI) — hepsi kasıtlı re-export
  "imported but unused" (payloads facade, phases/__init__ vb.). **Yeni undefined name = 0** (T1→T15 boyunca artış yok).
- **Kod-dışı varlık bütünlüğü:** 22 wordlist + payload yükleyici (T3 kanonik `core/payloads`) çalışıyor
  (xss=438, sqli=373, lfi=432, cmdi=360 yüklendi); report.html.j2 mevcut; config.json+schema repo kökünde.
  Wordlist orphan denetimi 2026-06-11'de yapıldı (lfi/params/values bağlandı) — yeniden gerekmedi.
- **B3-FLAG orphan'lar (dedup DEĞİL, 6boyut B3'e ait — körü körüne silinmedi, T15'te yalnız mutabakat):**
  `analysis.cloud_hints` (T4), `chain_reactor.analyze_chains` (T2), `utils/system.ensure_dir`+`reporting._ensure_dir`
  (T9) hâlâ flag'li → 6boyut B3 pasının işi. Dedup kapsamında DEĞİL. [[plan_6boyut_tam_denetim]]

### TAM DOĞRULAMA (final gate)
- **Birim+entegrasyon:** `tests/unit` + `tests/integration` → **352 passed**.
- **Benchmark:** TP=5 FP=0 FN=0 TN=5 · **Precision=100% Recall=100% F1=1.00**.
- **pyflakes:** 69 (taban ile aynı, regresyon yok).

**T15 SONUÇ:** 0 konsolidasyon (scripts bağımsız-CLI/kanonik-tüketici; varlık silinmez/yükleyici T3'te tekil).
PROJECT_MAP güncel, ölü-referans yok, varlıklar bütün, 352 test + benchmark FP=0/Recall=100%. **T15 TAMAM.**

---

## ═══════════════ DEDUP PLANI TAMAMLANDI (T1–T15) ═══════════════

**Toplam 17 konsolidasyon** (faz başına ~1-3 gerçek tekrar — kalan "tekrar"lar kanıtla KORUNDU):
- **T1** #1 subfinder→SubfinderIntegration · #2 XSS→ATO→xss.XSSToATOChain · #3 JS-sır→js_analyzer
- **T3** #4 fullwidth→mutator.to_fullwidth
- **T4** #8 browser-sır→js_analyzer · **T5** #7 SQL-hata→SQLErrorDetector
- **T6** #5 token-bucket→rate_controller · **T7** #9 CSRF→auth_flow.extract_csrf · **T8** #6 CVSS-band→cvss
- **T10** #10 is_available→base · **T11** #11 severity-rank→reporters (+latent bug fix)
- **T12** #12 _make_websecure_runner→commands · #13 diff-rank→reporters
- **T13** #14 api/server._to_dict · #15 FindingRepository INSERT · #16 _BaseRepository
- **T14** #17 crawler-sır→js_analyzer (6→34)

**0-konsolidasyon (zaten-tekil, kanıtla korundu):** T2 (exploit-core, DIP), T9 (altyapı, farklı-konvansiyon),
T15 (kod-dışı/scripts). **DESEN:** kod tabanı iyi-katmanlanmış — çoğu "tekrar" facade/adapter/farklı-seviye/
farklı-amaç çıktı; her biri kanıtla korundu, körü körüne hiçbir şey silinmedi (ADIM2 merge manifest her adayda).

**SIRADA-DIŞI kalan (BATCH-FLAG — ayrı, dikkatli, benchmark-validated pas):** T3-encoding-motor yığını
(mutator↔EncodingVariantGenerator↔AdaptiveMutationEngine, 2 paralel canlı, SQLi/XSS recall-kritik), TLS-cert
(scan_tls iki-dosyada), JWT-forge primitifleri, LFI-RCE (benchmark-recall riski). Bunlar bilinçli ERTELENDİ.
**B3-orphan'lar** 6boyut B3'e devredildi. Final durum: 352 test, benchmark FP=0/Recall=100%, pyflakes 69, PROJECT_MAP güncel.
