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
- **Commit:** (aşağıdaki commit)
