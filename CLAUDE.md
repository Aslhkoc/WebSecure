# WebSecure — Claude Kuralları

## Geliştirme Kuralları (Her Zaman Geçerli)

1. **Sürekli iyileştirme** — Her değişiklik mevcut kodu daha iyi hale getirmeli
2. **SOLID prensipleri** — Single Responsibility, Open/Closed, Liskov, Interface Segregation, Dependency Inversion
3. **OOP yapısı** — BaseScanner abstract interface, scanner sınıfları bu interface'i implement etmeli
4. **Bug-free, robust sistem** — Hata yönetimi eksiksiz olmalı, edge case'ler düşünülmeli
5. **Yeni dosya açma** — Mevcut dosyalar üzerinde çalış, gereksiz yere yeni dosya oluşturma

## Git / Push Kuralları

- **Her değişikten sonra direkt push yap** — silme, ekleme, geliştirme, bug fix fark etmez
- Önce `master` branch'ine merge et (worktree'deysen ana repoya git)
- Sonra `git push origin master`
- Kullanıcı `git pull` ile çeker, PR bekleme
