# WebSecure — Claude Kuralları

## Geliştirme Kuralları (Her Zaman Geçerli)

1. **Sürekli iyileştirme** — Her değişiklik mevcut kodu daha iyi hale getirmeli
2. **SOLID prensipleri** — Single Responsibility, Open/Closed, Liskov, Interface Segregation, Dependency Inversion
3. **OOP yapısı** — BaseScanner abstract interface, scanner sınıfları bu interface'i implement etmeli
4. **Bug-free, robust sistem** — Hata yönetimi eksiksiz olmalı, edge case'ler düşünülmeli
5. **Yeni dosya açma** — Mevcut dosyalar üzerinde çalış, gereksiz yere yeni dosya oluşturma

## Git / Push Kuralları

- **Her değişiklikten sonra otomatik olarak commit et ve push yap** — kullanıcının hatırlatmasına gerek yok
- Worktree'deysen: ana repoya (`C:\Users\Acer\PycharmProjects\WebSecure`) geç, `master`'a merge et, `git push origin master`
- Silme, ekleme, geliştirme, bug fix, refactor — her türlü değişiklik push edilmeli
- PR açma, onay bekleme — direkt `master`'a push
- Kullanıcının hiçbir git komutu çalıştırmasına gerek kalmamalı
