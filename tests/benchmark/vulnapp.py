# -*- coding: utf-8 -*-
"""
WebSecure Benchmark — Yerel Zafiyetli Test Hedefi (ground-truth etiketli)
=========================================================================
Tek dosyalık, BAĞIMLILIKSIZ (yalnız stdlib http.server) bir hedef uygulama.
Her route ya KASITLI ZAFİYETLİ ya da GÜVENLİ (sanitize edilmiş) eşleniktir:

  - Zafiyetli route'lar  → scanner DOĞRU tespit ederse  True Positive (TP)
  - Güvenli  route'lar   → scanner YANLIŞ tespit ederse False Positive (FP)
  - Zafiyetli ama tespit edilmeyen → False Negative (FN)

Böylece precision/recall/F1 ölçülebilir. ground_truth.py etiketleri tutar.

ÖNEMLİ: Bu uygulama bilerek zafiyetlidir; YALNIZCA localhost'ta benchmark
amacıyla çalıştırılır. İnternete açılmamalıdır.

Kullanım:
    from tests.benchmark.vulnapp import start_vulnapp
    httpd, base = start_vulnapp()       # 127.0.0.1:<ephemeral>
    ...  # tara
    httpd.shutdown()
"""
from __future__ import annotations

import html
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

# ── Zafiyet tetikleyici sabit imzalar (scanner detektörleriyle birebir uyumlu) ──
_MARIADB_SQL_ERROR = (
    "You have an error in your SQL syntax; check the manual that corresponds "
    "to your MariaDB server version for the right syntax to use near"
)
_ETC_PASSWD = (
    "root:x:0:0:root:/root:/bin/bash\n"
    "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
    "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
)
_CMD_ID_OUTPUT = "uid=0(root) gid=0(root) groups=0(root)"
_DOTENV = (
    "APP_ENV=production\n"
    "DB_HOST=10.0.0.5\n"
    "DB_PASSWORD=S3cr3tP@ssw0rd!\n"
    "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
    "STRIPE_SECRET_KEY=sk_live_51H8xQeEXAMPLEsecretKEY1234567890abcd\n"
)


def _sqli_marks(v: str) -> bool:
    """Girişte SQL-bozucu karakter var mı (kasıtlı zafiyetli yol)."""
    return any(ch in v for ch in ("'", '"', "\\", ";"))


def _cmdi_marks(v: str) -> bool:
    """Girişte komut-ayraç / komut anahtarı var mı."""
    low = v.lower()
    return any(s in v for s in (";", "|", "&", "`", "$(")) or any(
        s in low for s in ("id", "whoami", "sleep", "cat ", "uname")
    )


def _lfi_marks(v: str) -> bool:
    return ("../" in v) or ("..\\" in v) or ("etc/passwd" in v) or ("%2e%2e" in v.lower())


class _VulnHandler(BaseHTTPRequestHandler):
    server_version = "VulnApp/1.0"

    # Gürültüyü sustur (benchmark çıktısını kirletmesin)
    def log_message(self, *args, **kwargs):  # noqa: D401
        return

    # ---- yardımcılar ----
    def _send(self, code: int, body: str, ctype: str = "text/html; charset=utf-8",
              extra_headers: dict | None = None):
        data = body.encode("utf-8", errors="replace")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        # NOT: Güvenlik header'ları BİLEREK eksik (header scanner TP için).
        for k, v in (extra_headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def _qs(self, parsed):
        return {k: (v[0] if v else "") for k, v in parse_qs(parsed.query).items()}

    # ---- routing ----
    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"
        q = self._qs(parsed)

        # --- Ana sayfa: crawler için link havuzu ---
        if path == "/":
            links = [
                "/product?id=1", "/search?q=test", "/redirect?url=/home",
                "/download?file=readme.txt", "/ping?host=127.0.0.1",
                "/safe_product?id=1", "/safe_search?q=test",
                "/api/users", "/.env",
            ]
            body = "<html><body><h1>VulnApp</h1>" + "".join(
                f'<a href="{l}">{l}</a><br>' for l in links
            ) + "</body></html>"
            return self._send(200, body)

        # === SQLi — ZAFİYETLİ: girişteki tırnak DB hatasını sızdırır ===
        if path == "/product":
            v = q.get("id", "")
            if _sqli_marks(v):
                return self._send(
                    500,
                    f"<html><body><h2>Database Error</h2><pre>{_MARIADB_SQL_ERROR} "
                    f"'{html.escape(v)}'</pre></body></html>",
                )
            return self._send(200, f"<html><body>Product #{html.escape(v)}</body></html>")

        # === SQLi — GÜVENLİ: parametrize, asla hata sızdırmaz (FP ölçümü) ===
        if path == "/safe_product":
            v = q.get("id", "")
            if not v.isdigit():
                return self._send(400, "<html><body>Invalid product id</body></html>")
            return self._send(200, f"<html><body>Product #{html.escape(v)}</body></html>")

        # === Reflected XSS — ZAFİYETLİ: giriş HTML'e ham yansıtılır ===
        if path == "/search":
            v = q.get("q", "")
            return self._send(
                200, f"<html><body>You searched for: {v}</body></html>"
            )

        # === XSS — GÜVENLİ: html.escape ile kaçışlanır (FP ölçümü) ===
        if path == "/safe_search":
            v = q.get("q", "")
            return self._send(
                200, f"<html><body>You searched for: {html.escape(v)}</body></html>"
            )

        # === Open Redirect — ZAFİYETLİ: url param Location'a ham yazılır ===
        if path == "/redirect":
            v = q.get("url", "/")
            return self._send(302, "Redirecting...", extra_headers={"Location": v})

        # === Open Redirect — GÜVENLİ: KATI site-içi relatif yol whitelist'i ===
        # Yalnız `^/[harf/rakam/_/-]*$` kabul; `//`, `/\`, `%2f`, `\`, `:` gibi
        # tüm bilinen bypass vektörlerini reddeder (gerçekten güvenli referans).
        if path == "/safe_redirect":
            import re as _re
            v = q.get("url", "/")
            if _re.fullmatch(r"/[A-Za-z0-9_/-]*", v) and not v.startswith("//"):
                return self._send(302, "Redirecting...", extra_headers={"Location": v})
            return self._send(400, "<html><body>Blocked external redirect</body></html>")

        # === LFI / Path Traversal — ZAFİYETLİ: traversal'da passwd döner ===
        if path == "/download":
            v = q.get("file", "")
            if _lfi_marks(v):
                return self._send(200, _ETC_PASSWD, ctype="text/plain; charset=utf-8")
            return self._send(200, f"Contents of {html.escape(v)}",
                              ctype="text/plain; charset=utf-8")

        # === LFI — GÜVENLİ: yalnız dosya adı (traversal stripped) ===
        if path == "/safe_download":
            v = q.get("file", "")
            base = v.replace("\\", "/").split("/")[-1]
            return self._send(200, f"Contents of {html.escape(base)}",
                              ctype="text/plain; charset=utf-8")

        # === Command Injection — ZAFİYETLİ: komut anahtarında çıktı döner ===
        if path == "/ping":
            v = q.get("host", "")
            if _cmdi_marks(v):
                body = (f"PING output for {html.escape(v)}\n{_CMD_ID_OUTPUT}\n"
                        if any(s in v.lower() for s in ("id", "whoami", "uname"))
                        else f"PING {html.escape(v)}: 64 bytes\n{_ETC_PASSWD}")
                return self._send(200, body, ctype="text/plain; charset=utf-8")
            return self._send(200, f"PING {html.escape(v)}: 64 bytes",
                              ctype="text/plain; charset=utf-8")

        # === Command Injection — GÜVENLİ: alfasayısal+nokta dışını reddet ===
        if path == "/safe_ping":
            v = q.get("host", "")
            if all(c.isalnum() or c in ".-" for c in v) and v:
                return self._send(200, f"PING {html.escape(v)}: 64 bytes",
                                  ctype="text/plain; charset=utf-8")
            return self._send(400, "Invalid host")

        # === Info Disclosure — ZAFİYETLİ: .env açıkta ===
        if path == "/.env":
            return self._send(200, _DOTENV, ctype="text/plain; charset=utf-8")

        # === Normal JSON API (recon/crawl yemi; FP ölçümü — vuln değil) ===
        if path == "/api/users":
            return self._send(
                200,
                '{"users":[{"id":1,"name":"alice"},{"id":2,"name":"bob"}]}',
                ctype="application/json",
            )

        return self._send(404, "<html><body>Not Found</body></html>")

    def do_POST(self):
        # Basit login (auth testleri için yer tutucu) — vuln değil
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"
        if path == "/login":
            return self._send(200, '{"status":"ok"}', ctype="application/json")
        return self.do_GET()


def start_vulnapp(host: str = "127.0.0.1", port: int = 0) -> tuple[ThreadingHTTPServer, str]:
    """
    Zafiyetli test hedefini ayrı bir thread'de başlatır.
    Döner: (httpd, base_url). Kapatmak için: httpd.shutdown(); httpd.server_close()
    """
    httpd = ThreadingHTTPServer((host, port), _VulnHandler)
    actual_port = httpd.server_address[1]
    base_url = f"http://{host}:{actual_port}"
    t = threading.Thread(target=httpd.serve_forever, name="vulnapp", daemon=True)
    t.start()
    return httpd, base_url


if __name__ == "__main__":
    import time
    srv, base = start_vulnapp(port=8099)
    print(f"[vulnapp] Çalışıyor: {base}  (Ctrl+C ile durdur)")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        srv.shutdown()
        srv.server_close()
        print("\n[vulnapp] Durdu.")
