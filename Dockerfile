# ============================================================
# WebSecure — Multi-stage Docker image
# Tüm dış araçlar dahil: nuclei, httpx, ffuf, nmap, sqlmap…
# ============================================================
# Build:  docker build -t websecure .
# Run:    docker run --rm websecure scan --target https://target.com --profile cicd
# Shell:  docker run --rm -it websecure bash
# ============================================================

# ---- Stage 1: Go araçlarını indir ---------------------------
FROM golang:1.22-alpine AS go-builder

RUN apk add --no-cache git curl unzip

WORKDIR /tools

# ProjectDiscovery araçları (tek go install çağrısı)
RUN go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest      && \
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest            && \
    go install -v github.com/projectdiscovery/katana/cmd/katana@latest          && \
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest

# Diğer Go araçları
RUN go install -v github.com/ffuf/ffuf/v2@latest  && \
    go install -v github.com/hahwul/dalfox/v2@latest

# ---- Stage 2: Runtime image ---------------------------------
FROM python:3.11-slim

LABEL maintainer="WebSecure" \
      description="Cross-platform web security scanner" \
      version="2.0.4"

# Sistem paketleri: nmap + feroxbuster (apt) + sqlmap
RUN apt-get update && apt-get install -y --no-install-recommends \
        nmap \
        curl \
        git \
        wget \
        unzip \
        chromium \
        chromium-driver \
    && rm -rf /var/lib/apt/lists/*

# Go binary'lerini kopyala
COPY --from=go-builder /root/go/bin/ /usr/local/bin/

# feroxbuster — GitHub releases'tan (apt sürümü eski)
RUN FEROX_URL=$(curl -s https://api.github.com/repos/epi052/feroxbuster/releases/latest \
        | grep browser_download_url \
        | grep linux.*musl.*tar.gz \
        | grep -v sha256 \
        | head -1 \
        | cut -d '"' -f 4) && \
    curl -sSL "$FEROX_URL" | tar -xz -C /usr/local/bin/ feroxbuster && \
    chmod +x /usr/local/bin/feroxbuster || echo "[!] feroxbuster indirilemedi, devam ediliyor"

# sqlmap (Python, Git clone)
RUN git clone --depth 1 https://github.com/sqlmapproject/sqlmap /opt/sqlmap && \
    ln -s /opt/sqlmap/sqlmap.py /usr/local/bin/sqlmap

# Nuclei templates
RUN nuclei -update-templates -silent || true

# Python bağımlılıkları
WORKDIR /app
COPY websecure/setup.py ./
RUN pip install --no-cache-dir \
        requests \
        beautifulsoup4 \
        lxml \
        tldextract \
        cryptography \
        pyOpenSSL \
        sslyze \
        jinja2 \
        cvss \
        pyyaml \
        rich \
        playwright && \
    playwright install chromium --with-deps && \
    pip install --no-cache-dir curl_cffi || true

# WebSecure kaynak kodu
COPY websecure/ /app/websecure/
ENV PYTHONPATH=/app

# Chromium path — Playwright için
ENV PLAYWRIGHT_BROWSERS_PATH=/ms-playwright
RUN playwright install chromium || true

# Sağlıklı başlangıç kontrolü
HEALTHCHECK --interval=30s --timeout=5s CMD python -c "import websecure; print('ok')" || exit 1

ENTRYPOINT ["python", "-m", "websecure"]
CMD ["--help"]
