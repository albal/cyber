FROM python:3.12-slim AS base
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /app

# Scanner CLIs: naabu, httpx, nuclei (ProjectDiscovery, Go binaries)
# Build-time approach: download release binaries to keep the image lean.
ARG NAABU_VERSION=2.3.5
ARG HTTPX_VERSION=1.6.10
ARG NUCLEI_VERSION=3.3.10
ARG TARGETARCH=amd64

RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl unzip libpcap-dev \
      build-essential libffi-dev libssl-dev \
    && rm -rf /var/lib/apt/lists/* \
    && set -eux; \
       cd /tmp; \
       curl -fsSL -o naabu.zip   "https://github.com/projectdiscovery/naabu/releases/download/v${NAABU_VERSION}/naabu_${NAABU_VERSION}_linux_${TARGETARCH}.zip"; \
       curl -fsSL -o httpx.zip   "https://github.com/projectdiscovery/httpx/releases/download/v${HTTPX_VERSION}/httpx_${HTTPX_VERSION}_linux_${TARGETARCH}.zip"; \
       curl -fsSL -o nuclei.zip  "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_${TARGETARCH}.zip"; \
       unzip -j naabu.zip   -d /usr/local/bin/ naabu; \
       unzip -j httpx.zip   -d /usr/local/bin/ httpx; \
       unzip -j nuclei.zip  -d /usr/local/bin/ nuclei; \
       chmod +x /usr/local/bin/naabu /usr/local/bin/httpx /usr/local/bin/nuclei; \
       rm -f /tmp/*.zip

COPY src ./src
COPY pyproject.toml ./
RUN pip install --upgrade pip && pip install -e .[dev]

# Pre-fetch nuclei templates at build time (cached layer)
RUN nuclei -update-templates -silent || true

ENV C_FORCE_ROOT=1
CMD ["celery", "-A", "cyberscan_worker.celery_app:celery_app", "worker", "--loglevel=info", "-Q", "recon,vuln,tls,passive,feeds"]
