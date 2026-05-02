FROM python:3.12-slim AS base
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
      curl ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 10001 cyberscan \
    && useradd  --system --uid 10001 --gid cyberscan --home /app --shell /sbin/nologin cyberscan

COPY src ./src
COPY pyproject.toml ./
COPY alembic.ini ./
COPY alembic ./alembic
RUN pip install --upgrade pip && pip install -e .[dev] \
    && chown -R cyberscan:cyberscan /app

# Numeric USER so Kubernetes' runAsNonRoot guard accepts the image — the
# kubelet refuses to start a container when it can't statically verify
# that the configured user isn't uid 0.
USER 10001:10001

EXPOSE 8000
CMD ["uvicorn", "cyberscan_api.main:app", "--host", "0.0.0.0", "--port", "8000"]
