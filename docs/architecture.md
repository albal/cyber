# Cyberscan — Architecture (v0.1)

## Containers

```
┌──────────┐      ┌──────────┐      ┌──────────┐
│ frontend │ ───► │ backend  │ ───► │ postgres │
│ Next.js  │      │ FastAPI  │      └──────────┘
└──────────┘      └────┬─────┘
                       │ enqueue
                       ▼
                  ┌──────────┐      ┌──────────┐
                  │  redis   │ ───► │  worker  │ ─── naabu/httpx/nuclei
                  │ (Celery) │      │  Celery  │
                  └──────────┘      └────┬─────┘
                                         │ artifacts
                                         ▼
                                    ┌──────────┐
                                    │  minio   │
                                    └──────────┘
```

Five container roles in v0.1:

| Role     | Image                  | Notes                                                  |
| -------- | ---------------------- | ------------------------------------------------------ |
| frontend | `cyberscan-frontend`   | Next.js 15 (App Router), Tailwind                      |
| backend  | `cyberscan-backend`    | FastAPI + SQLAlchemy 2 + Alembic                       |
| db       | `postgres:16-alpine`   | One DB; row-level tenant isolation lands in v0.2       |
| queue    | `redis:7-alpine`       | Celery broker + result backend                         |
| worker   | `cyberscan-worker`     | Bakes scanner CLIs; sslyze runs from an isolated CLI venv |
| (minio)  | `minio:latest`         | Artifact storage (raw scanner output, feed snapshots)  |

`juice-shop` is included in `docker-compose.yml` as a benign in-network test target.

## Scan pipeline (v0.1, single task)

```
POST /api/v1/scans
  └─► verify asset.verification_status == 'verified'
  └─► create scans row (status=queued)
  └─► celery_app.send_task('cyberscan_worker.pipeline.run_scan', queue='recon')
        └─► naabu  (top 1000 ports)
        └─► httpx  (service fingerprint)
        └─► nuclei (sharded by 4 across discovered URLs)
        └─► sslyze CLI subprocess (TLS checks)
        └─► consolidate
              ├─ enrich CVE → cvss/kev (postgres lookup)
              ├─ composite risk score (cvss·45% + epss·25% + kev·15% + exposure·10% + exploit·5%)
              ├─ dedupe (sha256 of asset+template+cves+location)
              ├─ diff vs previous scans of the same asset
              └─ persist findings rows + scan summary
        └─► status=completed
```

Frontend polls `GET /api/v1/scans/{id}` (websocket route exists, used selectively).

## Phased delivery

See [the implementation plan](../../.claude/plans/come-up-with-a-misty-duckling.md) for the full
v0.1 → v1.0 roadmap.
