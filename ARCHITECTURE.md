# Cyberscan — Architecture

Cyberscan is a fast, OSS-only web vulnerability scanner with an enterprise-grade
UX. A user pastes a URL, proves they own the target, and receives a prioritized,
CVE-enriched list of findings — KEV-flagged, EPSS-weighted, with remediation —
in minutes.

This document explains how the system is put together and how a scan flows
through it end to end. For the security-focused view (trust boundaries, controls,
residual risks) see [`docs/threat-model.md`](docs/threat-model.md); for the
condensed container diagram see [`docs/architecture.md`](docs/architecture.md).

---

## 1. High-level overview

Cyberscan is a small set of cooperating services built around an asynchronous
job queue. The browser talks to a thin API; the API persists state and enqueues
work; a fleet of workers run the actual scanner CLIs against the target and write
findings back.

```
        ┌──────────┐      ┌──────────┐      ┌──────────┐
        │ frontend │ ───► │ backend  │ ───► │ postgres │
        │ Next.js  │ ◄─── │ FastAPI  │ ◄─── │  (RLS)   │
        └──────────┘      └────┬─────┘      └────▲─────┘
                               │ enqueue          │ findings
                               ▼                  │
                          ┌──────────┐      ┌─────┴────┐
                          │  redis   │ ───► │  workers │ ─── naabu / httpx /
                          │ (Celery) │      │  Celery  │     katana / nuclei /
                          └──────────┘      └────┬─────┘     sslyze / ZAP
                               ▲                 │ artifacts
              ┌──────────┐     │ beat            ▼
              │   beat   │ ────┘            ┌──────────┐
              │ schedule │                  │  minio   │
              └──────────┘                  └──────────┘
                                                 │
                                                 ▼
                                          ┌──────────┐
                                          │  target  │  (untrusted)
                                          └──────────┘
```

The design goal is a clean split between the **synchronous control plane**
(frontend + backend + Postgres), which is always fast and never blocks on a
scan, and the **asynchronous data plane** (Redis + workers), which does the slow,
network-bound scanning work and reports progress back through the database.

---

## 2. Components

| Component  | Tech                                   | Responsibility |
| ---------- | -------------------------------------- | -------------- |
| `frontend` | Next.js 15 (App Router), Tailwind      | UI for assets, verification, scans, findings, tokens. Proxies `/api/*` to the backend. |
| `backend`  | FastAPI + SQLAlchemy 2 + Alembic       | REST API, auth, RBAC, tenant isolation, enqueues scans, serves findings/reports. |
| `db`       | PostgreSQL 16                          | Single source of truth. Tenant data isolated with Row-Level Security. |
| `queue`    | Redis 7                                | Celery broker + result backend. |
| `worker`   | Celery + scanner CLIs                  | Runs the scan pipeline: recon → crawl → vuln → TLS → passive → consolidate. |
| `beat`     | Celery Beat                            | Per-minute tick that dispatches scheduled scans and refreshes feeds. |
| `minio`    | MinIO (S3-compatible)                  | Artifact storage: raw scanner output, feed snapshots. |
| `juice-shop` / `verify-target` | OWASP Juice Shop behind nginx | Local-dev benign scan target with `.well-known` verification support. |

Source layout (see [`README.md`](README.md) for the full map):

- `apps/frontend` — Next.js client (`src/app/*` routes, `src/lib/api.ts`).
- `apps/backend` — FastAPI app (`cyberscan_api`): `routers/`, `core/`,
  `services/`, `models/`, Alembic `alembic/versions/`.
- `apps/worker` — Celery app (`cyberscan_worker`): `pipeline.py`, `recon/`,
  `vuln/`, `tls/`, `passive/`, `feeds/`, `scheduler.py`, `notify/`.
- `packages/risk-engine` — shared scoring/dedupe/diff helpers (mirrored by the
  worker's `risk.py`).
- `packages/compliance-map` — CWE → OWASP/PCI/NIST/CIS lookup.
- `charts/cyberscan` — Helm umbrella chart for Kubernetes.
- `deploy/` — kind bootstrap and local verify-target config.

### Backend internals

The FastAPI app (`apps/backend/src/cyberscan_api/main.py`) wires:

- **Security-headers middleware** — sets `X-Content-Type-Options`,
  `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `Permissions-Policy`,
  and conditional HSTS on HTTPS requests.
- **CORS middleware** — origins from `CORS_ORIGINS`; credentials disabled only in
  the wildcard case.
- **Routers** — `auth`, `assets`, `scans`, `notifications`, `tokens`, `audit`.
- **`/healthz`** — liveness probe.

Core helpers live under `core/` (config, DB session/GUC handling, JWT/security,
Celery client, Fernet crypto, role checks) and request-scoped logic under
`services/` (auth dependency, ownership verification, audit logging, OIDC,
client-IP extraction, rate limiting, PDF report rendering).

### Worker internals

The Celery app (`apps/worker/.../celery_app.py`) registers three task modules —
`pipeline`, `feeds.tasks`, `scheduler` — and runs with `task_acks_late`,
`task_reject_on_worker_lost`, and `worker_prefetch_multiplier=1` so a crashed
worker re-queues its job and a single long scan never starves a prefetch buffer.

Scanner wrappers each shell out to a CLI and normalize its output into typed
hits:

- `recon/naabu.py` — port discovery (top 1000 ports).
- `recon/httpx_probe.py` — service / tech fingerprint.
- `recon/subfinder.py` — optional subdomain enumeration.
- `recon/katana.py` — recursive crawl (links, JS bundles, source maps,
  `robots.txt`, `sitemap.xml`).
- `vuln/nuclei.py` — templated vuln checks, sharded across discovered URLs.
- `tls/sslyze_runner.py` — TLS deep inspection (runs from an isolated CLI venv).
- `passive/zap_baseline.py` — ZAP baseline / built-in header-check fallback.

---

## 3. The scan pipeline

A scan is a single Celery task — `cyberscan_worker.pipeline.run_scan`,
bound to the `recon` queue — that orchestrates every stage in order and writes
progress to the `scans` row as it goes. The frontend polls
`GET /api/v1/scans/{id}` to render the live progress bar (a WebSocket route also
exists and is used selectively).

```
POST /api/v1/scans
  └─► assert asset.verification_status == 'verified'
  └─► (intrusive=true ⇒ assert verified_at >= now() - 7 days)
  └─► insert scans row (status=queued)
  └─► celery send_task('pipeline.run_scan', queue='recon')

run_scan(scan_id, tenant_id, intrusive):
  set status=running, stage=recon
  ├─ Stage 0  subfinder      (opt-in)  enumerate subdomains → extra seeds
  ├─ Stage 1  naabu          port discovery (top 1000)
  │           httpx          service / tech fingerprint
  ├─ Stage 1b katana         crawl: links + JS bundles + sitemaps + robots
  ├─ Stage 2a nuclei         sharded across crawled URLs (tags or -as)
  ├─ Stage 2b sslyze         TLS checks on each TLS endpoint
  ├─ Stage 2c ZAP baseline   passive (or zap-full-scan.py when intrusive)
  └─ Stage 3  consolidate
        ├─ enrich CVE → CVSS / KEV / EPSS  (Postgres feed lookup)
        ├─ composite risk score
        ├─ dedupe (sha256 of asset+template+cves+location)
        ├─ diff vs the asset's previous scan (new / unchanged / fixed)
        ├─ map CWE → OWASP/PCI/NIST/CIS compliance tags
        └─ persist findings rows + scan summary
  set status=completed
```

### Stage details

- **Recon** (`naabu` → `httpx`) discovers open ports and fingerprints the
  services running on them, falling back to the raw `target_url` if nothing is
  found.
- **Crawl** (`katana`) is the highest-leverage stage: without it Nuclei only ever
  sees the homepage, so on single-page apps it never reaches `/api/*`, `/rest/*`,
  `/admin`, etc. Crawl depth/limits come from settings
  (`CRAWL_DEPTH`, `CRAWL_MAX_URLS`, `CRAWL_TIMEOUT_S`), with a deeper depth for
  intrusive scans.
- **Vuln** (`nuclei`) is sharded across the crawled URLs (`NUCLEI_SHARDS`) for
  parallelism. A non-intrusive scan runs a fixed tag set
  (`cve, exposure, misconfig, tech, exposed-panel, default-login, exposed-tokens,
  js, config`); an intrusive scan instead passes `-as` (automatic scan) to enable
  fuzz/brute/DAST templates.
- **TLS** (`sslyze`) inspects each TLS endpoint (443/8443) for weak protocols,
  Heartbleed, ROBOT, weak DH, missing HSTS, etc.
- **Passive** (`zap_baseline`) runs the ZAP baseline (or `zap-full-scan.py` when
  intrusive), with a built-in header/cookie-flag fallback when ZAP isn't on the
  PATH. Fan-out is capped to keep within the ~15-minute SLA.
- **Consolidate** enriches, scores, dedupes, diffs, tags, and persists.

Each stage calls `_check_cancelled()` so a user-requested cancel takes effect
promptly, and `_set_state()` to advance `stage`/`progress` for live polling.
Authenticated scans decrypt the asset's stored credential and attach it to the
crawler and Nuclei requests so logged-in routes are explored too.

### Authenticated scans

Per-asset credentials (cookie / bearer / basic / custom header) are encrypted at
rest with Fernet (HKDF-SHA256 derived from `API_SECRET_KEY`). The worker decrypts
them in-process right before invoking a scanner, attaches them to every request,
and never logs or returns the plaintext. A decryption failure (e.g. after
`API_SECRET_KEY` rotation) falls back to anonymous scanning with a log line and is
never fatal.

---

## 4. Risk scoring, dedupe, and diffing

Findings are normalized into a single composite risk score (0–100) so a CVE, a
TLS weakness, and a missing header can be ranked on one axis (`risk.py` /
`packages/risk-engine`):

```
score = 0.45·cvss_norm     (CVSS ×10, 0..100)
      + 0.25·epss_pct       (EPSS percentile ×100)
      + 0.15·kev_bonus      (100 if on CISA KEV)
      + 0.10·exposure_factor (internet 100 / auth 40 / internal 10)
      + 0.05·exploit_bonus   (weaponized 100 / public 70 / none 0)
```

Severity bands: **Critical ≥ 85, High ≥ 70, Medium ≥ 40, Low ≥ 15, else Info**.
Any KEV finding is floored to at least **High**.

- **Dedupe** — each finding gets a stable `sha256(asset + template + sorted CVEs
  + location)` key, so re-scanning the same asset updates rather than multiplies
  findings.
- **Diff** — comparing the current scan's keys against the asset's previous scan
  labels each finding `new`, `unchanged`, or `fixed`, which drives the
  "what changed since last scan" view and severity-filtered notifications.
- **Compliance mapping** — CWE IDs map to OWASP/PCI/NIST/CIS tags via
  `packages/compliance-map`.

---

## 5. Data model

All domain tables live in Postgres (`apps/backend/.../models/tables.py`); every
tenant-scoped table carries a `tenant_id` FK.

| Table                   | Purpose |
| ----------------------- | ------- |
| `tenants`               | Top-level isolation boundary. |
| `users`                 | Accounts with a `role` (`viewer < analyst < admin < owner`). |
| `assets`                | Scan targets: `target_url`, `hostname`, verification state, schedule cron, subdomain-enum flag. |
| `scans`                 | One run: `status`, `stage`, `progress`, `summary` (JSON), `intrusive`. |
| `findings`              | Enriched results: severity, risk, CVE/CWE IDs, location, remediation, references, compliance tags, diff status. |
| `asset_credentials`     | Fernet-encrypted scan credentials (only `kind`/`label`/timestamp exposed). |
| `notification_channels` | Email/Slack/Teams targets with per-channel `min_severity`. |
| `api_tokens`            | `cyb_*` bearer tokens for CI/CD, SHA-256-hashed at rest. |
| `audit_log`            | Append-only record of state-changing actions. |

Schema is managed with Alembic migrations under `apps/backend/alembic/versions/`
(initial schema, multi-tenancy + feeds, RLS hardening, asset credentials, etc.).

---

## 6. Tenancy and authorization

Cyberscan is multi-tenant on a single shared schema, isolated by **Postgres
Row-Level Security**:

- Every tenant-scoped table has RLS **forced** (applies even to the table owner).
- The policy allows a row when `tenant_id = current_setting('app.tenant_id')`,
  or when the GUC is unset (migration/seed mode).
- The backend's auth dependency pins `app.tenant_id` per request with a
  transaction-scoped `set_config(..., true)`, so a query can never read another
  tenant's rows even if application code has a bug.

**Authentication** supports local JWT sessions (bcrypt passwords), long-lived
`cyb_*` API tokens (SHA-256-hashed, shown once), and optional OIDC (JWTs verified
via JWKS, users auto-provisioned into `OIDC_DEFAULT_TENANT`).

**Authorization** is role-based via `require_role()` on write endpoints:
`viewer` (read-only) < `analyst` (verify/scan/schedule) < `admin` (tokens +
notification channels) < `owner` (seeded / role-claimed).

**Ownership verification** must pass before scanning: a 24-byte token proved via
`.well-known/cyberscan-<token>.txt`, DNS TXT, or an HTTP header. Verification
expires after 90 days, and intrusive scans require re-verification within 7 days.

---

## 7. Scheduling and feeds

Rather than one Celery Beat entry per asset, a single per-minute Beat tick
(`scheduler.dispatch_due_scans`) reads every enabled asset's `schedule_cron`,
fires `run_scan` for those whose cron matches the current minute (deduped via
`last_scheduled_at`), and skips unverified assets. This keeps the scheduler
stateless — assets can be added/edited/removed at runtime without restarting
Beat.

Vulnerability feeds are refreshed by tasks on the `feeds` queue
(`feeds.tasks`): **NVD** (CVSS), **CISA KEV**, **EPSS**, and **OSV**. They can be
driven by Beat or by a Kubernetes CronJob, and run from bundled fixtures in local
dev (`FEEDS_USE_FIXTURES`). The consolidation stage reads these tables to enrich
findings.

---

## 8. Notifications

When a scan completes, `notify/dispatcher.py` pushes results to configured
channels — **Email (SMTP)**, **Slack incoming webhook**, and **MS Teams
webhook** — each filtered by its own `min_severity` so a channel only sees
findings at or above its threshold.

---

## 9. Deployment

### Local development

`docker-compose.yml` brings up the full stack — `db`, `queue` (Redis), `minio`,
`backend`, `worker`, `beat`, `frontend` — plus `juice-shop` and an nginx
`verify-target` that serves `.well-known/cyberscan-*.txt` so ownership
verification works locally. The worker container is granted `NET_RAW`/`NET_ADMIN`
for naabu SYN scans.

```bash
make up     # build images, start the stack + juice-shop
make seed   # run migrations + ingest cached NVD/KEV fixtures
make e2e    # run the end-to-end test
# open http://localhost:3000  (admin@example.com / admin)
```

### Kubernetes

The Helm umbrella chart (`charts/cyberscan`) deploys the same components with
production concerns layered on:

- **Per-pool workers** — separate deployments for the `recon`, `vuln`, `tls`,
  `passive`, and `feeds` queues, so heavy stages scale independently.
- **Autoscaling** — KEDA `ScaledObject`s scale worker pools on Redis queue depth.
- **Networking** — `Ingress` (TLS), and `NetworkPolicy` that keeps every flow
  in-cluster except the worker → scan-target egress.
- **Storage** — Postgres, Redis, MinIO, and a shared read-only PVC for
  Nuclei templates (refreshed by a CronJob).
- **Ops** — migrations Job, DB-backup CronJob, feeds CronJob, `PodDisruptionBudget`s,
  and a Prometheus `ServiceMonitor`.
- **Secrets** — app secret manifest by default, or External Secrets Operator
  (Vault / cloud KMS) when `externalSecrets.enabled=true`.

---

## 10. Request lifecycle (end to end)

1. **Add asset** — user creates an asset; backend stores it with a verification
   token and `pending` status, writing an `audit_log` entry.
2. **Verify ownership** — user publishes the token (file / DNS / header); the
   backend verifies and stamps `verified_at`.
3. **Start scan** — `POST /api/v1/scans` checks verification (and the 7-day
   freshness rule for intrusive), inserts a `queued` scan, and enqueues
   `run_scan` on the `recon` queue.
4. **Run pipeline** — a worker pins the tenant GUC, then runs recon → crawl →
   vuln → TLS → passive, updating `stage`/`progress` throughout.
5. **Consolidate** — findings are enriched from the feed tables, scored, deduped,
   diffed against the previous scan, compliance-tagged, and persisted; the scan
   is marked `completed` with a summary.
6. **Notify & view** — channels above their `min_severity` are notified; the
   user views findings in the UI or exports a PDF report; the audit log records
   the state-changing actions throughout.

---

## 11. Design principles

- **Control plane stays fast** — the API never blocks on a scan; all slow work is
  queued and reported back through the database.
- **Stateless, restart-safe workers** — `task_acks_late` + per-minute scheduling
  mean a crashed worker re-queues its job and Beat needs no per-asset state.
- **Defense in depth for tenancy** — forced Postgres RLS backs up
  application-level checks, so a code bug can't leak cross-tenant data.
- **OSS-only scanners, normalized output** — heterogeneous tools (naabu, httpx,
  katana, nuclei, sslyze, ZAP) are wrapped behind typed interfaces and folded
  into one risk model.
- **Prove ownership before scanning** — verification + intrusive-scan gating keep
  the tool from being pointed at targets the user doesn't control.
