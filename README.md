# Cyberscan

Fast, OSS-only web vulnerability scanner with an enterprise-grade UX.

Paste a URL, prove you own it, and get a prioritized list of findings — CVE-enriched, KEV-flagged, with remediation — in minutes.

## v0.1 MVP scope

- Single-tenant; basic auth.
- Scanners: **Naabu** (port discovery), **httpx** (service fingerprint), **Nuclei** (vuln checks).
- Target verification: **HTTP file upload** at `/.well-known/cyberscan-<token>.txt`.
- Findings enriched with **NVD** + **CISA KEV**; composite risk score.
- Frontend: Next.js. Backend: FastAPI. Queue: Redis+Celery. DB: PostgreSQL. Storage: MinIO.
- Local dev: docker-compose with OWASP Juice Shop as a pre-wired test target.

## v0.2 — Enterprise foundations (in progress on `v0.2-enterprise` branch)

- **Multi-tenant**: tenants table; `tenant_id` on assets / scans / findings / audit log; Postgres RLS scoped via `app.tenant_id` GUC.
- **RBAC**: `owner` > `admin` > `analyst` > `viewer`; enforced via `require_role()` on write endpoints.
- **More scanners**: `sslyze` for TLS deep inspection, ZAP baseline (with a built-in fallback header check when ZAP isn't on PATH).
- **EPSS** ingestion + lookup feeds the composite risk score.
- **Notifications**: Email (SMTP) + Slack incoming webhook + MS Teams webhook with per-channel `min_severity` filter.
- **Helm**: per-pool worker deployments (`recon`, `vuln`, `tls`, `passive`, `feeds`).

## Quick start (local)

```bash
make up        # build images, start the stack + juice-shop
make seed      # run migrations + ingest cached NVD/KEV fixtures
make e2e       # run the end-to-end test
open http://localhost:3000
```

Login: `admin@example.com` / `admin` (default seed account).

## Repo layout

See [docs/architecture.md](docs/architecture.md). Top-level:

- `apps/frontend` — Next.js 15
- `apps/backend` — FastAPI
- `apps/worker` — Celery workers wrapping scanner CLIs
- `packages/risk-engine` — scoring + dedupe + diffing
- `packages/compliance-map` — CWE → OWASP/PCI/NIST/CIS lookup
- `charts/cyberscan` — Helm umbrella chart (stub at v0.1)
- `deploy/kind` — k8s-on-kind bootstrap
- `tests/{integration,e2e,fixtures}`

## Roadmap

Phased delivery is documented in [docs/architecture.md](docs/architecture.md).

## License

MIT — see [LICENSE](LICENSE).
