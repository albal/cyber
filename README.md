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
