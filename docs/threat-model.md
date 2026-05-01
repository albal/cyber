# Threat model

This document captures the assets we protect, the actors we defend against,
and the controls in place. It's deliberately scoped to v1.0 — capabilities
that don't yet exist (e.g. SAML SSO, secrets-vault integration) are listed
under **Out of scope** so reviewers see the gap explicitly.

## In-scope assets

| Asset                         | Why it matters |
| ----------------------------- | -------------- |
| Scan findings (CVE list)      | Discloses customers' vulnerable surface; high-value to attackers. |
| Vulnerability feeds (CVE/KEV/EPSS/OSV) | Public data — integrity matters more than confidentiality. |
| Asset ownership tokens        | Possession proves a customer owns a target; theft enables unauthorized scanning. |
| Notification webhooks         | Slack / Teams URLs are bearer-secret. |
| API tokens                    | `cyb_*` long-lived bearer tokens for CI/CD; equivalent to a session JWT. |
| Audit log                     | Required for SOC2 evidence; tampering hides attacker actions. |

## Actors

- **External attacker** — anonymous, untrusted. Default-deny.
- **Tenant user** — authenticated, scoped to one tenant via JWT/OIDC/API token.
  Roles (lowest → highest): `viewer` < `analyst` < `admin` < `owner`.
- **Cross-tenant attacker** — authenticated user attempting to read or write
  another tenant's data. Defended by Postgres RLS (`FORCE ROW LEVEL SECURITY`)
  combined with the `app.tenant_id` session GUC.
- **Operator / on-call** — has cluster admin; fully trusted. Database owner
  bypasses RLS only when no GUC is set (migrations, seed).

## Trust boundaries

```
[ Internet ] ──► [ Ingress / TLS ] ──► [ frontend ] ──► [ backend ]
                                                            │
                            ┌───────────── enqueue ─────────┤
                            ▼                               │
                     [ redis (broker) ]                     │
                            │                               ▼
                            ▼                          [ postgres ]
                    [ worker pools ]                        ▲
                            │                               │
                            └────── update findings ────────┘
                            │
                            ▼
                  [ scan target ]    (untrusted destination)
```

Every arrow except `worker → scan target` is in-cluster. Worker → target is
the one **outbound** flow to untrusted networks.

## Controls

### Authentication
- Local JWT for browser sessions; bcrypt-hashed passwords.
- API tokens are SHA-256-hashed at rest; plaintext shown once.
- OIDC (optional): JWTs from `OIDC_ISSUER` are verified via JWKS;
  users are auto-provisioned into the `OIDC_DEFAULT_TENANT` tenant.

### Authorization
- Roles enforced via `require_role()` on write endpoints.
- `viewer` cannot create assets, scans, channels, or tokens.
- `analyst` and above can verify, scan, and edit schedules.
- `admin` is required for tokens and notification channel CRUD.
- `owner` is reserved for the seeded admin (and any role-claim'd OIDC user).

### Tenant isolation
- Every tenant-scoped table (assets, scans, findings, audit_log,
  notification_channels, users, api_tokens) carries `tenant_id` (FK
  to `tenants.id`, NOT NULL).
- All have `ROW LEVEL SECURITY` **forced** (migration 0004) so the policy
  applies even to the table owner.
- Policy: `tenant_id = current_setting('app.tenant_id')` OR GUC unset
  (migration / seed mode). The auth dependency pins the GUC per request via
  `set_config('app.tenant_id', :tid, true)` (transaction-scoped).

### Asset-ownership verification
- Three methods: `.well-known/cyberscan-<token>.txt`, DNS TXT, HTTP header.
- Tokens are 24-byte URL-safe random.
- **Verification expires after 90 days** (warned at 75; blocking at 90).
- **Intrusive scans require re-verification within the last 7 days.**

### Active-scan gating
- Default scans use Nuclei medium-severity-and-up + ZAP baseline (passive).
- `intrusive=true` lifts the severity floor and runs `zap-full-scan.py`
  (active spider + active scan). Backend rejects the request unless
  `verified_at >= now() - 7 days`.

### Audit log
- Append-only; no UPDATE/DELETE endpoints.
- Captures: `asset.create`, `asset.verify`, `asset.schedule`, `scan.create`,
  `notification.create`, `notification.delete`, `token.create`,
  `token.revoke`.
- Exposed as paged JSON, streaming CSV, and JSONL for SIEM ingest.

### Secret handling
- Helm chart secret manifest carries DB DSN, Redis DSN, JWT secret, S3 creds,
  SMTP creds.
- For Kubernetes deploys, set `externalSecrets.enabled=true` to mount via
  External Secrets Operator (Vault / cloud KMS).
- `.env` is `.gitignore`d; `.env.example` is the template.

## Out of scope (v1.0)

- **SAML SSO** — only OIDC. Customers needing SAML route via Keycloak as
  an OIDC bridge.
- **Hardware key (FIDO2 / WebAuthn)** — local password + JWT only.
- **Per-tenant Postgres schemas** — single shared schema with RLS. Highly
  regulated tenants would want per-tenant DB or schema separation.
- **WAF in front of `/api/v1/scans`** — recommended for SaaS deployments;
  out of chart scope.
- **Rate limiting** — relies on ingress-nginx `nginx.ingress.kubernetes.io/limit-rps`.
  No application-level token-bucket.
- **Outbound egress allowlist for workers** — workers need to reach
  arbitrary scan targets, so the chart's NetworkPolicy is permissive on
  egress (`{}` in `worker-*`). Customers wanting tighter control should
  edit the policy or run an egress proxy.

## Known residual risks

1. **Webhook URL leakage in the audit log** — the audit log records
   `notification.create` with the channel kind but not the URL. URLs live
   only in `notification_channels.target` which is RLS-scoped. Exporting
   the audit log does not leak webhook URLs.
2. **Scan target SSRF** — the worker fetches `/.well-known/...` on the
   target during verification. If a tenant adds an asset for an internal
   address (`http://kube-api:6443`), the worker would attempt the request.
   Block list is enforced at the `Asset.create` API for `.gov`, `.mil` and
   configurable RFC1918 ranges. **Self-hosted only**: internal targets are
   allowed by default; SaaS deployments should set
   `BLOCK_INTERNAL_TARGETS=true` (TODO for v1.1).
3. **JWT key length** — the bundled `dev-secret-change-me` is shorter than
   PyJWT's recommended HS256 key length. The Helm chart auto-generates a
   long key on first install (`randAlphaNum 48`).

## Where to file issues

`SECURITY.md` (top-level) carries the disclosure address.
