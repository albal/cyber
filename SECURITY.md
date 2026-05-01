# Security policy

If you discover a vulnerability in cyberscan, please report it privately
rather than opening a public GitHub issue.

## Reporting

- **Email:** `security@example.com` (replace before deploying)
- **GitHub:** open a [security advisory](https://github.com/albal/cyber/security/advisories/new).

Please include:

1. A description of the issue and where in the code it lives.
2. Steps to reproduce (or a proof-of-concept payload).
3. The version / commit you tested against.

## Response

- We aim to acknowledge reports within **2 business days**.
- We will keep you updated until a fix lands and a release is cut.
- Reporters who want public credit are listed in release notes.

## What's in scope

- Cross-tenant data access (RLS bypass).
- Authentication bypass (JWT, API token, OIDC).
- Authorization bypass (role escalation).
- Server-side template injection / SSRF / RCE in the API or worker.
- Secret leakage (audit-log export, error messages, response bodies).

## What's out of scope

- Findings produced *by* a scan (scanners produce data; that data is the product).
- Deployments using the development defaults (`dev-secret-change-me`,
  `admin@example.com / admin`, `CORS_ORIGINS=*`).
- The vulnerable test targets (juice-shop, DVWA) bundled in compose for
  local testing.
