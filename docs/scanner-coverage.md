# Scanner coverage

What cyberscan can and cannot detect, and how to push the numbers higher.

## Pipeline at a glance

```text
naabu (port discovery)
   │
   ▼
httpx (service / tech fingerprint)
   │
   ▼
katana (recursive crawl: links + JS bundles + sitemaps + robots.txt)
   │
   ▼
nuclei (sharded; templates: cve / exposure / misconfig / tech /
                              exposed-panel / default-login / js)
   │
   ▼
sslyze (TLS deep inspection)
   │
   ▼
ZAP baseline (passive)  →  intrusive=true switches to zap-full-scan.py
```

The crawl stage is the single biggest lever. Without it, Nuclei only
sees the homepage URL, which on single-page apps means it never reaches
`/api/*`, `/rest/*`, `/ftp/*`, `/admin`, etc.

## What we find well (passive + non-intrusive)

| Category | Caught by | Notes |
| -- | -- | -- |
| Missing security headers (CSP, XCTO, Referrer-Policy, …) | ZAP baseline + built-in fallback | Always on |
| Insecure cookie flags (`Secure`, `HttpOnly`) | Built-in fallback | Always on |
| Weak / deprecated TLS protocols (SSLv2/3, TLS 1.0/1.1) | sslyze | Per port |
| Heartbleed (CVE-2014-0160), ROBOT, weak DH | sslyze | Per port |
| Missing HSTS | sslyze | Per port |
| Exposed admin / dev panels | nuclei `exposed-panel` tag | Crawl-driven |
| Default logins (Tomcat, Jenkins, Grafana, Redis, …) | nuclei `default-login` tag | Tries known creds |
| Source-map / `.git` / `.env` exposure | nuclei `exposure` tag | |
| Hard-coded tokens in JS bundles | nuclei `js` + `exposed-tokens` | Reads `*.js` from crawl |
| Tech detection (Express, Angular, jQuery, WordPress, …) | nuclei `tech` + httpx | |
| Public CVEs in known versions | nuclei `cve` | Cross-references NVD/KEV/EPSS |

## What we find when `intrusive=true`

Intrusive scans require ownership re-verification within 7 days and run with
nuclei's `-as` (automatic scan) flag plus `zap-full-scan.py`:

| Category | How |
| -- | -- |
| SQL injection | nuclei DAST + ZAP active scanner |
| Reflected / DOM XSS | nuclei DAST + ZAP active spider |
| Open redirect | nuclei `intrusive` |
| SSRF | nuclei + ZAP active |
| LFI / path traversal | nuclei `intrusive` + ZAP active |
| CSRF (form-token absence) | ZAP active |
| Brute-forceable login | nuclei `bruteforce` (with `-as`) |

## What we don't find (and why)

Most of these need stateful, business-logic-aware scanning — well beyond a
generic vulnerability scanner.

- **Logical flaws** (e.g., "buy a product without paying", "leak admin's
  basket"). Requires app-specific test cases.
- **Multi-step authentication bypasses** (e.g., 2FA bypass). Needs a
  crafted login sequence.
- **Race conditions / TOCTOU**. Requires concurrent requests with state.
- **Insecure deserialization in custom protocols**. Needs payload-shaped
  understanding of the app's API.
- **Stored XSS that requires login + privileged context**. Spider doesn't
  log in by default; authenticated scans land in v1.1.

## Extending coverage

### 1. Bigger crawl

Set `CRAWL_DEPTH=5` and `CRAWL_MAX_URLS=2000` for richer SPAs. Trade-off:
crawl time grows roughly linearly.

### 2. JavaScript-rendered routes

Set `KATANA_HEADLESS=1` in the worker env. Requires Chromium in the worker
image (not bundled by default — image grows ~150MB). For most APIs the
HTTP-only crawl plus JS-bundle parsing already finds the routes.

### 3. Authenticated scans

Configure per-asset auth from the UI (Asset detail → **Authentication**)
or via the API:

```bash
# Cookie session
curl -X PUT https://scan.example.com/api/v1/assets/<id>/credentials \
  -H "Authorization: Bearer cyb_..." \
  -H 'Content-Type: application/json' \
  -d '{"kind":"cookie","label":"admin session","cookie_header":"session=abc; csrf=xyz"}'

# Bearer token (OAuth, JWT, etc.)
... -d '{"kind":"bearer","token":"eyJhbGc..."}'

# HTTP Basic
... -d '{"kind":"basic","username":"admin","password":"hunter2"}'

# Custom header (e.g. X-API-Key)
... -d '{"kind":"header","name":"X-API-Key","value":"k1"}'
```

The credential is encrypted at rest with Fernet keyed off `API_SECRET_KEY`.
Decryption happens in the worker right before each scanner invocation; the
plaintext is never logged or returned by GET (only `kind` + `label` + the
creation timestamp are exposed). The crawler (katana) and Nuclei both
attach the credential to every request, so JS-bundle endpoints, REST
APIs, and admin paths are explored just like the unauthenticated home
page would be.

The scan summary includes `authenticated: true` and `auth_kind` once
credentials are applied. A decryption failure (e.g., `API_SECRET_KEY`
rotated) falls back to anonymous scanning with a log line, never fatal.

### 4. Custom Nuclei templates

Mount a directory at `/root/nuclei-templates/custom/` in the worker; the
default tag set picks them up automatically.

### 5. ZAP active by default

Toggle `intrusive=true` on the scan. For Helm deploys, set
`zap.enabled=true` so the passive worker pool talks to a daemonized ZAP
on the cluster network.

## Reality check on Juice Shop

Juice Shop has 100+ "challenges" but most are **business-logic puzzles**
(e.g., "register an admin", "leak an order's coupon"). A generic scanner
should expect to catch:

- All ~6 missing-header / cookie-flag findings (always on).
- Exposed `/ftp/`, `/encryptionkeys/`, `.well-known/` paths (crawl + nuclei
  `exposure`).
- The known-vulnerable npm packages baked into Juice Shop's `package.json`
  (nuclei `cve` once we surface SBOM tagging — v1.1).
- A handful of API path enumeration findings (`/api/Users`, `/rest/products/search`)
  with intrusive=true (ZAP active + nuclei DAST).

In practice, a non-intrusive scan should land **~15-25 findings** on
Juice Shop after crawl is in place; intrusive should push that to
**~40-50**. Anything above that on the same target requires custom
business-logic test cases the framework doesn't speak.
