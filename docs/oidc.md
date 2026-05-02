# OIDC sign-in (Google / Microsoft / Apple)

Cyberscan can accept **OpenID Connect** bearer tokens issued by an external
identity provider. This document covers how to wire up Google, Microsoft
(Entra ID / Azure AD) and Apple sign-in.

## How it works (read this first)

Cyberscan's backend is a **token verifier**, not an OIDC client. There is no
built-in "Sign in with Google" button on the frontend, and the backend does
not perform the OAuth code exchange, hold client secrets, or issue refresh
tokens. Instead, the flow is:

1. The user authenticates with the IdP (interactively, in a browser).
2. The IdP — or a layer in front of cyberscan — produces a **JWT** for the
   user.
3. The client (browser, CLI, CI job) sends that JWT to cyberscan as
   `Authorization: Bearer <token>`.
4. The backend verifies the signature against the issuer's JWKS, validates
   `iss` / `aud` / `exp` / `iat`, and either looks up the existing user by
   email or auto-provisions a new one in `OIDC_DEFAULT_TENANT`.

Two important consequences:

- **One issuer at a time.** `OIDC_ISSUER` is a single string. To accept
  Google, Microsoft *and* Apple simultaneously you need a federation hub
  (Keycloak, Auth0, Okta, Authentik, …) that presents a single issuer to
  cyberscan and federates outward to each upstream IdP. This is **Pattern
  A** below and is the recommended approach.
- **The browser still needs a way to obtain that JWT.** If you don't want to
  run a federation hub, deploy [oauth2-proxy] (or a similar OIDC-aware
  reverse proxy) in front of cyberscan. The proxy handles the OAuth dance
  and forwards the upstream IdP's ID token to cyberscan as a bearer header.
  This is **Pattern B**.

[oauth2-proxy]: https://oauth2-proxy.github.io/oauth2-proxy/

## Backend settings

All OIDC configuration lives in environment variables on the backend
(and any worker pods that need to validate tokens — currently only the
backend does).

| Variable                | Default       | Notes |
|-------------------------|---------------|-------|
| `OIDC_ISSUER`           | *(unset)*     | Setting this enables OIDC. Must match the `iss` claim **exactly**, including trailing slash if the IdP emits one. |
| `OIDC_AUDIENCE`         | `cyberscan`   | Must match the `aud` claim. For Google, this is the OAuth client ID. For Entra, the application (client) ID or its `api://...` URI. |
| `OIDC_DEFAULT_TENANT`   | `default`     | Tenant **slug** (not ID) into which new users are auto-provisioned. The tenant must already exist. |
| `OIDC_EMAIL_CLAIM`      | `email`       | Falls back to `preferred_username` if the configured claim is missing. |
| `OIDC_ROLE_CLAIM`       | `role`        | If present and recognised, the value sets the user's role on each sign-in. Recognised values: `owner`, `admin`, `analyst`, `viewer`. Unknown values fall back to `viewer` on first provision and are ignored on subsequent sign-ins. |

Set these via Helm `backend.env`:

```yaml
backend:
  env:
    OIDC_ISSUER: "https://auth.example.com/realms/cyberscan"
    OIDC_AUDIENCE: "cyberscan"
    OIDC_DEFAULT_TENANT: "default"
    OIDC_EMAIL_CLAIM: "email"
    OIDC_ROLE_CLAIM: "role"
```

Or in `docker-compose.yml` / `.env` for local development.

> **Note on tenant existence.** The chart's `migrate` Job seeds a `default`
> tenant. If you set `OIDC_DEFAULT_TENANT` to anything else, create that
> tenant before the first OIDC sign-in or provisioning will fail with
> `OIDC default tenant '<slug>' not found — refusing auto-provision`.

## Pattern A — Keycloak as a federation hub (recommended)

Keycloak (or any equivalent IdP) acts as the single OIDC issuer cyberscan
trusts and federates to Google / Microsoft / Apple upstream. End users see
"Sign in with Google / Microsoft / Apple" buttons on Keycloak's login page.

### 1. Deploy Keycloak

Out of scope for this doc — use the upstream Helm chart, a SaaS instance,
or any existing deployment. Whatever path you pick, you need:

- A realm (e.g. `cyberscan`).
- HTTPS terminated at a public URL (`https://auth.example.com`).
- Admin access to configure clients and identity providers.

### 2. Create the cyberscan client in Keycloak

In your realm:

1. **Clients → Create client.**
   - Client type: **OpenID Connect**
   - Client ID: `cyberscan`
   - Name: `Cyberscan`
2. **Capability config:**
   - Client authentication: **On** (confidential client).
   - Standard flow: **On** (authorization code).
   - Direct access grants: **Off** (we don't want password grants).
   - Service accounts roles: **Off** (unless you also want machine-to-machine).
3. **Login settings:**
   - Valid redirect URIs: the URL of whatever client will perform the
     code exchange. If you're using oauth2-proxy in front of cyberscan,
     add its `/oauth2/callback` URL. If users authenticate via a custom
     SPA, add that SPA's redirect URI.
   - Web origins: same hosts as redirect URIs.

After saving, note:

- **Issuer URL**: `https://auth.example.com/realms/cyberscan`
- **Client ID**: `cyberscan`

Set these on cyberscan:

```yaml
backend:
  env:
    OIDC_ISSUER: "https://auth.example.com/realms/cyberscan"
    OIDC_AUDIENCE: "cyberscan"
```

### 3. Add an audience mapper (Keycloak-specific)

By default Keycloak issues access tokens whose `aud` is **not** the client
ID — cyberscan's verification will fail with `Invalid audience`. Add a
mapper:

1. **Clients → cyberscan → Client scopes.**
2. Open the dedicated scope (`cyberscan-dedicated`).
3. **Add mapper → By configuration → Audience.**
   - Name: `cyberscan-aud`
   - Included Client Audience: `cyberscan`
   - Add to access token: **On**
   - Add to ID token: **On**

### 4. Optional: a `role` mapper

If you want Keycloak roles to drive cyberscan's `Role` enum:

1. Create realm roles `owner`, `admin`, `analyst`, `viewer`.
2. **Clients → cyberscan → Client scopes → cyberscan-dedicated → Add
   mapper → By configuration → User Realm Role.**
3. Token claim name: `role` (matches `OIDC_ROLE_CLAIM`).
4. Add to access token + ID token.
5. Multivalued: **Off** (cyberscan accepts a list, but a scalar is
   simpler). If you leave it multivalued, cyberscan picks the first
   recognised value.

Assign the appropriate realm role to each user. Users without any
recognised role land in `viewer` on first provision.

### 5. Federate Google

In Keycloak: **Identity providers → Add provider → Google.**

You need a Google OAuth client:

1. Go to <https://console.cloud.google.com/apis/credentials>.
2. **Create credentials → OAuth client ID → Web application.**
3. Authorised redirect URIs: copy the **Redirect URI** value Keycloak
   shows on the Google provider page (it looks like
   `https://auth.example.com/realms/cyberscan/broker/google/endpoint`).
4. Save. Copy the client ID and secret into Keycloak.

OAuth consent screen: if your project is in *Testing* mode, only added
test users can sign in. Move to *Production* (or use an internal
workspace project) before opening to real users.

### 6. Federate Microsoft (Entra ID / Azure AD)

In Keycloak: **Identity providers → Add provider → OpenID Connect v1.0**
(or "Microsoft" if your Keycloak version exposes it directly).

In the [Entra admin center](https://entra.microsoft.com/):

1. **App registrations → New registration.**
   - Name: `Cyberscan via Keycloak`
   - Supported account types: pick "Accounts in this organisational
     directory only" for single-tenant, or one of the multi-tenant
     options if you need to accept any Microsoft account.
   - Redirect URI (Web): the `/broker/microsoft/endpoint` URL Keycloak
     shows on the provider page.
2. **Certificates & secrets → New client secret.** Copy the value
     immediately — it is only shown once.
3. **API permissions → Microsoft Graph → Delegated → `openid`,
   `profile`, `email`.** Grant admin consent.
4. Configure Keycloak's provider:
   - Client ID: the application (client) ID.
   - Client secret: the secret from step 2.
   - Authorization URL:
     `https://login.microsoftonline.com/<tenant>/oauth2/v2.0/authorize`
     (use `common` for multi-tenant).
   - Token URL: `https://login.microsoftonline.com/<tenant>/oauth2/v2.0/token`.
   - Default scopes: `openid profile email`.

> Microsoft does **not** always include an `email` claim — for personal
> accounts it sometimes only emits `preferred_username`. Cyberscan falls
> back to `preferred_username` automatically, so this is usually fine.

### 7. Federate Apple

Apple Sign In is the fiddliest of the three because Apple uses a JWT as
the client secret and only emits the user's email **once**, on the first
authorisation.

In Keycloak: **Identity providers → Add provider → OpenID Connect v1.0**
(Keycloak ≥ 25 exposes a dedicated "Apple" provider — prefer that if
available, since it auto-generates the client secret JWT).

In [Apple Developer](https://developer.apple.com/account/):

1. **Certificates, IDs & Profiles → Identifiers → +.**
   - Type: **Services IDs**.
   - Description / Identifier: e.g. `com.example.cyberscan.signin`.
   - Enable **Sign In with Apple**, configure with your primary App ID,
     and add the Keycloak `/broker/apple/endpoint` URL as a return URL.
2. **Keys → +.**
   - Key name: `Cyberscan Apple SignIn`.
   - Enable **Sign In with Apple** and associate the App ID.
   - Download the `.p8` private key. **Apple shows it once.**
   - Note the Key ID and your Team ID.
3. In Keycloak's provider config:
   - Client ID: the **Services ID** from step 1 (not the App ID).
   - If using the dedicated Apple provider: paste the `.p8` key, Key ID
     and Team ID — Keycloak generates the client secret JWT for you.
   - If using a generic OIDC provider, you must generate a signed JWT
     (ES256) every six months and paste it as the client secret.
   - Authorization URL: `https://appleid.apple.com/auth/authorize`
   - Token URL: `https://appleid.apple.com/auth/token`
   - Default scopes: `openid name email`.
   - Issuer: `https://appleid.apple.com`.

> **Email-relay caveat.** Users who select "Hide my email" sign in with
> a `@privaterelay.appleid.com` address. That is the email cyberscan
> records. Apple does *not* re-send the real email on subsequent logins,
> so if you delete the user record you can't recover the original
> address from Apple alone.

### 8. Test end-to-end

```bash
# Grab a token via the browser flow (oauth2-proxy or similar), then:
curl -fsS https://scan.example.com/api/v1/me \
  -H "Authorization: Bearer $TOKEN"
```

A 200 response with the user payload means OIDC is wired up. A 401 with
`OIDC token rejected: ...` in the backend logs means the token failed
verification — see *Troubleshooting*.

## Pattern B — oauth2-proxy in front of cyberscan

Use this when you want to point cyberscan at **one** upstream IdP
(typically Google Workspace or Entra ID) without running a federation
hub. oauth2-proxy handles the browser-facing OAuth dance and injects the
IdP's ID token into the upstream request.

Sketch (Helm values for `oauth2-proxy/oauth2-proxy` chart, in front of
the cyberscan Ingress):

```yaml
config:
  clientID: "<google-or-entra-client-id>"
  clientSecret: "<secret>"
  cookieSecret: "<32-byte-base64>"
extraArgs:
  provider: oidc
  oidc-issuer-url: "https://accounts.google.com"      # or Entra issuer
  email-domain: "example.com"
  pass-access-token: "true"
  pass-authorization-header: "true"
  set-authorization-header: "true"                    # forwards the ID token
  upstream: "http://cyberscan-cyberscan-backend:8000"
```

Cyberscan settings:

```yaml
backend:
  env:
    OIDC_ISSUER: "https://accounts.google.com"        # Google
    # OIDC_ISSUER: "https://login.microsoftonline.com/<tenant>/v2.0"   # Entra single-tenant
    OIDC_AUDIENCE: "<same client id you gave oauth2-proxy>"
```

Limitation: this pattern only handles browser sessions. CLI / CI clients
still need to obtain a JWT directly from the IdP (e.g. Google service
account ID tokens, Entra client-credentials with `id_token` flow) and
present it as `Authorization: Bearer`. Mixing patterns is fine — the
backend doesn't care where the JWT came from, only that the signature
and claims check out.

## Direct issuers — quick reference

If you decide to bypass Keycloak/oauth2-proxy and verify tokens minted
directly by Google or Microsoft (e.g. in a machine-to-machine flow), the
issuer values are:

| Provider                    | `OIDC_ISSUER`                                                           | `OIDC_AUDIENCE`        |
|-----------------------------|-------------------------------------------------------------------------|------------------------|
| Google                      | `https://accounts.google.com`                                           | OAuth client ID        |
| Microsoft Entra (single)    | `https://login.microsoftonline.com/<tenantId>/v2.0`                     | App (client) ID or `api://...` URI |
| Microsoft Entra (multi)     | `https://login.microsoftonline.com/common/v2.0` *(see note)*            | App (client) ID        |
| Apple                       | `https://appleid.apple.com`                                             | Services ID            |

> **Multi-tenant Entra caveat.** With `common`, the `iss` claim in real
> tokens is `https://login.microsoftonline.com/<actual-tenantId>/v2.0`,
> **not** `.../common/v2.0`. Cyberscan's verifier requires an exact match,
> so multi-tenant Entra without a federation hub does not work out of the
> box. Either pin a single tenant or front it with Keycloak.

## Role mapping

The role claim is consulted on every sign-in:

- First sign-in: provisions the user with the claim's role, or `viewer`
  if the claim is missing or unrecognised.
- Subsequent sign-ins: if the claim's value differs from the stored
  role and is recognised, the user record is updated.
- The seeded admin (`SEED_ADMIN_EMAIL`) is the only `owner` by default;
  to grant `owner` to an OIDC user, emit `"role": "owner"` in their
  token claims.

Tenant assignment is **fixed at provisioning time**. To move an OIDC
user between tenants, update the row directly in the `users` table
(or delete and let them re-provision).

## Disabling password login

OIDC tokens are accepted **alongside** the local JWT issued by
`/api/v1/auth/login`. To force everyone through the IdP:

1. Don't expose the login form in the frontend (or wrap the whole UI
   behind oauth2-proxy).
2. Disable the seeded admin once an OIDC `owner` exists:
   ```sql
   UPDATE users SET password_hash = '!disabled' WHERE email = '<seed-admin>';
   ```
   The local login flow uses bcrypt verification, so `!disabled` (which
   is not a valid bcrypt hash) will always fail.

There is intentionally no global "OIDC only" toggle — locking yourself
out of the local admin while the IdP is broken is too easy.

## Troubleshooting

The runbook has a focused checklist at
[runbook.md → "OIDC users can't sign in"](runbook.md#oidc-users-cant-sign-in).
The most common failures, in order:

1. **`Invalid issuer`** — `OIDC_ISSUER` doesn't byte-match the `iss`
   claim. Decode the token at <https://jwt.io>, copy `iss` verbatim.
2. **`Invalid audience`** — `OIDC_AUDIENCE` doesn't match `aud`.
   Keycloak in particular needs the audience mapper described above.
3. **`OIDC token missing email/preferred_username claim`** — the IdP
   isn't releasing email. Add an email mapper / scope on the IdP, or
   change `OIDC_EMAIL_CLAIM` to a claim it does emit.
4. **`OIDC default tenant '<slug>' not found`** — create the tenant
   first.
5. **`Signature verification failed`** — JWKS rotation. The backend
   caches keys for one hour; restart the backend to force a re-fetch,
   or wait it out.

Backend logs are the source of truth; every rejection prints the
underlying `pyjwt` reason.
