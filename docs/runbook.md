# Runbook

Day-2 operations for cyberscan. Each section starts with the symptom you'll
see, then the diagnosis, then the fix.

## Common health checks

```bash
# Backend liveness
curl -fsS http://<host>:8000/healthz

# Worker queue depth (suspect "scans not progressing")
docker compose exec queue redis-cli llen recon
docker compose exec queue redis-cli llen vuln
docker compose exec queue redis-cli llen passive

# Database connectivity
docker compose exec db pg_isready -U cyberscan

# How many scans are running right now?
docker compose exec db psql -U cyberscan -d cyberscan -c \
  "SELECT status, count(*) FROM scans GROUP BY status"
```

In Kubernetes, swap `docker compose exec` for `kubectl exec deploy/<…>`.

## Scans never start (status stays `queued`)

**Diagnosis:**
1. Confirm a worker is consuming the `recon` queue:
   `kubectl logs deploy/cyberscan-worker-recon | tail`
2. Check broker connectivity:
   `kubectl exec deploy/cyberscan-worker-recon -- celery -A cyberscan_worker.celery_app:celery_app inspect ping`
3. Look for FK / RLS errors in backend logs (`set_config` not pinning).

**Fix:** Restart the recon worker; check `CELERY_BROKER_URL` matches Redis;
verify migration 0004 applied (`alembic current`).

## Scans fail at the `vuln/shard*` stage with a Nuclei timeout

**Diagnosis:** Nuclei's default per-template timeout is 10s; on slow targets
or many templates this exceeds the 600s task timeout per shard.

**Fix:**
- Bump `NUCLEI_SHARDS` (smaller buckets per shard).
- Set per-tenant scan timeout to 30 minutes (intrusive runs).
- Confirm `nuclei -update-templates` completed at image build (logs).

## "intrusive scans require ownership re-verification within the last 7 days"

The API returns 400 on `POST /scans` with `intrusive=true`. **Diagnosis:**
`verified_at` on the asset is older than 7 days.

**Fix:** From the UI: open the asset → click "Verify" again. From the API:
`POST /api/v1/assets/<id>/verify` with the same token already in place.

## Schedule fires twice or not at all

**Diagnosis:** Celery Beat is a singleton; running two beats double-fires.
Check there is exactly one beat pod:
`kubectl get pods -l app.kubernetes.io/component=beat`.

**Fix:** Helm sets `strategy: Recreate` and `replicas: 1`. If you scaled it
up manually, scale back to 1. If 0, redeploy.

## Backend crashes on boot with `column "schedule_cron" does not exist`

The schema and the code are out of sync — migrations never ran.

**Fix:**
```bash
# docker compose
docker compose exec backend alembic upgrade head

# Helm
kubectl exec deploy/cyberscan-backend -- alembic upgrade head
```

The chart runs migrations as a `pre-install,pre-upgrade` Job; if it failed,
inspect:
```bash
kubectl get jobs
kubectl logs job/cyberscan-cyberscan-migrate
```

## Findings not enriched with KEV / EPSS

The feeds CronJob hasn't fired (or fixture mode is on in prod).

**Fix:**
```bash
# Manually trigger a feed refresh
kubectl create job --from=cronjob/cyberscan-cyberscan-feeds feeds-now
kubectl logs -l job-name=feeds-now -f

# Confirm rows
kubectl exec deploy/cyberscan-postgresql -- psql -U cyberscan -d cyberscan \
  -c "SELECT count(*) FROM cves; SELECT count(*) FROM kev; SELECT count(*) FROM epss"
```

## OIDC users can't sign in

Symptoms: 401 `invalid or expired token` even though the IdP says login
succeeded.

**Diagnosis order:**
1. Backend logs for `OIDC token rejected: ...` — print the actual reason.
2. `OIDC_ISSUER` matches the `iss` claim exactly (trailing slash matters).
3. `OIDC_AUDIENCE` matches the `aud` claim — Keycloak emits the client id.
4. Default tenant exists: `SELECT slug FROM tenants` should include
   whatever `OIDC_DEFAULT_TENANT` is set to.

**Fix:** Once misconfiguration is corrected, restart the backend so the
JWKS cache is fresh.

## Disk fills with raw scan artifacts in MinIO

**Diagnosis:** `mc du minio/cyberscan-artifacts` (or any S3 client).

**Fix:** Apply a lifecycle rule to expire artifacts older than N days:
```bash
mc ilm add minio/cyberscan-artifacts --expire-days "90"
```

## Audit-log export hangs / OOMs

The endpoint streams with `yield_per(500)`; the issue is most likely a
client buffering the entire response in memory (`curl > file.csv` is fine;
some browsers buffer).

**Fix:** Use `curl -o file.csv` directly; for very large tenants, prefer
the JSONL endpoint (`/api/v1/audit-log/export.jsonl`).

## Rolling back a bad release

```bash
# Kubernetes
helm rollback cyberscan        # to previous
helm rollback cyberscan 5      # to revision 5

# Database — only if the new release added a backwards-incompatible migration
kubectl exec deploy/cyberscan-backend -- alembic downgrade -1
```

Caveat: the chart has `helm.sh/hook: pre-upgrade` migrations — rolling back
the chart does **not** automatically run downgrade.

## Where to look first

| Symptom | First place |
| -- | -- |
| 5xx from API | `kubectl logs deploy/cyberscan-backend` |
| Scan stuck | `kubectl logs deploy/cyberscan-worker-<pool>` |
| Beat not firing | `kubectl logs deploy/cyberscan-beat` |
| Notifications missing | `audit_log` rows for `notification.create` exist? Channel `enabled`? Webhook URL still valid? |
| OIDC fail | backend logs grep `OIDC` |
| RLS leaks | run the `test_tenant_isolation.py` suite against a clone of prod (`pg_dump` to a copy) |
