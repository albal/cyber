#!/usr/bin/env bash
# Run a scan N times against a verified asset and print p50 / p95 wall-clock.
#
# Usage:
#   API=http://localhost:8000 \
#   TOKEN=cyb_xxx_or_jwt \
#   ASSET_ID=<uuid> \
#   N=10 \
#   INTRUSIVE=false \
#   bash scripts/bench.sh
#
# TOKEN can be either a 'cyb_*' API token (recommended for CI) or a session
# JWT obtained from POST /api/v1/auth/login.
set -euo pipefail

API="${API:-http://localhost:8000}"
N="${N:-10}"
INTRUSIVE="${INTRUSIVE:-false}"
SLEEP_S="${SLEEP_S:-2}"
: "${TOKEN:?set TOKEN=<api-token-or-jwt>}"
: "${ASSET_ID:?set ASSET_ID=<uuid>}"

command -v jq  >/dev/null || { echo "bench: jq is required"; exit 2; }
command -v curl >/dev/null || { echo "bench: curl is required"; exit 2; }

times=()
for i in $(seq 1 "$N"); do
  start=$(date +%s)
  scan_id=$(curl -fsS -X POST "$API/api/v1/scans" \
    -H "Authorization: Bearer $TOKEN" \
    -H 'Content-Type: application/json' \
    -d "{\"asset_id\":\"$ASSET_ID\",\"intrusive\":$INTRUSIVE}" | jq -r .id)

  while :; do
    status=$(curl -fsS "$API/api/v1/scans/$scan_id" \
      -H "Authorization: Bearer $TOKEN" | jq -r .status)
    case "$status" in
      completed|partial|failed) break ;;
    esac
    sleep "$SLEEP_S"
  done

  end=$(date +%s)
  elapsed=$((end - start))
  echo "run $i: ${elapsed}s ($status, intrusive=$INTRUSIVE)"
  times+=("$elapsed")
done

# Sort and pick p50 / p95.
sorted=$(printf "%s\n" "${times[@]}" | sort -n)
p50_idx=$(( (N + 1) / 2 ))
p95_idx=$(( (N * 95 + 99) / 100 ))
p50=$(echo "$sorted" | sed -n "${p50_idx}p")
p95=$(echo "$sorted" | sed -n "${p95_idx}p")
echo "---"
echo "n=$N intrusive=$INTRUSIVE  p50=${p50}s  p95=${p95}s"
