#!/usr/bin/env bash
# Run the e2e scan flow N times and print p50/p95 wall-clock.
# Requires: jq, curl, a logged-in JWT in $TOKEN, and an existing verified asset id in $ASSET_ID.
set -euo pipefail

API="${API:-http://localhost:8000}"
N="${N:-10}"
: "${TOKEN:?set TOKEN=<jwt>}"
: "${ASSET_ID:?set ASSET_ID=<uuid>}"

times=()
for i in $(seq 1 "$N"); do
  start=$(date +%s)
  scan_id=$(curl -s -X POST "$API/api/v1/scans" \
    -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
    -d "{\"asset_id\":\"$ASSET_ID\"}" | jq -r .id)
  while true; do
    status=$(curl -s "$API/api/v1/scans/$scan_id" -H "Authorization: Bearer $TOKEN" | jq -r .status)
    if [[ "$status" == "completed" || "$status" == "partial" || "$status" == "failed" ]]; then
      break
    fi
    sleep 2
  done
  end=$(date +%s)
  elapsed=$((end - start))
  echo "run $i: ${elapsed}s ($status)"
  times+=("$elapsed")
done

# p50 / p95
sorted=$(printf "%s\n" "${times[@]}" | sort -n)
p50_idx=$(( N / 2 ))
p95_idx=$(( (N * 95 + 99) / 100 - 1 ))
p50=$(echo "$sorted" | sed -n "$((p50_idx + 1))p")
p95=$(echo "$sorted" | sed -n "$((p95_idx + 1))p")
echo "p50=${p50}s p95=${p95}s"
