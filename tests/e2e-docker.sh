#!/usr/bin/env bash
# sirr/tests/e2e-docker.sh — Docker smoke test
# Pulls the sirrd image, verifies /health, push, and get via curl.
# Usage: bash tests/e2e-docker.sh
set -euo pipefail

PORT=39994
BASE=http://localhost:$PORT
DOCKER_KEY="docker-test-api-key"
PASS=0; FAIL=0

check() {
  if [ "$1" = "$2" ]; then
    echo "✅ $3"; ((PASS++))
  else
    echo "❌ $3 (expected '$2', got '$1')"; ((FAIL++))
  fi
}

trap "docker rm -f sirr-e2e-test 2>/dev/null || true" EXIT

docker rm -f sirr-e2e-test 2>/dev/null || true

docker run -d --name sirr-e2e-test \
  -p "${PORT}:39999" \
  -e SIRR_MASTER_API_KEY="$DOCKER_KEY" \
  ghcr.io/sirrlock/sirrd

# Wait for health
for i in $(seq 1 20); do
  if curl -sf "$BASE/health" >/dev/null 2>&1; then break; fi
  sleep 0.3
done

STATUS=$(curl -s "$BASE/health" | python3 -c "import sys,json; print(json.load(sys.stdin)['status'])")
check "$STATUS" "ok" "Docker container healthy"

curl -sf -X POST "$BASE/secrets" \
  -H "Authorization: Bearer $DOCKER_KEY" \
  -H "Content-Type: application/json" \
  -d '{"key":"DOCKER_TEST","value":"docker-ok","ttl_seconds":60}' >/dev/null

VALUE=$(curl -s "$BASE/secrets/DOCKER_TEST" | python3 -c "import sys,json; print(json.load(sys.stdin)['value'])")
check "$VALUE" "docker-ok" "Docker: push and get public secret"

echo ""
echo "Results: $PASS passed, $FAIL failed"
[ $FAIL -eq 0 ] && exit 0 || exit 1
