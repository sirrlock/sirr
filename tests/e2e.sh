#!/usr/bin/env bash
# sirr/tests/e2e.sh — full multi-tenant E2E integration scenario
# Starts its own isolated sirrd on port 39998, runs all checks, then cleans up.
# Usage: bash tests/e2e.sh
set -euo pipefail

PORT=39998
BASE=http://localhost:$PORT
PASS=0; FAIL=0

check() {
  if [ "$1" = "$2" ]; then
    echo "✅ $3"; ((PASS++)) || true
  else
    echo "❌ $3 (expected '$2', got '$1')"; ((FAIL++)) || true
  fi
}

# ── Start isolated sirrd with auto-init ───────────────────────────────────────
# SIRR_API_KEY:    HTTP auth master key
# SIRR_AUTOINIT=1: bootstrap default org + admin principal + 2 temp keys (30 min)
# SIRR_LICENSE_KEY: format-valid key → Business tier (unlimited orgs + principals)
MASTER_KEY="e2e-test-api-key"
LICENSE_KEY="sirr_lic_0000000000000000000000000000000000000000"
E2E_DIR=$(mktemp -d)
SIRR_DATA_DIR="$E2E_DIR" SIRR_API_KEY="$MASTER_KEY" SIRR_AUTOINIT=1 \
  SIRR_LICENSE_KEY="$LICENSE_KEY" sirrd serve --port $PORT >"$E2E_DIR/sirrd.log" 2>&1 &
SIRRD_PID=$!
trap "kill $SIRRD_PID 2>/dev/null; rm -rf '$E2E_DIR'" EXIT

# Wait for server to be ready (poll /health)
for i in $(seq 1 30); do
  if curl -sf "$BASE/health" >/dev/null 2>&1; then break; fi
  sleep 0.3
done

# Parse bootstrap info from log (auto-init prints org_id, principal_id, and keys to stderr→log)
ORG_ID=$(grep "org_id:" "$E2E_DIR/sirrd.log" | head -1 | awk '{print $NF}') || true
BOOTSTRAP_KEY=$(grep -o 'key=sirr_key_[0-9a-f]*' "$E2E_DIR/sirrd.log" | head -1 | sed 's/key=//') || true

# ── PASS 1: Health ─────────────────────────────────────────────────────────────
HEALTH=$(curl -s "$BASE/health" | python3 -c "import sys,json; print(json.load(sys.stdin)['status'])")
check "$HEALTH" "ok" "server health"

# ── PASS 2: Bootstrap info parsed ─────────────────────────────────────────────
[ -n "$ORG_ID" ] && { echo "✅ auto-init: org created ($ORG_ID)"; ((PASS++)) || true; } \
               || { echo "❌ auto-init: ORG_ID empty"; ((FAIL++)) || true; }
[ -n "$BOOTSTRAP_KEY" ] && { echo "✅ auto-init: bootstrap key parsed"; ((PASS++)) || true; } \
                        || { echo "❌ auto-init: BOOTSTRAP_KEY empty"; ((FAIL++)) || true; }

# ── PASS 3: Additional principals (alice=writer, bob=reader) ───────────────────
# Master key can create principals in existing orgs.
ALICE_RESP=$(curl -s -X POST "$BASE/orgs/$ORG_ID/principals" \
  -H "Authorization: Bearer $MASTER_KEY" \
  -H "Content-Type: application/json" \
  -d '{"name":"alice","role":"writer"}')
ALICE_ID=$(echo "$ALICE_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['id'])")
[ -n "$ALICE_ID" ] && { echo "✅ create alice principal (writer)"; ((PASS++)) || true; } \
                   || { echo "❌ create alice (empty id or error: $ALICE_RESP)"; ((FAIL++)) || true; }

BOB_RESP=$(curl -s -X POST "$BASE/orgs/$ORG_ID/principals" \
  -H "Authorization: Bearer $MASTER_KEY" \
  -H "Content-Type: application/json" \
  -d '{"name":"bob","role":"reader"}')
BOB_ID=$(echo "$BOB_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['id'])")
[ -n "$BOB_ID" ] && { echo "✅ create bob principal (reader)"; ((PASS++)) || true; } \
                 || { echo "❌ create bob (empty id or error: $BOB_RESP)"; ((FAIL++)) || true; }

# NOTE: No principal key issuance — POST /me/keys is self-service only; master key forbidden (403).
# Role enforcement (alice can push, bob cannot) needs a future admin key-issuance endpoint.

# ── PASS 4: Public bucket ──────────────────────────────────────────────────────
curl -sf -X POST "$BASE/secrets" \
  -H "Authorization: Bearer $MASTER_KEY" \
  -H "Content-Type: application/json" \
  -d '{"key":"PUBLIC_E2E","value":"hello-public","ttl_seconds":3600}' >/dev/null
check "$(curl -s "$BASE/secrets/PUBLIC_E2E" | python3 -c "import sys,json; print(json.load(sys.stdin)['value'])")" \
  "hello-public" "public secret: read without auth"

# ── PASS 5: Org-scoped secrets (admin bootstrap key) — core access-control test ─
# BOOTSTRAP_KEY is the auto-init admin principal key (tied to ORG_ID).
curl -sf -X POST "$BASE/orgs/$ORG_ID/secrets" \
  -H "Authorization: Bearer $BOOTSTRAP_KEY" \
  -H "Content-Type: application/json" \
  -d '{"key":"PRIVATE_E2E","value":"secret123","ttl_seconds":3600,"max_reads":10}' >/dev/null

check "$(curl -s "$BASE/orgs/$ORG_ID/secrets/PRIVATE_E2E" \
  -H "Authorization: Bearer $BOOTSTRAP_KEY" | python3 -c "import sys,json; print(json.load(sys.stdin)['value'])")" \
  "secret123" "org secret: admin key can read"

check "$(curl -s -o /dev/null -w "%{http_code}" "$BASE/orgs/$ORG_ID/secrets/PRIVATE_E2E")" \
  "401" "org secret: no auth → 401"

check "$(curl -s -o /dev/null -w "%{http_code}" "$BASE/orgs/$ORG_ID/secrets/PRIVATE_E2E" \
  -H "Authorization: Bearer wrong-key-doesnt-exist")" \
  "401" "org secret: wrong key → 401"

# ── PASS 6: Burn-after-read ────────────────────────────────────────────────────
curl -sf -X POST "$BASE/orgs/$ORG_ID/secrets" \
  -H "Authorization: Bearer $BOOTSTRAP_KEY" \
  -H "Content-Type: application/json" \
  -d '{"key":"BURN_E2E","value":"burnme","ttl_seconds":3600,"max_reads":1}' >/dev/null

BURN1=$(curl -s "$BASE/orgs/$ORG_ID/secrets/BURN_E2E" \
  -H "Authorization: Bearer $BOOTSTRAP_KEY" | python3 -c "import sys,json; print(json.load(sys.stdin)['value'])")
BURN2=$(curl -s -o /dev/null -w "%{http_code}" "$BASE/orgs/$ORG_ID/secrets/BURN_E2E" \
  -H "Authorization: Bearer $BOOTSTRAP_KEY")
check "$BURN1" "burnme" "burn-after-read: first read returns value"
check "$BURN2" "404" "burn-after-read: second read → 404 (burned)"

# ── Results ────────────────────────────────────────────────────────────────────
echo ""
echo "Results: $PASS passed, $FAIL failed"
[ $FAIL -eq 0 ] && exit 0 || exit 1
