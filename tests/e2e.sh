#!/usr/bin/env bash
# sirr/tests/e2e.sh — full multi-tenant E2E integration scenario
# Starts its own isolated sirrd on port 39998, runs all checks, then cleans up.
# NO license key — tests the real free-tier experience a user gets.
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

json() { python3 -c "import sys,json; print(json.load(sys.stdin)$1)"; }
status() { curl -s -o /dev/null -w "%{http_code}" "$@"; }

# ── Start isolated sirrd — NO auto-init, NO license key ───────────────────────
# This is the real first-run experience: empty server, master key only.
MASTER_KEY="e2e-test-api-key"
E2E_DIR=$(mktemp -d)
SIRR_DATA_DIR="$E2E_DIR" SIRR_MASTER_API_KEY="$MASTER_KEY" \
  SIRR_RATE_LIMIT_PER_SECOND=1000 SIRR_RATE_LIMIT_BURST=1000 \
  sirrd serve --port $PORT >"$E2E_DIR/sirrd.log" 2>&1 &
SIRRD_PID=$!
trap "kill $SIRRD_PID 2>/dev/null; rm -rf '$E2E_DIR'" EXIT

for i in $(seq 1 30); do
  if curl -sf "$BASE/health" >/dev/null 2>&1; then break; fi
  sleep 0.3
done

# ── 1: Health ─────────────────────────────────────────────────────────────────
HEALTH=$(curl -s "$BASE/health" | json "['status']")
check "$HEALTH" "ok" "server health"

# ── 2: Create org (master key, no license) ────────────────────────────────────
ORG_RESP=$(curl -s -X POST "$BASE/orgs" \
  -H "Authorization: Bearer $MASTER_KEY" \
  -H "Content-Type: application/json" \
  -d '{"name":"acme"}')
ORG_ID=$(echo "$ORG_RESP" | json "['id']")
check "$(echo "$ORG_RESP" | json "['name']")" "acme" "create org: acme"

# ── 3: Create second org (no license limits) ─────────────────────────────────
ORG2_RESP=$(curl -s -X POST "$BASE/orgs" \
  -H "Authorization: Bearer $MASTER_KEY" \
  -H "Content-Type: application/json" \
  -d '{"name":"globex"}')
ORG2_ID=$(echo "$ORG2_RESP" | json "['id']")
check "$(echo "$ORG2_RESP" | json "['name']")" "globex" "create second org: globex"

# ── 4: Create principal (owner) ───────────────────────────────────────────────
OWNER_RESP=$(curl -s -X POST "$BASE/orgs/$ORG_ID/principals" \
  -H "Authorization: Bearer $MASTER_KEY" \
  -H "Content-Type: application/json" \
  -d '{"name":"alice","role":"owner"}')
OWNER_ID=$(echo "$OWNER_RESP" | json "['id']")
check "$(echo "$OWNER_RESP" | json "['role']")" "owner" "create principal: alice (owner)"

# ── 5: Create second principal (no license limits) ────────────────────────────
WRITER_RESP=$(curl -s -X POST "$BASE/orgs/$ORG_ID/principals" \
  -H "Authorization: Bearer $MASTER_KEY" \
  -H "Content-Type: application/json" \
  -d '{"name":"bob","role":"writer"}')
WRITER_ID=$(echo "$WRITER_RESP" | json "['id']")
check "$(echo "$WRITER_RESP" | json "['role']")" "writer" "create second principal: no tier limit"

# ── 6: Master issues key for principal ────────────────────────────────────────
KEY_RESP=$(curl -s -X POST "$BASE/orgs/$ORG_ID/principals/$OWNER_ID/keys" \
  -H "Authorization: Bearer $MASTER_KEY" \
  -H "Content-Type: application/json" \
  -d '{"name":"alice-key","valid_for_seconds":3600}')
ALICE_KEY=$(echo "$KEY_RESP" | json "['key']")
[ -n "$ALICE_KEY" ] && { echo "✅ master issues key for alice"; ((PASS++)) || true; } \
                     || { echo "❌ key creation failed: $KEY_RESP"; ((FAIL++)) || true; }

WRITER_KEY_RESP=$(curl -s -X POST "$BASE/orgs/$ORG_ID/principals/$WRITER_ID/keys" \
  -H "Authorization: Bearer $MASTER_KEY" \
  -H "Content-Type: application/json" \
  -d '{"name":"bob-key","valid_for_seconds":3600}')
BOB_KEY=$(echo "$WRITER_KEY_RESP" | json "['key']")
[ -n "$BOB_KEY" ] && { echo "✅ master issues key for bob"; ((PASS++)) || true; } \
                   || { echo "❌ key creation failed: $WRITER_KEY_RESP"; ((FAIL++)) || true; }

# ── 7: Principal can authenticate with issued key ─────────────────────────────
ME_RESP=$(curl -s "$BASE/me" -H "Authorization: Bearer $ALICE_KEY")
check "$(echo "$ME_RESP" | json "['name']")" "alice" "alice authenticates with her key"

ME_RESP2=$(curl -s "$BASE/me" -H "Authorization: Bearer $BOB_KEY")
check "$(echo "$ME_RESP2" | json "['name']")" "bob" "bob authenticates with his key"

# ── 8: Owner can create org secret ────────────────────────────────────────────
curl -sf -X POST "$BASE/orgs/$ORG_ID/secrets" \
  -H "Authorization: Bearer $ALICE_KEY" \
  -H "Content-Type: application/json" \
  -d '{"key":"DB_URL","value":"postgres://localhost/myapp","ttl_seconds":3600,"max_reads":100}' >/dev/null
check "$(curl -s "$BASE/orgs/$ORG_ID/secrets/DB_URL" \
  -H "Authorization: Bearer $ALICE_KEY" | json "['value']")" \
  "postgres://localhost/myapp" "owner can set and read org secret"

# ── 9: Writer can create but reader cannot ────────────────────────────────────
READER_RESP=$(curl -s -X POST "$BASE/orgs/$ORG_ID/principals" \
  -H "Authorization: Bearer $MASTER_KEY" \
  -H "Content-Type: application/json" \
  -d '{"name":"carol","role":"reader"}')
READER_ID=$(echo "$READER_RESP" | json "['id']")
READER_KEY_RESP=$(curl -s -X POST "$BASE/orgs/$ORG_ID/principals/$READER_ID/keys" \
  -H "Authorization: Bearer $MASTER_KEY" \
  -H "Content-Type: application/json" \
  -d '{"name":"carol-key","valid_for_seconds":3600}')
CAROL_KEY=$(echo "$READER_KEY_RESP" | json "['key']")

# reader has ReadMy (r) not ReadOrg (R) — can only read secrets they own
READER_STATUS=$(status "$BASE/orgs/$ORG_ID/secrets/DB_URL" \
  -H "Authorization: Bearer $CAROL_KEY")
# 403 (permission denied) or 404 (secret not visible) are both correct
if [ "$READER_STATUS" = "403" ] || [ "$READER_STATUS" = "404" ]; then
  echo "✅ reader cannot read other's secret (ReadMy only) → $READER_STATUS"; ((PASS++)) || true
else
  echo "❌ reader cannot read other's secret (expected 403/404, got $READER_STATUS)"; ((FAIL++)) || true
fi

check "$(status -X POST "$BASE/orgs/$ORG_ID/secrets" \
  -H "Authorization: Bearer $CAROL_KEY" \
  -H "Content-Type: application/json" \
  -d '{"key":"NOPE","value":"denied"}')" \
  "403" "reader cannot create org secret"

# ── 10: Writer can create secrets ─────────────────────────────────────────────
curl -sf -X POST "$BASE/orgs/$ORG_ID/secrets" \
  -H "Authorization: Bearer $BOB_KEY" \
  -H "Content-Type: application/json" \
  -d '{"key":"WRITER_SECRET","value":"bob-wrote-this","ttl_seconds":3600,"max_reads":100}' >/dev/null
check "$(curl -s "$BASE/orgs/$ORG_ID/secrets/WRITER_SECRET" \
  -H "Authorization: Bearer $BOB_KEY" | json "['value']")" \
  "bob-wrote-this" "writer can set and read org secret"

# ══════════════════════════════════════════════════════════════════════════════
# SECOND COMPANY: Globex — full parallel setup with same secret key names
# Proves two orgs on the same server don't interfere with each other.
# ══════════════════════════════════════════════════════════════════════════════

# ── 11: Globex principals + keys ─────────────────────────────────────────────
G_OWNER_RESP=$(curl -s -X POST "$BASE/orgs/$ORG2_ID/principals" \
  -H "Authorization: Bearer $MASTER_KEY" \
  -H "Content-Type: application/json" \
  -d '{"name":"hank","role":"owner"}')
G_OWNER_ID=$(echo "$G_OWNER_RESP" | json "['id']")
check "$(echo "$G_OWNER_RESP" | json "['name']")" "hank" "globex: create hank (owner)"

G_WRITER_RESP=$(curl -s -X POST "$BASE/orgs/$ORG2_ID/principals" \
  -H "Authorization: Bearer $MASTER_KEY" \
  -H "Content-Type: application/json" \
  -d '{"name":"marge","role":"writer"}')
G_WRITER_ID=$(echo "$G_WRITER_RESP" | json "['id']")
check "$(echo "$G_WRITER_RESP" | json "['name']")" "marge" "globex: create marge (writer)"

G_OWNER_KEY_RESP=$(curl -s -X POST "$BASE/orgs/$ORG2_ID/principals/$G_OWNER_ID/keys" \
  -H "Authorization: Bearer $MASTER_KEY" \
  -H "Content-Type: application/json" \
  -d '{"name":"hank-key","valid_for_seconds":3600}')
HANK_KEY=$(echo "$G_OWNER_KEY_RESP" | json "['key']")
[ -n "$HANK_KEY" ] && { echo "✅ globex: master issues key for hank"; ((PASS++)) || true; } \
                    || { echo "❌ globex: key creation failed: $G_OWNER_KEY_RESP"; ((FAIL++)) || true; }

G_WRITER_KEY_RESP=$(curl -s -X POST "$BASE/orgs/$ORG2_ID/principals/$G_WRITER_ID/keys" \
  -H "Authorization: Bearer $MASTER_KEY" \
  -H "Content-Type: application/json" \
  -d '{"name":"marge-key","valid_for_seconds":3600}')
MARGE_KEY=$(echo "$G_WRITER_KEY_RESP" | json "['key']")
[ -n "$MARGE_KEY" ] && { echo "✅ globex: master issues key for marge"; ((PASS++)) || true; } \
                     || { echo "❌ globex: key creation failed: $G_WRITER_KEY_RESP"; ((FAIL++)) || true; }

# ── 12: Globex owner sets DB_URL — same key name as acme ─────────────────────
curl -sf -X POST "$BASE/orgs/$ORG2_ID/secrets" \
  -H "Authorization: Bearer $HANK_KEY" \
  -H "Content-Type: application/json" \
  -d '{"key":"DB_URL","value":"postgres://globex-db:5432/globex","ttl_seconds":3600,"max_reads":100}' >/dev/null
check "$(curl -s "$BASE/orgs/$ORG2_ID/secrets/DB_URL" \
  -H "Authorization: Bearer $HANK_KEY" | json "['value']")" \
  "postgres://globex-db:5432/globex" "globex: DB_URL has globex value"

# ── 13: Acme's DB_URL is still acme's value (not overwritten) ────────────────
check "$(curl -s "$BASE/orgs/$ORG_ID/secrets/DB_URL" \
  -H "Authorization: Bearer $ALICE_KEY" | json "['value']")" \
  "postgres://localhost/myapp" "acme: DB_URL still has acme value"

# ── 14: Cross-org isolation — principals can't reach other org ────────────────
check "$(status "$BASE/orgs/$ORG_ID/secrets/DB_URL" \
  -H "Authorization: Bearer $HANK_KEY")" \
  "403" "hank (globex) cannot read acme secrets"

check "$(status "$BASE/orgs/$ORG2_ID/secrets/DB_URL" \
  -H "Authorization: Bearer $ALICE_KEY")" \
  "403" "alice (acme) cannot read globex secrets"

check "$(status -X POST "$BASE/orgs/$ORG_ID/secrets" \
  -H "Authorization: Bearer $MARGE_KEY" \
  -H "Content-Type: application/json" \
  -d '{"key":"HACK","value":"nope"}')" \
  "403" "marge (globex) cannot write to acme"

check "$(status -X POST "$BASE/orgs/$ORG2_ID/secrets" \
  -H "Authorization: Bearer $BOB_KEY" \
  -H "Content-Type: application/json" \
  -d '{"key":"HACK","value":"nope"}')" \
  "403" "bob (acme) cannot write to globex"

# ── 15: Globex writer can work in her own org ─────────────────────────────────
MARGE_SET_RESP=$(curl -s -X POST "$BASE/orgs/$ORG2_ID/secrets" \
  -H "Authorization: Bearer $MARGE_KEY" \
  -H "Content-Type: application/json" \
  -d '{"key":"API_KEY","value":"globex-api-key-123","ttl_seconds":3600,"max_reads":100}')
check "$(echo "$MARGE_SET_RESP" | json "['key']")" "API_KEY" "marge can create secret in globex"
MARGE_READ_RAW=$(curl -s -w "\n%{http_code}" "$BASE/orgs/$ORG2_ID/secrets/API_KEY" \
  -H "Authorization: Bearer $MARGE_KEY")
MARGE_READ_STATUS=$(echo "$MARGE_READ_RAW" | tail -1)
MARGE_READ_BODY=$(echo "$MARGE_READ_RAW" | head -1)
if [ "$MARGE_READ_STATUS" = "200" ]; then
  check "$(echo "$MARGE_READ_BODY" | json "['value']")" "globex-api-key-123" "marge can read her secret in globex"
else
  echo "❌ marge can read her secret in globex (HTTP $MARGE_READ_STATUS: $MARGE_READ_BODY)"; ((FAIL++)) || true
fi

# ══════════════════════════════════════════════════════════════════════════════
# SHARED TESTS (public bucket, burn-after-read, self-service keys)
# ══════════════════════════════════════════════════════════════════════════════

# ── 16: Public bucket (no auth) ──────────────────────────────────────────────
PUSH_RESP=$(curl -s -X POST "$BASE/secrets" \
  -H "Authorization: Bearer $MASTER_KEY" \
  -H "Content-Type: application/json" \
  -d '{"value":"hello-public","ttl_seconds":3600}')
PUBLIC_ID=$(echo "$PUSH_RESP" | json "['id']")
check "$(curl -s "$BASE/secrets/$PUBLIC_ID" | json "['value']")" \
  "hello-public" "public dead drop: push and read"

# ── 17: Burn-after-read ──────────────────────────────────────────────────────
curl -sf -X POST "$BASE/orgs/$ORG_ID/secrets" \
  -H "Authorization: Bearer $ALICE_KEY" \
  -H "Content-Type: application/json" \
  -d '{"key":"BURN_E2E","value":"burnme","ttl_seconds":3600,"max_reads":1}' >/dev/null

BURN1=$(curl -s "$BASE/orgs/$ORG_ID/secrets/BURN_E2E" \
  -H "Authorization: Bearer $ALICE_KEY" | json "['value']")
BURN2=$(status "$BASE/orgs/$ORG_ID/secrets/BURN_E2E" \
  -H "Authorization: Bearer $ALICE_KEY")
check "$BURN1" "burnme" "burn-after-read: first read returns value"
check "$BURN2" "404" "burn-after-read: second read → 404 (burned)"

# ── 18: Self-service key creation ─────────────────────────────────────────────
SELF_KEY_RESP=$(curl -s -X POST "$BASE/me/keys" \
  -H "Authorization: Bearer $ALICE_KEY" \
  -H "Content-Type: application/json" \
  -d '{"name":"alice-self-key","valid_for_seconds":3600}')
ALICE_KEY2=$(echo "$SELF_KEY_RESP" | json "['key']")
[ -n "$ALICE_KEY2" ] && { echo "✅ alice creates her own key (self-service)"; ((PASS++)) || true; } \
                      || { echo "❌ self-service key failed: $SELF_KEY_RESP"; ((FAIL++)) || true; }

ME_SELF=$(curl -s "$BASE/me" -H "Authorization: Bearer $ALICE_KEY2")
check "$(echo "$ME_SELF" | json "['name']")" "alice" "self-service key authenticates as alice"

# ── Results ───────────────────────────────────────────────────────────────────
echo ""
echo "Results: $PASS passed, $FAIL failed"
[ $FAIL -eq 0 ] && exit 0 || exit 1
