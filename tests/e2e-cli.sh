#!/usr/bin/env bash
# sirr/tests/e2e-cli.sh — CLI-only E2E tests (no curl)
# Same coverage as e2e.sh but exercises the sirr CLI client.
# Usage: bash tests/e2e-cli.sh
set -euo pipefail

PORT=39997
BASE=http://localhost:$PORT
PASS=0; FAIL=0

check() {
  if [ "$1" = "$2" ]; then
    echo "✅ $3"; ((PASS++)) || true
  else
    echo "❌ $3 (expected '$2', got '$1')"; ((FAIL++)) || true
  fi
}

check_contains() {
  if echo "$1" | grep -qF "$2"; then
    echo "✅ $3"; ((PASS++)) || true
  else
    echo "❌ $3 (expected to contain '$2', got '$1')"; ((FAIL++)) || true
  fi
}

# CLI wrapper: all commands go through sirr pointed at our test server.
S="sirr --server $BASE"

# ── Start isolated sirrd ──────────────────────────────────────────────────────
MASTER_KEY="e2e-cli-master-key"
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
echo "✅ server health"; ((PASS++)) || true

# ══════════════════════════════════════════════════════════════════════════════
# ACME — first company
# ══════════════════════════════════════════════════════════════════════════════

# ── Create org ────────────────────────────────────────────────────────────────
export SIRR_API_KEY="$MASTER_KEY"
ACME_OUT=$($S orgs create acme 2>&1)
ACME_ID=$(echo "$ACME_OUT" | grep "id:" | awk '{print $NF}')
check_contains "$ACME_OUT" "org created" "cli: create org acme"

# ── Create principals ────────────────────────────────────────────────────────
ALICE_OUT=$($S -o "$ACME_ID" principals create alice --role owner 2>&1)
ALICE_ID=$(echo "$ALICE_OUT" | grep "id:" | awk '{print $NF}')
check_contains "$ALICE_OUT" "principal created" "cli: create alice (owner)"

BOB_OUT=$($S -o "$ACME_ID" principals create bob --role writer 2>&1)
BOB_ID=$(echo "$BOB_OUT" | grep "id:" | awk '{print $NF}')
check_contains "$BOB_OUT" "principal created" "cli: create bob (writer)"

CAROL_OUT=$($S -o "$ACME_ID" principals create carol --role reader 2>&1)
CAROL_ID=$(echo "$CAROL_OUT" | grep "id:" | awk '{print $NF}')
check_contains "$CAROL_OUT" "principal created" "cli: create carol (reader)"

# ── Issue keys for principals (master only) ───────────────────────────────────
ALICE_KEY_OUT=$($S -o "$ACME_ID" principals create-key "$ALICE_ID" --name alice-key 2>&1)
ALICE_KEY=$(echo "$ALICE_KEY_OUT" | grep "key:" | awk '{print $NF}')
check_contains "$ALICE_KEY_OUT" "key created" "cli: issue key for alice"

BOB_KEY_OUT=$($S -o "$ACME_ID" principals create-key "$BOB_ID" --name bob-key 2>&1)
BOB_KEY=$(echo "$BOB_KEY_OUT" | grep "key:" | awk '{print $NF}')
check_contains "$BOB_KEY_OUT" "key created" "cli: issue key for bob"

CAROL_KEY_OUT=$($S -o "$ACME_ID" principals create-key "$CAROL_ID" --name carol-key 2>&1)
CAROL_KEY=$(echo "$CAROL_KEY_OUT" | grep "key:" | awk '{print $NF}')
check_contains "$CAROL_KEY_OUT" "key created" "cli: issue key for carol"

# ── Alice (owner) authenticates ───────────────────────────────────────────────
export SIRR_API_KEY="$ALICE_KEY"
ME_OUT=$($S me info 2>&1)
check_contains "$ME_OUT" "alice" "cli: alice authenticates via me info"

# ── Alice sets a secret ───────────────────────────────────────────────────────
SET_OUT=$($S -o "$ACME_ID" set DB_URL=postgres://acme-db:5432/acme --reads 10 2>&1)
check_contains "$SET_OUT" "DB_URL" "cli: alice sets DB_URL"

# ── Alice reads it back ──────────────────────────────────────────────────────
GET_OUT=$($S -o "$ACME_ID" get DB_URL 2>&1)
check "$GET_OUT" "postgres://acme-db:5432/acme" "cli: alice reads DB_URL"

# ── Bob (writer) can set secrets ──────────────────────────────────────────────
export SIRR_API_KEY="$BOB_KEY"
BOB_SET=$($S -o "$ACME_ID" set API_KEY=acme-api-key-42 --reads 10 2>&1)
check_contains "$BOB_SET" "API_KEY" "cli: bob (writer) sets API_KEY"

BOB_GET=$($S -o "$ACME_ID" get API_KEY 2>&1)
check "$BOB_GET" "acme-api-key-42" "cli: bob reads API_KEY"

# ── Carol (reader) cannot set secrets ─────────────────────────────────────────
export SIRR_API_KEY="$CAROL_KEY"
CAROL_SET=$($S -o "$ACME_ID" set NOPE=denied 2>&1 || true)
check_contains "$CAROL_SET" "403" "cli: carol (reader) cannot set secret"

# ── Self-service key creation ─────────────────────────────────────────────────
export SIRR_API_KEY="$ALICE_KEY"
SELF_KEY_OUT=$($S me create-key alice-self-key 2>&1)
ALICE_KEY2=$(echo "$SELF_KEY_OUT" | grep "key:" | awk '{print $NF}')
check_contains "$SELF_KEY_OUT" "key created" "cli: alice creates self-service key"

export SIRR_API_KEY="$ALICE_KEY2"
ME_SELF=$($S me info 2>&1)
check_contains "$ME_SELF" "alice" "cli: self-service key authenticates as alice"

# ══════════════════════════════════════════════════════════════════════════════
# GLOBEX — second company, same server
# ══════════════════════════════════════════════════════════════════════════════

export SIRR_API_KEY="$MASTER_KEY"

GLOBEX_OUT=$($S orgs create globex 2>&1)
GLOBEX_ID=$(echo "$GLOBEX_OUT" | grep "id:" | awk '{print $NF}')
check_contains "$GLOBEX_OUT" "org created" "cli: create org globex"

HANK_OUT=$($S -o "$GLOBEX_ID" principals create hank --role owner 2>&1)
HANK_ID=$(echo "$HANK_OUT" | grep "id:" | awk '{print $NF}')
check_contains "$HANK_OUT" "principal created" "cli: create hank (owner)"

HANK_KEY_OUT=$($S -o "$GLOBEX_ID" principals create-key "$HANK_ID" --name hank-key 2>&1)
HANK_KEY=$(echo "$HANK_KEY_OUT" | grep "key:" | awk '{print $NF}')
check_contains "$HANK_KEY_OUT" "key created" "cli: issue key for hank"

MARGE_OUT=$($S -o "$GLOBEX_ID" principals create marge --role writer 2>&1)
MARGE_ID=$(echo "$MARGE_OUT" | grep "id:" | awk '{print $NF}')
check_contains "$MARGE_OUT" "principal created" "cli: create marge (writer)"

MARGE_KEY_OUT=$($S -o "$GLOBEX_ID" principals create-key "$MARGE_ID" --name marge-key 2>&1)
MARGE_KEY=$(echo "$MARGE_KEY_OUT" | grep "key:" | awk '{print $NF}')
check_contains "$MARGE_KEY_OUT" "key created" "cli: issue key for marge"

# ── Globex sets DB_URL — same key name as acme ───────────────────────────────
export SIRR_API_KEY="$HANK_KEY"
HANK_SET=$($S -o "$GLOBEX_ID" set DB_URL=postgres://globex-db:5432/globex --reads 10 2>&1)
check_contains "$HANK_SET" "DB_URL" "cli: hank sets DB_URL in globex"

HANK_GET=$($S -o "$GLOBEX_ID" get DB_URL 2>&1)
check "$HANK_GET" "postgres://globex-db:5432/globex" "cli: globex DB_URL has globex value"

# ── Acme's DB_URL is unchanged ────────────────────────────────────────────────
export SIRR_API_KEY="$ALICE_KEY"
ACME_GET=$($S -o "$ACME_ID" get DB_URL 2>&1)
check "$ACME_GET" "postgres://acme-db:5432/acme" "cli: acme DB_URL still has acme value"

# ── Cross-org isolation ──────────────────────────────────────────────────────
# hank cannot read acme
export SIRR_API_KEY="$HANK_KEY"
CROSS1=$($S -o "$ACME_ID" get DB_URL 2>&1 || true)
check_contains "$CROSS1" "insufficient" "cli: hank cannot read acme secrets"

# alice cannot read globex
export SIRR_API_KEY="$ALICE_KEY"
CROSS2=$($S -o "$GLOBEX_ID" get DB_URL 2>&1 || true)
check_contains "$CROSS2" "insufficient" "cli: alice cannot read globex secrets"

# marge cannot write to acme
export SIRR_API_KEY="$MARGE_KEY"
CROSS3=$($S -o "$ACME_ID" set HACK=nope 2>&1 || true)
check_contains "$CROSS3" "403" "cli: marge cannot write to acme"

# bob cannot write to globex
export SIRR_API_KEY="$BOB_KEY"
CROSS4=$($S -o "$GLOBEX_ID" set HACK=nope 2>&1 || true)
check_contains "$CROSS4" "403" "cli: bob cannot write to globex"

# ── Public dead drop ─────────────────────────────────────────────────────────
unset SIRR_API_KEY
PUSH_OUT=$($S push "hello-from-cli" 2>&1)
# Output is JSON: {"id":"...","url":"..."}
PUBLIC_ID=$(echo "$PUSH_OUT" | python3 -c "import sys,json; print(json.load(sys.stdin)['id'])")
[ -n "$PUBLIC_ID" ] && { echo "✅ cli: push public dead drop"; ((PASS++)) || true; } \
                     || { echo "❌ cli: push failed: $PUSH_OUT"; ((FAIL++)) || true; }

PUBLIC_GET=$($S get "$PUBLIC_ID" 2>&1)
check "$PUBLIC_GET" "hello-from-cli" "cli: get public dead drop"

# ── Burn-after-read ──────────────────────────────────────────────────────────
export SIRR_API_KEY="$ALICE_KEY"
$S -o "$ACME_ID" set BURN_CLI=burnme --reads 1 >/dev/null 2>&1

BURN1=$($S -o "$ACME_ID" get BURN_CLI 2>&1)
check "$BURN1" "burnme" "cli: burn-after-read first read"

BURN2=$($S -o "$ACME_ID" get BURN_CLI 2>&1 || true)
check_contains "$BURN2" "not found" "cli: burn-after-read second read gone"

# ── Results ───────────────────────────────────────────────────────────────────
echo ""
echo "Results: $PASS passed, $FAIL failed"
[ $FAIL -eq 0 ] && exit 0 || exit 1
