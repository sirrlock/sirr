#!/usr/bin/env bash
# sirr/tests/e2e.sh — end-to-end smoke test against real binaries
# Starts sirrd, exercises sirr CLI + curl, then cleans up.
# Usage: cargo build --release && bash tests/e2e.sh
set -euo pipefail

PORT=39998
BASE=http://127.0.0.1:$PORT
PASS=0; FAIL=0

check() {
  if [ "$1" = "$2" ]; then
    echo "  ✅ $3"; ((PASS++)) || true
  else
    echo "  ❌ $3 (expected '$2', got '$1')"; ((FAIL++)) || true
  fi
}

check_contains() {
  if echo "$1" | grep -qF "$2"; then
    echo "  ✅ $3"; ((PASS++)) || true
  else
    echo "  ❌ $3 (expected to contain '$2', got '$1')"; ((FAIL++)) || true
  fi
}

status() { curl -s -o /dev/null -w "%{http_code}" "$@"; }

# ── Setup ────────────────────────────────────────────────────────────────────

E2E_DIR=$(mktemp -d)
SOCKET="$E2E_DIR/sirrd.sock"
SIRRD=./target/release/sirrd
SIRR=./target/release/sirr

if [ ! -f "$SIRRD" ] || [ ! -f "$SIRR" ]; then
  echo "Build first: cargo build --release"
  exit 1
fi

cleanup() {
  kill "$SIRRD_PID" 2>/dev/null || true
  rm -rf "$E2E_DIR"
}
trap cleanup EXIT

# Start sirrd in public mode (default)
"$SIRRD" serve \
  --bind "127.0.0.1:$PORT" \
  --data-dir "$E2E_DIR" \
  --admin-socket "$SOCKET" \
  >"$E2E_DIR/sirrd.log" 2>&1 &
SIRRD_PID=$!

# Wait for server
for i in $(seq 1 30); do
  if curl -sf "$BASE/health" >/dev/null 2>&1; then break; fi
  sleep 0.2
done

if ! curl -sf "$BASE/health" >/dev/null 2>&1; then
  echo "sirrd failed to start. Log:"
  cat "$E2E_DIR/sirrd.log"
  exit 1
fi

echo "sirrd running (pid $SIRRD_PID, port $PORT)"
echo ""

# ══════════════════════════════════════════════════════════════════════════════
# PUBLIC MODE (default)
# ══════════════════════════════════════════════════════════════════════════════

echo "── Public mode ──"

# Push a secret (anonymous, no token)
PUSH_OUT=$(SIRR_SERVER="$BASE" "$SIRR" push "hello-public" --reads 3 2>&1)
HASH=$(echo "$PUSH_OUT" | grep -oE '[a-f0-9]{64}')
[ -n "$HASH" ] && { echo "  ✅ push returns hash"; ((PASS++)) || true; } \
               || { echo "  ❌ push failed: $PUSH_OUT"; ((FAIL++)) || true; }

# Read it back
GET_OUT=$(SIRR_SERVER="$BASE" "$SIRR" get "$HASH" 2>&1)
check "$GET_OUT" "hello-public" "get returns value"

# Inspect (HEAD) — does NOT consume a read
INSPECT_OUT=$(SIRR_SERVER="$BASE" "$SIRR" inspect "$HASH" 2>&1)
check_contains "$INSPECT_OUT" "reads-remaining" "inspect shows metadata"

# Read again (should still work — inspect didn't consume)
GET_OUT2=$(SIRR_SERVER="$BASE" "$SIRR" get "$HASH" 2>&1)
check "$GET_OUT2" "hello-public" "get after inspect still works"

# Burn it
BURN_OUT=$(SIRR_SERVER="$BASE" "$SIRR" burn "$HASH" 2>&1)
check_contains "$BURN_OUT" "burned" "burn succeeds"

# Read after burn → gone
BURN_GET=$(SIRR_SERVER="$BASE" "$SIRR" get "$HASH" 2>&1 || true)
check_contains "$BURN_GET" "gone" "get after burn is gone"

# Burn-after-read: push with --reads 1
PUSH2_OUT=$(SIRR_SERVER="$BASE" "$SIRR" push "one-shot" --reads 1 2>&1)
HASH2=$(echo "$PUSH2_OUT" | grep -oE '[a-f0-9]{64}')
READ1=$(SIRR_SERVER="$BASE" "$SIRR" get "$HASH2" 2>&1)
check "$READ1" "one-shot" "burn-after-read: first read"
READ2_STATUS=$(status "$BASE/secret/$HASH2")
check "$READ2_STATUS" "410" "burn-after-read: second read → 410"

# Push with prefix
PUSH3_OUT=$(SIRR_SERVER="$BASE" "$SIRR" push "prefixed" --prefix "db1_" 2>&1)
HASH3=$(echo "$PUSH3_OUT" | grep -oE 'db1_[a-f0-9]{64}')
[ -n "$HASH3" ] && { echo "  ✅ prefix appears in hash"; ((PASS++)) || true; } \
               || { echo "  ❌ prefix missing: $PUSH3_OUT"; ((FAIL++)) || true; }

echo ""

# ══════════════════════════════════════════════════════════════════════════════
# SWITCH TO PRIVATE MODE
# ══════════════════════════════════════════════════════════════════════════════

echo "── Private mode ──"

# Switch visibility
SIRR_ADMIN_SOCKET="$SOCKET" "$SIRRD" visibility set private >/dev/null 2>&1
VIS_OUT=$(SIRR_ADMIN_SOCKET="$SOCKET" "$SIRRD" visibility get 2>&1)
check_contains "$VIS_OUT" "private" "visibility set to private"

# Anonymous push should fail
ANON_PUSH_STATUS=$(status -X POST "$BASE/secret" \
  -H "Content-Type: application/json" \
  -d '{"value":"should-fail"}')
check "$ANON_PUSH_STATUS" "401" "anon push rejected in private mode"

# Create a key
KEY_OUT=$(SIRR_ADMIN_SOCKET="$SOCKET" "$SIRRD" keys create alice 2>&1)
TOKEN=$(echo "$KEY_OUT" | grep -oE '[a-f0-9]{64}')
[ -n "$TOKEN" ] && { echo "  ✅ keys create returns token"; ((PASS++)) || true; } \
               || { echo "  ❌ keys create failed: $KEY_OUT"; ((FAIL++)) || true; }

# List keys
LIST_OUT=$(SIRR_ADMIN_SOCKET="$SOCKET" "$SIRRD" keys list 2>&1)
check_contains "$LIST_OUT" "alice" "keys list shows alice"

# Keyed push
PUSH4_OUT=$(SIRR_SERVER="$BASE" SIRR_TOKEN="$TOKEN" "$SIRR" push "private-secret" --reads 5 2>&1)
HASH4=$(echo "$PUSH4_OUT" | grep -oE '[a-f0-9]{64}')
[ -n "$HASH4" ] && { echo "  ✅ keyed push succeeds"; ((PASS++)) || true; } \
               || { echo "  ❌ keyed push failed: $PUSH4_OUT"; ((FAIL++)) || true; }

# Anonymous read still works (reads are universal)
ANON_READ=$(curl -s "$BASE/secret/$HASH4")
check_contains "$ANON_READ" "private-secret" "anon read works in private mode"

# Patch (owner only)
PATCH_OUT=$(SIRR_SERVER="$BASE" SIRR_TOKEN="$TOKEN" "$SIRR" patch "$HASH4" "patched-value" 2>&1)
check_contains "$PATCH_OUT" "$HASH4" "owner can patch"

# Read patched value
PATCHED_READ=$(SIRR_SERVER="$BASE" "$SIRR" get "$HASH4" 2>&1)
check "$PATCHED_READ" "patched-value" "patched value reads back"

# Audit (owner only)
AUDIT_OUT=$(SIRR_SERVER="$BASE" SIRR_TOKEN="$TOKEN" "$SIRR" audit "$HASH4" 2>&1)
check_contains "$AUDIT_OUT" "secret.create" "audit shows create event"
check_contains "$AUDIT_OUT" "secret.read" "audit shows read event"
check_contains "$AUDIT_OUT" "secret.patch" "audit shows patch event"

# Audit without token → 401
AUDIT_ANON_STATUS=$(status "$BASE/secret/$HASH4/audit")
check "$AUDIT_ANON_STATUS" "401" "anon audit rejected"

# Create second key — wrong key can't patch/burn
KEY2_OUT=$(SIRR_ADMIN_SOCKET="$SOCKET" "$SIRRD" keys create bob 2>&1)
TOKEN2=$(echo "$KEY2_OUT" | grep -oE '[a-f0-9]{64}')

WRONG_PATCH_STATUS=$(status -X PATCH "$BASE/secret/$HASH4" \
  -H "Authorization: Bearer $TOKEN2" \
  -H "Content-Type: application/json" \
  -d '{"value":"hacked"}')
check "$WRONG_PATCH_STATUS" "404" "wrong key patch → 404 (not 403)"

WRONG_BURN_STATUS=$(status -X DELETE "$BASE/secret/$HASH4" \
  -H "Authorization: Bearer $TOKEN2")
check "$WRONG_BURN_STATUS" "404" "wrong key burn → 404 (not 403)"

# Owner burns
BURN2_OUT=$(SIRR_SERVER="$BASE" SIRR_TOKEN="$TOKEN" "$SIRR" burn "$HASH4" 2>&1)
check_contains "$BURN2_OUT" "burned" "owner burns own secret"

# Admin: keys secrets
SECRETS_OUT=$(SIRR_ADMIN_SOCKET="$SOCKET" "$SIRRD" keys secrets alice 2>&1)
check_contains "$SECRETS_OUT" "count" "keys secrets shows stats"

echo ""

# ══════════════════════════════════════════════════════════════════════════════
# BOTH MODE
# ══════════════════════════════════════════════════════════════════════════════

echo "── Both mode ──"

SIRR_ADMIN_SOCKET="$SOCKET" "$SIRRD" visibility set both >/dev/null 2>&1

# Anonymous push works
PUSH5_OUT=$(SIRR_SERVER="$BASE" "$SIRR" push "anon-in-both" 2>&1)
HASH5=$(echo "$PUSH5_OUT" | grep -oE '[a-f0-9]{64}')
[ -n "$HASH5" ] && { echo "  ✅ anon push in both mode"; ((PASS++)) || true; } \
               || { echo "  ❌ anon push failed: $PUSH5_OUT"; ((FAIL++)) || true; }

# Keyed push also works
PUSH6_OUT=$(SIRR_SERVER="$BASE" SIRR_TOKEN="$TOKEN" "$SIRR" push "keyed-in-both" 2>&1)
HASH6=$(echo "$PUSH6_OUT" | grep -oE '[a-f0-9]{64}')
[ -n "$HASH6" ] && { echo "  ✅ keyed push in both mode"; ((PASS++)) || true; } \
               || { echo "  ❌ keyed push failed: $PUSH6_OUT"; ((FAIL++)) || true; }

echo ""

# ══════════════════════════════════════════════════════════════════════════════
# NONE MODE (lockdown)
# ══════════════════════════════════════════════════════════════════════════════

echo "── None mode (lockdown) ──"

SIRR_ADMIN_SOCKET="$SOCKET" "$SIRRD" visibility set none >/dev/null 2>&1

LOCK_READ=$(status "$BASE/secret/$HASH5")
check "$LOCK_READ" "503" "read → 503 in none mode"

LOCK_PUSH=$(status -X POST "$BASE/secret" \
  -H "Content-Type: application/json" \
  -d '{"value":"nope"}')
check "$LOCK_PUSH" "503" "push → 503 in none mode"

# Recover
SIRR_ADMIN_SOCKET="$SOCKET" "$SIRRD" visibility set public >/dev/null 2>&1
RECOVER_READ=$(SIRR_SERVER="$BASE" "$SIRR" get "$HASH5" 2>&1)
check "$RECOVER_READ" "anon-in-both" "read works after recovery from none"

echo ""

# ══════════════════════════════════════════════════════════════════════════════
# WEBHOOK (quick check — just verify no crash)
# ══════════════════════════════════════════════════════════════════════════════

echo "── Webhook (smoke) ──"

# Create a key with a webhook URL (pointed at nothing — we just check it doesn't crash sirrd)
SIRR_ADMIN_SOCKET="$SOCKET" "$SIRRD" visibility set private >/dev/null 2>&1
WH_KEY_OUT=$(SIRR_ADMIN_SOCKET="$SOCKET" "$SIRRD" keys create webhook-test \
  --webhook "http://127.0.0.1:19999/hook" 2>&1)
WH_TOKEN=$(echo "$WH_KEY_OUT" | grep -oE '[a-f0-9]{64}')

# Push with webhook key — should succeed even though webhook target is down
WH_PUSH_OUT=$(SIRR_SERVER="$BASE" SIRR_TOKEN="$WH_TOKEN" "$SIRR" push "webhook-secret" --reads 1 2>&1)
WH_HASH=$(echo "$WH_PUSH_OUT" | grep -oE '[a-f0-9]{64}')
[ -n "$WH_HASH" ] && { echo "  ✅ push with webhook key (fire-and-forget, target down)"; ((PASS++)) || true; } \
                   || { echo "  ❌ push with webhook key failed: $WH_PUSH_OUT"; ((FAIL++)) || true; }

echo ""

# ══════════════════════════════════════════════════════════════════════════════
# ADMIN: purge + audit
# ══════════════════════════════════════════════════════════════════════════════

echo "── Admin operations ──"

PURGE_OUT=$(SIRR_ADMIN_SOCKET="$SOCKET" "$SIRRD" keys purge alice --yes 2>&1)
check_contains "$PURGE_OUT" "burned" "keys purge alice"

AUDIT_ADMIN=$(SIRR_ADMIN_SOCKET="$SOCKET" "$SIRRD" audit --limit 5 2>&1)
# Should have some events from all the operations above
[ -n "$AUDIT_ADMIN" ] && { echo "  ✅ admin audit returns events"; ((PASS++)) || true; } \
                       || { echo "  ❌ admin audit empty"; ((FAIL++)) || true; }

# Delete keys
SIRR_ADMIN_SOCKET="$SOCKET" "$SIRRD" keys delete alice >/dev/null 2>&1
SIRR_ADMIN_SOCKET="$SOCKET" "$SIRRD" keys delete bob >/dev/null 2>&1
SIRR_ADMIN_SOCKET="$SOCKET" "$SIRRD" keys delete webhook-test >/dev/null 2>&1

LIST_AFTER=$(SIRR_ADMIN_SOCKET="$SOCKET" "$SIRRD" keys list 2>&1)
check_contains "$LIST_AFTER" "no keys" "all keys deleted"

echo ""

# ── Results ───────────────────────────────────────────────────────────────────
echo "════════════════════════════════════════"
echo "Results: $PASS passed, $FAIL failed"
echo "════════════════════════════════════════"
[ $FAIL -eq 0 ] && exit 0 || exit 1
