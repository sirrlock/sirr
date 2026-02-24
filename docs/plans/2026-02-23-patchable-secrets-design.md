# Patchable Secrets, HEAD Metadata, and Auth Overhaul

**Date:** 2026-02-23

## Summary

Three interconnected changes to Sirr:

1. Add a `delete` flag to secrets — `delete=false` secrets are patchable and sealed (not deleted) when reads are exhausted.
2. Add `HEAD /secrets/:key` returning read stats via headers.
3. Remove mandatory master-key auth; use server-generated encryption key; add optional CORS and API key for write-protection.

## 1. Auth & Encryption Overhaul

### Current state

`SIRR_MASTER_KEY` env var does double duty:
- Argon2id seed for ChaCha20Poly1305 encryption key
- Bearer token for all API routes

### New state

**Encryption:** Server generates a random 32-byte key on first boot, stored as `sirr.key` next to `sirr.db`. Argon2id derivation from master key is removed.

**Auth:** `require_auth` middleware removed. All routes are public by default.

**Optional write-protection:** New env var `SIRR_API_KEY`. When set, POST/PATCH/DELETE require `Authorization: Bearer <SIRR_API_KEY>`. GET/HEAD are always public.

**CORS:** New env vars:
- `SIRR_CORS_ORIGINS` — comma-separated allowed origins (default: `*`)
- `SIRR_CORS_METHODS` — comma-separated methods (default: `GET,HEAD,POST,PATCH,DELETE,OPTIONS`)

**Breaking change:** Existing databases encrypted with Argon2id(master_key) will NOT be readable. This is acceptable for an ephemeral secret store.

**Removed env vars:** `SIRR_MASTER_KEY` (no longer used).

## 2. `delete` Flag

### Model change

```rust
pub struct SecretRecord {
    pub value_encrypted: Vec<u8>,
    pub nonce: [u8; 12],
    pub created_at: i64,
    pub expires_at: Option<i64>,
    pub max_reads: Option<u32>,
    pub read_count: u32,
    pub delete: bool,           // NEW — default true
}
```

### Behavior matrix

| `delete` | `read_count >= max_reads` | GET result           | Record fate       |
|----------|--------------------------|----------------------|-------------------|
| `true`   | yes                      | 200 (final read)     | Deleted from DB   |
| `false`  | yes                      | 410 Gone             | Stays in DB (sealed) |
| either   | TTL expired              | 404                  | Pruned by sweep   |

### State transitions

```
                 PATCH (resets read_count)
                 ┌──────────┐
                 v          │
  [active] ──read──> [sealed] ──DELETE──> [gone]
     │                                       ^
     └────── delete=true, final read ────────┘
```

### Method semantics

- `is_expired(now)` — TTL check only.
- `is_burned()` — `delete == true && read_count >= max_reads`. Triggers record deletion.
- `is_sealed()` — `delete == false && read_count >= max_reads`. Blocks reads, allows PATCH.

## 3. PATCH /secrets/:key

**Constraint:** Only allowed on secrets where `delete == false`. Returns 409 Conflict for `delete == true` secrets.

**Request body:**
```json
{
  "value": "new-value",        // optional
  "max_reads": 10,             // optional
  "ttl_seconds": 3600          // optional
}
```

All fields optional. Omitted fields keep their current values.

**Side effects:**
- `read_count` reset to 0 (always, regardless of which fields changed).
- If `value` provided, re-encrypt with new nonce.
- If `ttl_seconds` provided, recompute `expires_at` from now.

**Response:** 200 with updated metadata.

**Store method:** `Store::patch(key, value?, max_reads?, ttl_seconds?) -> Result<Option<SecretMeta>>`

## 4. HEAD /secrets/:key

**Public.** Does NOT increment read_count.

**Response headers:**
| Header | Value | Example |
|--------|-------|---------|
| `X-Sirr-Read-Count` | current reads | `3` |
| `X-Sirr-Reads-Remaining` | max_reads - read_count, or `unlimited` | `7` |
| `X-Sirr-Delete` | `true` or `false` | `false` |
| `X-Sirr-Created-At` | unix timestamp | `1708700000` |
| `X-Sirr-Expires-At` | unix timestamp or absent | `1708703600` |
| `X-Sirr-Status` | `active`, `sealed`, or absent | `sealed` |

**Status codes:** 200 (exists), 404 (not found or TTL expired), 410 (sealed).

**Store method:** `Store::head(key) -> Result<Option<(SecretMeta, bool)>>` — returns metadata + sealed status without side effects.

## 5. URL Scheme

URLs are `https://<host>/secrets/<key>`. The `#` fragment is client-side only (never sent to server).

Users can use UUIDs as key names for unguessable URLs:
```bash
sirr push MY_SECRET=value --delete=false --reads 5
# Share: https://sirr.example.com/secrets/MY_SECRET
```

## 6. API Surface (final)

| Method | Route | Auth | Purpose |
|--------|-------|------|---------|
| GET | `/health` | none | Health check |
| POST | `/secrets` | API key (if set) | Create secret |
| GET | `/secrets` | API key (if set) | List all secrets metadata |
| GET | `/secrets/:key` | none | Read secret (burns read) |
| HEAD | `/secrets/:key` | none | Read stats (no burn) |
| PATCH | `/secrets/:key` | API key (if set) | Update value/config (delete=false only) |
| DELETE | `/secrets/:key` | API key (if set) | Delete secret |
| POST | `/prune` | API key (if set) | Force prune expired |

## 7. Files to modify

### Rust crates
- `crates/sirr-server/src/store/model.rs` — add `delete` field, split is_expired
- `crates/sirr-server/src/store/db.rs` — add `head()`, `patch()`, update `put()` and `get()`
- `crates/sirr-server/src/store/crypto.rs` — add `generate_key()` (random 32 bytes, no Argon2id)
- `crates/sirr-server/src/handlers.rs` — add `head_secret`, `patch_secret`, update `create_secret`
- `crates/sirr-server/src/server.rs` — new routes, remove require_auth, add CORS, add optional API key auth
- `crates/sirr-server/src/auth.rs` — replace with optional API key middleware
- `crates/sirr-server/src/lib.rs` — update AppState (remove master_key, add optional api_key)
- `crates/sirr/src/main.rs` — update CLI args (remove --token, add --api-key, add --delete flag)

### Tests
- `crates/sirr-server/src/store/db.rs` — tests for head, patch, sealed behavior
