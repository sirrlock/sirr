# Patchable Secrets Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add patchable secrets (delete flag), HEAD metadata endpoint, and replace master-key auth with server-generated encryption key + optional API key write-protection.

**Architecture:** Three layers of change bottom-up: (1) model + crypto foundations, (2) store operations, (3) HTTP handlers + routing + auth. The CLI updates last since it's a consumer of the server library.

**Tech Stack:** Rust (axum 0.8, redb 2, chacha20poly1305 0.10, tower-http CORS), existing test infra (tempfile + built-in `#[test]`)

**Design doc:** `docs/plans/2026-02-23-patchable-secrets-design.md`

---

### Task 1: Crypto — generate_key() and remove Argon2id dependency

**Files:**
- Modify: `crates/sirr-server/src/store/crypto.rs`

**Step 1: Write the failing test**

Add to the existing `#[cfg(test)] mod tests` block in `crypto.rs`:

```rust
#[test]
fn generate_key_round_trip() {
    let key = generate_key();
    let plaintext = b"test with generated key";
    let (ct, nonce) = encrypt(&key, plaintext).unwrap();
    let pt = decrypt(&key, &ct, &nonce).unwrap();
    assert_eq!(pt, plaintext);
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test -p sirr-server generate_key_round_trip`
Expected: FAIL — `generate_key` not defined

**Step 3: Implement generate_key()**

Add to `crypto.rs` (after `generate_salt`):

```rust
/// Generate a random 32-byte encryption key (no Argon2id derivation).
pub fn generate_key() -> EncryptionKey {
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    EncryptionKey(key)
}

/// Load an existing key from bytes, or return None if wrong length.
pub fn load_key(bytes: &[u8]) -> Option<EncryptionKey> {
    if bytes.len() != 32 {
        return None;
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(bytes);
    Some(EncryptionKey(key))
}
```

**Step 4: Run test to verify it passes**

Run: `cargo test -p sirr-server generate_key_round_trip`
Expected: PASS

**Step 5: Verify all existing tests still pass**

Run: `cargo test -p sirr-server`
Expected: All pass (existing derive_key tests still work)

**Step 6: Commit**

```bash
git add crates/sirr-server/src/store/crypto.rs
git commit -m "feat: add generate_key() for server-side random encryption key"
```

---

### Task 2: Model — add `delete` field and split expiry checks

**Files:**
- Modify: `crates/sirr-server/src/store/model.rs`

**Step 1: Write failing tests**

Add to end of `model.rs` (new test module):

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn make_record(delete: bool, max_reads: Option<u32>, read_count: u32) -> SecretRecord {
        SecretRecord {
            value_encrypted: vec![],
            nonce: [0u8; 12],
            created_at: 1000,
            expires_at: None,
            max_reads,
            read_count,
            delete,
        }
    }

    #[test]
    fn is_expired_only_checks_ttl() {
        let r = make_record(true, Some(1), 5); // read_count > max_reads but is_expired only checks TTL
        assert!(!r.is_expired(1000)); // not TTL-expired
        let r2 = SecretRecord { expires_at: Some(500), ..r };
        assert!(r2.is_expired(1000)); // TTL-expired
    }

    #[test]
    fn is_burned_only_when_delete_true() {
        let r = make_record(true, Some(3), 3);
        assert!(r.is_burned());
        let r2 = make_record(false, Some(3), 3);
        assert!(!r2.is_burned()); // delete=false, so not burned
    }

    #[test]
    fn is_sealed_only_when_delete_false() {
        let r = make_record(false, Some(3), 3);
        assert!(r.is_sealed());
        let r2 = make_record(true, Some(3), 3);
        assert!(!r2.is_sealed()); // delete=true, so not sealed
    }

    #[test]
    fn no_max_reads_never_burned_or_sealed() {
        let r = make_record(true, None, 100);
        assert!(!r.is_burned());
        assert!(!r.is_sealed());
    }
}
```

**Step 2: Run tests to verify they fail**

Run: `cargo test -p sirr-server model::tests`
Expected: FAIL — `delete` field doesn't exist, methods don't exist

**Step 3: Update SecretRecord and add methods**

Replace the entire model.rs content:

```rust
use serde::{Deserialize, Serialize};
use zeroize::ZeroizeOnDrop;

/// Stored in redb as bincode-encoded bytes.
/// `value_encrypted` is ChaCha20Poly1305 ciphertext over the raw secret value.
/// All metadata is plaintext so the background sweep can evict without decrypting.
#[derive(Debug, Clone, Serialize, Deserialize, ZeroizeOnDrop)]
pub struct SecretRecord {
    /// ChaCha20Poly1305 ciphertext (value + tag).
    pub value_encrypted: Vec<u8>,
    /// Per-record random 12-byte nonce.
    pub nonce: [u8; 12],
    /// Unix timestamp (seconds) when the record was created.
    pub created_at: i64,
    /// Optional Unix timestamp (seconds) after which the record is expired.
    pub expires_at: Option<i64>,
    /// Optional maximum number of reads before the record self-destructs or seals.
    pub max_reads: Option<u32>,
    /// How many times this record has been read.
    pub read_count: u32,
    /// If true (default), record is deleted when max_reads is reached.
    /// If false, record is sealed (reads blocked, PATCH allowed).
    #[serde(default = "default_delete")]
    pub delete: bool,
}

fn default_delete() -> bool {
    true
}

impl SecretRecord {
    /// Returns true if this record has expired by TTL only.
    pub fn is_expired(&self, now: i64) -> bool {
        matches!(self.expires_at, Some(exp) if now >= exp)
    }

    /// Returns true if this record should be deleted (delete=true and read limit hit).
    pub fn is_burned(&self) -> bool {
        self.delete && matches!(self.max_reads, Some(max) if self.read_count >= max)
    }

    /// Returns true if this record is sealed (delete=false and read limit hit).
    pub fn is_sealed(&self) -> bool {
        !self.delete && matches!(self.max_reads, Some(max) if self.read_count >= max)
    }
}

/// Metadata returned on list/describe endpoints — never includes the value.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretMeta {
    pub key: String,
    pub created_at: i64,
    pub expires_at: Option<i64>,
    pub max_reads: Option<u32>,
    pub read_count: u32,
    pub delete: bool,
}
```

Note: `#[serde(default = "default_delete")]` ensures backward compatibility — old records without the `delete` field deserialize with `delete: true` (existing burn behavior preserved).

**Step 4: Run tests to verify they pass**

Run: `cargo test -p sirr-server model::tests`
Expected: PASS

**Step 5: Fix compilation errors in db.rs**

The `db.rs` code calls `record.is_expired(now)` which previously checked both TTL and reads. Now it only checks TTL. Update `db.rs`:

In `Store::get()`, replace the expiry logic (lines ~100-127) with:

```rust
// Lazy expiry check (TTL only).
if record.is_expired(now) {
    table.remove(secret_key)?;
    debug!(key = %secret_key, "lazy-evicted expired secret");
    None
} else if record.is_sealed() {
    // Sealed: reads exhausted on delete=false secret.
    None // Handler will return 410
} else {
    record.read_count += 1;

    // Decrypt before potentially deleting the record.
    let plaintext = super::crypto::decrypt(
        &self.key,
        &record.value_encrypted,
        &record.nonce,
    )
    .context("decrypt value")?;

    let value = String::from_utf8(plaintext)
        .context("secret value is not valid UTF-8")?;

    // Check burn condition AFTER incrementing.
    if record.is_burned() {
        table.remove(secret_key)?;
        debug!(key = %secret_key, "burned after final read");
    } else {
        // Write back updated read_count.
        let updated = encode(&record)?;
        table.insert(secret_key, updated.as_slice())?;
    }

    Some(value)
}
```

In `Store::put()`, add `delete` parameter:

```rust
pub fn put(
    &self,
    secret_key: &str,
    value: &str,
    ttl_seconds: Option<u64>,
    max_reads: Option<u32>,
    delete: bool,
) -> Result<()> {
```

And add `delete` to the `SecretRecord` construction:

```rust
let record = SecretRecord {
    value_encrypted,
    nonce,
    created_at: now,
    expires_at,
    max_reads,
    read_count: 0,
    delete,
};
```

In `Store::list()`, add `delete` to SecretMeta construction:

```rust
metas.push(SecretMeta {
    key: k.value().to_owned(),
    created_at: record.created_at,
    expires_at: record.expires_at,
    max_reads: record.max_reads,
    read_count: record.read_count,
    delete: record.delete,
});
```

In `Store::prune()`, update the expiry check to also prune burned records:

```rust
if record.is_expired(now) || record.is_burned() {
    keys.push(k.value().to_owned());
}
```

**Step 6: Fix existing tests in db.rs**

Update all `s.put(...)` calls to include the `delete` parameter:

```rust
// put_get_delete test:
s.put("MY_KEY", "my-value", None, None, true).unwrap();

// read_limit_burn test:
s.put("BURN", "secret", None, Some(1), true).unwrap();

// ttl_expiry test:
s.put("EXPIRED", "value", Some(0), None, true).unwrap();

// list_excludes_expired test:
s.put("LIVE", "v", Some(3600), None, true).unwrap();
s.put("DEAD", "v", Some(0), None, true).unwrap();
```

**Step 7: Fix handlers.rs**

In `create_secret`, update the `store.put` call to pass `delete` from request body.

Add `delete` to `CreateRequest`:

```rust
#[derive(Debug, Deserialize)]
pub struct CreateRequest {
    pub key: String,
    pub value: String,
    pub ttl_seconds: Option<u64>,
    pub max_reads: Option<u32>,
    #[serde(default = "default_delete")]
    pub delete: Option<bool>,
}

fn default_delete() -> Option<bool> {
    Some(true)
}
```

Update the `store.put` call:

```rust
.put(&body.key, &body.value, body.ttl_seconds, body.max_reads, body.delete.unwrap_or(true))
```

**Step 8: Run all tests**

Run: `cargo test -p sirr-server`
Expected: All pass

**Step 9: Commit**

```bash
git add crates/sirr-server/src/store/model.rs crates/sirr-server/src/store/db.rs crates/sirr-server/src/handlers.rs
git commit -m "feat: add delete flag to SecretRecord, split expiry into burned/sealed"
```

---

### Task 3: Store — add head() and patch() methods

**Files:**
- Modify: `crates/sirr-server/src/store/db.rs`

**Step 1: Write failing tests for head()**

Add to the `#[cfg(test)] mod tests` block in `db.rs`:

```rust
#[test]
fn head_returns_meta_without_incrementing() {
    let (s, _dir) = make_store();
    s.put("H", "val", None, Some(5), true).unwrap();
    let (meta, sealed) = s.head("H").unwrap().unwrap();
    assert_eq!(meta.read_count, 0);
    assert_eq!(meta.max_reads, Some(5));
    assert!(!sealed);
    // Call head again — still 0
    let (meta2, _) = s.head("H").unwrap().unwrap();
    assert_eq!(meta2.read_count, 0);
}

#[test]
fn head_returns_none_for_expired() {
    let (s, _dir) = make_store();
    s.put("HE", "val", Some(0), None, true).unwrap();
    assert!(s.head("HE").unwrap().is_none());
}

#[test]
fn head_returns_sealed_status() {
    let (s, _dir) = make_store();
    s.put("HS", "val", None, Some(1), false).unwrap();
    s.get("HS").unwrap(); // read once, hits limit
    let (meta, sealed) = s.head("HS").unwrap().unwrap();
    assert!(sealed);
    assert_eq!(meta.read_count, 1);
}
```

**Step 2: Run tests to verify they fail**

Run: `cargo test -p sirr-server head_returns`
Expected: FAIL — `head` method not defined

**Step 3: Implement head()**

Add to `impl Store` in `db.rs`:

```rust
/// Retrieve metadata for a secret without incrementing read_count.
/// Returns (meta, is_sealed). Returns None if not found or TTL-expired.
pub fn head(&self, secret_key: &str) -> Result<Option<(SecretMeta, bool)>> {
    let now = Self::now();
    let read_txn = self.db.begin_read()?;
    let table = read_txn.open_table(SECRETS)?;

    let raw_bytes: Option<Vec<u8>> =
        table.get(secret_key)?.map(|guard| guard.value().to_vec());

    match raw_bytes {
        None => Ok(None),
        Some(bytes) => {
            let record: SecretRecord = decode(&bytes)?;
            if record.is_expired(now) {
                return Ok(None);
            }
            let sealed = record.is_sealed();
            Ok(Some((
                SecretMeta {
                    key: secret_key.to_owned(),
                    created_at: record.created_at,
                    expires_at: record.expires_at,
                    max_reads: record.max_reads,
                    read_count: record.read_count,
                    delete: record.delete,
                },
                sealed,
            )))
        }
    }
}
```

**Step 4: Run head tests**

Run: `cargo test -p sirr-server head_returns`
Expected: PASS

**Step 5: Write failing tests for patch()**

```rust
#[test]
fn patch_updates_value_and_resets_count() {
    let (s, _dir) = make_store();
    s.put("P", "old", None, Some(5), false).unwrap();
    s.get("P").unwrap(); // read_count = 1
    let meta = s.patch("P", Some("new"), None, None).unwrap().unwrap();
    assert_eq!(meta.read_count, 0); // reset
    assert_eq!(s.get("P").unwrap(), Some("new".into()));
}

#[test]
fn patch_rejects_delete_true_secret() {
    let (s, _dir) = make_store();
    s.put("PD", "val", None, None, true).unwrap();
    let err = s.patch("PD", Some("new"), None, None);
    assert!(err.is_err()); // should error for delete=true
}

#[test]
fn patch_unseals_secret() {
    let (s, _dir) = make_store();
    s.put("PS", "val", None, Some(1), false).unwrap();
    s.get("PS").unwrap(); // now sealed
    assert!(s.get("PS").unwrap().is_none()); // sealed, can't read
    s.patch("PS", None, Some(5), None).unwrap(); // unseal with new max_reads
    assert_eq!(s.get("PS").unwrap(), Some("val".into())); // readable again
}

#[test]
fn patch_not_found() {
    let (s, _dir) = make_store();
    let result = s.patch("NOPE", Some("val"), None, None).unwrap();
    assert!(result.is_none());
}
```

**Step 6: Run tests to verify they fail**

Run: `cargo test -p sirr-server patch_`
Expected: FAIL — `patch` method not defined

**Step 7: Implement patch()**

Add to `impl Store` in `db.rs`:

```rust
/// Update an existing secret (only if delete=false).
/// Resets read_count to 0. Returns updated metadata.
/// Returns Err if the secret has delete=true.
/// Returns Ok(None) if not found or TTL-expired.
pub fn patch(
    &self,
    secret_key: &str,
    new_value: Option<&str>,
    new_max_reads: Option<u32>,
    new_ttl_seconds: Option<u64>,
) -> Result<Option<SecretMeta>> {
    let now = Self::now();

    let write_txn = self.db.begin_write()?;
    let result = {
        let mut table = write_txn.open_table(SECRETS)?;

        let raw_bytes: Option<Vec<u8>> =
            table.get(secret_key)?.map(|guard| guard.value().to_vec());

        match raw_bytes {
            None => Ok(None),
            Some(bytes) => {
                let mut record: SecretRecord = decode(&bytes)?;

                if record.is_expired(now) {
                    table.remove(secret_key)?;
                    return Ok(None);
                }

                if record.delete {
                    anyhow::bail!("cannot patch a secret with delete=true");
                }

                // Update value if provided.
                if let Some(val) = new_value {
                    let (encrypted, nonce) =
                        super::crypto::encrypt(&self.key, val.as_bytes())
                            .context("encrypt patched value")?;
                    record.value_encrypted = encrypted;
                    record.nonce = nonce;
                }

                // Update max_reads if provided.
                if let Some(max) = new_max_reads {
                    record.max_reads = Some(max);
                }

                // Update TTL if provided.
                if let Some(ttl) = new_ttl_seconds {
                    record.expires_at = Some(now + ttl as i64);
                }

                // Always reset read_count.
                record.read_count = 0;

                let updated = encode(&record)?;
                table.insert(secret_key, updated.as_slice())?;

                Ok(Some(SecretMeta {
                    key: secret_key.to_owned(),
                    created_at: record.created_at,
                    expires_at: record.expires_at,
                    max_reads: record.max_reads,
                    read_count: 0,
                    delete: record.delete,
                }))
            }
        }
    };
    write_txn.commit()?;
    result
}
```

**Step 8: Run all tests**

Run: `cargo test -p sirr-server`
Expected: All pass

**Step 9: Commit**

```bash
git add crates/sirr-server/src/store/db.rs
git commit -m "feat: add Store::head() and Store::patch() methods"
```

---

### Task 4: Store — update get() to return sealed status

**Files:**
- Modify: `crates/sirr-server/src/store/db.rs`

The current `get()` returns `Option<String>` but the handler needs to distinguish "not found" from "sealed" to return 404 vs 410. Change the return type.

**Step 1: Write failing test**

```rust
#[test]
fn get_sealed_returns_sealed_variant() {
    let (s, _dir) = make_store();
    s.put("GS", "val", None, Some(1), false).unwrap();
    assert!(matches!(s.get("GS").unwrap(), GetResult::Value(_)));
    assert!(matches!(s.get("GS").unwrap(), GetResult::Sealed));
}
```

**Step 2: Define GetResult enum and update get()**

Add near the top of `db.rs`:

```rust
/// Result of a secret retrieval.
#[derive(Debug, PartialEq)]
pub enum GetResult {
    /// Secret found and decrypted. Read counter was incremented.
    Value(String),
    /// Secret exists but is sealed (delete=false, reads exhausted).
    Sealed,
    /// Secret not found or TTL-expired.
    NotFound,
}
```

Change `Store::get` signature from `Result<Option<String>>` to `Result<GetResult>`:

```rust
pub fn get(&self, secret_key: &str) -> Result<GetResult> {
```

Update the body — return `GetResult::NotFound` where it currently returns `None`, `GetResult::Value(value)` where it returns `Some(value)`, and add `GetResult::Sealed` for the sealed branch:

```rust
if record.is_expired(now) {
    table.remove(secret_key)?;
    debug!(key = %secret_key, "lazy-evicted expired secret");
    GetResult::NotFound
} else if record.is_sealed() {
    GetResult::Sealed
} else {
    record.read_count += 1;
    // ... decrypt ...
    if record.is_burned() {
        table.remove(secret_key)?;
        debug!(key = %secret_key, "burned after final read");
    } else {
        let updated = encode(&record)?;
        table.insert(secret_key, updated.as_slice())?;
    }
    GetResult::Value(value)
}
```

And for the `None` (key doesn't exist) case: `GetResult::NotFound`.

**Step 3: Fix existing tests**

Update existing `get()` assertions:

```rust
// put_get_delete:
assert_eq!(s.get("MY_KEY").unwrap(), GetResult::Value("my-value".into()));
// ...
assert_eq!(s.get("MY_KEY").unwrap(), GetResult::NotFound);

// read_limit_burn:
assert_eq!(s.get("BURN").unwrap(), GetResult::Value("secret".into()));
assert_eq!(s.get("BURN").unwrap(), GetResult::NotFound);

// ttl_expiry:
assert_eq!(s.get("EXPIRED").unwrap(), GetResult::NotFound);
```

**Step 4: Update handlers.rs to use GetResult**

In `handlers.rs`, update `get_secret`:

```rust
use crate::store::db::GetResult;

pub async fn get_secret(State(state): State<AppState>, Path(key): Path<String>) -> Response {
    match state.store.get(&key) {
        Ok(GetResult::Value(value)) => Json(json!({ "key": key, "value": value })).into_response(),
        Ok(GetResult::Sealed) => (
            StatusCode::GONE,
            Json(json!({"error": "secret is sealed — reads exhausted"})),
        )
            .into_response(),
        Ok(GetResult::NotFound) => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "not found or expired"})),
        )
            .into_response(),
        Err(e) => internal_error(e),
    }
}
```

Also update `store/mod.rs` to export GetResult:

```rust
pub use db::{GetResult, Store};
```

**Step 5: Run all tests**

Run: `cargo test -p sirr-server`
Expected: All pass

**Step 6: Commit**

```bash
git add crates/sirr-server/src/store/db.rs crates/sirr-server/src/store/mod.rs crates/sirr-server/src/handlers.rs
git commit -m "feat: Store::get() returns GetResult enum (Value/Sealed/NotFound)"
```

---

### Task 5: Auth overhaul — server-generated key + optional API key

**Files:**
- Modify: `crates/sirr-server/src/store/crypto.rs` (already done in Task 1)
- Modify: `crates/sirr-server/src/server.rs`
- Modify: `crates/sirr-server/src/auth.rs`
- Modify: `crates/sirr-server/src/lib.rs`

**Step 1: Update AppState**

In `lib.rs`, replace `master_key: String` with `api_key: Option<String>`:

```rust
#[derive(Clone)]
pub struct AppState {
    pub store: store::Store,
    /// Optional API key for write-protecting mutations.
    pub api_key: Option<String>,
    /// Validated license status (set at startup).
    pub license: license::LicenseStatus,
}
```

**Step 2: Replace auth.rs with optional API key middleware**

Replace the entire `auth.rs`:

```rust
use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use constant_time_eq::constant_time_eq;
use serde_json::json;

use crate::AppState;

/// Axum middleware that optionally validates `Authorization: Bearer <api_key>`.
/// If no API key is configured (SIRR_API_KEY not set), all requests pass through.
pub async fn require_api_key(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    let Some(expected) = &state.api_key else {
        // No API key configured — all writes are open.
        return next.run(request).await;
    };

    let token = request
        .headers()
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));

    match token {
        Some(t) if constant_time_eq(t.as_bytes(), expected.as_bytes()) => {
            next.run(request).await
        }
        _ => (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "unauthorized — valid SIRR_API_KEY required for this endpoint"})),
        )
            .into_response(),
    }
}
```

**Step 3: Update server.rs**

Replace the router setup and key loading. Key changes:

1. Load or generate `sirr.key` instead of deriving from master key.
2. Split routes into public (GET, HEAD) and protected (POST, PATCH, DELETE, list).
3. Add CORS layer.
4. Remove `master_key` from ServerConfig, add `api_key`.

```rust
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub api_key: Option<String>,
    pub license_key: Option<String>,
    pub data_dir: Option<PathBuf>,
    pub sweep_interval: Duration,
    pub cors_origins: Option<String>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: std::env::var("SIRR_HOST").unwrap_or_else(|_| "0.0.0.0".into()),
            port: std::env::var("SIRR_PORT")
                .ok()
                .and_then(|p| p.parse().ok())
                .unwrap_or(8080),
            api_key: std::env::var("SIRR_API_KEY").ok(),
            license_key: std::env::var("SIRR_LICENSE_KEY").ok(),
            data_dir: std::env::var("SIRR_DATA_DIR").ok().map(PathBuf::from),
            sweep_interval: Duration::from_secs(300),
            cors_origins: std::env::var("SIRR_CORS_ORIGINS").ok(),
        }
    }
}
```

In `run()`, replace the salt/key loading:

```rust
// Load or generate the encryption key (replaces Argon2id derivation).
let enc_key = load_or_create_key(&data_dir)?;
```

Replace router:

```rust
use crate::{
    auth::require_api_key,
    handlers::{create_secret, delete_secret, get_secret, head_secret, health, list_secrets, patch_secret, prune_secrets},
    license, AppState,
};
use tower_http::cors::{Any, CorsLayer};

// ...

let state = AppState {
    store,
    api_key: cfg.api_key,
    license: lic_status,
};

// CORS
let cors = build_cors(cfg.cors_origins.as_deref());

// Public routes (no auth).
let public = Router::new()
    .route("/health", get(health))
    .route("/secrets/{key}", get(get_secret))
    .route("/secrets/{key}", head(head_secret));

// Protected routes (API key required if configured).
let protected = Router::new()
    .route("/secrets", get(list_secrets))
    .route("/secrets", post(create_secret))
    .route("/secrets/{key}", patch(patch_secret))
    .route("/secrets/{key}", delete(delete_secret))
    .route("/prune", post(prune_secrets))
    .layer(middleware::from_fn_with_state(state.clone(), require_api_key));

let app = Router::new()
    .merge(public)
    .merge(protected)
    .with_state(state)
    .layer(cors)
    .layer(TraceLayer::new_for_http());
```

Add the `head` import from axum routing and the CORS builder:

```rust
use axum::routing::{delete, get, head, patch, post};

fn build_cors(origins: Option<&str>) -> CorsLayer {
    let cors = CorsLayer::new()
        .allow_methods([
            http::Method::GET,
            http::Method::HEAD,
            http::Method::POST,
            http::Method::PATCH,
            http::Method::DELETE,
            http::Method::OPTIONS,
        ])
        .allow_headers(Any);

    match origins {
        Some(o) => {
            let origins: Vec<_> = o
                .split(',')
                .filter_map(|s| s.trim().parse().ok())
                .collect();
            cors.allow_origin(origins)
        }
        None => cors.allow_origin(Any),
    }
}
```

Replace `load_or_create_salt` with `load_or_create_key`:

```rust
fn load_or_create_key(data_dir: &std::path::Path) -> Result<crate::store::crypto::EncryptionKey> {
    let key_path = data_dir.join("sirr.key");
    if key_path.exists() {
        let bytes = std::fs::read(&key_path).context("read sirr.key")?;
        crate::store::crypto::load_key(&bytes)
            .ok_or_else(|| anyhow::anyhow!("sirr.key is corrupt (expected 32 bytes, got {})", bytes.len()))
    } else {
        let key = crate::store::crypto::generate_key();
        std::fs::write(&key_path, key.as_bytes()).context("write sirr.key")?;
        info!("generated new encryption key");
        Ok(key)
    }
}
```

Remove `load_or_create_salt` function entirely. Also remove the salt-related code in `run()`.

**Step 4: Build and fix any remaining compilation errors**

Run: `cargo build -p sirr-server`
Expected: Success

**Step 5: Run tests**

Run: `cargo test -p sirr-server`
Expected: All pass

**Step 6: Commit**

```bash
git add crates/sirr-server/src/lib.rs crates/sirr-server/src/auth.rs crates/sirr-server/src/server.rs
git commit -m "feat: replace master-key auth with server-generated key + optional API key"
```

---

### Task 6: Handlers — add head_secret and patch_secret

**Files:**
- Modify: `crates/sirr-server/src/handlers.rs`

**Step 1: Add head_secret handler**

```rust
// ── Head ──────────────────────────────────────────────────────────────────────

pub async fn head_secret(State(state): State<AppState>, Path(key): Path<String>) -> Response {
    match state.store.head(&key) {
        Ok(Some((meta, sealed))) => {
            let status = if sealed {
                StatusCode::GONE
            } else {
                StatusCode::OK
            };

            let reads_remaining = match meta.max_reads {
                Some(max) => (max.saturating_sub(meta.read_count)).to_string(),
                None => "unlimited".to_string(),
            };

            let mut builder = Response::builder()
                .status(status)
                .header("X-Sirr-Read-Count", meta.read_count.to_string())
                .header("X-Sirr-Reads-Remaining", reads_remaining)
                .header("X-Sirr-Delete", meta.delete.to_string())
                .header("X-Sirr-Created-At", meta.created_at.to_string());

            if let Some(exp) = meta.expires_at {
                builder = builder.header("X-Sirr-Expires-At", exp.to_string());
            }

            if sealed {
                builder = builder.header("X-Sirr-Status", "sealed");
            } else {
                builder = builder.header("X-Sirr-Status", "active");
            }

            builder.body(axum::body::Body::empty()).unwrap()
        }
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "not found or expired"})),
        )
            .into_response(),
        Err(e) => internal_error(e),
    }
}
```

**Step 2: Add patch_secret handler**

```rust
// ── Patch ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct PatchRequest {
    pub value: Option<String>,
    pub max_reads: Option<u32>,
    pub ttl_seconds: Option<u64>,
}

pub async fn patch_secret(
    State(state): State<AppState>,
    Path(key): Path<String>,
    Json(body): Json<PatchRequest>,
) -> Response {
    if let Some(ref v) = body.value {
        if v.len() > 1_048_576 {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "value exceeds 1 MiB limit"})),
            )
                .into_response();
        }
    }

    match state.store.patch(
        &key,
        body.value.as_deref(),
        body.max_reads,
        body.ttl_seconds,
    ) {
        Ok(Some(meta)) => Json(meta).into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "not found or expired"})),
        )
            .into_response(),
        Err(e) => {
            // Check if this is a "cannot patch delete=true" error.
            let msg = e.to_string();
            if msg.contains("cannot patch") {
                (
                    StatusCode::CONFLICT,
                    Json(json!({"error": msg})),
                )
                    .into_response()
            } else {
                internal_error(e)
            }
        }
    }
}
```

**Step 3: Build**

Run: `cargo build -p sirr-server`
Expected: Success

**Step 4: Run all tests**

Run: `cargo test -p sirr-server`
Expected: All pass

**Step 5: Commit**

```bash
git add crates/sirr-server/src/handlers.rs
git commit -m "feat: add head_secret and patch_secret handlers"
```

---

### Task 7: CLI — update for new auth model + delete flag

**Files:**
- Modify: `crates/sirr/src/main.rs`

**Step 1: Update CLI args**

Replace `--token` / `SIRR_TOKEN` with `--api-key` / `SIRR_API_KEY`:

```rust
/// API key for write operations ($SIRR_API_KEY)
#[arg(long, env = "SIRR_API_KEY")]
api_key: Option<String>,
```

Add `--delete` flag to `Push` command (note: CLI flag is `--no-delete` since delete=true is default):

```rust
Push {
    #[arg(name = "TARGET")]
    target: String,
    #[arg(long)]
    ttl: Option<String>,
    #[arg(long)]
    reads: Option<u32>,
    /// Keep the secret after reads are exhausted (enables PATCH)
    #[arg(long)]
    no_delete: bool,
},
```

**Step 2: Update command dispatch**

- `cmd_serve`: Remove `SIRR_MASTER_KEY` requirement. Pass `api_key` from env.
- Read commands (`get`, `share`): No auth needed — don't send Bearer token.
- Write commands (`push`, `delete`, `list`, `pull`, `run`, `prune`): Send Bearer token only if `api_key` is set.
- `push_one`: Add `delete` field to JSON body.

Replace `require_token` with optional auth helper:

```rust
fn auth_header(api_key: &Option<String>) -> Option<String> {
    api_key.as_ref().map(|k| format!("Bearer {k}"))
}
```

Update `push_one` to accept and send `delete`:

```rust
async fn push_one(
    server: &str,
    api_key: &Option<String>,
    key: &str,
    value: &str,
    ttl_seconds: Option<u64>,
    max_reads: Option<u32>,
    delete: bool,
) -> Result<()> {
    let client = Client::new();
    let body = serde_json::json!({
        "key": key,
        "value": value,
        "ttl_seconds": ttl_seconds,
        "max_reads": max_reads,
        "delete": delete,
    });

    let mut req = client.post(format!("{}/secrets", server.trim_end_matches('/')));
    if let Some(key) = api_key {
        req = req.bearer_auth(key);
    }
    let resp = req.json(&body).send().await.context("HTTP request failed")?;

    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        anyhow::bail!("server returned {status}: {text}");
    }
    Ok(())
}
```

Update all callers: replace `&token` with `&cli.api_key`, remove `require_token` calls for read operations (`get`, `share`), make write operations use optional auth.

For `cmd_serve`, update to:

```rust
async fn cmd_serve(host: String, port: u16) -> Result<()> {
    let cfg = sirr_server::ServerConfig {
        host,
        port,
        api_key: std::env::var("SIRR_API_KEY").ok(),
        license_key: std::env::var("SIRR_LICENSE_KEY").ok(),
        data_dir: std::env::var("SIRR_DATA_DIR").ok().map(Into::into),
        ..Default::default()
    };

    sirr_server::run(cfg).await
}
```

**Step 3: Build**

Run: `cargo build -p sirr`
Expected: Success

**Step 4: Commit**

```bash
git add crates/sirr/src/main.rs
git commit -m "feat: CLI uses optional SIRR_API_KEY, adds --no-delete flag to push"
```

---

### Task 8: Clean up — remove argon2 dependency if possible

**Files:**
- Modify: `crates/sirr-server/Cargo.toml`
- Modify: `crates/sirr-server/src/store/crypto.rs`

**Step 1: Check if argon2 is still used**

The `derive_key` function uses argon2. If we keep it for backward compat, leave the dep. If we fully remove it:

- Remove `derive_key` and `base64_encode` from `crypto.rs`
- Remove the `derive_key` tests
- Remove `argon2 = "0.5"` from Cargo.toml
- Remove the salt file loading from server.rs (already done in Task 5)

**Step 2: Remove argon2 code from crypto.rs**

Remove: `derive_key()`, `base64_encode()`, `argon2` imports, and the two tests that use `derive_key`.

Keep: `EncryptionKey`, `generate_key`, `load_key`, `generate_salt` (still used? check — if not, remove), `encrypt`, `decrypt`.

Actually `generate_salt` is no longer needed either. Remove it.

Update the remaining test:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let key = generate_key();
        let plaintext = b"hello, sirr!";
        let (ct, nonce) = encrypt(&key, plaintext).unwrap();
        let pt = decrypt(&key, &ct, &nonce).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn wrong_key_fails() {
        let key1 = generate_key();
        let key2 = generate_key();
        let (ct, nonce) = encrypt(&key1, b"secret").unwrap();
        assert!(decrypt(&key2, &ct, &nonce).is_err());
    }

    #[test]
    fn generate_key_round_trip() {
        let key = generate_key();
        let plaintext = b"test with generated key";
        let (ct, nonce) = encrypt(&key, plaintext).unwrap();
        let pt = decrypt(&key, &ct, &nonce).unwrap();
        assert_eq!(pt, plaintext);
    }
}
```

**Step 3: Remove argon2 from Cargo.toml**

Remove line: `argon2 = "0.5"`

**Step 4: Update db.rs test helper**

The `make_store()` function still calls `generate_salt` and `derive_key`. Update to use `generate_key`:

```rust
fn make_store() -> (Store, tempfile::TempDir) {
    let key = super::super::crypto::generate_key();
    let dir = tempdir().unwrap();
    let path = dir.path().join("test.db");
    let store = Store::open(&path, key).unwrap();
    (store, dir)
}
```

**Step 5: Build and test**

Run: `cargo build --all && cargo test --all`
Expected: Success

**Step 6: Commit**

```bash
git add crates/sirr-server/Cargo.toml crates/sirr-server/src/store/crypto.rs crates/sirr-server/src/store/db.rs
git commit -m "chore: remove argon2 dependency, use server-generated key everywhere"
```

---

### Task 9: Final verification and docs

**Step 1: Full build and test**

Run: `cargo build --all && cargo test --all && cargo clippy --all-targets`

**Step 2: Update CLAUDE.md**

Update the architecture section, commands, key constraints, and env vars to reflect:
- No more `SIRR_MASTER_KEY`
- New `SIRR_API_KEY` (optional)
- New `SIRR_CORS_ORIGINS` (optional)
- New `delete` flag behavior
- New `PATCH` and `HEAD` endpoints
- `GetResult` enum

**Step 3: Update README.md**

Reflect new API surface, env vars, auth model.

**Step 4: Commit**

```bash
git add CLAUDE.md README.md
git commit -m "docs: update for patchable secrets, HEAD endpoint, and auth overhaul"
```
