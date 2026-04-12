#![allow(clippy::result_large_err)]

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Mutex;

use redb::{Database, ReadableTable, TableDefinition};
use thiserror::Error;

use crate::store::audit::{AuditEvent, AuditQuery};
use crate::store::crypto::EncryptionKey;
use crate::store::keys::KeyRecord;
use crate::store::model::SecretRecord;
use crate::store::visibility::Visibility;

// ── Table definitions ─────────────────────────────────────────────────────────

const SECRETS: TableDefinition<&str, &[u8]> = TableDefinition::new("secrets");
const KEYS_BY_ID: TableDefinition<&str, &[u8]> = TableDefinition::new("keys_by_id");
const KEYS_BY_HASH: TableDefinition<&[u8; 32], &str> = TableDefinition::new("keys_by_hash");
const KEYS_BY_NAME: TableDefinition<&str, &str> = TableDefinition::new("keys_by_name");
const AUDIT: TableDefinition<u64, &[u8]> = TableDefinition::new("audit");
const CONFIG: TableDefinition<&str, &[u8]> = TableDefinition::new("config");

// ── Config keys ───────────────────────────────────────────────────────────────

const CFG_VISIBILITY: &str = "visibility";
const CFG_AUDIT_COUNTER: &str = "audit_counter";

// ── Error type ────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("secret not found")]
    NotFound,
    #[error("secret is burned")]
    Burned,
    #[error("secret has expired")]
    Expired,
    #[error("wrong owner key")]
    WrongOwner,
    #[error("key not found")]
    KeyNotFound,
    #[error("database error: {0}")]
    Db(#[from] redb::Error),
    #[error("database open error: {0}")]
    DatabaseError(#[from] redb::DatabaseError),
    #[error("transaction error: {0}")]
    Transaction(#[from] redb::TransactionError),
    #[error("table error: {0}")]
    Table(#[from] redb::TableError),
    #[error("storage error: {0}")]
    Storage(#[from] redb::StorageError),
    #[error("commit error: {0}")]
    Commit(#[from] redb::CommitError),
    #[error("crypto error: {0}")]
    Crypto(anyhow::Error),
    #[error("encode error: {0}")]
    Encode(#[from] bincode::error::EncodeError),
    #[error("decode error: {0}")]
    Decode(#[from] bincode::error::DecodeError),
}

// ── Store ─────────────────────────────────────────────────────────────────────

pub struct Store {
    db: Database,
    /// Mutex protecting the audit counter. In a single-process daemon this is fine.
    audit_counter: Mutex<u64>,
}

impl Store {
    /// Open (or create) the redb database at `path`.
    ///
    /// All six tables are created on first open so subsequent transactions can
    /// rely on them existing.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let db = Database::create(path)?;

        // Ensure all tables exist by opening them in a write transaction.
        let txn = db.begin_write()?;
        {
            txn.open_table(SECRETS)?;
            txn.open_table(KEYS_BY_ID)?;
            txn.open_table(KEYS_BY_HASH)?;
            txn.open_table(KEYS_BY_NAME)?;
            txn.open_table(AUDIT)?;
            txn.open_table(CONFIG)?;
        }
        txn.commit()?;

        // Read the current audit counter from the config table.
        let counter = {
            let rtxn = db.begin_read()?;
            let tbl = rtxn.open_table(CONFIG)?;
            match tbl.get(CFG_AUDIT_COUNTER)? {
                Some(v) => {
                    let (val, _): (u64, _) =
                        bincode::serde::decode_from_slice(v.value(), bincode::config::standard())?;
                    val
                }
                None => 0,
            }
        };

        Ok(Self {
            db,
            audit_counter: Mutex::new(counter),
        })
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    fn encode<T: serde::Serialize>(v: &T) -> Result<Vec<u8>, StoreError> {
        Ok(bincode::serde::encode_to_vec(
            v,
            bincode::config::standard(),
        )?)
    }

    fn decode<T: for<'de> serde::Deserialize<'de>>(bytes: &[u8]) -> Result<T, StoreError> {
        let (v, _) = bincode::serde::decode_from_slice(bytes, bincode::config::standard())?;
        Ok(v)
    }

    // ── Visibility ────────────────────────────────────────────────────────────

    /// Persist `v` to the `config` table.
    pub fn set_visibility(&self, v: Visibility) -> Result<(), StoreError> {
        let txn = self.db.begin_write()?;
        {
            let mut tbl = txn.open_table(CONFIG)?;
            tbl.insert(CFG_VISIBILITY, Self::encode(&v)?.as_slice())?;
        }
        txn.commit()?;
        Ok(())
    }

    /// Read persisted `Visibility`; returns `Visibility::Public` if not yet set.
    pub fn get_visibility(&self) -> Result<Visibility, StoreError> {
        let rtxn = self.db.begin_read()?;
        let tbl = rtxn.open_table(CONFIG)?;
        match tbl.get(CFG_VISIBILITY)? {
            Some(v) => Self::decode(v.value()),
            None => Ok(Visibility::Public),
        }
    }

    // ── Secrets ───────────────────────────────────────────────────────────────

    /// Insert a new `SecretRecord`. The record's `hash` is used as the key.
    pub fn create_secret(&self, record: &SecretRecord) -> Result<(), StoreError> {
        let txn = self.db.begin_write()?;
        {
            let mut tbl = txn.open_table(SECRETS)?;
            tbl.insert(record.hash.as_str(), Self::encode(record)?.as_slice())?;
        }
        txn.commit()?;
        Ok(())
    }

    /// Retrieve a `SecretRecord` by hash, or `None` if it doesn't exist.
    pub fn get_secret(&self, hash: &str) -> Result<Option<SecretRecord>, StoreError> {
        let rtxn = self.db.begin_read()?;
        let tbl = rtxn.open_table(SECRETS)?;
        match tbl.get(hash)? {
            Some(v) => Ok(Some(Self::decode(v.value())?)),
            None => Ok(None),
        }
    }

    /// Atomically consume one read from the secret.
    ///
    /// Checks TTL expiry, decrements `reads_remaining`, decrypts the value.
    /// If this is the last read (`should_burn_after_read()`), the secret is
    /// burned: ciphertext and nonce are zeroed, `burned` flag is set.
    ///
    /// Returns `(plaintext, burned)` or `Err(NotFound | Burned | Expired)`.
    pub fn consume_read(
        &self,
        hash: &str,
        now: i64,
        key: &EncryptionKey,
    ) -> Result<(Vec<u8>, bool), StoreError> {
        let txn = self.db.begin_write()?;
        let (plaintext, burned) = {
            let mut tbl = txn.open_table(SECRETS)?;

            // Read current record — clone bytes before dropping guard.
            let bytes = match tbl.get(hash)? {
                Some(v) => v.value().to_vec(),
                None => return Err(StoreError::NotFound),
            };

            let mut record: SecretRecord = Self::decode(&bytes)?;

            if record.is_burned() {
                return Err(StoreError::Burned);
            }
            if record.is_expired(now) {
                // Tombstone it.
                record.burned = true;
                record.value_ciphertext = vec![];
                record.nonce = [0u8; 12];
                tbl.insert(hash, Self::encode(&record)?.as_slice())?;
                return Err(StoreError::Expired);
            }

            // Decrypt before we potentially zero the ciphertext.
            let plaintext =
                crate::store::crypto::decrypt(key, &record.value_ciphertext, &record.nonce)
                    .map_err(StoreError::Crypto)?;

            let burned = record.should_burn_after_read();

            if burned {
                record.burned = true;
                record.value_ciphertext = vec![];
                record.nonce = [0u8; 12];
            }

            // Decrement reads_remaining if finite.
            if let Some(ref mut rem) = record.reads_remaining {
                if *rem > 0 {
                    *rem -= 1;
                }
            }

            tbl.insert(hash, Self::encode(&record)?.as_slice())?;
            (plaintext, burned)
        };
        txn.commit()?;
        Ok((plaintext, burned))
    }

    /// Re-encrypt the secret value with a fresh nonce.
    ///
    /// Asserts `owner_key_id` matches the stored record's owner.
    /// `new_ttl` and `new_reads` are optional resets — `None` means frozen (keep existing value).
    pub fn patch_secret(
        &self,
        hash: &str,
        new_value: &[u8],
        owner_key_id: &str,
        new_ttl: Option<i64>,
        new_reads: Option<u32>,
        key: &EncryptionKey,
    ) -> Result<SecretRecord, StoreError> {
        let txn = self.db.begin_write()?;
        let updated = {
            let mut tbl = txn.open_table(SECRETS)?;

            let bytes = match tbl.get(hash)? {
                Some(v) => v.value().to_vec(),
                None => return Err(StoreError::NotFound),
            };
            let mut record: SecretRecord = Self::decode(&bytes)?;

            if record.is_burned() {
                return Err(StoreError::Burned);
            }

            // Ownership check.
            if record.owner_key_id.as_deref() != Some(owner_key_id) {
                return Err(StoreError::WrongOwner);
            }

            // Re-encrypt with fresh nonce.
            let (ciphertext, nonce) =
                crate::store::crypto::encrypt(key, new_value).map_err(StoreError::Crypto)?;
            record.value_ciphertext = ciphertext;
            record.nonce = nonce;

            // Optional resets.
            if let Some(ttl) = new_ttl {
                record.ttl_expires_at = Some(ttl);
            }
            if let Some(reads) = new_reads {
                record.reads_remaining = Some(reads);
            }

            tbl.insert(hash, Self::encode(&record)?.as_slice())?;
            record
        };
        txn.commit()?;
        Ok(updated)
    }

    /// Burn the secret: set `burned=true`, zero ciphertext+nonce.
    ///
    /// For keyed secrets, `owner_key_id` must match; pass `None` to skip the check
    /// (anonymous secrets can be burned by anyone).
    pub fn burn_secret(&self, hash: &str, owner_key_id: Option<&str>) -> Result<(), StoreError> {
        let txn = self.db.begin_write()?;
        {
            let mut tbl = txn.open_table(SECRETS)?;

            let bytes = match tbl.get(hash)? {
                Some(v) => v.value().to_vec(),
                None => return Err(StoreError::NotFound),
            };
            let mut record: SecretRecord = Self::decode(&bytes)?;

            if record.is_burned() {
                return Err(StoreError::Burned);
            }

            // Ownership check for keyed secrets.
            if let Some(oid) = owner_key_id {
                if record.owner_key_id.as_deref() != Some(oid) {
                    return Err(StoreError::WrongOwner);
                }
            }

            record.burned = true;
            record.value_ciphertext = vec![];
            record.nonce = [0u8; 12];

            tbl.insert(hash, Self::encode(&record)?.as_slice())?;
        }
        txn.commit()?;
        Ok(())
    }

    // ── Keys ──────────────────────────────────────────────────────────────────

    /// Create a new API key. Generates a ULID id, 32-byte random token, and
    /// blake3-hashes the token. Stores in all three key tables.
    ///
    /// Returns `(KeyRecord, plaintext_token_hex)` — the plaintext is shown once.
    pub fn create_key(
        &self,
        name: &str,
        valid_after: Option<i64>,
        valid_before: Option<i64>,
        webhook_url: Option<String>,
    ) -> Result<(KeyRecord, String), StoreError> {
        use rand::rngs::OsRng;
        use rand::RngCore;
        use ulid::Ulid;

        let id = Ulid::new().to_string();
        let created_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        // Generate 32-byte random token.
        let mut token_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut token_bytes);
        let token_hex = hex::encode(token_bytes);

        // blake3 hash for storage.
        let hash = *blake3::hash(&token_bytes).as_bytes();

        let record = KeyRecord {
            id: id.clone(),
            name: name.to_string(),
            hash,
            created_at,
            valid_after,
            valid_before,
            webhook_url,
        };

        let txn = self.db.begin_write()?;
        {
            let mut by_id = txn.open_table(KEYS_BY_ID)?;
            let mut by_hash = txn.open_table(KEYS_BY_HASH)?;
            let mut by_name = txn.open_table(KEYS_BY_NAME)?;

            by_id.insert(record.id.as_str(), Self::encode(&record)?.as_slice())?;
            by_hash.insert(&hash, record.id.as_str())?;
            by_name.insert(record.name.as_str(), record.id.as_str())?;
        }
        txn.commit()?;

        Ok((record, token_hex))
    }

    /// Look up a key by its bearer token (hex string).
    ///
    /// Hashes the token with blake3 and looks up the hash in `keys_by_hash`.
    /// Returns `None` if not found.
    pub fn find_key_by_token(&self, token_hex: &str) -> Result<Option<KeyRecord>, StoreError> {
        let token_bytes = match hex::decode(token_hex) {
            Ok(b) if b.len() == 32 => b,
            _ => return Ok(None),
        };
        let hash = *blake3::hash(&token_bytes).as_bytes();
        self.find_key_by_hash(&hash)
    }

    /// Look up a key by its blake3 hash (internal use).
    fn find_key_by_hash(&self, hash: &[u8; 32]) -> Result<Option<KeyRecord>, StoreError> {
        let rtxn = self.db.begin_read()?;
        let by_hash = rtxn.open_table(KEYS_BY_HASH)?;
        let key_id = match by_hash.get(hash)? {
            Some(v) => v.value().to_string(),
            None => return Ok(None),
        };
        drop(by_hash);
        drop(rtxn);

        let rtxn2 = self.db.begin_read()?;
        let by_id = rtxn2.open_table(KEYS_BY_ID)?;
        match by_id.get(key_id.as_str())? {
            Some(v) => Ok(Some(Self::decode(v.value())?)),
            None => Ok(None),
        }
    }

    /// List all keys in `keys_by_id`.
    pub fn list_keys(&self) -> Result<Vec<KeyRecord>, StoreError> {
        let rtxn = self.db.begin_read()?;
        let tbl = rtxn.open_table(KEYS_BY_ID)?;
        let mut results = Vec::new();
        for entry in tbl.iter()? {
            let (_, v) = entry?;
            results.push(Self::decode(v.value())?);
        }
        Ok(results)
    }

    /// Delete a key by name. Removes from all three key tables.
    pub fn delete_key(&self, name: &str) -> Result<(), StoreError> {
        // First resolve name → id.
        let key_id = {
            let rtxn = self.db.begin_read()?;
            let by_name = rtxn.open_table(KEYS_BY_NAME)?;
            match by_name.get(name)? {
                Some(v) => v.value().to_string(),
                None => return Err(StoreError::KeyNotFound),
            }
        };

        // Resolve id → record (to get the hash).
        let record: KeyRecord = {
            let rtxn = self.db.begin_read()?;
            let by_id = rtxn.open_table(KEYS_BY_ID)?;
            match by_id.get(key_id.as_str())? {
                Some(v) => Self::decode(v.value())?,
                None => return Err(StoreError::KeyNotFound),
            }
        };

        let txn = self.db.begin_write()?;
        {
            let mut by_id = txn.open_table(KEYS_BY_ID)?;
            let mut by_hash = txn.open_table(KEYS_BY_HASH)?;
            let mut by_name = txn.open_table(KEYS_BY_NAME)?;

            by_id.remove(record.id.as_str())?;
            by_hash.remove(&record.hash)?;
            by_name.remove(name)?;
        }
        txn.commit()?;
        Ok(())
    }

    // ── Key-scoped secret queries ─────────────────────────────────────────────

    /// Count active (non-burned) secrets owned by `key_id` and build a prefix histogram.
    ///
    /// Prefix = everything before the last `_` + 32-hex-char suffix.
    /// Returns `(count, histogram)`.
    pub fn secrets_owned_by(
        &self,
        key_id: &str,
    ) -> Result<(usize, BTreeMap<String, usize>), StoreError> {
        let rtxn = self.db.begin_read()?;
        let tbl = rtxn.open_table(SECRETS)?;
        let mut count = 0usize;
        let mut histogram: BTreeMap<String, usize> = BTreeMap::new();

        for entry in tbl.iter()? {
            let (_, v) = entry?;
            let record: SecretRecord = Self::decode(v.value())?;
            if record.is_burned() {
                continue;
            }
            if record.owner_key_id.as_deref() != Some(key_id) {
                continue;
            }
            count += 1;

            // Extract prefix: everything before the last underscore.
            let prefix = extract_prefix(&record.hash);
            *histogram.entry(prefix).or_insert(0) += 1;
        }

        Ok((count, histogram))
    }

    /// Burn every active secret owned by `key_id`. Returns count burned.
    pub fn purge_secrets_for_key(&self, key_id: &str) -> Result<usize, StoreError> {
        // Collect hashes to burn first (avoid mixing read + write iterators).
        let hashes_to_burn: Vec<String> = {
            let rtxn = self.db.begin_read()?;
            let tbl = rtxn.open_table(SECRETS)?;
            let mut v = Vec::new();
            for entry in tbl.iter()? {
                let (k, val) = entry?;
                let record: SecretRecord = Self::decode(val.value())?;
                if !record.is_burned() && record.owner_key_id.as_deref() == Some(key_id) {
                    v.push(k.value().to_string());
                }
            }
            v
        };

        let count = hashes_to_burn.len();
        let txn = self.db.begin_write()?;
        {
            let mut tbl = txn.open_table(SECRETS)?;
            for hash in &hashes_to_burn {
                // Clone bytes before dropping AccessGuard to allow subsequent insert.
                let bytes_opt: Option<Vec<u8>> =
                    tbl.get(hash.as_str())?.map(|g| g.value().to_vec());
                if let Some(bytes) = bytes_opt {
                    let mut record: SecretRecord = Self::decode(&bytes)?;
                    record.burned = true;
                    record.value_ciphertext = vec![];
                    record.nonce = [0u8; 12];
                    tbl.insert(hash.as_str(), Self::encode(&record)?.as_slice())?;
                }
            }
        }
        txn.commit()?;
        Ok(count)
    }

    // ── Audit ─────────────────────────────────────────────────────────────────

    /// Append an audit event. Assigns a monotonically increasing id.
    pub fn record_audit(&self, mut event: AuditEvent) -> Result<u64, StoreError> {
        let id = {
            let mut counter = self.audit_counter.lock().unwrap();
            *counter += 1;
            *counter
        };
        event.id = id;

        let txn = self.db.begin_write()?;
        {
            let mut audit_tbl = txn.open_table(AUDIT)?;
            audit_tbl.insert(id, Self::encode(&event)?.as_slice())?;

            // Persist the counter.
            let mut cfg = txn.open_table(CONFIG)?;
            cfg.insert(CFG_AUDIT_COUNTER, Self::encode(&id)?.as_slice())?;
        }
        txn.commit()?;
        Ok(id)
    }

    /// Query audit events with optional filters. Returns newest-first up to `limit`.
    pub fn query_audit(&self, query: &AuditQuery) -> Result<Vec<AuditEvent>, StoreError> {
        let rtxn = self.db.begin_read()?;
        let tbl = rtxn.open_table(AUDIT)?;

        let mut results: Vec<AuditEvent> = Vec::new();

        // Iterate in reverse (newest first).
        for entry in tbl.iter()?.rev() {
            let (_, v) = entry?;
            let event: AuditEvent = Self::decode(v.value())?;

            if let Some(since) = query.since {
                if event.timestamp < since {
                    continue;
                }
            }
            if let Some(until) = query.until {
                if event.timestamp >= until {
                    continue;
                }
            }
            if let Some(ref action) = query.action {
                if &event.action != action {
                    continue;
                }
            }
            if let Some(ref key_id) = query.key_id {
                if event.key_id.as_ref() != Some(key_id) {
                    continue;
                }
            }
            if let Some(ref hash) = query.hash {
                if event.hash.as_ref() != Some(hash) {
                    continue;
                }
            }

            results.push(event);

            if query.limit > 0 && results.len() >= query.limit {
                break;
            }
        }

        Ok(results)
    }

    // ── Pruning ───────────────────────────────────────────────────────────────

    /// Hard-delete burned secrets older than `SIRR_TOMBSTONE_RETENTION_DAYS` (default 7).
    /// Returns count deleted.
    pub fn prune_tombstones(&self, now: i64) -> Result<usize, StoreError> {
        let retention_days: i64 = std::env::var("SIRR_TOMBSTONE_RETENTION_DAYS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(7);
        let cutoff = now - retention_days * 86_400;

        let hashes_to_delete: Vec<String> = {
            let rtxn = self.db.begin_read()?;
            let tbl = rtxn.open_table(SECRETS)?;
            let mut v = Vec::new();
            for entry in tbl.iter()? {
                let (k, val) = entry?;
                let record: SecretRecord = Self::decode(val.value())?;
                if record.is_burned() && record.created_at < cutoff {
                    v.push(k.value().to_string());
                }
            }
            v
        };

        let count = hashes_to_delete.len();
        let txn = self.db.begin_write()?;
        {
            let mut tbl = txn.open_table(SECRETS)?;
            for hash in &hashes_to_delete {
                tbl.remove(hash.as_str())?;
            }
        }
        txn.commit()?;
        Ok(count)
    }

    /// Hard-delete audit events older than `SIRR_AUDIT_RETENTION_DAYS` (default 30).
    /// Returns count deleted.
    pub fn prune_audit(&self, now: i64) -> Result<usize, StoreError> {
        let retention_days: i64 = std::env::var("SIRR_AUDIT_RETENTION_DAYS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(30);
        let cutoff = now - retention_days * 86_400;

        let ids_to_delete: Vec<u64> = {
            let rtxn = self.db.begin_read()?;
            let tbl = rtxn.open_table(AUDIT)?;
            let mut v = Vec::new();
            for entry in tbl.iter()? {
                let (k, val) = entry?;
                let event: AuditEvent = Self::decode(val.value())?;
                if event.timestamp < cutoff {
                    v.push(k.value());
                }
            }
            v
        };

        let count = ids_to_delete.len();
        let txn = self.db.begin_write()?;
        {
            let mut tbl = txn.open_table(AUDIT)?;
            for id in &ids_to_delete {
                tbl.remove(id)?;
            }
        }
        txn.commit()?;
        Ok(count)
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Extract the prefix from a hash string.
/// A prefix is everything before the last `_` (if present).
/// `"db1_abc123"` → `"db1_"`, `"abc123"` → `"(unprefixed)"`.
fn extract_prefix(hash: &str) -> String {
    match hash.rfind('_') {
        Some(pos) => hash[..=pos].to_string(),
        None => "(unprefixed)".to_string(),
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::audit::ACTION_SECRET_CREATE;
    use crate::store::crypto::generate_key;
    use tempfile::tempdir;

    fn open_temp_store() -> (Store, tempfile::TempDir) {
        let dir = tempdir().unwrap();
        let store = Store::open(dir.path().join("test.db")).unwrap();
        (store, dir)
    }

    fn make_secret(hash: &str, key: &EncryptionKey) -> SecretRecord {
        let value = b"hello world";
        let (ct, nonce) = crate::store::crypto::encrypt(key, value).unwrap();
        SecretRecord {
            hash: hash.to_string(),
            value_ciphertext: ct,
            nonce,
            created_at: 1_000_000,
            ttl_expires_at: None,
            reads_remaining: None,
            burned: false,
            owner_key_id: None,
            created_by_ip: None,
        }
    }

    // ── Sub-task 5: Store::open ───────────────────────────────────────────────

    #[test]
    fn open_creates_store() {
        let (_store, _dir) = open_temp_store();
        // If we get here without panicking, the store opened successfully.
    }

    #[test]
    fn visibility_round_trip_across_reopen() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("vis.db");

        {
            let store = Store::open(&path).unwrap();
            store.set_visibility(Visibility::Private).unwrap();
        }

        {
            let store = Store::open(&path).unwrap();
            let v = store.get_visibility().unwrap();
            assert_eq!(v, Visibility::Private);
        }
    }

    #[test]
    fn default_visibility_is_public() {
        let (store, _dir) = open_temp_store();
        assert_eq!(store.get_visibility().unwrap(), Visibility::Public);
    }

    // ── Sub-task 6 + 7: create_secret / get_secret ───────────────────────────

    #[test]
    fn create_and_get_secret() {
        let (store, _dir) = open_temp_store();
        let key = generate_key();
        let record = make_secret("abc123", &key);

        store.create_secret(&record).unwrap();
        let got = store.get_secret("abc123").unwrap().unwrap();
        assert_eq!(got.hash, "abc123");
        assert_eq!(got.value_ciphertext, record.value_ciphertext);
    }

    #[test]
    fn get_secret_not_found_returns_none() {
        let (store, _dir) = open_temp_store();
        let result = store.get_secret("nonexistent").unwrap();
        assert!(result.is_none());
    }

    // ── Sub-task 8: consume_read ──────────────────────────────────────────────

    #[test]
    fn consume_read_returns_plaintext() {
        let (store, _dir) = open_temp_store();
        let key = generate_key();
        let record = make_secret("hash1", &key);
        store.create_secret(&record).unwrap();

        let (pt, burned) = store.consume_read("hash1", 999_999, &key).unwrap();
        assert_eq!(pt, b"hello world");
        assert!(!burned, "unlimited reads should not burn");
    }

    #[test]
    fn consume_read_burns_on_last_read() {
        let (store, _dir) = open_temp_store();
        let key = generate_key();
        let value = b"one-shot";
        let (ct, nonce) = crate::store::crypto::encrypt(&key, value).unwrap();
        let record = SecretRecord {
            hash: "oneshot".to_string(),
            value_ciphertext: ct,
            nonce,
            created_at: 1_000_000,
            ttl_expires_at: None,
            reads_remaining: Some(1),
            burned: false,
            owner_key_id: None,
            created_by_ip: None,
        };
        store.create_secret(&record).unwrap();

        let (pt, burned) = store.consume_read("oneshot", 999_999, &key).unwrap();
        assert_eq!(pt, b"one-shot");
        assert!(burned, "reads_remaining=1 should burn on read");

        // Subsequent read must fail.
        let err = store.consume_read("oneshot", 999_999, &key).unwrap_err();
        assert!(matches!(err, StoreError::Burned));
    }

    #[test]
    fn consume_read_expired_returns_error() {
        let (store, _dir) = open_temp_store();
        let key = generate_key();
        let mut record = make_secret("expired_secret", &key);
        record.ttl_expires_at = Some(1_000_000); // expires at t=1M

        store.create_secret(&record).unwrap();

        // now = 2M, past TTL.
        let err = store
            .consume_read("expired_secret", 2_000_000, &key)
            .unwrap_err();
        assert!(matches!(err, StoreError::Expired));
    }

    #[test]
    fn consume_read_not_found_returns_error() {
        let (store, _dir) = open_temp_store();
        let key = generate_key();
        let err = store.consume_read("nope", 1_000_000, &key).unwrap_err();
        assert!(matches!(err, StoreError::NotFound));
    }

    // ── Sub-task 9: patch_secret ──────────────────────────────────────────────

    #[test]
    fn patch_secret_frozen_keeps_ttl_and_reads() {
        let (store, _dir) = open_temp_store();
        let key = generate_key();
        let (ct, nonce) = crate::store::crypto::encrypt(&key, b"original").unwrap();
        let record = SecretRecord {
            hash: "patch_me".to_string(),
            value_ciphertext: ct,
            nonce,
            created_at: 1_000_000,
            ttl_expires_at: Some(9_999_999),
            reads_remaining: Some(5),
            burned: false,
            owner_key_id: Some("key-001".to_string()),
            created_by_ip: None,
        };
        store.create_secret(&record).unwrap();

        // Patch with no reset.
        let updated = store
            .patch_secret("patch_me", b"updated value", "key-001", None, None, &key)
            .unwrap();

        assert_eq!(
            updated.ttl_expires_at,
            Some(9_999_999),
            "TTL should be frozen"
        );
        assert_eq!(updated.reads_remaining, Some(5), "reads should be frozen");

        // Verify decryption works.
        let (pt, _) = store.consume_read("patch_me", 500_000, &key).unwrap();
        assert_eq!(pt, b"updated value");
    }

    #[test]
    fn patch_secret_reset_ttl_and_reads() {
        let (store, _dir) = open_temp_store();
        let key = generate_key();
        let (ct, nonce) = crate::store::crypto::encrypt(&key, b"original").unwrap();
        let record = SecretRecord {
            hash: "patch_reset".to_string(),
            value_ciphertext: ct,
            nonce,
            created_at: 1_000_000,
            ttl_expires_at: Some(2_000_000),
            reads_remaining: Some(2),
            burned: false,
            owner_key_id: Some("key-002".to_string()),
            created_by_ip: None,
        };
        store.create_secret(&record).unwrap();

        let updated = store
            .patch_secret(
                "patch_reset",
                b"new value",
                "key-002",
                Some(5_000_000),
                Some(10),
                &key,
            )
            .unwrap();

        assert_eq!(updated.ttl_expires_at, Some(5_000_000));
        assert_eq!(updated.reads_remaining, Some(10));
    }

    #[test]
    fn patch_secret_wrong_owner_returns_error() {
        let (store, _dir) = open_temp_store();
        let key = generate_key();
        let (ct, nonce) = crate::store::crypto::encrypt(&key, b"val").unwrap();
        let record = SecretRecord {
            hash: "owned".to_string(),
            value_ciphertext: ct,
            nonce,
            created_at: 1_000_000,
            ttl_expires_at: None,
            reads_remaining: None,
            burned: false,
            owner_key_id: Some("alice".to_string()),
            created_by_ip: None,
        };
        store.create_secret(&record).unwrap();

        let err = store
            .patch_secret("owned", b"hax", "bob", None, None, &key)
            .unwrap_err();
        assert!(matches!(err, StoreError::WrongOwner));
    }

    // ── Sub-task 10: burn_secret ──────────────────────────────────────────────

    #[test]
    fn burn_secret_tombstones_record() {
        let (store, _dir) = open_temp_store();
        let key = generate_key();
        let record = make_secret("burn_me", &key);
        store.create_secret(&record).unwrap();

        store.burn_secret("burn_me", None).unwrap();

        // Tombstone should still exist.
        let got = store.get_secret("burn_me").unwrap().unwrap();
        assert!(got.is_burned());
        assert!(got.value_ciphertext.is_empty());
        assert_eq!(got.nonce, [0u8; 12]);
    }

    #[test]
    fn burn_secret_subsequent_consume_returns_burned() {
        let (store, _dir) = open_temp_store();
        let key = generate_key();
        let record = make_secret("burn_then_read", &key);
        store.create_secret(&record).unwrap();
        store.burn_secret("burn_then_read", None).unwrap();

        let err = store
            .consume_read("burn_then_read", 1_000_000, &key)
            .unwrap_err();
        assert!(matches!(err, StoreError::Burned));
    }

    // ── Sub-task 11: create_key ───────────────────────────────────────────────

    #[test]
    fn create_key_and_lookup_by_name_and_token() {
        let (store, _dir) = open_temp_store();

        let (record, token) = store.create_key("alice", None, None, None).unwrap();
        assert_eq!(record.name, "alice");

        // Lookup by token.
        let found = store.find_key_by_token(&token).unwrap().unwrap();
        assert_eq!(found.id, record.id);

        // Lookup by name indirectly through list.
        let keys = store.list_keys().unwrap();
        assert!(keys.iter().any(|k| k.name == "alice"));
    }

    // ── Sub-task 12: find_key_by_token ───────────────────────────────────────

    #[test]
    fn wrong_token_returns_none() {
        let (store, _dir) = open_temp_store();
        store.create_key("alice", None, None, None).unwrap();

        // A valid-length hex token but not matching any key.
        let fake = hex::encode([42u8; 32]);
        let result = store.find_key_by_token(&fake).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn malformed_token_returns_none() {
        let (store, _dir) = open_temp_store();
        let result = store.find_key_by_token("not-valid-hex").unwrap();
        assert!(result.is_none());
    }

    // ── Sub-task 13: list_keys ────────────────────────────────────────────────

    #[test]
    fn list_keys_returns_all() {
        let (store, _dir) = open_temp_store();
        store.create_key("alice", None, None, None).unwrap();
        store.create_key("bob", None, None, None).unwrap();
        store.create_key("carol", None, None, None).unwrap();

        let keys = store.list_keys().unwrap();
        assert_eq!(keys.len(), 3);
    }

    // ── Sub-task 14: delete_key ───────────────────────────────────────────────

    #[test]
    fn delete_key_removes_from_all_tables() {
        let (store, _dir) = open_temp_store();
        let (_, token) = store.create_key("alice", None, None, None).unwrap();

        store.delete_key("alice").unwrap();

        // By name: list should be empty.
        let keys = store.list_keys().unwrap();
        assert!(keys.is_empty());

        // By token: should be None.
        let result = store.find_key_by_token(&token).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn delete_key_not_found_returns_error() {
        let (store, _dir) = open_temp_store();
        let err = store.delete_key("nobody").unwrap_err();
        assert!(matches!(err, StoreError::KeyNotFound));
    }

    // ── Sub-task 15: secrets_owned_by ────────────────────────────────────────

    #[test]
    fn secrets_owned_by_count_and_histogram() {
        let (store, _dir) = open_temp_store();
        let key = generate_key();

        // 3 secrets for key A with prefix "db1_".
        for i in 0..3 {
            let (ct, nonce) = crate::store::crypto::encrypt(&key, b"val").unwrap();
            let record = SecretRecord {
                hash: format!("db1_{:032x}", i),
                value_ciphertext: ct,
                nonce,
                created_at: 1_000_000,
                ttl_expires_at: None,
                reads_remaining: None,
                burned: false,
                owner_key_id: Some("key-A".to_string()),
                created_by_ip: None,
            };
            store.create_secret(&record).unwrap();
        }

        // 2 secrets for key A unprefixed.
        for i in 3..5 {
            let (ct, nonce) = crate::store::crypto::encrypt(&key, b"val").unwrap();
            let record = SecretRecord {
                hash: format!("nopfx{:032x}", i),
                value_ciphertext: ct,
                nonce,
                created_at: 1_000_000,
                ttl_expires_at: None,
                reads_remaining: None,
                burned: false,
                owner_key_id: Some("key-A".to_string()),
                created_by_ip: None,
            };
            store.create_secret(&record).unwrap();
        }

        // 2 secrets for key B.
        for i in 0..2 {
            let (ct, nonce) = crate::store::crypto::encrypt(&key, b"val").unwrap();
            let record = SecretRecord {
                hash: format!("prod_{:032x}", i),
                value_ciphertext: ct,
                nonce,
                created_at: 1_000_000,
                ttl_expires_at: None,
                reads_remaining: None,
                burned: false,
                owner_key_id: Some("key-B".to_string()),
                created_by_ip: None,
            };
            store.create_secret(&record).unwrap();
        }

        let (count, hist) = store.secrets_owned_by("key-A").unwrap();
        assert_eq!(count, 5);
        assert_eq!(hist.get("db1_").copied().unwrap_or(0), 3);
        assert_eq!(hist.get("(unprefixed)").copied().unwrap_or(0), 2);

        let (count_b, _) = store.secrets_owned_by("key-B").unwrap();
        assert_eq!(count_b, 2);
    }

    // ── Sub-task 16: purge_secrets_for_key ───────────────────────────────────

    #[test]
    fn purge_secrets_for_key_burns_all() {
        let (store, _dir) = open_temp_store();
        let key = generate_key();

        for i in 0..5 {
            let (ct, nonce) = crate::store::crypto::encrypt(&key, b"val").unwrap();
            let record = SecretRecord {
                hash: format!("purge_{i}"),
                value_ciphertext: ct,
                nonce,
                created_at: 1_000_000,
                ttl_expires_at: None,
                reads_remaining: None,
                burned: false,
                owner_key_id: Some("victim-key".to_string()),
                created_by_ip: None,
            };
            store.create_secret(&record).unwrap();
        }

        let burned = store.purge_secrets_for_key("victim-key").unwrap();
        assert_eq!(burned, 5);

        // All 5 should be tombstones.
        for i in 0..5 {
            let r = store.get_secret(&format!("purge_{i}")).unwrap().unwrap();
            assert!(r.is_burned());
        }
    }

    // ── Sub-task 17: set/get_visibility ──────────────────────────────────────

    #[test]
    fn set_and_get_visibility() {
        let (store, _dir) = open_temp_store();
        store.set_visibility(Visibility::Both).unwrap();
        assert_eq!(store.get_visibility().unwrap(), Visibility::Both);
    }

    // ── Sub-task 18: record_audit / query_audit ───────────────────────────────

    #[test]
    fn audit_insert_and_query_newest_first() {
        let (store, _dir) = open_temp_store();

        for i in 0..3 {
            let mut ev = AuditEvent::new(
                ACTION_SECRET_CREATE,
                None,
                Some(format!("hash_{i}")),
                "127.0.0.1".to_string(),
                true,
                None,
            );
            ev.timestamp = 1_000_000 + i as i64;
            store.record_audit(ev).unwrap();
        }

        let query = AuditQuery {
            limit: 2,
            ..Default::default()
        };
        let results = store.query_audit(&query).unwrap();
        assert_eq!(results.len(), 2);
        // Newest first: id 3, then id 2.
        assert_eq!(results[0].id, 3);
        assert_eq!(results[1].id, 2);
    }

    #[test]
    fn audit_query_filter_by_action() {
        let (store, _dir) = open_temp_store();

        store
            .record_audit(AuditEvent::new(
                ACTION_SECRET_CREATE,
                None,
                None,
                "1.1.1.1".to_string(),
                true,
                None,
            ))
            .unwrap();
        store
            .record_audit(AuditEvent::new(
                crate::store::audit::ACTION_SECRET_READ,
                None,
                None,
                "1.1.1.1".to_string(),
                true,
                None,
            ))
            .unwrap();

        let query = AuditQuery {
            action: Some(ACTION_SECRET_CREATE.to_string()),
            limit: 10,
            ..Default::default()
        };
        let results = store.query_audit(&query).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].action, ACTION_SECRET_CREATE);
    }

    // ── Sub-task 19: prune_tombstones ────────────────────────────────────────

    #[test]
    fn prune_tombstones_removes_old_burned_secrets() {
        let (store, _dir) = open_temp_store();
        let enc_key = generate_key();
        let (ct, nonce) = crate::store::crypto::encrypt(&enc_key, b"val").unwrap();

        // Secret burned at t=0.
        let mut record = SecretRecord {
            hash: "old_burn".to_string(),
            value_ciphertext: ct,
            nonce,
            created_at: 0, // very old
            ttl_expires_at: None,
            reads_remaining: None,
            burned: true,
            owner_key_id: None,
            created_by_ip: None,
        };
        record.value_ciphertext = vec![];
        record.nonce = [0u8; 12];
        store.create_secret(&record).unwrap();

        // now = 7 days + 1 second past the cutoff (created_at=0).
        // Default retention = 7 days = 604800s.
        let now = 604_801i64;

        // Override env var is not needed since default is 7.
        let pruned = store.prune_tombstones(now).unwrap();
        assert_eq!(pruned, 1);

        // Secret should be gone.
        let result = store.get_secret("old_burn").unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn prune_tombstones_keeps_recent_burned() {
        let (store, _dir) = open_temp_store();
        let enc_key = generate_key();

        // Burned secret but very recent.
        let record = SecretRecord {
            hash: "recent_burn".to_string(),
            value_ciphertext: vec![],
            nonce: [0u8; 12],
            created_at: 1_000_000,
            ttl_expires_at: None,
            reads_remaining: None,
            burned: true,
            owner_key_id: None,
            created_by_ip: None,
        };
        store.create_secret(&record).unwrap();

        // now is only 1 day past created_at; retention = 7 days.
        let now = 1_000_000 + 86_400;
        let pruned = store.prune_tombstones(now).unwrap();
        assert_eq!(pruned, 0);

        let _ = enc_key; // suppress unused warning
    }

    // ── Sub-task 20: prune_audit ──────────────────────────────────────────────

    #[test]
    fn prune_audit_removes_old_events() {
        let (store, _dir) = open_temp_store();

        // Insert an event with a very old timestamp.
        let mut ev = AuditEvent::new(
            ACTION_SECRET_CREATE,
            None,
            None,
            "1.1.1.1".to_string(),
            true,
            None,
        );
        ev.timestamp = 0; // epoch
        store.record_audit(ev).unwrap();

        // now = 30 days + 1 second past epoch. Default retention = 30 days.
        let now = 30 * 86_400 + 1;
        let pruned = store.prune_audit(now).unwrap();
        assert_eq!(pruned, 1);

        let query = AuditQuery {
            limit: 100,
            ..Default::default()
        };
        let results = store.query_audit(&query).unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn prune_audit_keeps_recent_events() {
        let (store, _dir) = open_temp_store();

        // A recent audit event.
        let ev = AuditEvent::new(
            ACTION_SECRET_CREATE,
            None,
            None,
            "1.1.1.1".to_string(),
            true,
            None,
        );
        store.record_audit(ev).unwrap();

        // now is only 1 day from "now" (which is wall clock ≈ today).
        // Retention is 30 days, so nothing should be pruned.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
            + 86_400;
        let pruned = store.prune_audit(now).unwrap();
        assert_eq!(pruned, 0);
    }

    // ── extract_prefix helper ─────────────────────────────────────────────────

    #[test]
    fn extract_prefix_with_underscore() {
        assert_eq!(extract_prefix("db1_abc"), "db1_");
        assert_eq!(extract_prefix("prod_secret_abc"), "prod_secret_");
    }

    #[test]
    fn extract_prefix_without_underscore() {
        assert_eq!(extract_prefix("abcdef1234"), "(unprefixed)");
    }
}
