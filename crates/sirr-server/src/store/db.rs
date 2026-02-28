use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use redb::{Database, ReadableTable, TableDefinition};
use tokio::time;
use tracing::{debug, info, warn};

use super::audit::{AuditEvent, AuditQuery};
use super::crypto::EncryptionKey;
use super::model::{SecretMeta, SecretRecord};

const SECRETS: TableDefinition<&str, &[u8]> = TableDefinition::new("secrets");
const AUDIT_LOG: TableDefinition<u64, &[u8]> = TableDefinition::new("audit_log");
const COUNTERS: TableDefinition<&str, u64> = TableDefinition::new("counters");
const AUDIT_SEQ_KEY: &str = "audit_seq";

/// Marker byte for v2 record format (with key version tracking).
/// Legacy records (v1) start with a bincode varint for Vec length (always >= 16
/// for ChaCha20Poly1305 ciphertext), so 0x01 is unambiguous.
const RECORD_V2_MARKER: u8 = 0x01;

/// Result of a secret retrieval.
#[derive(Debug, PartialEq)]
pub enum GetResult {
    /// Secret found and decrypted. Read counter was incremented.
    /// Contains (value, webhook_url).
    Value(String, Option<String>),
    /// Secret found, decrypted, and burned (final read with delete=true).
    /// Contains (value, webhook_url).
    Burned(String, Option<String>),
    /// Secret exists but is sealed (delete=false, reads exhausted).
    Sealed,
    /// Secret not found or TTL-expired.
    NotFound,
}

/// Thread-safe handle to the redb store.
#[derive(Clone)]
pub struct Store {
    pub(crate) db: Arc<Database>,
    key: Arc<EncryptionKey>,
    key_version: u8,
}

impl Store {
    /// Open (or create) the database at `path`, using `key` for encryption.
    pub fn open(path: &Path, key: EncryptionKey) -> Result<Self> {
        Self::open_versioned(path, key, 1)
    }

    /// Open (or create) the database at `path`, using `key` with an explicit version tag.
    /// The `key_version` is stored alongside each encrypted record to support key rotation.
    pub fn open_versioned(path: &Path, key: EncryptionKey, key_version: u8) -> Result<Self> {
        let db = Database::create(path).context("open redb database")?;

        // Ensure all tables exist.
        let write_txn = db.begin_write()?;
        write_txn.open_table(SECRETS)?;
        write_txn.open_table(AUDIT_LOG)?;
        write_txn.open_table(COUNTERS)?;
        write_txn.open_table(super::webhooks::WEBHOOKS)?;
        write_txn.open_table(super::api_keys::API_KEYS)?;
        write_txn.commit()?;

        Ok(Self {
            db: Arc::new(db),
            key: Arc::new(key),
            key_version,
        })
    }

    fn now() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64
    }

    /// Insert or overwrite a secret.
    pub fn put(
        &self,
        secret_key: &str,
        value: &str,
        ttl_seconds: Option<u64>,
        max_reads: Option<u32>,
        delete: bool,
        webhook_url: Option<String>,
    ) -> Result<()> {
        let now = Self::now();
        let expires_at = ttl_seconds.map(|ttl| now + ttl as i64);

        let (value_encrypted, nonce) =
            super::crypto::encrypt(&self.key, value.as_bytes()).context("encrypt value")?;

        let record = SecretRecord {
            value_encrypted,
            nonce,
            created_at: now,
            expires_at,
            max_reads,
            read_count: 0,
            delete,
            webhook_url,
        };

        let bytes = encode(&record, self.key_version)?;
        let write_txn = self.db.begin_write()?;
        {
            let mut table = write_txn.open_table(SECRETS)?;
            table.insert(secret_key, bytes.as_slice())?;
        }
        write_txn.commit()?;

        debug!(key = %secret_key, "stored secret");
        Ok(())
    }

    /// Retrieve a secret's value, incrementing its read counter.
    /// Returns `GetResult::NotFound` if the key doesn't exist or has expired / burned.
    /// Returns `GetResult::Sealed` if the secret exists but reads are exhausted (delete=false).
    /// Returns `GetResult::Value(value)` on success.
    pub fn get(&self, secret_key: &str) -> Result<GetResult> {
        let now = Self::now();

        // We need a write transaction to atomically increment read_count.
        let write_txn = self.db.begin_write()?;
        let result = {
            let mut table = write_txn.open_table(SECRETS)?;

            // Read the raw bytes and immediately clone them so the AccessGuard
            // (which borrows `table`) is dropped before any mutation.
            let raw_bytes: Option<Vec<u8>> =
                table.get(secret_key)?.map(|guard| guard.value().to_vec());

            match raw_bytes {
                None => GetResult::NotFound,
                Some(bytes) => {
                    let (mut record, record_key_version) = decode(&bytes)?;

                    if record.is_expired(now) {
                        table.remove(secret_key)?;
                        debug!(key = %secret_key, "lazy-evicted expired secret");
                        GetResult::NotFound
                    } else if record.is_sealed() {
                        GetResult::Sealed
                    } else {
                        record.read_count += 1;

                        let plaintext = super::crypto::decrypt(
                            &self.key,
                            &record.value_encrypted,
                            &record.nonce,
                        )
                        .context("decrypt value")?;

                        let value = String::from_utf8(plaintext)
                            .context("secret value is not valid UTF-8")?;

                        let webhook_url = record.webhook_url.clone();
                        if record.is_burned() {
                            table.remove(secret_key)?;
                            debug!(key = %secret_key, "burned after final read");
                            GetResult::Burned(value, webhook_url)
                        } else {
                            let updated = encode(&record, record_key_version)?;
                            table.insert(secret_key, updated.as_slice())?;
                            GetResult::Value(value, webhook_url)
                        }
                    }
                }
            }
        };
        write_txn.commit()?;
        Ok(result)
    }

    /// Delete a secret by key. Returns true if it existed.
    pub fn delete(&self, secret_key: &str) -> Result<bool> {
        let write_txn = self.db.begin_write()?;
        let existed = {
            let mut table = write_txn.open_table(SECRETS)?;
            // Clone the guard value immediately so the borrow ends before commit.
            let existed = table.remove(secret_key)?.is_some();
            existed
        };
        write_txn.commit()?;
        Ok(existed)
    }

    /// List metadata for all non-expired secrets.
    pub fn list(&self) -> Result<Vec<SecretMeta>> {
        let now = Self::now();
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(SECRETS)?;

        let mut metas = Vec::new();
        for item in table.iter()? {
            let (k, v) = item?;
            let (record, _kv) = decode(v.value())?;
            if !record.is_expired(now) {
                metas.push(SecretMeta {
                    key: k.value().to_owned(),
                    created_at: record.created_at,
                    expires_at: record.expires_at,
                    max_reads: record.max_reads,
                    read_count: record.read_count,
                    delete: record.delete,
                });
            }
        }
        Ok(metas)
    }

    /// Remove all expired secrets. Returns the names of removed keys.
    pub fn prune(&self) -> Result<Vec<String>> {
        let now = Self::now();

        // Collect expired keys in a read pass first.
        let expired_keys: Vec<String> = {
            let read_txn = self.db.begin_read()?;
            let table = read_txn.open_table(SECRETS)?;
            let mut keys = Vec::new();
            for item in table.iter()? {
                let (k, v) = item?;
                let (record, _kv) = decode(v.value())?;
                if record.is_expired(now) || record.is_burned() {
                    keys.push(k.value().to_owned());
                }
            }
            keys
        };

        if expired_keys.is_empty() {
            return Ok(vec![]);
        }

        let write_txn = self.db.begin_write()?;
        {
            let mut table = write_txn.open_table(SECRETS)?;
            for key in &expired_keys {
                table.remove(key.as_str())?;
            }
        }
        write_txn.commit()?;

        let removed = expired_keys.len();
        if removed > 0 {
            info!(removed, "pruned expired secrets");
        }
        Ok(expired_keys)
    }

    /// Retrieve metadata for a secret without incrementing read_count.
    /// Returns (meta, is_sealed). Returns None if not found or TTL-expired.
    pub fn head(&self, secret_key: &str) -> Result<Option<(SecretMeta, bool)>> {
        let now = Self::now();
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(SECRETS)?;

        let raw_bytes: Option<Vec<u8>> = table.get(secret_key)?.map(|guard| guard.value().to_vec());

        match raw_bytes {
            None => Ok(None),
            Some(bytes) => {
                let (record, _kv) = decode(&bytes)?;
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
                    let (mut record, record_key_version) = decode(&bytes)?;

                    if record.is_expired(now) {
                        table.remove(secret_key)?;
                        return Ok(None);
                    }

                    if record.delete {
                        anyhow::bail!("cannot patch a secret with delete=true");
                    }

                    if let Some(val) = new_value {
                        let (encrypted, nonce) = super::crypto::encrypt(&self.key, val.as_bytes())
                            .context("encrypt patched value")?;
                        record.value_encrypted = encrypted;
                        record.nonce = nonce;
                    }

                    if let Some(max) = new_max_reads {
                        record.max_reads = Some(max);
                    }

                    if let Some(ttl) = new_ttl_seconds {
                        record.expires_at = Some(now + ttl as i64);
                    }

                    record.read_count = 0;

                    let updated = encode(&record, record_key_version)?;
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

    // ── Audit log ─────────────────────────────────────────────────────────

    /// Record an audit event. Allocates a monotonic ID via the counters table.
    pub fn record_audit(&self, mut event: AuditEvent) -> Result<()> {
        let write_txn = self.db.begin_write()?;
        {
            let mut counters = write_txn.open_table(COUNTERS)?;
            let seq = counters.get(AUDIT_SEQ_KEY)?.map(|g| g.value()).unwrap_or(0) + 1;
            counters.insert(AUDIT_SEQ_KEY, seq)?;
            event.id = seq;

            let bytes = bincode::serde::encode_to_vec(&event, bincode::config::standard())
                .context("bincode encode audit event")?;
            let mut audit = write_txn.open_table(AUDIT_LOG)?;
            audit.insert(event.id, bytes.as_slice())?;
        }
        write_txn.commit()?;
        Ok(())
    }

    /// List audit events matching the query, most recent first.
    pub fn list_audit(&self, query: &AuditQuery) -> Result<Vec<AuditEvent>> {
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(AUDIT_LOG)?;

        let mut events = Vec::new();
        for item in table.iter()?.rev() {
            let (_k, v) = item?;
            let (event, _): (AuditEvent, _) =
                bincode::serde::decode_from_slice(v.value(), bincode::config::standard())
                    .context("bincode decode audit event")?;

            if let Some(since) = query.since {
                if event.timestamp < since {
                    break; // IDs are monotonic, older events follow — stop early.
                }
            }
            if let Some(until) = query.until {
                if event.timestamp > until {
                    continue;
                }
            }
            if let Some(ref action) = query.action {
                if event.action != *action {
                    continue;
                }
            }
            events.push(event);
            if events.len() >= query.limit {
                break;
            }
        }
        Ok(events)
    }

    /// Remove audit events older than `retention_seconds`. Returns count removed.
    pub fn prune_audit(&self, retention_seconds: i64) -> Result<usize> {
        let cutoff = Self::now() - retention_seconds;

        // Read pass: collect IDs to remove.
        let ids_to_remove: Vec<u64> = {
            let read_txn = self.db.begin_read()?;
            let table = read_txn.open_table(AUDIT_LOG)?;
            let mut ids = Vec::new();
            for item in table.iter()? {
                let (k, v) = item?;
                let (event, _): (AuditEvent, _) =
                    bincode::serde::decode_from_slice(v.value(), bincode::config::standard())
                        .context("bincode decode audit for prune")?;
                if event.timestamp < cutoff {
                    ids.push(k.value());
                } else {
                    break; // IDs are monotonic — remaining are newer.
                }
            }
            ids
        };

        if ids_to_remove.is_empty() {
            return Ok(0);
        }

        let write_txn = self.db.begin_write()?;
        {
            let mut table = write_txn.open_table(AUDIT_LOG)?;
            for id in &ids_to_remove {
                table.remove(*id)?;
            }
        }
        write_txn.commit()?;

        let removed = ids_to_remove.len();
        if removed > 0 {
            info!(removed, "pruned old audit events");
        }
        Ok(removed)
    }

    /// Spawn a background task that prunes old audit events periodically.
    pub fn spawn_audit_sweep(self, interval: Duration, retention_seconds: i64) {
        tokio::spawn(async move {
            let mut ticker = time::interval(interval);
            ticker.tick().await; // skip first immediate tick
            loop {
                ticker.tick().await;
                if let Err(e) = self.prune_audit(retention_seconds) {
                    warn!(error = %e, "audit sweep error");
                }
            }
        });
    }

    /// Spawn a background Tokio task that calls `prune()` every `interval`.
    /// If a `WebhookSender` is provided, fires `secret.expired` for each pruned key.
    pub fn spawn_sweep(
        self,
        interval: Duration,
        webhook_sender: Option<crate::webhooks::WebhookSender>,
    ) {
        tokio::spawn(async move {
            let mut ticker = time::interval(interval);
            ticker.tick().await; // skip first immediate tick
            loop {
                ticker.tick().await;
                match self.prune() {
                    Ok(pruned_keys) => {
                        if let Some(ref sender) = webhook_sender {
                            for key in &pruned_keys {
                                sender.fire(
                                    "secret.expired",
                                    key,
                                    serde_json::json!({"reason": "ttl_or_burned"}),
                                );
                            }
                        }
                    }
                    Err(e) => {
                        warn!(error = %e, "background sweep error");
                    }
                }
            }
        });
    }

    /// Return the highest key version found across all stored records.
    /// Returns 1 if the database is empty (legacy default).
    pub fn max_key_version(&self) -> Result<u8> {
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(SECRETS)?;
        let mut max = 1u8;
        for item in table.iter()? {
            let (_k, v) = item?;
            let (_record, kv) = decode(v.value())?;
            max = max.max(kv);
        }
        Ok(max)
    }

    /// Re-encrypt all non-expired records with `new_key`, tagging them with
    /// `new_key_version`. The current `self.key` is used to decrypt.
    /// Returns the number of records rotated.
    pub fn rotate(&self, new_key: &EncryptionKey, new_key_version: u8) -> Result<usize> {
        let now = Self::now();

        // Read pass: collect all raw bytes keyed by secret name.
        let entries: Vec<(String, Vec<u8>)> = {
            let read_txn = self.db.begin_read()?;
            let table = read_txn.open_table(SECRETS)?;
            let mut out = Vec::new();
            for item in table.iter()? {
                let (k, v) = item?;
                out.push((k.value().to_owned(), v.value().to_vec()));
            }
            out
        };

        if entries.is_empty() {
            return Ok(0);
        }

        // Write pass: decrypt with old key, re-encrypt with new key.
        let write_txn = self.db.begin_write()?;
        let mut count = 0usize;
        {
            let mut table = write_txn.open_table(SECRETS)?;
            for (key, raw_bytes) in &entries {
                let (record, _old_version) = decode(raw_bytes)?;

                // Skip expired records — they'll be pruned normally.
                if record.is_expired(now) {
                    continue;
                }

                // Decrypt with old key.
                let plaintext =
                    super::crypto::decrypt(&self.key, &record.value_encrypted, &record.nonce)
                        .context("decrypt for rotation")?;

                // Re-encrypt with new key.
                let (new_encrypted, new_nonce) =
                    super::crypto::encrypt(new_key, &plaintext).context("encrypt for rotation")?;

                let new_record = SecretRecord {
                    value_encrypted: new_encrypted,
                    nonce: new_nonce,
                    created_at: record.created_at,
                    expires_at: record.expires_at,
                    max_reads: record.max_reads,
                    read_count: record.read_count,
                    delete: record.delete,
                    webhook_url: record.webhook_url.clone(),
                };

                let new_bytes = encode(&new_record, new_key_version)?;
                table.insert(key.as_str(), new_bytes.as_slice())?;
                count += 1;
            }
        }
        write_txn.commit()?;

        info!(rotated = count, new_key_version, "key rotation complete");
        Ok(count)
    }
}

/// Encode a SecretRecord in v2 format: `[RECORD_V2_MARKER, key_version] + bincode(record)`.
fn encode(record: &SecretRecord, key_version: u8) -> Result<Vec<u8>> {
    let payload = bincode::serde::encode_to_vec(record, bincode::config::standard())
        .context("bincode encode")?;
    let mut out = Vec::with_capacity(2 + payload.len());
    out.push(RECORD_V2_MARKER);
    out.push(key_version);
    out.extend_from_slice(&payload);
    Ok(out)
}

/// Decode bytes into `(SecretRecord, key_version)`.
/// Handles both v2 format (prefixed) and legacy v1 format (raw bincode).
fn decode(bytes: &[u8]) -> Result<(SecretRecord, u8)> {
    if bytes.is_empty() {
        anyhow::bail!("empty record");
    }
    if bytes[0] == RECORD_V2_MARKER {
        // v2 format: [0x01, key_version, bincode...]
        if bytes.len() < 3 {
            anyhow::bail!("truncated v2 record");
        }
        let key_version = bytes[1];
        let (record, _) =
            bincode::serde::decode_from_slice(&bytes[2..], bincode::config::standard())
                .context("bincode decode v2")?;
        Ok((record, key_version))
    } else {
        // Legacy v1: raw bincode, no version prefix. Assume key_version = 1.
        let (record, _) = bincode::serde::decode_from_slice(bytes, bincode::config::standard())
            .context("bincode decode")?;
        Ok((record, 1))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn make_store() -> (Store, tempfile::TempDir) {
        let key = super::super::crypto::generate_key();
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.db");
        let store = Store::open(&path, key).unwrap();
        (store, dir)
    }

    #[test]
    fn put_get_delete() {
        let (s, _dir) = make_store();
        s.put("MY_KEY", "my-value", None, None, true, None).unwrap();
        assert_eq!(
            s.get("MY_KEY").unwrap(),
            GetResult::Value("my-value".into(), None)
        );
        assert!(s.delete("MY_KEY").unwrap());
        assert_eq!(s.get("MY_KEY").unwrap(), GetResult::NotFound);
    }

    #[test]
    fn read_limit_burn() {
        let (s, _dir) = make_store();
        s.put("BURN", "secret", None, Some(1), true, None).unwrap();
        assert_eq!(
            s.get("BURN").unwrap(),
            GetResult::Burned("secret".into(), None)
        );
        // Second read should return NotFound — record was burned.
        assert_eq!(s.get("BURN").unwrap(), GetResult::NotFound);
    }

    #[test]
    fn ttl_expiry() {
        let (s, _dir) = make_store();
        // TTL = 0 means already expired.
        s.put("EXPIRED", "value", Some(0), None, true, None)
            .unwrap();
        assert_eq!(s.get("EXPIRED").unwrap(), GetResult::NotFound);
    }

    #[test]
    fn list_excludes_expired() {
        let (s, _dir) = make_store();
        s.put("LIVE", "v", Some(3600), None, true, None).unwrap();
        s.put("DEAD", "v", Some(0), None, true, None).unwrap();
        let metas = s.list().unwrap();
        assert!(metas.iter().any(|m| m.key == "LIVE"));
        assert!(!metas.iter().any(|m| m.key == "DEAD"));
    }

    #[test]
    fn head_returns_meta_without_incrementing() {
        let (s, _dir) = make_store();
        s.put("H", "val", None, Some(5), true, None).unwrap();
        let (meta, sealed) = s.head("H").unwrap().unwrap();
        assert_eq!(meta.read_count, 0);
        assert_eq!(meta.max_reads, Some(5));
        assert!(!sealed);
        let (meta2, _) = s.head("H").unwrap().unwrap();
        assert_eq!(meta2.read_count, 0);
    }

    #[test]
    fn head_returns_none_for_expired() {
        let (s, _dir) = make_store();
        s.put("HE", "val", Some(0), None, true, None).unwrap();
        assert!(s.head("HE").unwrap().is_none());
    }

    #[test]
    fn head_returns_sealed_status() {
        let (s, _dir) = make_store();
        s.put("HS", "val", None, Some(1), false, None).unwrap();
        s.get("HS").unwrap(); // read once, hits limit
        let (meta, sealed) = s.head("HS").unwrap().unwrap();
        assert!(sealed);
        assert_eq!(meta.read_count, 1);
    }

    #[test]
    fn patch_updates_value_and_resets_count() {
        let (s, _dir) = make_store();
        s.put("P", "old", None, Some(5), false, None).unwrap();
        s.get("P").unwrap(); // read_count = 1
        let meta = s.patch("P", Some("new"), None, None).unwrap().unwrap();
        assert_eq!(meta.read_count, 0); // reset
        assert_eq!(s.get("P").unwrap(), GetResult::Value("new".into(), None));
    }

    #[test]
    fn patch_rejects_delete_true_secret() {
        let (s, _dir) = make_store();
        s.put("PD", "val", None, None, true, None).unwrap();
        let err = s.patch("PD", Some("new"), None, None);
        assert!(err.is_err()); // should error for delete=true
    }

    #[test]
    fn patch_unseals_secret() {
        let (s, _dir) = make_store();
        s.put("PS", "val", None, Some(1), false, None).unwrap();
        s.get("PS").unwrap(); // now sealed
        assert_eq!(s.get("PS").unwrap(), GetResult::Sealed); // sealed, can't read
        s.patch("PS", None, Some(5), None).unwrap(); // unseal with new max_reads
        assert_eq!(s.get("PS").unwrap(), GetResult::Value("val".into(), None)); // readable again
    }

    #[test]
    fn patch_not_found() {
        let (s, _dir) = make_store();
        let result = s.patch("NOPE", Some("val"), None, None).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn get_sealed_returns_sealed_variant() {
        let (s, _dir) = make_store();
        s.put("GS", "val", None, Some(1), false, None).unwrap();
        assert!(matches!(s.get("GS").unwrap(), GetResult::Value(..)));
        assert!(matches!(s.get("GS").unwrap(), GetResult::Sealed));
    }

    // ── Audit tests ──────────────────────────────────────────────────────

    #[test]
    fn record_and_list_audit() {
        let (s, _dir) = make_store();

        s.record_audit(AuditEvent::new(
            "secret.create",
            Some("KEY1".into()),
            "127.0.0.1".into(),
            true,
            None,
        ))
        .unwrap();
        s.record_audit(AuditEvent::new(
            "secret.read",
            Some("KEY1".into()),
            "10.0.0.1".into(),
            true,
            None,
        ))
        .unwrap();

        let query = AuditQuery {
            since: None,
            until: None,
            action: None,
            limit: 100,
        };
        let events = s.list_audit(&query).unwrap();
        assert_eq!(events.len(), 2);
        // Most recent first.
        assert_eq!(events[0].action, "secret.read");
        assert_eq!(events[0].id, 2);
        assert_eq!(events[1].action, "secret.create");
        assert_eq!(events[1].id, 1);
    }

    #[test]
    fn audit_query_filters() {
        let (s, _dir) = make_store();

        // Insert 5 events.
        for i in 0..5 {
            let action = if i % 2 == 0 {
                "secret.create"
            } else {
                "secret.read"
            };
            s.record_audit(AuditEvent::new(
                action,
                Some(format!("K{i}")),
                "127.0.0.1".into(),
                true,
                None,
            ))
            .unwrap();
        }

        // Filter by action.
        let events = s
            .list_audit(&AuditQuery {
                since: None,
                until: None,
                action: Some("secret.create".into()),
                limit: 100,
            })
            .unwrap();
        assert_eq!(events.len(), 3); // indices 0, 2, 4

        // Limit.
        let events = s
            .list_audit(&AuditQuery {
                since: None,
                until: None,
                action: None,
                limit: 2,
            })
            .unwrap();
        assert_eq!(events.len(), 2);
    }

    #[test]
    fn audit_prune_removes_old_entries() {
        let (s, _dir) = make_store();

        // Insert an event with a manually backdated timestamp.
        let mut old_event = AuditEvent::new(
            "secret.create",
            Some("OLD".into()),
            "127.0.0.1".into(),
            true,
            None,
        );
        old_event.timestamp = 1000; // far in the past

        s.record_audit(old_event).unwrap();
        s.record_audit(AuditEvent::new(
            "secret.read",
            Some("NEW".into()),
            "127.0.0.1".into(),
            true,
            None,
        ))
        .unwrap();

        // Prune with a short retention (anything older than 1 day from now).
        let removed = s.prune_audit(86400).unwrap();
        assert_eq!(removed, 1);

        let events = s
            .list_audit(&AuditQuery {
                since: None,
                until: None,
                action: None,
                limit: 100,
            })
            .unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].action, "secret.read");
    }
}
