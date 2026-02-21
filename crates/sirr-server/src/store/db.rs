use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use redb::{Database, ReadableTable, TableDefinition};
use tokio::time;
use tracing::{debug, info, warn};

use super::crypto::EncryptionKey;
use super::model::{SecretMeta, SecretRecord};

const SECRETS: TableDefinition<&str, &[u8]> = TableDefinition::new("secrets");

/// Thread-safe handle to the redb store.
#[derive(Clone)]
pub struct Store {
    db: Arc<Database>,
    key: Arc<EncryptionKey>,
}

impl Store {
    /// Open (or create) the database at `path`, using `key` for encryption.
    pub fn open(path: &Path, key: EncryptionKey) -> Result<Self> {
        let db = Database::create(path).context("open redb database")?;

        // Ensure the table exists.
        let write_txn = db.begin_write()?;
        write_txn.open_table(SECRETS)?;
        write_txn.commit()?;

        Ok(Self {
            db: Arc::new(db),
            key: Arc::new(key),
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
        };

        let bytes = encode(&record)?;
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
    /// Returns `None` if the key doesn't exist or has expired / burned.
    pub fn get(&self, secret_key: &str) -> Result<Option<String>> {
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
                None => None,
                Some(bytes) => {
                    let mut record: SecretRecord = decode(&bytes)?;

                    // Lazy expiry check.
                    if record.is_expired(now) {
                        table.remove(secret_key)?;
                        debug!(key = %secret_key, "lazy-evicted expired secret");
                        None
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
                        if record.is_expired(now) {
                            table.remove(secret_key)?;
                            debug!(key = %secret_key, "burned after final read");
                        } else {
                            // Write back updated read_count.
                            let updated = encode(&record)?;
                            table.insert(secret_key, updated.as_slice())?;
                        }

                        Some(value)
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
            let record: SecretRecord = decode(v.value())?;
            if !record.is_expired(now) {
                metas.push(SecretMeta {
                    key: k.value().to_owned(),
                    created_at: record.created_at,
                    expires_at: record.expires_at,
                    max_reads: record.max_reads,
                    read_count: record.read_count,
                });
            }
        }
        Ok(metas)
    }

    /// Remove all expired secrets. Returns count of removed entries.
    pub fn prune(&self) -> Result<usize> {
        let now = Self::now();

        // Collect expired keys in a read pass first.
        let expired_keys: Vec<String> = {
            let read_txn = self.db.begin_read()?;
            let table = read_txn.open_table(SECRETS)?;
            let mut keys = Vec::new();
            for item in table.iter()? {
                let (k, v) = item?;
                let record: SecretRecord = decode(v.value())?;
                if record.is_expired(now) {
                    keys.push(k.value().to_owned());
                }
            }
            keys
        };

        if expired_keys.is_empty() {
            return Ok(0);
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
        Ok(removed)
    }

    /// Spawn a background Tokio task that calls `prune()` every `interval`.
    pub fn spawn_sweep(self, interval: Duration) {
        tokio::spawn(async move {
            let mut ticker = time::interval(interval);
            ticker.tick().await; // skip first immediate tick
            loop {
                ticker.tick().await;
                if let Err(e) = self.prune() {
                    warn!(error = %e, "background sweep error");
                }
            }
        });
    }
}

fn encode(record: &SecretRecord) -> Result<Vec<u8>> {
    bincode::serde::encode_to_vec(record, bincode::config::standard()).context("bincode encode")
}

fn decode(bytes: &[u8]) -> Result<SecretRecord> {
    let (record, _) = bincode::serde::decode_from_slice(bytes, bincode::config::standard())
        .context("bincode decode")?;
    Ok(record)
}

#[cfg(test)]
mod tests {
    use super::super::crypto::{derive_key, generate_salt};
    use super::*;
    use tempfile::tempdir;

    fn make_store() -> (Store, tempfile::TempDir) {
        let salt = generate_salt();
        let key = derive_key("test-key", &salt).unwrap();
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.db");
        let store = Store::open(&path, key).unwrap();
        (store, dir)
    }

    #[test]
    fn put_get_delete() {
        let (s, _dir) = make_store();
        s.put("MY_KEY", "my-value", None, None).unwrap();
        assert_eq!(s.get("MY_KEY").unwrap(), Some("my-value".into()));
        assert!(s.delete("MY_KEY").unwrap());
        assert_eq!(s.get("MY_KEY").unwrap(), None);
    }

    #[test]
    fn read_limit_burn() {
        let (s, _dir) = make_store();
        s.put("BURN", "secret", None, Some(1)).unwrap();
        assert_eq!(s.get("BURN").unwrap(), Some("secret".into()));
        // Second read should return None — record was burned.
        assert_eq!(s.get("BURN").unwrap(), None);
    }

    #[test]
    fn ttl_expiry() {
        let (s, _dir) = make_store();
        // TTL = 0 means already expired.
        s.put("EXPIRED", "value", Some(0), None).unwrap();
        assert_eq!(s.get("EXPIRED").unwrap(), None);
    }

    #[test]
    fn list_excludes_expired() {
        let (s, _dir) = make_store();
        s.put("LIVE", "v", Some(3600), None).unwrap();
        s.put("DEAD", "v", Some(0), None).unwrap();
        let metas = s.list().unwrap();
        assert!(metas.iter().any(|m| m.key == "LIVE"));
        assert!(!metas.iter().any(|m| m.key == "DEAD"));
    }
}
