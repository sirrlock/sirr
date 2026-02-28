use anyhow::{Context, Result};
use redb::{ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};

pub(crate) const API_KEYS: TableDefinition<&str, &[u8]> = TableDefinition::new("api_keys");

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Permission {
    Read,
    Write,
    Delete,
    Admin,
}

impl Permission {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "read" => Some(Self::Read),
            "write" => Some(Self::Write),
            "delete" => Some(Self::Delete),
            "admin" => Some(Self::Admin),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
            Self::Delete => "delete",
            Self::Admin => "admin",
        }
    }
}

impl std::fmt::Display for Permission {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKeyRecord {
    pub id: String,
    pub key_hash: Vec<u8>,
    pub label: String,
    pub permissions: Vec<Permission>,
    pub prefix: Option<String>,
    pub created_at: i64,
}

/// Generate a new API key in the format `sirr_key_<32 hex chars>`.
pub fn generate_api_key() -> String {
    use rand::Rng;
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill(&mut bytes);
    format!("sirr_key_{}", hex::encode(bytes))
}

/// Generate a short random ID for an API key record.
pub fn generate_key_id() -> String {
    use rand::Rng;
    let mut bytes = [0u8; 8];
    rand::thread_rng().fill(&mut bytes);
    hex::encode(bytes)
}

/// Hash a key with SHA-256 for storage lookup.
pub fn hash_key(key: &str) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(key.as_bytes());
    hasher.finalize().to_vec()
}

impl super::db::Store {
    /// Insert an API key record.
    pub fn put_api_key(&self, record: &ApiKeyRecord) -> Result<()> {
        let bytes = bincode::serde::encode_to_vec(record, bincode::config::standard())
            .context("bincode encode api key")?;

        let write_txn = self.db.begin_write()?;
        {
            let mut table = write_txn.open_table(API_KEYS)?;
            table.insert(record.id.as_str(), bytes.as_slice())?;
        }
        write_txn.commit()?;
        Ok(())
    }

    /// List all API key records.
    pub fn list_api_keys(&self) -> Result<Vec<ApiKeyRecord>> {
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(API_KEYS)?;

        let mut records = Vec::new();
        for item in table.iter()? {
            let (_k, v) = item?;
            let (record, _): (ApiKeyRecord, _) =
                bincode::serde::decode_from_slice(v.value(), bincode::config::standard())
                    .context("bincode decode api key")?;
            records.push(record);
        }
        Ok(records)
    }

    /// Delete an API key by ID. Returns true if it existed.
    pub fn delete_api_key(&self, id: &str) -> Result<bool> {
        let write_txn = self.db.begin_write()?;
        let existed = {
            let mut table = write_txn.open_table(API_KEYS)?;
            let existed = table.remove(id)?.is_some();
            existed
        };
        write_txn.commit()?;
        Ok(existed)
    }

    /// Find an API key record by its SHA-256 hash. Scans all records.
    pub fn find_api_key_by_hash(&self, hash: &[u8]) -> Result<Option<ApiKeyRecord>> {
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(API_KEYS)?;

        for item in table.iter()? {
            let (_k, v) = item?;
            let (record, _): (ApiKeyRecord, _) =
                bincode::serde::decode_from_slice(v.value(), bincode::config::standard())
                    .context("bincode decode api key")?;
            if record.key_hash == hash {
                return Ok(Some(record));
            }
        }
        Ok(None)
    }

    /// Check if any scoped API keys exist in the store.
    pub fn has_api_keys(&self) -> Result<bool> {
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(API_KEYS)?;
        let has_any = table.iter()?.next().is_some();
        Ok(has_any)
    }
}
