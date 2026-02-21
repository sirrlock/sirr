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
    /// Optional maximum number of reads before the record self-destructs.
    pub max_reads: Option<u32>,
    /// How many times this record has been read.
    pub read_count: u32,
}

impl SecretRecord {
    /// Returns true if this record has expired by time or read count.
    pub fn is_expired(&self, now: i64) -> bool {
        if let Some(exp) = self.expires_at {
            if now >= exp {
                return true;
            }
        }
        if let Some(max) = self.max_reads {
            if self.read_count >= max {
                return true;
            }
        }
        false
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
}
