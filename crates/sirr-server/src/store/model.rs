use serde::{Deserialize, Serialize};
use zeroize::ZeroizeOnDrop;

#[derive(Debug, Clone, Serialize, Deserialize, ZeroizeOnDrop)]
pub struct SecretRecord {
    pub value_encrypted: Vec<u8>,
    pub nonce: [u8; 12],
    pub created_at: i64,
    pub expires_at: Option<i64>,
    pub max_reads: Option<u32>,
    pub read_count: u32,
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
        let r = make_record(true, Some(1), 5);
        assert!(!r.is_expired(1000));
        let mut r2 = make_record(true, Some(1), 5);
        r2.expires_at = Some(500);
        assert!(r2.is_expired(1000));
    }

    #[test]
    fn is_burned_only_when_delete_true() {
        let r = make_record(true, Some(3), 3);
        assert!(r.is_burned());
        let r2 = make_record(false, Some(3), 3);
        assert!(!r2.is_burned());
    }

    #[test]
    fn is_sealed_only_when_delete_false() {
        let r = make_record(false, Some(3), 3);
        assert!(r.is_sealed());
        let r2 = make_record(true, Some(3), 3);
        assert!(!r2.is_sealed());
    }

    #[test]
    fn no_max_reads_never_burned_or_sealed() {
        let r = make_record(true, None, 100);
        assert!(!r.is_burned());
        assert!(!r.is_sealed());
    }
}
