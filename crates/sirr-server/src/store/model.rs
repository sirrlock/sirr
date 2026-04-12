use serde::{Deserialize, Serialize};

/// A stored secret record. The `hash` field doubles as the redb key.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SecretRecord {
    /// Server-generated identifier: optional prefix + random hex.
    /// Knowing the hash is the read capability.
    pub hash: String,
    /// ChaCha20Poly1305 ciphertext. Zeroed on burn.
    pub value_ciphertext: Vec<u8>,
    /// 12-byte nonce. Zeroed on burn.
    pub nonce: [u8; 12],
    /// Unix seconds when the secret was created.
    pub created_at: i64,
    /// Optional expiry as unix seconds. `None` = no time limit.
    pub ttl_expires_at: Option<i64>,
    /// Remaining read count. `None` = unlimited. Decremented on each read.
    pub reads_remaining: Option<u32>,
    /// True once the secret has been burned (read limit hit, TTL expired, or explicit DELETE).
    pub burned: bool,
    /// Unix seconds when the secret was burned. `None` for active secrets.
    pub burned_at: Option<i64>,
    /// `Some(key.id)` for keyed secrets; `None` for anonymous dead-drops.
    pub owner_key_id: Option<String>,
    /// Audit metadata: IP that created the secret.
    pub created_by_ip: Option<String>,
}

impl SecretRecord {
    /// True when the secret's TTL has elapsed.
    pub fn is_expired(&self, now: i64) -> bool {
        match self.ttl_expires_at {
            Some(exp) => now >= exp,
            None => false,
        }
    }

    /// True when the burned flag is set (tombstone).
    pub fn is_burned(&self) -> bool {
        self.burned
    }

    /// True when the next read should atomically burn the secret
    /// (i.e. reads_remaining is Some(1)).
    pub fn should_burn_after_read(&self) -> bool {
        matches!(self.reads_remaining, Some(1))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> SecretRecord {
        SecretRecord {
            hash: "test_abc123".to_string(),
            value_ciphertext: vec![1, 2, 3],
            nonce: [0u8; 12],
            created_at: 1_000_000,
            ttl_expires_at: None,
            reads_remaining: None,
            burned: false,
            burned_at: None,
            owner_key_id: None,
            created_by_ip: Some("127.0.0.1".to_string()),
        }
    }

    #[test]
    fn not_expired_when_no_ttl() {
        let r = sample();
        assert!(!r.is_expired(9_999_999));
    }

    #[test]
    fn expired_when_past_ttl() {
        let mut r = sample();
        r.ttl_expires_at = Some(1_000_100);
        assert!(!r.is_expired(1_000_099));
        assert!(r.is_expired(1_000_100));
        assert!(r.is_expired(2_000_000));
    }

    #[test]
    fn is_burned_reflects_flag() {
        let mut r = sample();
        assert!(!r.is_burned());
        r.burned = true;
        assert!(r.is_burned());
    }

    #[test]
    fn should_burn_after_read_only_at_one() {
        let mut r = sample();
        r.reads_remaining = None;
        assert!(!r.should_burn_after_read());
        r.reads_remaining = Some(2);
        assert!(!r.should_burn_after_read());
        r.reads_remaining = Some(1);
        assert!(r.should_burn_after_read());
        r.reads_remaining = Some(0);
        assert!(!r.should_burn_after_read());
    }

    #[test]
    fn bincode_round_trip() {
        let record = SecretRecord {
            hash: "prefix_deadbeef".to_string(),
            value_ciphertext: vec![10, 20, 30, 40],
            nonce: [7u8; 12],
            created_at: 1_712_846_400,
            ttl_expires_at: Some(1_712_850_000),
            reads_remaining: Some(3),
            burned: false,
            burned_at: None,
            owner_key_id: Some("01HZ1234".to_string()),
            created_by_ip: Some("10.0.0.1".to_string()),
        };

        let encoded = bincode::serde::encode_to_vec(&record, bincode::config::standard()).unwrap();
        let (decoded, _): (SecretRecord, _) =
            bincode::serde::decode_from_slice(&encoded, bincode::config::standard()).unwrap();

        assert_eq!(record, decoded);
    }
}
