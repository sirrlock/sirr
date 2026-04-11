use constant_time_eq::constant_time_eq_32;
use serde::{Deserialize, Serialize};

/// An API authentication credential. Stored in three redb tables:
/// `keys_by_id`, `keys_by_hash` (blake3 token hash → id), `keys_by_name` (name → id).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct KeyRecord {
    /// ULID — sortable, displayed in CLI output.
    pub id: String,
    /// Operator-chosen human label. Unique per server.
    pub name: String,
    /// blake3 hash of the bearer token. The plaintext token is shown once and discarded.
    pub hash: [u8; 32],
    /// Unix seconds when the key was created.
    pub created_at: i64,
    /// Optional time-window start (unix seconds). `None` = no lower bound.
    pub valid_after: Option<i64>,
    /// Optional time-window end (unix seconds). `None` = no upper bound.
    pub valid_before: Option<i64>,
    /// Optional webhook URL fired on lifecycle events for secrets owned by this key.
    pub webhook_url: Option<String>,
}

impl KeyRecord {
    /// True when the key is within its validity window.
    pub fn is_active(&self, now: i64) -> bool {
        if let Some(after) = self.valid_after {
            if now < after {
                return false;
            }
        }
        if let Some(before) = self.valid_before {
            if now >= before {
                return false;
            }
        }
        true
    }

    /// Constant-time comparison: blake3-hash `token` and compare to stored `hash`.
    pub fn verify_token(&self, token: &[u8]) -> bool {
        let computed = blake3::hash(token);
        constant_time_eq_32(computed.as_bytes(), &self.hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_hash() -> [u8; 32] {
        *blake3::hash(b"my-secret-token").as_bytes()
    }

    fn sample() -> KeyRecord {
        KeyRecord {
            id: "01HZ_SAMPLE".to_string(),
            name: "alice".to_string(),
            hash: sample_hash(),
            created_at: 1_712_846_400,
            valid_after: None,
            valid_before: None,
            webhook_url: None,
        }
    }

    #[test]
    fn is_active_no_window() {
        let k = sample();
        assert!(k.is_active(0));
        assert!(k.is_active(9_999_999_999));
    }

    #[test]
    fn is_active_before_window_start() {
        let mut k = sample();
        k.valid_after = Some(1_000_000);
        assert!(!k.is_active(999_999));
        assert!(k.is_active(1_000_000));
        assert!(k.is_active(2_000_000));
    }

    #[test]
    fn is_active_after_window_end() {
        let mut k = sample();
        k.valid_before = Some(1_000_000);
        assert!(k.is_active(999_999));
        assert!(!k.is_active(1_000_000));
        assert!(!k.is_active(2_000_000));
    }

    #[test]
    fn is_active_within_window() {
        let mut k = sample();
        k.valid_after = Some(1_000);
        k.valid_before = Some(2_000);
        assert!(!k.is_active(999));
        assert!(k.is_active(1_000));
        assert!(k.is_active(1_500));
        assert!(!k.is_active(2_000));
    }

    #[test]
    fn verify_token_correct() {
        let k = sample();
        assert!(k.verify_token(b"my-secret-token"));
    }

    #[test]
    fn verify_token_wrong() {
        let k = sample();
        assert!(!k.verify_token(b"wrong-token"));
    }

    #[test]
    fn bincode_round_trip() {
        let record = KeyRecord {
            id: "01JTEST".to_string(),
            name: "bob".to_string(),
            hash: [42u8; 32],
            created_at: 1_712_846_400,
            valid_after: Some(1_000_000),
            valid_before: None,
            webhook_url: Some("https://example.com/hook".to_string()),
        };

        let encoded = bincode::serde::encode_to_vec(&record, bincode::config::standard()).unwrap();
        let (decoded, _): (KeyRecord, _) =
            bincode::serde::decode_from_slice(&encoded, bincode::config::standard()).unwrap();

        assert_eq!(record, decoded);
    }
}
