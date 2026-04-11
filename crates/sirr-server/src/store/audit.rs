use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

// ── Action constants ──────────────────────────────────────────────────────────

pub const ACTION_SECRET_CREATE: &str = "secret.create";
pub const ACTION_SECRET_READ: &str = "secret.read";
pub const ACTION_SECRET_PATCH: &str = "secret.patch";
pub const ACTION_SECRET_BURN: &str = "secret.burn";
pub const ACTION_SECRET_EXPIRED: &str = "secret.expired";
pub const ACTION_KEY_CREATE: &str = "key.create";
pub const ACTION_KEY_DELETE: &str = "key.delete";
pub const ACTION_VISIBILITY_SET: &str = "visibility.set";

// ── AuditEvent ────────────────────────────────────────────────────────────────

/// A single audit log entry. Stored append-only in the `audit` redb table,
/// keyed by a monotonically incrementing `u64` id.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuditEvent {
    /// Monotonic ID assigned by the store; 0 at construction, set on insert.
    pub id: u64,
    /// Unix seconds.
    pub timestamp: i64,
    /// One of the `ACTION_*` constants above.
    pub action: String,
    /// The key id that performed the action, if any.
    pub key_id: Option<String>,
    /// The secret hash involved, if any.
    pub hash: Option<String>,
    /// Source IP address of the HTTP caller.
    pub source_ip: String,
    /// Whether the action succeeded.
    pub success: bool,
    /// Optional human-readable detail (e.g. error message on failure).
    pub detail: Option<String>,
}

impl AuditEvent {
    /// Construct a new `AuditEvent`. The `id` field is 0 and will be assigned
    /// by `Store::record_audit` on insertion.
    pub fn new(
        action: &str,
        key_id: Option<String>,
        hash: Option<String>,
        source_ip: String,
        success: bool,
        detail: Option<String>,
    ) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        Self {
            id: 0,
            timestamp,
            action: action.to_owned(),
            key_id,
            hash,
            source_ip,
            success,
            detail,
        }
    }
}

// ── AuditQuery ────────────────────────────────────────────────────────────────

/// Filter parameters for `Store::query_audit`.
#[derive(Debug, Default)]
pub struct AuditQuery {
    /// Return events with `timestamp >= since`.
    pub since: Option<i64>,
    /// Return events with `timestamp < until`.
    pub until: Option<i64>,
    /// Filter by exact action string.
    pub action: Option<String>,
    /// Filter by key_id.
    pub key_id: Option<String>,
    /// Filter by secret hash.
    pub hash: Option<String>,
    /// Maximum number of events to return. 0 = unlimited.
    pub limit: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_sets_zero_id_and_timestamp() {
        let ev = AuditEvent::new(
            ACTION_SECRET_CREATE,
            Some("key-01".to_string()),
            Some("hash_abc".to_string()),
            "127.0.0.1".to_string(),
            true,
            None,
        );
        assert_eq!(ev.id, 0);
        assert!(ev.timestamp > 0);
        assert_eq!(ev.action, ACTION_SECRET_CREATE);
        assert_eq!(ev.key_id.as_deref(), Some("key-01"));
        assert_eq!(ev.hash.as_deref(), Some("hash_abc"));
        assert!(ev.success);
    }

    #[test]
    fn new_anonymous_event_has_no_key_id() {
        let ev = AuditEvent::new(
            ACTION_SECRET_READ,
            None,
            Some("hash_xyz".to_string()),
            "10.0.0.1".to_string(),
            true,
            None,
        );
        assert!(ev.key_id.is_none());
    }

    #[test]
    fn bincode_round_trip() {
        let ev = AuditEvent {
            id: 42,
            timestamp: 1_712_846_400,
            action: ACTION_SECRET_BURN.to_string(),
            key_id: Some("01JKQ".to_string()),
            hash: Some("db1_deadbeef".to_string()),
            source_ip: "192.168.1.1".to_string(),
            success: true,
            detail: Some("burned after last read".to_string()),
        };

        let encoded = bincode::serde::encode_to_vec(&ev, bincode::config::standard()).unwrap();
        let (decoded, _): (AuditEvent, _) =
            bincode::serde::decode_from_slice(&encoded, bincode::config::standard()).unwrap();

        assert_eq!(ev, decoded);
    }

    #[test]
    fn action_constants_are_correct_strings() {
        assert_eq!(ACTION_SECRET_CREATE, "secret.create");
        assert_eq!(ACTION_SECRET_READ, "secret.read");
        assert_eq!(ACTION_SECRET_PATCH, "secret.patch");
        assert_eq!(ACTION_SECRET_BURN, "secret.burn");
        assert_eq!(ACTION_SECRET_EXPIRED, "secret.expired");
        assert_eq!(ACTION_KEY_CREATE, "key.create");
        assert_eq!(ACTION_KEY_DELETE, "key.delete");
        assert_eq!(ACTION_VISIBILITY_SET, "visibility.set");
    }
}
