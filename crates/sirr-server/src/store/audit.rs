use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

// ── Action constants ─────────────────────────────────────────────────────────

pub const ACTION_SECRET_CREATE: &str = "secret.create";
pub const ACTION_SECRET_READ: &str = "secret.read";
pub const ACTION_SECRET_BURNED: &str = "secret.burned";
pub const ACTION_SECRET_DELETE: &str = "secret.delete";
pub const ACTION_SECRET_PATCH: &str = "secret.patch";
pub const ACTION_SECRET_LIST: &str = "secret.list";
pub const ACTION_SECRET_PRUNE: &str = "secret.prune";
pub const ACTION_SECRET_EXPIRED: &str = "secret.expired";
pub const ACTION_WEBHOOK_CREATE: &str = "webhook.create";
pub const ACTION_WEBHOOK_DELETE: &str = "webhook.delete";
pub const ACTION_KEY_CREATE: &str = "key.create";
pub const ACTION_KEY_DELETE: &str = "key.delete";

// ── AuditEvent ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub id: u64,
    pub timestamp: i64,
    pub action: String,
    pub key: Option<String>,
    pub source_ip: String,
    pub success: bool,
    pub detail: Option<String>,
}

impl AuditEvent {
    pub fn new(
        action: &str,
        key: Option<String>,
        source_ip: String,
        success: bool,
        detail: Option<String>,
    ) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        Self {
            id: 0, // allocated by store
            timestamp,
            action: action.to_owned(),
            key,
            source_ip,
            success,
            detail,
        }
    }
}

// ── AuditQuery ───────────────────────────────────────────────────────────────

pub struct AuditQuery {
    pub since: Option<i64>,
    pub until: Option<i64>,
    pub action: Option<String>,
    pub limit: usize,
}
