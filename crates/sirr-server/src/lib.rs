pub mod auth;
pub mod dirs;
pub mod handlers;
pub mod heartbeat;
pub mod license;
pub mod server;
pub mod store;
pub mod validator;
pub mod webhooks;

/// Shared application state threaded through axum handlers.
#[derive(Clone)]
pub struct AppState {
    pub store: store::Store,
    /// Optional API key for write-protecting mutations.
    pub api_key: Option<String>,
    /// Validated license status (set at startup).
    pub license: license::LicenseStatus,
    /// Online license validator (present only when a license key is configured).
    pub validator: Option<validator::OnlineValidator>,
    /// Webhook sender for dispatching event notifications.
    pub webhook_sender: Option<webhooks::WebhookSender>,
    /// Peer IPs (CIDRs) whose X-Forwarded-For / X-Real-IP headers are trusted
    /// for audit-log IP attribution. Empty = never trust proxy headers.
    pub trusted_proxies: std::sync::Arc<Vec<ipnet::IpNet>>,
    /// When true, key names in /audit responses are replaced with
    /// `sha256:<first 8 hex chars>` instead of the raw name.
    pub redact_audit_keys: bool,
}

pub use server::{read_key_file, resolve_data_dir, run, ServerConfig};
