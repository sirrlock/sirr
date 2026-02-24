pub mod auth;
pub mod dirs;
pub mod handlers;
pub mod license;
pub mod server;
pub mod store;

/// Shared application state threaded through axum handlers.
#[derive(Clone)]
pub struct AppState {
    pub store: store::Store,
    /// Optional API key for write-protecting mutations.
    pub api_key: Option<String>,
    /// Validated license status (set at startup).
    pub license: license::LicenseStatus,
}

pub use server::{read_key_file, resolve_data_dir, run, ServerConfig};
