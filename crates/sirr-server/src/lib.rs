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
    /// The raw master key string, used for bearer-token comparison.
    pub master_key: String,
    /// Validated license status (set at startup).
    pub license: license::LicenseStatus,
}

pub use server::{load_or_create_salt, read_key_file, resolve_data_dir, resolve_master_key, run, ServerConfig};
