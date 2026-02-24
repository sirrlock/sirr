use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use axum::{
    middleware,
    routing::{delete, get, post},
    Router,
};
use tower_http::trace::TraceLayer;
use tracing::info;

use crate::{
    auth::require_auth,
    handlers::{create_secret, delete_secret, get_secret, health, list_secrets, prune_secrets},
    license, AppState,
};

pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub master_key: String,
    pub license_key: Option<String>,
    pub data_dir: Option<PathBuf>,
    pub sweep_interval: Duration,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: std::env::var("SIRR_HOST").unwrap_or_else(|_| "0.0.0.0".into()),
            port: std::env::var("SIRR_PORT")
                .ok()
                .and_then(|p| p.parse().ok())
                .unwrap_or(8080),
            master_key: std::env::var("SIRR_MASTER_KEY").unwrap_or_default(),
            license_key: std::env::var("SIRR_LICENSE_KEY").ok(),
            data_dir: std::env::var("SIRR_DATA_DIR").ok().map(PathBuf::from),
            sweep_interval: Duration::from_secs(300),
        }
    }
}

/// Read a master key from a file, trimming surrounding whitespace.
/// Fails if the file cannot be read or is empty after trimming.
pub fn read_key_file(path: &std::path::Path) -> Result<String> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("read key file: {}", path.display()))?;
    let key = content.trim().to_string();
    if key.is_empty() {
        anyhow::bail!("key file is empty: {}", path.display());
    }
    Ok(key)
}

/// Resolve the master key from `SIRR_MASTER_KEY_FILE` (preferred) or `SIRR_MASTER_KEY`.
/// File-based delivery is recommended for production — env vars are visible via
/// `docker inspect` and `/proc`.
pub fn resolve_master_key() -> Result<String> {
    if let Ok(path) = std::env::var("SIRR_MASTER_KEY_FILE") {
        let key = read_key_file(std::path::Path::new(&path))?;
        if std::env::var("SIRR_MASTER_KEY").is_ok() {
            tracing::warn!(
                "both SIRR_MASTER_KEY and SIRR_MASTER_KEY_FILE are set; using file"
            );
        }
        return Ok(key);
    }
    std::env::var("SIRR_MASTER_KEY")
        .context("SIRR_MASTER_KEY or SIRR_MASTER_KEY_FILE environment variable is required")
}

/// Resolve the data directory and load the persisted salt.
/// Public so the CLI rotate command can reuse this logic.
pub fn resolve_data_dir(data_dir: Option<&PathBuf>) -> Result<PathBuf> {
    match data_dir {
        Some(d) => {
            std::fs::create_dir_all(d).context("create data dir")?;
            Ok(d.clone())
        }
        None => {
            let d = std::env::var("SIRR_DATA_DIR").ok().map(PathBuf::from);
            match d {
                Some(d) => {
                    std::fs::create_dir_all(&d).context("create data dir")?;
                    Ok(d)
                }
                None => crate::dirs::data_dir(),
            }
        }
    }
}

pub async fn run(cfg: ServerConfig) -> Result<()> {
    // Resolve data directory.
    let data_dir = resolve_data_dir(cfg.data_dir.as_ref())?;

    info!(data_dir = %data_dir.display(), "using data directory");

    // Load or generate the Argon2id salt.
    let salt = load_or_create_salt(&data_dir)?;

    // Derive encryption key from master key + salt.
    let enc_key = crate::store::crypto::derive_key(&cfg.master_key, &salt)
        .context("derive encryption key")?;

    // Open redb store.
    let db_path = data_dir.join("sirr.db");
    let store = crate::store::Store::open(&db_path, enc_key).context("open store")?;

    // Spawn background sweep.
    store.clone().spawn_sweep(cfg.sweep_interval);

    // Validate license key.
    let lic_status = license::effective_status(cfg.license_key.as_deref());
    match &lic_status {
        license::LicenseStatus::Free => {
            info!(
                "running on free tier (≤{} secrets)",
                license::FREE_TIER_LIMIT
            );
        }
        license::LicenseStatus::Licensed => {
            info!("license key accepted — unlimited secrets");
        }
        license::LicenseStatus::Invalid(reason) => {
            anyhow::bail!("invalid SIRR_LICENSE_KEY: {reason}");
        }
    }

    let state = AppState {
        store,
        master_key: cfg.master_key,
        license: lic_status,
    };

    // Build router.
    let protected = Router::new()
        .route("/secrets", get(list_secrets))
        .route("/secrets", post(create_secret))
        .route("/secrets/:key", get(get_secret))
        .route("/secrets/:key", delete(delete_secret))
        .route("/prune", post(prune_secrets))
        .layer(middleware::from_fn_with_state(state.clone(), require_auth));

    let app = Router::new()
        .route("/health", get(health))
        .merge(protected)
        .with_state(state)
        .layer(TraceLayer::new_for_http());

    let addr: SocketAddr = format!("{}:{}", cfg.host, cfg.port)
        .parse()
        .context("invalid host/port")?;

    info!(%addr, "sirr server listening");
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .context("bind listener")?;

    axum::serve(listener, app).await.context("server error")
}

pub fn load_or_create_salt(data_dir: &std::path::Path) -> Result<[u8; 32]> {
    let salt_path = data_dir.join("sirr.salt");
    if salt_path.exists() {
        let bytes = std::fs::read(&salt_path).context("read sirr.salt")?;
        if bytes.len() != 32 {
            anyhow::bail!(
                "sirr.salt is corrupt (expected 32 bytes, got {})",
                bytes.len()
            );
        }
        let mut salt = [0u8; 32];
        salt.copy_from_slice(&bytes);
        Ok(salt)
    } else {
        let salt = crate::store::crypto::generate_salt();
        std::fs::write(&salt_path, salt).context("write sirr.salt")?;
        info!("generated new encryption salt");
        Ok(salt)
    }
}
