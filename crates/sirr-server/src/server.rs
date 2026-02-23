use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use axum::{
    middleware,
    routing::{delete, get, head, patch, post},
    Router,
};
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;
use tracing::info;

use crate::{
    auth::require_api_key,
    handlers::{
        create_secret, delete_secret, get_secret, head_secret, health, list_secrets,
        patch_secret, prune_secrets,
    },
    license, AppState,
};

pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub api_key: Option<String>,
    pub license_key: Option<String>,
    pub data_dir: Option<PathBuf>,
    pub sweep_interval: Duration,
    pub cors_origins: Option<String>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: std::env::var("SIRR_HOST").unwrap_or_else(|_| "0.0.0.0".into()),
            port: std::env::var("SIRR_PORT")
                .ok()
                .and_then(|p| p.parse().ok())
                .unwrap_or(8080),
            api_key: std::env::var("SIRR_API_KEY").ok(),
            license_key: std::env::var("SIRR_LICENSE_KEY").ok(),
            data_dir: std::env::var("SIRR_DATA_DIR").ok().map(PathBuf::from),
            sweep_interval: Duration::from_secs(300),
            cors_origins: std::env::var("SIRR_CORS_ORIGINS").ok(),
        }
    }
}

pub async fn run(cfg: ServerConfig) -> Result<()> {
    // Resolve data directory.
    let data_dir = match cfg.data_dir {
        Some(d) => {
            std::fs::create_dir_all(&d).context("create data dir")?;
            d
        }
        None => crate::dirs::data_dir()?,
    };

    info!(data_dir = %data_dir.display(), "using data directory");

    // Load or generate the encryption key.
    let enc_key = load_or_create_key(&data_dir)?;

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
        api_key: cfg.api_key,
        license: lic_status,
    };

    let cors = build_cors(cfg.cors_origins.as_deref());

    // Public routes (no auth required).
    let public = Router::new()
        .route("/health", get(health))
        .route("/secrets/{key}", get(get_secret))
        .route("/secrets/{key}", head(head_secret));

    // Protected routes (API key required if configured).
    let protected = Router::new()
        .route("/secrets", get(list_secrets))
        .route("/secrets", post(create_secret))
        .route("/secrets/{key}", patch(patch_secret))
        .route("/secrets/{key}", delete(delete_secret))
        .route("/prune", post(prune_secrets))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            require_api_key,
        ));

    let app = Router::new()
        .merge(public)
        .merge(protected)
        .with_state(state)
        .layer(cors)
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

fn load_or_create_key(
    data_dir: &std::path::Path,
) -> Result<crate::store::crypto::EncryptionKey> {
    let key_path = data_dir.join("sirr.key");
    if key_path.exists() {
        let bytes = std::fs::read(&key_path).context("read sirr.key")?;
        crate::store::crypto::load_key(&bytes).ok_or_else(|| {
            anyhow::anyhow!(
                "sirr.key is corrupt (expected 32 bytes, got {})",
                bytes.len()
            )
        })
    } else {
        let key = crate::store::crypto::generate_key();
        std::fs::write(&key_path, key.as_bytes()).context("write sirr.key")?;
        info!("generated new encryption key");
        Ok(key)
    }
}

fn build_cors(origins: Option<&str>) -> CorsLayer {
    let cors = CorsLayer::new()
        .allow_methods([
            http::Method::GET,
            http::Method::HEAD,
            http::Method::POST,
            http::Method::PATCH,
            http::Method::DELETE,
            http::Method::OPTIONS,
        ])
        .allow_headers(Any);

    match origins {
        Some(o) => {
            let origins: Vec<_> = o
                .split(',')
                .filter_map(|s| s.trim().parse().ok())
                .collect();
            cors.allow_origin(origins)
        }
        None => cors.allow_origin(Any),
    }
}
