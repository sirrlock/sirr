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
use tracing::{info, warn};

use crate::{
    auth::require_api_key,
    handlers::{
        audit_events, create_api_key, create_secret, create_webhook, delete_api_key, delete_secret,
        delete_webhook, get_secret, head_secret, health, list_api_keys, list_secrets,
        list_webhooks, patch_secret, prune_secrets,
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
    pub audit_retention_days: u64,
    pub validation_url: String,
    pub validation_cache_secs: u64,
    /// Set `SIRR_HEARTBEAT=false` to disable instance heartbeat reporting.
    pub heartbeat: bool,
    /// Signing key for per-secret webhook URLs ($SIRR_WEBHOOK_SECRET).
    pub webhook_secret: Option<String>,
    /// Instance identifier for webhook event payloads ($SIRR_INSTANCE_ID).
    pub instance_id: Option<String>,
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
            audit_retention_days: std::env::var("SIRR_AUDIT_RETENTION_DAYS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(30),
            validation_url: std::env::var("SIRR_VALIDATION_URL")
                .unwrap_or_else(|_| "https://secretdrop.app/api/validate".into()),
            validation_cache_secs: std::env::var("SIRR_VALIDATION_CACHE_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(3600),
            heartbeat: std::env::var("SIRR_HEARTBEAT")
                .map(|v| v != "false" && v != "0")
                .unwrap_or(true),
            webhook_secret: std::env::var("SIRR_WEBHOOK_SECRET").ok(),
            instance_id: std::env::var("SIRR_INSTANCE_ID").ok(),
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
            tracing::warn!("both SIRR_MASTER_KEY and SIRR_MASTER_KEY_FILE are set; using file");
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

    // Load or generate the encryption key.
    // Read raw key bytes for instance ID generation (before they're wrapped).
    let key_path = data_dir.join("sirr.key");
    let enc_key = load_or_create_key(&data_dir)?;
    let key_bytes_for_id = std::fs::read(&key_path).ok();

    // Open redb store.
    let db_path = data_dir.join("sirr.db");
    let store = crate::store::Store::open(&db_path, enc_key).context("open store")?;

    // Resolve instance ID for webhook payloads.
    let webhook_instance_id = cfg
        .instance_id
        .clone()
        .unwrap_or_else(|| gethostname().unwrap_or_else(|| "unknown".into()));

    // Initialize webhook sender.
    let webhook_sender = crate::webhooks::WebhookSender::new(
        store.clone(),
        webhook_instance_id,
        cfg.webhook_secret.clone(),
    );

    // Spawn background sweeps (with webhook sender for expired events).
    store
        .clone()
        .spawn_sweep(cfg.sweep_interval, Some(webhook_sender.clone()));
    let retention_secs = (cfg.audit_retention_days * 86400) as i64;
    store
        .clone()
        .spawn_audit_sweep(cfg.sweep_interval, retention_secs);

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

    // Derive the heartbeat endpoint from the validation URL base.
    let heartbeat_url = cfg
        .validation_url
        .replace("/api/validate", "/api/instances/heartbeat");

    // Set up online license validation if a license key is configured and format is valid.
    let validator = if lic_status == license::LicenseStatus::Licensed {
        if let Some(ref key) = cfg.license_key {
            let v = crate::validator::OnlineValidator::new(
                key.clone(),
                cfg.validation_url,
                cfg.validation_cache_secs,
                259200, // 72-hour grace period
            );
            let valid = v.validate_startup(&store).await;
            if !valid {
                warn!("license rejected online — server will enforce free-tier limits above 100 secrets");
            }
            Some(v)
        } else {
            None
        }
    } else {
        None
    };

    // Spawn instance heartbeat if enabled and a license key is present.
    if cfg.heartbeat {
        if let (Some(ref license_key), Some(ref raw_bytes)) = (&cfg.license_key, &key_bytes_for_id)
        {
            let instance_id = crate::heartbeat::instance_id_from_key(raw_bytes);
            info!(instance_id = %instance_id, "starting instance heartbeat");
            crate::heartbeat::spawn_heartbeat(crate::heartbeat::HeartbeatConfig {
                endpoint: heartbeat_url,
                license_key: license_key.clone(),
                instance_id,
                store: store.clone(),
            });
        }
    }

    let state = AppState {
        store,
        api_key: cfg.api_key,
        license: lic_status,
        validator,
        webhook_sender: Some(webhook_sender),
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
        .route("/audit", get(audit_events))
        .route("/webhooks", post(create_webhook))
        .route("/webhooks", get(list_webhooks))
        .route("/webhooks/{id}", delete(delete_webhook))
        .route("/keys", post(create_api_key))
        .route("/keys", get(list_api_keys))
        .route("/keys/{id}", delete(delete_api_key))
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

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .context("server error")
}

fn load_or_create_key(data_dir: &std::path::Path) -> Result<crate::store::crypto::EncryptionKey> {
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

fn gethostname() -> Option<String> {
    std::process::Command::new("hostname")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
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
            let origins: Vec<_> = o.split(',').filter_map(|s| s.trim().parse().ok()).collect();
            cors.allow_origin(origins)
        }
        None => cors.allow_origin(Any),
    }
}
