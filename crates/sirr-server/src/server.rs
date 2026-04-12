use std::path::PathBuf;
use std::sync::Arc;

use crate::handlers::{router, AppState};
use crate::store::{crypto, Store, Visibility};

// ── Config ────────────────────────────────────────────────────────────────────

pub struct ServerConfig {
    pub bind_addr: std::net::SocketAddr,
    pub data_dir: PathBuf,
    pub admin_socket: PathBuf,
    pub visibility: Visibility,
    pub retention_days: i64,
    pub base_url: String,
    pub verbose: bool,
}

// ── Schema version ────────────────────────────────────────────────────────────

const SCHEMA_VERSION: &str = "2";
const CFG_SCHEMA_VERSION: &str = "schema_version";

// ── Bootstrap ─────────────────────────────────────────────────────────────────

/// Seed or validate the store after opening.
///
/// First boot: write schema_version.
/// Subsequent boots: check schema_version; exit with code 1 if stale.
fn bootstrap(store: &Store) -> anyhow::Result<()> {
    // Check for schema_version in the config table.
    let schema_ver = store.get_config_str(CFG_SCHEMA_VERSION)?;

    match schema_ver.as_deref() {
        None => {
            // First boot — fresh database.
            store.set_config_str(CFG_SCHEMA_VERSION, SCHEMA_VERSION)?;
            tracing::info!("sirrd: fresh store initialized (schema v{SCHEMA_VERSION})");
        }
        Some(v) if v < SCHEMA_VERSION => {
            // Stale schema — fatal.
            eprintln!(
                "ERROR: redb store is from sirrd <= 1.x, which used the org/principal model\n\
                 \x20      this version of sirrd cannot read it. The simplest path forward is:\n\
                 \x20        1. Stop sirrd\n\
                 \x20        2. Move the sirr.db to a backup location\n\
                 \x20        3. Start sirrd — a fresh store will be created"
            );
            std::process::exit(1);
        }
        Some(_) => {
            // Normal boot — nothing extra to do.
        }
    }

    Ok(())
}

// ── run() ─────────────────────────────────────────────────────────────────────

pub async fn run(config: ServerConfig) -> anyhow::Result<()> {
    // 1. Init tracing. When --verbose, include audit events (info level).
    {
        use tracing_subscriber::EnvFilter;
        let filter = if config.verbose {
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"))
        } else {
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info,sirr_server::store::db=warn"))
        };
        tracing_subscriber::fmt().with_env_filter(filter).init();
    }

    // 2. Load or generate the encryption key.
    std::fs::create_dir_all(&config.data_dir)?;
    let key_path = config.data_dir.join("sirr.key");

    let encryption_key = if key_path.exists() {
        let bytes = std::fs::read(&key_path)?;
        crypto::load_key(&bytes)
            .ok_or_else(|| anyhow::anyhow!("invalid key file at {}", key_path.display()))?
    } else {
        let key = crypto::generate_key();
        std::fs::write(&key_path, key.as_bytes())?;
        tracing::info!(
            "sirrd: generated new encryption key at {}",
            key_path.display()
        );
        key
    };

    // 3. Open store + bootstrap.
    let store = Store::open(config.data_dir.join("sirr.db"))?;
    bootstrap(&store)?;

    let store = Arc::new(store);

    // 4. Build shared visibility lock (seeded from CLI flag).
    let visibility = Arc::new(tokio::sync::RwLock::new(config.visibility));
    tracing::info!("sirrd: visibility={}", config.visibility);

    // 5. Build HTTP router.
    let state = AppState {
        store: store.clone(),
        encryption_key: Arc::new(encryption_key),
        visibility: visibility.clone(),
        webhook_sender: crate::webhooks::WebhookSender::new(),
        base_url: config.base_url.clone(),
    };
    let app = router(state);

    // 6. Spawn admin socket task.
    crate::admin::spawn_admin_socket(store, visibility, config.admin_socket);

    // 7. Bind TCP listener.
    let listener = tokio::net::TcpListener::bind(&config.bind_addr).await?;

    // Startup banner.
    let version = env!("CARGO_PKG_VERSION");
    eprintln!();
    eprintln!("  sirrd v{version}");
    eprintln!("  listening on http://{}", config.bind_addr);
    eprintln!("  visibility:  {}", config.visibility);
    if config.verbose {
        eprintln!("  verbose:     on (live audit events)");
    }
    eprintln!();
    eprintln!("  Tip: point the CLI at this server with:");
    eprintln!("    export SIRR_SERVER=http://{}", config.bind_addr);
    eprintln!("    sirr push \"my-secret\"");
    eprintln!();

    // 8. Serve with graceful shutdown on SIGINT/SIGTERM.
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    tracing::info!("sirrd: shutdown complete");
    Ok(())
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sigterm = signal(SignalKind::terminate()).expect("failed to register SIGTERM");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {},
            _ = sigterm.recv() => {},
        }
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c().await.ok();
    }
}
