use std::path::PathBuf;
use std::sync::Arc;

use crate::handlers::{router, AppState};
use crate::store::{crypto, Store, Visibility};

// ── Config ────────────────────────────────────────────────────────────────────

pub struct ServerConfig {
    pub bind_addr: std::net::SocketAddr,
    pub data_dir: PathBuf,
    pub admin_socket: PathBuf,
}

// ── Schema version ────────────────────────────────────────────────────────────

const SCHEMA_VERSION: &str = "2";
const CFG_SCHEMA_VERSION: &str = "schema_version";

// ── Bootstrap ─────────────────────────────────────────────────────────────────

/// Seed or validate the store after opening.
///
/// First boot: write schema_version and initial visibility.
/// Subsequent boots: check schema_version; exit with code 1 if stale.
fn bootstrap(store: &Store) -> anyhow::Result<()> {
    // Check for schema_version in the config table.
    let schema_ver = store.get_config_str(CFG_SCHEMA_VERSION)?;

    match schema_ver.as_deref() {
        None => {
            // First boot — fresh database.
            // Seed schema version.
            store.set_config_str(CFG_SCHEMA_VERSION, SCHEMA_VERSION)?;

            // Seed visibility from env var (default Public).
            let vis = initial_visibility();
            store.set_visibility(vis)?;

            tracing::info!(
                "sirrd: fresh store initialized (schema v{SCHEMA_VERSION}, visibility={vis})"
            );
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
            // Normal boot — check for visibility override.
            if std::env::var("SIRR_VISIBILITY_RESET").as_deref() == Ok("true") {
                let vis = initial_visibility();
                store.set_visibility(vis)?;
                tracing::info!(
                    "sirrd: SIRR_VISIBILITY_RESET=true — visibility overridden to {vis}"
                );
            }
        }
    }

    Ok(())
}

/// Read `SIRR_VISIBILITY` env var; default to `Public`.
fn initial_visibility() -> Visibility {
    std::env::var("SIRR_VISIBILITY")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(Visibility::Public)
}

// ── run() ─────────────────────────────────────────────────────────────────────

pub async fn run(config: ServerConfig) -> anyhow::Result<()> {
    // 1. Init tracing.
    tracing_subscriber::fmt::init();

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

    // 4. Build HTTP router.
    let state = AppState {
        store: store.clone(),
        encryption_key: Arc::new(encryption_key),
    };
    let app = router(state);

    // 5. Spawn admin socket task.
    crate::admin::spawn_admin_socket(store, config.admin_socket);

    // 6. Bind TCP listener.
    let listener = tokio::net::TcpListener::bind(&config.bind_addr).await?;
    tracing::info!("sirrd: HTTP listening on {}", config.bind_addr);

    // 7. Serve with graceful shutdown on SIGINT/SIGTERM.
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
