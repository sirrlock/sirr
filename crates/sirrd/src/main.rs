use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

// ── CLI definition ─────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(
    name = "sirrd",
    about = "Sirrd — ephemeral secret vault server daemon",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the Sirr HTTP server
    Serve {
        /// Port to listen on (default: $SIRR_PORT or 39999)
        #[arg(long, env = "SIRR_PORT", default_value = "39999")]
        port: u16,
        /// Host to bind (default: $SIRR_HOST or 0.0.0.0)
        #[arg(long, env = "SIRR_HOST", default_value = "0.0.0.0")]
        host: String,
        /// Log level: error, warn, info, debug, verbose (default: $SIRR_LOG_LEVEL or warn)
        #[arg(long, env = "SIRR_LOG_LEVEL")]
        log_level: Option<String>,
    },
    /// Rotate the encryption key (offline). Re-encrypts all records with a new
    /// master key. Requires direct access to the sirr.key and sirr.db files.
    Rotate,
}

// ── Entry point ───────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    let effective_log_level = if let Commands::Serve { ref log_level, .. } = cli.command {
        let raw = log_level
            .clone()
            .or_else(|| std::env::var("SIRR_LOG_LEVEL").ok())
            .unwrap_or_else(|| "warn".into());
        if raw.eq_ignore_ascii_case("verbose") {
            "debug".to_owned()
        } else {
            raw
        }
    } else {
        std::env::var("SIRR_LOG_LEVEL").unwrap_or_else(|_| "warn".into())
    };

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::new(&effective_log_level))
        .init();

    match cli.command {
        Commands::Serve {
            port,
            host,
            log_level: _,
        } => cmd_serve(host, port, effective_log_level).await,

        Commands::Rotate => cmd_rotate().await,
    }
}

// ── Command implementations ───────────────────────────────────────────────────

async fn cmd_serve(host: String, port: u16, log_level: String) -> Result<()> {
    let no_banner = std::env::var("NO_BANNER")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    let cfg = sirr_server::ServerConfig {
        host,
        port,
        api_key: std::env::var("SIRR_API_KEY").ok(),
        license_key: std::env::var("SIRR_LICENSE_KEY").ok(),
        data_dir: std::env::var("SIRR_DATA_DIR").ok().map(Into::into),
        log_level,
        no_banner,
        ..Default::default()
    };

    sirr_server::run(cfg).await
}

async fn cmd_rotate() -> Result<()> {
    // Resolve data directory.
    let data_dir_env = std::env::var("SIRR_DATA_DIR").ok().map(Into::into);
    let data_dir = sirr_server::resolve_data_dir(data_dir_env.as_ref())?;

    // Load the current encryption key from sirr.key.
    let key_path = data_dir.join("sirr.key");
    let old_bytes =
        std::fs::read(&key_path).context("read sirr.key — is the server initialized?")?;
    let old_key = sirr_server::store::crypto::load_key(&old_bytes)
        .ok_or_else(|| anyhow::anyhow!("sirr.key is corrupt (expected 32 bytes)"))?;

    // Open the store with the old key.
    let db_path = data_dir.join("sirr.db");
    let store = sirr_server::store::Store::open(&db_path, old_key).context("open store")?;

    // Determine new key version (increment from current max).
    let current_version = store.max_key_version()?;
    let new_version = current_version
        .checked_add(1)
        .context("key version overflow (max 255 rotations)")?;

    // Generate a new random key and re-encrypt all records.
    let new_key = sirr_server::store::crypto::generate_key();
    let count = store.rotate(&new_key, new_version)?;

    // Write the new key to sirr.key.
    std::fs::write(&key_path, new_key.as_bytes()).context("write new sirr.key")?;

    println!("rotated {count} secret(s) to key version {new_version}");
    println!("new encryption key written to {}", key_path.display());
    Ok(())
}
