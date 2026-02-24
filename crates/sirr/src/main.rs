use std::collections::HashMap;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use reqwest::Client;
use serde_json::Value;
use tracing_subscriber::EnvFilter;

// ── CLI definition ─────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(name = "sirr", about = "Sirr (سر) — ephemeral secret vault", version)]
struct Cli {
    /// Sirr server URL (default: http://localhost:8080 or $SIRR_SERVER)
    #[arg(long, env = "SIRR_SERVER", default_value = "http://localhost:8080")]
    server: String,

    /// API key for write operations ($SIRR_API_KEY)
    #[arg(long, env = "SIRR_API_KEY")]
    api_key: Option<String>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the Sirr HTTP server
    Serve {
        /// Port to listen on (default: $SIRR_PORT or 8080)
        #[arg(long, env = "SIRR_PORT", default_value = "8080")]
        port: u16,
        /// Host to bind (default: $SIRR_HOST or 0.0.0.0)
        #[arg(long, env = "SIRR_HOST", default_value = "0.0.0.0")]
        host: String,
    },
    /// Push a secret: `KEY=value` or a `.env` file path
    Push {
        /// KEY=value pair or path to a .env file
        #[arg(name = "TARGET")]
        target: String,
        /// TTL duration e.g. 1h, 30m, 7d
        #[arg(long)]
        ttl: Option<String>,
        /// Maximum number of reads before self-destructing
        #[arg(long)]
        reads: Option<u32>,
        /// Keep the secret after reads are exhausted (enables PATCH)
        #[arg(long)]
        no_delete: bool,
    },
    /// Get a secret by key
    Get {
        /// Secret key name
        key: String,
    },
    /// Pull all secrets into a .env file
    Pull {
        /// Path to write the .env file (default: .env)
        #[arg(default_value = ".env")]
        path: String,
    },
    /// Run a command with secrets injected as environment variables
    Run {
        /// Command and arguments
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<String>,
    },
    /// Print a shareable one-time URL for a secret
    Share {
        /// Secret key name
        key: String,
    },
    /// List all active secrets (metadata only)
    List,
    /// Delete a secret
    Delete {
        /// Secret key name
        key: String,
    },
    /// Delete all expired secrets immediately
    Prune,
    /// Rotate the encryption key (offline). Re-encrypts all records with a new
    /// master key. Requires SIRR_MASTER_KEY (or _FILE) for the current key and
    /// SIRR_NEW_MASTER_KEY (or _FILE) for the replacement.
    Rotate,
}

// ── Entry point ───────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_env("SIRR_LOG_LEVEL").unwrap_or_else(|_| EnvFilter::new("warn")),
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Serve { port, host } => cmd_serve(host, port).await,

        Commands::Push {
            target,
            ttl,
            reads,
            no_delete,
        } => {
            cmd_push(
                &cli.server,
                &cli.api_key,
                &target,
                ttl.as_deref(),
                reads,
                !no_delete,
            )
            .await
        }

        Commands::Get { key } => cmd_get(&cli.server, &key).await,

        Commands::Pull { path } => cmd_pull(&cli.server, &cli.api_key, &path).await,

        Commands::Run { command } => cmd_run(&cli.server, &cli.api_key, &command).await,

        Commands::Share { key } => {
            println!("{}/secrets/{}", cli.server.trim_end_matches('/'), key);
            Ok(())
        }

        Commands::List => cmd_list(&cli.server, &cli.api_key).await,

        Commands::Delete { key } => cmd_delete(&cli.server, &cli.api_key, &key).await,

        Commands::Prune => cmd_prune(&cli.server, &cli.api_key).await,

        Commands::Rotate => cmd_rotate().await,
    }
}

// ── Command implementations ───────────────────────────────────────────────────

async fn cmd_serve(host: String, port: u16) -> Result<()> {
    let cfg = sirr_server::ServerConfig {
        host,
        port,
        api_key: std::env::var("SIRR_API_KEY").ok(),
        license_key: std::env::var("SIRR_LICENSE_KEY").ok(),
        data_dir: std::env::var("SIRR_DATA_DIR").ok().map(Into::into),
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
    let old_bytes = std::fs::read(&key_path).context("read sirr.key — is the server initialized?")?;
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

async fn cmd_push(
    server: &str,
    api_key: &Option<String>,
    target: &str,
    ttl: Option<&str>,
    reads: Option<u32>,
    delete: bool,
) -> Result<()> {
    let ttl_seconds = ttl.map(parse_duration).transpose()?;

    // Check if target looks like a file path (contains '/' or is a filename that exists).
    if !target.contains('=') {
        // Treat as .env file path.
        return push_env_file(server, api_key, target, ttl_seconds, reads, delete).await;
    }

    // KEY=value
    let (key, value) = target
        .split_once('=')
        .context("expected KEY=value or a .env file path")?;

    push_one(server, api_key, key, value, ttl_seconds, reads, delete).await?;
    println!("✓ pushed {key}");
    Ok(())
}

async fn push_env_file(
    server: &str,
    api_key: &Option<String>,
    path: &str,
    ttl_seconds: Option<u64>,
    reads: Option<u32>,
    delete: bool,
) -> Result<()> {
    let entries =
        dotenvy::from_filename_iter(path).with_context(|| format!("read .env file: {path}"))?;

    let mut count = 0usize;
    for entry in entries {
        let (key, value) = entry.context("parse .env entry")?;
        push_one(server, api_key, &key, &value, ttl_seconds, reads, delete).await?;
        println!("✓ pushed {key}");
        count += 1;
    }
    println!("{count} secret(s) pushed from {path}");
    Ok(())
}

async fn push_one(
    server: &str,
    api_key: &Option<String>,
    key: &str,
    value: &str,
    ttl_seconds: Option<u64>,
    max_reads: Option<u32>,
    delete: bool,
) -> Result<()> {
    let client = Client::new();
    let body = serde_json::json!({
        "key": key,
        "value": value,
        "ttl_seconds": ttl_seconds,
        "max_reads": max_reads,
        "delete": delete,
    });

    let req = client.post(format!("{}/secrets", server.trim_end_matches('/')));
    let resp = with_auth(req, api_key)
        .json(&body)
        .send()
        .await
        .context("HTTP request failed")?;

    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        anyhow::bail!("server returned {status}: {text}");
    }
    Ok(())
}

async fn cmd_get(server: &str, key: &str) -> Result<()> {
    let client = Client::new();
    let resp = client
        .get(format!("{}/secrets/{}", server.trim_end_matches('/'), key))
        .send()
        .await
        .context("HTTP request failed")?;

    let status = resp.status();
    let json: Value = resp.json().await.context("parse response")?;

    if status.is_success() {
        let value = json["value"].as_str().unwrap_or("");
        println!("{value}");
    } else {
        let error = json["error"].as_str().unwrap_or("unknown error");
        anyhow::bail!("{error}");
    }
    Ok(())
}

async fn cmd_pull(server: &str, api_key: &Option<String>, path: &str) -> Result<()> {
    let metas = fetch_list(server, api_key).await?;
    let mut lines = Vec::new();

    for meta in &metas {
        let value = fetch_value(server, &meta.key).await?;
        lines.push(format!("{}={}", meta.key, shell_escape(&value)));
    }

    std::fs::write(path, lines.join("\n") + "\n").context("write .env file")?;
    println!("wrote {} secret(s) to {path}", lines.len());
    Ok(())
}

async fn cmd_run(server: &str, api_key: &Option<String>, command: &[String]) -> Result<()> {
    if command.is_empty() {
        anyhow::bail!("no command provided after --");
    }

    let metas = fetch_list(server, api_key).await?;
    let mut env_vars: HashMap<String, String> = HashMap::new();

    for meta in &metas {
        if let Ok(value) = fetch_value(server, &meta.key).await {
            env_vars.insert(meta.key.clone(), value);
        }
    }

    let (prog, args) = command.split_first().unwrap();
    let status = std::process::Command::new(prog)
        .args(args)
        .envs(&env_vars)
        .status()
        .with_context(|| format!("failed to execute {prog}"))?;

    std::process::exit(status.code().unwrap_or(1));
}

async fn cmd_list(server: &str, api_key: &Option<String>) -> Result<()> {
    let metas = fetch_list(server, api_key).await?;
    if metas.is_empty() {
        println!("(no active secrets)");
        return Ok(());
    }
    for m in &metas {
        let ttl_info = match m.expires_at {
            Some(exp) => {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs() as i64;
                let secs_left = exp - now;
                if secs_left > 0 {
                    format!("expires in {}", format_duration(secs_left as u64))
                } else {
                    "expired".to_string()
                }
            }
            None => "no TTL".to_string(),
        };
        let reads_info = match m.max_reads {
            Some(max) => format!("{}/{} reads", m.read_count, max),
            None => format!("{} reads", m.read_count),
        };
        let delete_info = if m.delete { "" } else { " [patchable]" };
        println!("  {} — {} — {}{}", m.key, ttl_info, reads_info, delete_info);
    }
    Ok(())
}

async fn cmd_delete(server: &str, api_key: &Option<String>, key: &str) -> Result<()> {
    let client = Client::new();
    let req = client.delete(format!("{}/secrets/{}", server.trim_end_matches('/'), key));
    let resp = with_auth(req, api_key)
        .send()
        .await
        .context("HTTP request failed")?;

    if resp.status().is_success() {
        println!("✓ deleted {key}");
    } else {
        let status = resp.status();
        let json: Value = resp.json().await.unwrap_or_default();
        anyhow::bail!(
            "server returned {status}: {}",
            json["error"].as_str().unwrap_or("")
        );
    }
    Ok(())
}

async fn cmd_prune(server: &str, api_key: &Option<String>) -> Result<()> {
    let client = Client::new();
    let req = client.post(format!("{}/prune", server.trim_end_matches('/')));
    let resp = with_auth(req, api_key)
        .send()
        .await
        .context("HTTP request failed")?;

    if resp.status().is_success() {
        let json: Value = resp.json().await?;
        let n = json["pruned"].as_u64().unwrap_or(0);
        println!("pruned {n} expired secret(s)");
    } else {
        let status = resp.status();
        anyhow::bail!("server returned {status}");
    }
    Ok(())
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn with_auth(
    builder: reqwest::RequestBuilder,
    api_key: &Option<String>,
) -> reqwest::RequestBuilder {
    match api_key {
        Some(key) => builder.bearer_auth(key),
        None => builder,
    }
}

/// Parse human duration strings like "1h", "30m", "7d", "5s" into seconds.
fn parse_duration(s: &str) -> Result<u64> {
    let d: humantime::Duration = s
        .parse()
        .with_context(|| format!("invalid duration: {s}"))?;
    Ok(d.as_secs())
}

fn format_duration(secs: u64) -> String {
    if secs >= 86400 {
        format!("{}d", secs / 86400)
    } else if secs >= 3600 {
        format!("{}h", secs / 3600)
    } else if secs >= 60 {
        format!("{}m", secs / 60)
    } else {
        format!("{}s", secs)
    }
}

fn shell_escape(s: &str) -> String {
    if s.contains(|c: char| c.is_whitespace() || matches!(c, '"' | '\'' | '\\' | '$' | '`')) {
        format!(
            "\"{}\"",
            s.replace('\\', "\\\\")
                .replace('"', "\\\"")
                .replace('$', "\\$")
        )
    } else {
        s.to_owned()
    }
}

#[derive(serde::Deserialize)]
struct MetaItem {
    key: String,
    expires_at: Option<i64>,
    max_reads: Option<u32>,
    read_count: u32,
    delete: bool,
}

async fn fetch_list(server: &str, api_key: &Option<String>) -> Result<Vec<MetaItem>> {
    let client = Client::new();
    let req = client.get(format!("{}/secrets", server.trim_end_matches('/')));
    let resp = with_auth(req, api_key)
        .send()
        .await
        .context("HTTP request failed")?;

    if !resp.status().is_success() {
        let status = resp.status();
        anyhow::bail!("server returned {status}");
    }

    let json: Value = resp.json().await?;
    let metas: Vec<MetaItem> =
        serde_json::from_value(json["secrets"].clone()).context("parse secrets list")?;
    Ok(metas)
}

async fn fetch_value(server: &str, key: &str) -> Result<String> {
    let client = Client::new();
    let resp = client
        .get(format!("{}/secrets/{}", server.trim_end_matches('/'), key))
        .send()
        .await?;

    let json: Value = resp.json().await?;
    Ok(json["value"].as_str().unwrap_or("").to_owned())
}
