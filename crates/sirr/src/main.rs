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

    /// Bearer token for server auth ($SIRR_TOKEN)
    #[arg(long, env = "SIRR_TOKEN")]
    token: Option<String>,

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

        Commands::Push { target, ttl, reads } => {
            let token = require_token(&cli.token)?;
            cmd_push(&cli.server, &token, &target, ttl.as_deref(), reads).await
        }

        Commands::Get { key } => {
            let token = require_token(&cli.token)?;
            cmd_get(&cli.server, &token, &key).await
        }

        Commands::Pull { path } => {
            let token = require_token(&cli.token)?;
            cmd_pull(&cli.server, &token, &path).await
        }

        Commands::Run { command } => {
            let token = require_token(&cli.token)?;
            cmd_run(&cli.server, &token, &command).await
        }

        Commands::Share { key } => {
            println!("{}/secrets/{}", cli.server.trim_end_matches('/'), key);
            Ok(())
        }

        Commands::List => {
            let token = require_token(&cli.token)?;
            cmd_list(&cli.server, &token).await
        }

        Commands::Delete { key } => {
            let token = require_token(&cli.token)?;
            cmd_delete(&cli.server, &token, &key).await
        }

        Commands::Prune => {
            let token = require_token(&cli.token)?;
            cmd_prune(&cli.server, &token).await
        }
    }
}

// ── Command implementations ───────────────────────────────────────────────────

async fn cmd_serve(host: String, port: u16) -> Result<()> {
    let master_key = std::env::var("SIRR_MASTER_KEY")
        .context("SIRR_MASTER_KEY environment variable is required")?;
    if master_key.is_empty() {
        anyhow::bail!("SIRR_MASTER_KEY must not be empty");
    }

    let cfg = sirr_server::ServerConfig {
        host,
        port,
        master_key,
        license_key: std::env::var("SIRR_LICENSE_KEY").ok(),
        data_dir: std::env::var("SIRR_DATA_DIR").ok().map(Into::into),
        ..Default::default()
    };

    sirr_server::run(cfg).await
}

async fn cmd_push(
    server: &str,
    token: &str,
    target: &str,
    ttl: Option<&str>,
    reads: Option<u32>,
) -> Result<()> {
    let ttl_seconds = ttl.map(parse_duration).transpose()?;

    // Check if target looks like a file path (contains '/' or is a filename that exists).
    if !target.contains('=') {
        // Treat as .env file path.
        return push_env_file(server, token, target, ttl_seconds, reads).await;
    }

    // KEY=value
    let (key, value) = target
        .split_once('=')
        .context("expected KEY=value or a .env file path")?;

    push_one(server, token, key, value, ttl_seconds, reads).await?;
    println!("✓ pushed {key}");
    Ok(())
}

async fn push_env_file(
    server: &str,
    token: &str,
    path: &str,
    ttl_seconds: Option<u64>,
    reads: Option<u32>,
) -> Result<()> {
    let entries =
        dotenvy::from_filename_iter(path).with_context(|| format!("read .env file: {path}"))?;

    let mut count = 0usize;
    for entry in entries {
        let (key, value) = entry.context("parse .env entry")?;
        push_one(server, token, &key, &value, ttl_seconds, reads).await?;
        println!("✓ pushed {key}");
        count += 1;
    }
    println!("{count} secret(s) pushed from {path}");
    Ok(())
}

async fn push_one(
    server: &str,
    token: &str,
    key: &str,
    value: &str,
    ttl_seconds: Option<u64>,
    max_reads: Option<u32>,
) -> Result<()> {
    let client = Client::new();
    let body = serde_json::json!({
        "key": key,
        "value": value,
        "ttl_seconds": ttl_seconds,
        "max_reads": max_reads,
    });

    let resp = client
        .post(format!("{}/secrets", server.trim_end_matches('/')))
        .bearer_auth(token)
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

async fn cmd_get(server: &str, token: &str, key: &str) -> Result<()> {
    let client = Client::new();
    let resp = client
        .get(format!("{}/secrets/{}", server.trim_end_matches('/'), key))
        .bearer_auth(token)
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

async fn cmd_pull(server: &str, token: &str, path: &str) -> Result<()> {
    let metas = fetch_list(server, token).await?;
    let mut lines = Vec::new();

    for meta in &metas {
        let value = fetch_value(server, token, &meta.key).await?;
        lines.push(format!("{}={}", meta.key, shell_escape(&value)));
    }

    std::fs::write(path, lines.join("\n") + "\n").context("write .env file")?;
    println!("wrote {} secret(s) to {path}", lines.len());
    Ok(())
}

async fn cmd_run(server: &str, token: &str, command: &[String]) -> Result<()> {
    if command.is_empty() {
        anyhow::bail!("no command provided after --");
    }

    let metas = fetch_list(server, token).await?;
    let mut env_vars: HashMap<String, String> = HashMap::new();

    for meta in &metas {
        if let Ok(value) = fetch_value(server, token, &meta.key).await {
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

async fn cmd_list(server: &str, token: &str) -> Result<()> {
    let metas = fetch_list(server, token).await?;
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
        println!("  {} — {} — {}", m.key, ttl_info, reads_info);
    }
    Ok(())
}

async fn cmd_delete(server: &str, token: &str, key: &str) -> Result<()> {
    let client = Client::new();
    let resp = client
        .delete(format!("{}/secrets/{}", server.trim_end_matches('/'), key))
        .bearer_auth(token)
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

async fn cmd_prune(server: &str, token: &str) -> Result<()> {
    let client = Client::new();
    let resp = client
        .post(format!("{}/prune", server.trim_end_matches('/')))
        .bearer_auth(token)
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

fn require_token(token: &Option<String>) -> Result<String> {
    token
        .clone()
        .context("--token / SIRR_TOKEN is required for this command")
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
}

async fn fetch_list(server: &str, token: &str) -> Result<Vec<MetaItem>> {
    let client = Client::new();
    let resp = client
        .get(format!("{}/secrets", server.trim_end_matches('/')))
        .bearer_auth(token)
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

async fn fetch_value(server: &str, token: &str, key: &str) -> Result<String> {
    let client = Client::new();
    let resp = client
        .get(format!("{}/secrets/{}", server.trim_end_matches('/'), key))
        .bearer_auth(token)
        .send()
        .await?;

    let json: Value = resp.json().await?;
    Ok(json["value"].as_str().unwrap_or("").to_owned())
}
