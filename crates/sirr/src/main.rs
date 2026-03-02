use std::collections::HashMap;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use reqwest::{Client, Response};
use serde_json::Value;
use tracing_subscriber::EnvFilter;

// ── CLI definition ─────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(name = "sirr", about = "Sirr — ephemeral secret vault", version)]
struct Cli {
    /// Sirr server URL (default: sirr://localhost:39999 or $SIRR_SERVER)
    #[arg(long, env = "SIRR_SERVER", default_value = "sirr://localhost:39999")]
    server: String,

    /// API key for write operations ($SIRR_API_KEY)
    #[arg(long, env = "SIRR_API_KEY")]
    api_key: Option<String>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
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
        /// Organization ID (if operating on org secrets)
        #[arg(long)]
        org: Option<String>,
    },
    /// Get a secret by key
    Get {
        /// Secret key name
        key: String,
        /// Organization ID (if operating on org secrets)
        #[arg(long)]
        org: Option<String>,
    },
    /// Pull all secrets into a .env file
    Pull {
        /// Path to write the .env file (default: .env)
        #[arg(default_value = ".env")]
        path: String,
        /// Organization ID (if operating on org secrets)
        #[arg(long)]
        org: Option<String>,
    },
    /// Run a command with secrets injected as environment variables
    Run {
        /// Command and arguments
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<String>,
        /// Organization ID (if operating on org secrets)
        #[arg(long)]
        org: Option<String>,
    },
    /// Print a shareable one-time URL for a secret
    Share {
        /// Secret key name
        key: String,
        /// Organization ID (if operating on org secrets)
        #[arg(long)]
        org: Option<String>,
    },
    /// List all active secrets (metadata only)
    List {
        /// Organization ID (if operating on org secrets)
        #[arg(long)]
        org: Option<String>,
    },
    /// Delete a secret
    Delete {
        /// Secret key name
        key: String,
        /// Organization ID (if operating on org secrets)
        #[arg(long)]
        org: Option<String>,
    },
    /// Delete all expired secrets immediately
    Prune {
        /// Organization ID (if operating on org secrets)
        #[arg(long)]
        org: Option<String>,
    },
    /// Manage webhooks
    #[command(subcommand)]
    Webhooks(WebhookCommand),
    /// Query the audit log
    Audit {
        /// Filter by timestamp (Unix epoch seconds)
        #[arg(long)]
        since: Option<i64>,
        /// Filter by action type (e.g. secret.create)
        #[arg(long)]
        action: Option<String>,
        /// Maximum events to return
        #[arg(long, default_value = "50")]
        limit: usize,
        /// Organization ID (if operating on org audit)
        #[arg(long)]
        org: Option<String>,
    },
    /// Manage scoped API keys
    #[command(subcommand)]
    Keys(KeyCommand),
    /// Manage organizations
    #[command(subcommand)]
    Orgs(OrgCommand),
    /// Manage principals
    #[command(subcommand)]
    Principals(PrincipalCommand),
    /// View/manage my account
    #[command(subcommand)]
    Me(MeCommand),
}

#[derive(Subcommand)]
enum WebhookCommand {
    /// List registered webhooks
    List {
        /// Organization ID (if operating on org webhooks)
        #[arg(long)]
        org: Option<String>,
    },
    /// Register a webhook URL
    Add {
        /// Webhook endpoint URL
        #[arg(name = "URL")]
        url: String,
        /// Comma-separated event types (default: all)
        #[arg(long, value_delimiter = ',')]
        events: Option<Vec<String>>,
        /// Organization ID (if operating on org webhooks)
        #[arg(long)]
        org: Option<String>,
    },
    /// Remove a webhook by ID
    Remove {
        /// Webhook ID
        #[arg(name = "ID")]
        id: String,
        /// Organization ID (if operating on org webhooks)
        #[arg(long)]
        org: Option<String>,
    },
}

#[derive(Subcommand)]
enum KeyCommand {
    /// List all scoped API keys
    List,
    /// Create a new scoped API key
    Create {
        /// Human-readable label
        #[arg(name = "LABEL")]
        label: String,
        /// Comma-separated permissions: read,write,delete,admin
        #[arg(long, value_delimiter = ',', default_value = "read,write")]
        permissions: Vec<String>,
        /// Optional prefix scope (e.g. PROD_)
        #[arg(long)]
        prefix: Option<String>,
    },
    /// Remove an API key by ID
    Remove {
        /// API key ID
        #[arg(name = "ID")]
        id: String,
    },
}

#[derive(Subcommand)]
enum OrgCommand {
    /// List all organizations
    List,
    /// Create a new organization
    Create {
        /// Organization name
        name: String,
    },
    /// Delete an organization by ID
    Delete {
        /// Organization ID
        id: String,
    },
}

#[derive(Subcommand)]
enum PrincipalCommand {
    /// List principals in an organization
    List {
        /// Organization ID
        #[arg(long)]
        org: String,
    },
    /// Create a new principal
    Create {
        /// Organization ID
        #[arg(long)]
        org: String,
        /// Principal name
        name: String,
        /// Role to assign (default: writer)
        #[arg(long, default_value = "writer")]
        role: String,
    },
    /// Delete a principal by ID
    Delete {
        /// Organization ID
        #[arg(long)]
        org: String,
        /// Principal ID
        id: String,
    },
}

#[derive(Subcommand)]
enum MeCommand {
    /// Show my account info
    Info,
    /// List my API keys
    Keys,
    /// Create a new API key for myself
    CreateKey {
        /// Key name/label
        name: String,
        /// Validity duration in seconds (default: 86400 = 24h)
        #[arg(long, default_value = "86400")]
        valid_for_seconds: u64,
    },
    /// Delete one of my API keys
    DeleteKey {
        /// Key ID to delete
        id: String,
    },
}

// ── Request context ───────────────────────────────────────────────────────────

/// Shared HTTP client + connection-normalized server URL + optional API key.
/// Created once in main and passed to every command.
struct Ctx {
    client: Client,
    server: String,
    api_key: Option<String>,
}

impl Ctx {
    fn new(server: String, api_key: Option<String>) -> Self {
        let server = server
            .trim_end_matches('/')
            .replace("sirr://", "http://")
            .replace("sirrs://", "https://");
        Self {
            client: Client::new(),
            server,
            api_key,
        }
    }

    fn get(&self, path: &str) -> reqwest::RequestBuilder {
        self.with_auth(self.client.get(format!("{}/{}", self.server, path)))
    }

    fn post(&self, path: &str) -> reqwest::RequestBuilder {
        self.with_auth(self.client.post(format!("{}/{}", self.server, path)))
    }

    fn delete(&self, path: &str) -> reqwest::RequestBuilder {
        self.with_auth(self.client.delete(format!("{}/{}", self.server, path)))
    }

    fn with_auth(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match &self.api_key {
            Some(key) => req.bearer_auth(key),
            None => req,
        }
    }
}

// ── Entry point ───────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    let log_level = std::env::var("SIRR_LOG_LEVEL").unwrap_or_else(|_| "warn".into());
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::new(&log_level))
        .init();

    let ctx = Ctx::new(cli.server, cli.api_key);

    match cli.command {
        Commands::Push {
            target,
            ttl,
            reads,
            no_delete,
            org,
        } => {
            cmd_push(
                &ctx,
                &target,
                ttl.as_deref(),
                reads,
                !no_delete,
                org.as_deref(),
            )
            .await
        }

        Commands::Get { key, org } => cmd_get(&ctx, &key, org.as_deref()).await,

        Commands::Pull { path, org } => cmd_pull(&ctx, &path, org.as_deref()).await,

        Commands::Run { command, org } => cmd_run(&ctx, &command, org.as_deref()).await,

        Commands::Share { key, org } => {
            let path = secrets_path(org.as_deref());
            println!("{}/{}/{}", ctx.server, path, key);
            Ok(())
        }

        Commands::List { org } => cmd_list(&ctx, org.as_deref()).await,

        Commands::Delete { key, org } => cmd_delete(&ctx, &key, org.as_deref()).await,

        Commands::Prune { org } => cmd_prune(&ctx, org.as_deref()).await,

        Commands::Webhooks(sub) => match sub {
            WebhookCommand::List { org } => cmd_webhook_list(&ctx, org.as_deref()).await,
            WebhookCommand::Add { url, events, org } => {
                cmd_webhook_add(&ctx, &url, events, org.as_deref()).await
            }
            WebhookCommand::Remove { id, org } => {
                cmd_webhook_remove(&ctx, &id, org.as_deref()).await
            }
        },

        Commands::Audit {
            since,
            action,
            limit,
            org,
        } => cmd_audit(&ctx, since, action.as_deref(), limit, org.as_deref()).await,

        Commands::Keys(sub) => match sub {
            KeyCommand::List => cmd_key_list(&ctx).await,
            KeyCommand::Create {
                label,
                permissions,
                prefix,
            } => cmd_key_create(&ctx, &label, permissions, prefix).await,
            KeyCommand::Remove { id } => cmd_key_remove(&ctx, &id).await,
        },

        Commands::Orgs(sub) => match sub {
            OrgCommand::List => cmd_org_list(&ctx).await,
            OrgCommand::Create { name } => cmd_org_create(&ctx, &name).await,
            OrgCommand::Delete { id } => cmd_org_delete(&ctx, &id).await,
        },

        Commands::Principals(sub) => match sub {
            PrincipalCommand::List { org } => cmd_principal_list(&ctx, &org).await,
            PrincipalCommand::Create { org, name, role } => {
                cmd_principal_create(&ctx, &org, &name, &role).await
            }
            PrincipalCommand::Delete { org, id } => cmd_principal_delete(&ctx, &org, &id).await,
        },

        Commands::Me(sub) => match sub {
            MeCommand::Info => cmd_me_info(&ctx).await,
            MeCommand::Keys => cmd_me_keys(&ctx).await,
            MeCommand::CreateKey {
                name,
                valid_for_seconds,
            } => cmd_me_create_key(&ctx, &name, valid_for_seconds).await,
            MeCommand::DeleteKey { id } => cmd_me_delete_key(&ctx, &id).await,
        },
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Checks the response status and returns it on success, or bails with the
/// server's status code and body text on failure.
async fn require_success(resp: Response) -> Result<Response> {
    if resp.status().is_success() {
        return Ok(resp);
    }
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    anyhow::bail!("server returned {status}: {text}")
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

/// Build the secrets path prefix depending on whether an org is specified.
fn secrets_path(org: Option<&str>) -> String {
    match org {
        Some(org_id) => format!("orgs/{org_id}/secrets"),
        None => "secrets".to_string(),
    }
}

fn webhooks_path(org: Option<&str>, id: Option<&str>) -> String {
    let base = match org {
        Some(org_id) => format!("orgs/{org_id}/webhooks"),
        None => "webhooks".to_string(),
    };
    match id {
        Some(id) => format!("{base}/{id}"),
        None => base,
    }
}

fn prune_path(org: Option<&str>) -> String {
    match org {
        Some(org_id) => format!("orgs/{org_id}/prune"),
        None => "prune".to_string(),
    }
}

fn audit_path(org: Option<&str>) -> String {
    match org {
        Some(org_id) => format!("orgs/{org_id}/audit"),
        None => "audit".to_string(),
    }
}

async fn fetch_list(ctx: &Ctx, org: Option<&str>) -> Result<Vec<MetaItem>> {
    let resp = require_success(
        ctx.get(&secrets_path(org))
            .send()
            .await
            .context("HTTP request failed")?,
    )
    .await?;

    let json: Value = resp.json().await?;
    let metas: Vec<MetaItem> =
        serde_json::from_value(json["secrets"].clone()).context("parse secrets list")?;
    Ok(metas)
}

async fn fetch_value(ctx: &Ctx, key: &str, org: Option<&str>) -> Result<String> {
    let path = format!("{}/{}", secrets_path(org), key);
    let resp = ctx.get(&path).send().await?;
    let json: Value = resp.json().await?;
    Ok(json["value"].as_str().unwrap_or("").to_owned())
}

// ── Command implementations ───────────────────────────────────────────────────

async fn cmd_push(
    ctx: &Ctx,
    target: &str,
    ttl: Option<&str>,
    reads: Option<u32>,
    delete: bool,
    org: Option<&str>,
) -> Result<()> {
    let ttl_seconds = ttl.map(parse_duration).transpose()?;

    if !target.contains('=') {
        return push_env_file(ctx, target, ttl_seconds, reads, delete, org).await;
    }

    let (key, value) = target
        .split_once('=')
        .context("expected KEY=value or a .env file path")?;

    push_one(ctx, key, value, ttl_seconds, reads, delete, org).await?;
    println!("✓ pushed {key}");
    Ok(())
}

async fn push_env_file(
    ctx: &Ctx,
    path: &str,
    ttl_seconds: Option<u64>,
    reads: Option<u32>,
    delete: bool,
    org: Option<&str>,
) -> Result<()> {
    let entries =
        dotenvy::from_filename_iter(path).with_context(|| format!("read .env file: {path}"))?;

    let mut count = 0usize;
    for entry in entries {
        let (key, value) = entry.context("parse .env entry")?;
        push_one(ctx, &key, &value, ttl_seconds, reads, delete, org).await?;
        println!("✓ pushed {key}");
        count += 1;
    }
    println!("{count} secret(s) pushed from {path}");
    Ok(())
}

async fn push_one(
    ctx: &Ctx,
    key: &str,
    value: &str,
    ttl_seconds: Option<u64>,
    max_reads: Option<u32>,
    delete: bool,
    org: Option<&str>,
) -> Result<()> {
    let body = serde_json::json!({
        "key": key,
        "value": value,
        "ttl_seconds": ttl_seconds,
        "max_reads": max_reads,
        "delete": delete,
    });

    require_success(
        ctx.post(&secrets_path(org))
            .json(&body)
            .send()
            .await
            .context("HTTP request failed")?,
    )
    .await?;
    Ok(())
}

async fn cmd_get(ctx: &Ctx, key: &str, org: Option<&str>) -> Result<()> {
    let path = format!("{}/{}", secrets_path(org), key);
    let resp = ctx.get(&path).send().await.context("HTTP request failed")?;

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

async fn cmd_pull(ctx: &Ctx, path: &str, org: Option<&str>) -> Result<()> {
    let metas = fetch_list(ctx, org).await?;
    let mut lines = Vec::new();

    for meta in &metas {
        let value = fetch_value(ctx, &meta.key, org).await?;
        lines.push(format!("{}={}", meta.key, shell_escape(&value)));
    }

    std::fs::write(path, lines.join("\n") + "\n").context("write .env file")?;
    println!("wrote {} secret(s) to {path}", lines.len());
    Ok(())
}

async fn cmd_run(ctx: &Ctx, command: &[String], org: Option<&str>) -> Result<()> {
    if command.is_empty() {
        anyhow::bail!("no command provided after --");
    }

    let metas = fetch_list(ctx, org).await?;
    let mut env_vars: HashMap<String, String> = HashMap::new();

    for meta in &metas {
        if let Ok(value) = fetch_value(ctx, &meta.key, org).await {
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

async fn cmd_list(ctx: &Ctx, org: Option<&str>) -> Result<()> {
    let metas = fetch_list(ctx, org).await?;
    if metas.is_empty() {
        println!("(no active secrets)");
        return Ok(());
    }

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    for m in &metas {
        let ttl_info = match m.expires_at {
            Some(exp) => {
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

async fn cmd_delete(ctx: &Ctx, key: &str, org: Option<&str>) -> Result<()> {
    let path = format!("{}/{}", secrets_path(org), key);
    require_success(
        ctx.delete(&path)
            .send()
            .await
            .context("HTTP request failed")?,
    )
    .await?;
    println!("✓ deleted {key}");
    Ok(())
}

async fn cmd_prune(ctx: &Ctx, org: Option<&str>) -> Result<()> {
    let resp = require_success(
        ctx.post(&prune_path(org))
            .send()
            .await
            .context("HTTP request failed")?,
    )
    .await?;

    let json: Value = resp.json().await?;
    let n = json["pruned"].as_u64().unwrap_or(0);
    println!("pruned {n} expired secret(s)");
    Ok(())
}

// ── Webhooks ─────────────────────────────────────────────────────────────

async fn cmd_webhook_list(ctx: &Ctx, org: Option<&str>) -> Result<()> {
    let resp = require_success(
        ctx.get(&webhooks_path(org, None))
            .send()
            .await
            .context("HTTP request failed")?,
    )
    .await?;

    let json: Value = resp.json().await?;
    let webhooks = json["webhooks"].as_array();
    match webhooks {
        Some(arr) if arr.is_empty() => println!("(no webhooks registered)"),
        Some(arr) => {
            for w in arr {
                let id = w["id"].as_str().unwrap_or("?");
                let url = w["url"].as_str().unwrap_or("?");
                let events = w["events"]
                    .as_array()
                    .map(|e| {
                        e.iter()
                            .filter_map(|v| v.as_str())
                            .collect::<Vec<_>>()
                            .join(",")
                    })
                    .unwrap_or_else(|| "*".into());
                println!("  {id}  {url}  [{events}]");
            }
        }
        None => println!("(no webhooks registered)"),
    }
    Ok(())
}

async fn cmd_webhook_add(
    ctx: &Ctx,
    url: &str,
    events: Option<Vec<String>>,
    org: Option<&str>,
) -> Result<()> {
    let mut body = serde_json::json!({"url": url});
    if let Some(evts) = events {
        body["events"] = serde_json::json!(evts);
    }

    let resp = require_success(
        ctx.post(&webhooks_path(org, None))
            .json(&body)
            .send()
            .await
            .context("HTTP request failed")?,
    )
    .await?;

    let json: Value = resp.json().await?;
    let id = json["id"].as_str().unwrap_or("?");
    let secret = json["secret"].as_str().unwrap_or("?");
    println!("webhook registered");
    println!("  id:     {id}");
    println!("  secret: {secret}");
    println!("  (save the secret — it won't be shown again)");
    Ok(())
}

async fn cmd_webhook_remove(ctx: &Ctx, id: &str, org: Option<&str>) -> Result<()> {
    require_success(
        ctx.delete(&webhooks_path(org, Some(id)))
            .send()
            .await
            .context("HTTP request failed")?,
    )
    .await?;
    println!("webhook {id} removed");
    Ok(())
}

// ── Audit ─────────────────────────────────────────────────────────────────

async fn cmd_audit(
    ctx: &Ctx,
    since: Option<i64>,
    action: Option<&str>,
    limit: usize,
    org: Option<&str>,
) -> Result<()> {
    let mut url = format!("{}?limit={limit}", audit_path(org));
    if let Some(s) = since {
        url.push_str(&format!("&since={s}"));
    }
    if let Some(a) = action {
        url.push_str(&format!("&action={a}"));
    }

    let resp = require_success(ctx.get(&url).send().await.context("HTTP request failed")?).await?;

    let json: Value = resp.json().await?;
    let events = json["events"].as_array();
    match events {
        Some(arr) if arr.is_empty() => println!("(no audit events)"),
        Some(arr) => {
            for e in arr {
                let ts = e["timestamp"].as_i64().unwrap_or(0);
                let action = e["action"].as_str().unwrap_or("?");
                let key = e["key"].as_str().unwrap_or("-");
                let ip = e["source_ip"].as_str().unwrap_or("?");
                let ok = if e["success"].as_bool().unwrap_or(false) {
                    "ok"
                } else {
                    "FAIL"
                };
                println!("  [{ts}] {action} key={key} ip={ip} {ok}");
            }
        }
        None => println!("(no audit events)"),
    }
    Ok(())
}

// ── API Keys ──────────────────────────────────────────────────────────────

async fn cmd_key_list(ctx: &Ctx) -> Result<()> {
    let resp = require_success(
        ctx.get("keys")
            .send()
            .await
            .context("HTTP request failed")?,
    )
    .await?;

    let json: Value = resp.json().await?;
    let keys = json["keys"].as_array();
    match keys {
        Some(arr) if arr.is_empty() => println!("(no API keys)"),
        Some(arr) => {
            for k in arr {
                let id = k["id"].as_str().unwrap_or("?");
                let label = k["label"].as_str().unwrap_or("?");
                let perms = k["permissions"]
                    .as_array()
                    .map(|p| {
                        p.iter()
                            .filter_map(|v| v.as_str())
                            .collect::<Vec<_>>()
                            .join(",")
                    })
                    .unwrap_or_default();
                let prefix = k["prefix"].as_str().unwrap_or("*");
                println!("  {id}  {label}  [{perms}]  prefix={prefix}");
            }
        }
        None => println!("(no API keys)"),
    }
    Ok(())
}

async fn cmd_key_create(
    ctx: &Ctx,
    label: &str,
    permissions: Vec<String>,
    prefix: Option<String>,
) -> Result<()> {
    let mut body = serde_json::json!({
        "label": label,
        "permissions": permissions,
    });
    if let Some(ref p) = prefix {
        body["prefix"] = serde_json::json!(p);
    }

    let resp = require_success(
        ctx.post("keys")
            .json(&body)
            .send()
            .await
            .context("HTTP request failed")?,
    )
    .await?;

    let json: Value = resp.json().await?;
    let id = json["id"].as_str().unwrap_or("?");
    let key = json["key"].as_str().unwrap_or("?");
    println!("API key created");
    println!("  id:    {id}");
    println!("  key:   {key}");
    println!("  (save the key — it won't be shown again)");
    Ok(())
}

async fn cmd_key_remove(ctx: &Ctx, id: &str) -> Result<()> {
    require_success(
        ctx.delete(&format!("keys/{id}"))
            .send()
            .await
            .context("HTTP request failed")?,
    )
    .await?;
    println!("API key {id} removed");
    Ok(())
}

// ── Orgs ──────────────────────────────────────────────────────────────────

async fn cmd_org_list(ctx: &Ctx) -> Result<()> {
    let resp = require_success(
        ctx.get("orgs")
            .send()
            .await
            .context("HTTP request failed")?,
    )
    .await?;

    let json: Value = resp.json().await?;
    let orgs = json["orgs"].as_array();
    match orgs {
        Some(arr) if arr.is_empty() => println!("(no organizations)"),
        Some(arr) => {
            for o in arr {
                let id = o["id"].as_str().unwrap_or("?");
                let name = o["name"].as_str().unwrap_or("?");
                println!("  {id}  {name}");
            }
        }
        None => println!("(no organizations)"),
    }
    Ok(())
}

async fn cmd_org_create(ctx: &Ctx, name: &str) -> Result<()> {
    let body = serde_json::json!({"name": name});

    let resp = require_success(
        ctx.post("orgs")
            .json(&body)
            .send()
            .await
            .context("HTTP request failed")?,
    )
    .await?;

    let json: Value = resp.json().await?;
    let id = json["id"].as_str().unwrap_or("?");
    println!("org created");
    println!("  id:   {id}");
    println!("  name: {name}");
    Ok(())
}

async fn cmd_org_delete(ctx: &Ctx, id: &str) -> Result<()> {
    require_success(
        ctx.delete(&format!("orgs/{id}"))
            .send()
            .await
            .context("HTTP request failed")?,
    )
    .await?;
    println!("org {id} deleted");
    Ok(())
}

// ── Principals ────────────────────────────────────────────────────────────

async fn cmd_principal_list(ctx: &Ctx, org: &str) -> Result<()> {
    let resp = require_success(
        ctx.get(&format!("orgs/{org}/principals"))
            .send()
            .await
            .context("HTTP request failed")?,
    )
    .await?;

    let json: Value = resp.json().await?;
    let principals = json["principals"].as_array();
    match principals {
        Some(arr) if arr.is_empty() => println!("(no principals)"),
        Some(arr) => {
            for p in arr {
                let id = p["id"].as_str().unwrap_or("?");
                let name = p["name"].as_str().unwrap_or("?");
                let role = p["role"].as_str().unwrap_or("?");
                println!("  {id}  {name}  role={role}");
            }
        }
        None => println!("(no principals)"),
    }
    Ok(())
}

async fn cmd_principal_create(ctx: &Ctx, org: &str, name: &str, role: &str) -> Result<()> {
    let body = serde_json::json!({
        "name": name,
        "role": role,
    });

    let resp = require_success(
        ctx.post(&format!("orgs/{org}/principals"))
            .json(&body)
            .send()
            .await
            .context("HTTP request failed")?,
    )
    .await?;

    let json: Value = resp.json().await?;
    let id = json["id"].as_str().unwrap_or("?");
    println!("principal created");
    println!("  id:   {id}");
    println!("  name: {name}");
    println!("  role: {role}");
    Ok(())
}

async fn cmd_principal_delete(ctx: &Ctx, org: &str, id: &str) -> Result<()> {
    require_success(
        ctx.delete(&format!("orgs/{org}/principals/{id}"))
            .send()
            .await
            .context("HTTP request failed")?,
    )
    .await?;
    println!("principal {id} deleted");
    Ok(())
}

// ── Me ────────────────────────────────────────────────────────────────────

async fn cmd_me_info(ctx: &Ctx) -> Result<()> {
    let resp = require_success(ctx.get("me").send().await.context("HTTP request failed")?).await?;

    let json: Value = resp.json().await?;
    let id = json["id"].as_str().unwrap_or("?");
    let name = json["name"].as_str().unwrap_or("?");
    let org_id = json["org_id"].as_str().unwrap_or("?");
    let role = json["role"].as_str().unwrap_or("?");
    println!("  id:     {id}");
    println!("  name:   {name}");
    println!("  org:    {org_id}");
    println!("  role:   {role}");

    if let Some(keys) = json["keys"].as_array() {
        println!("  keys:");
        for k in keys {
            let kid = k["id"].as_str().unwrap_or("?");
            let kname = k["name"].as_str().unwrap_or("?");
            println!("    {kid}  {kname}");
        }
    }
    Ok(())
}

async fn cmd_me_keys(ctx: &Ctx) -> Result<()> {
    let resp = require_success(ctx.get("me").send().await.context("HTTP request failed")?).await?;

    let json: Value = resp.json().await?;
    if let Some(keys) = json["keys"].as_array() {
        if keys.is_empty() {
            println!("(no keys)");
        } else {
            for k in keys {
                let kid = k["id"].as_str().unwrap_or("?");
                let kname = k["name"].as_str().unwrap_or("?");
                let valid_before = k["valid_before"].as_i64().unwrap_or(0);
                println!("  {kid}  {kname}  expires={valid_before}");
            }
        }
    } else {
        println!("(no keys)");
    }
    Ok(())
}

async fn cmd_me_create_key(ctx: &Ctx, name: &str, valid_for_seconds: u64) -> Result<()> {
    let body = serde_json::json!({
        "name": name,
        "valid_for_seconds": valid_for_seconds,
    });

    let resp = require_success(
        ctx.post("me/keys")
            .json(&body)
            .send()
            .await
            .context("HTTP request failed")?,
    )
    .await?;

    let json: Value = resp.json().await?;
    let id = json["id"].as_str().unwrap_or("?");
    let key = json["key"].as_str().unwrap_or("?");
    println!("key created");
    println!("  id:   {id}");
    println!("  key:  {key}");
    println!("  (save this key — it won't be shown again)");
    Ok(())
}

async fn cmd_me_delete_key(ctx: &Ctx, id: &str) -> Result<()> {
    require_success(
        ctx.delete(&format!("me/keys/{id}"))
            .send()
            .await
            .context("HTTP request failed")?,
    )
    .await?;
    println!("key {id} deleted");
    Ok(())
}
