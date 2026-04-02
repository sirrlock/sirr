use std::collections::HashMap;

use anyhow::{Context, Result};
use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::Shell;
use reqwest::{Client, Response};
use serde_json::Value;
use tracing_subscriber::EnvFilter;

// ── CLI definition ─────────────────────────────────────────────────────────────

/// Build version: CI sets SIRR_BUILD_VERSION at compile time; local builds use Cargo.toml version.
const BUILD_VERSION: &str = match option_env!("SIRR_BUILD_VERSION") {
    Some(v) => v,
    None => env!("CARGO_PKG_VERSION"),
};

#[derive(Parser)]
#[command(
    name = "sirr",
    about = "Sirr — ephemeral secrets that know when to disappear",
    version = BUILD_VERSION,
    disable_version_flag = true
)]
struct Cli {
    /// Server URL [default: https://sirr.sirrlock.com]
    #[arg(
        short = 's',
        long,
        env = "SIRR_SERVER",
        default_value = "https://sirr.sirrlock.com"
    )]
    server: String,

    /// API key for authentication
    #[arg(short = 'k', long, env = "SIRR_API_KEY")]
    api_key: Option<String>,

    /// Organization scope
    #[arg(short = 'o', long, env = "SIRR_ORG")]
    org: Option<String>,

    /// Print version
    #[arg(short = 'v', long = "version", action = clap::ArgAction::Version)]
    version: (),

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Push a secret to the public dead drop
    #[command(
        after_long_help = "Examples:\n  sirr push \"my-api-key\"\n  sirr push \"db://user:pass@host\" --ttl 1h --reads 3"
    )]
    Push {
        /// Secret value to push
        #[arg(name = "VALUE")]
        value: String,
        /// TTL duration (e.g. 1h, 30m, 7d)
        #[arg(long)]
        ttl: Option<String>,
        /// Max reads before burn [default: server decides]
        #[arg(long)]
        reads: Option<u32>,
    },

    /// Set a named secret in an org (requires --org)
    #[command(
        after_long_help = "Examples:\n  sirr set DB_PASS=hunter2 --org myteam\n  sirr set CERT -f ./cert.pem --org myteam\n  sirr set TOKEN=abc --org myteam --share"
    )]
    Set {
        /// KEY=VALUE pair
        #[arg(name = "TARGET")]
        target: String,
        /// Read value from file instead of argument
        #[arg(short = 'f', long = "file")]
        file: Option<String>,
        /// TTL duration (e.g. 1h, 30m, 7d)
        #[arg(long)]
        ttl: Option<String>,
        /// Max reads before burn [default: server decides]
        #[arg(long)]
        reads: Option<u32>,
        /// Keep sealed after reads exhausted (enables patch)
        #[arg(long)]
        no_delete: bool,
        /// Return shareable URL in response
        #[arg(long)]
        share: bool,
    },

    /// Retrieve a secret by ID (public) or key name (org)
    #[command(
        after_long_help = "Examples:\n  sirr get 13e8399ee6d70824\n  sirr get DB_PASS --org myteam\n  DB_PASS=$(sirr get abc123)"
    )]
    Get {
        /// Secret ID (public) or key name (with --org)
        #[arg(name = "ID_OR_KEY")]
        id_or_key: String,
    },

    /// List org secrets (metadata only, requires --org)
    #[command(after_long_help = "Examples:\n  sirr list --org myteam")]
    List,

    /// Delete a secret
    #[command(
        after_long_help = "Examples:\n  sirr delete 13e8399ee6d70824\n  sirr delete DB_PASS --org myteam"
    )]
    Delete {
        /// Secret ID (public) or key name (with --org)
        #[arg(name = "ID_OR_KEY")]
        id_or_key: String,
    },

    /// Remove expired/burned secrets
    #[command(
        after_long_help = "Examples:\n  sirr prune --org myteam\n  sirr prune --api-key <KEY>"
    )]
    Prune,

    /// Run a command with org secrets as env vars (requires --org)
    #[command(
        after_long_help = "Examples:\n  sirr run --org myteam -- node server.js\n  sirr run --org myteam -- docker compose up"
    )]
    Run {
        /// Command and arguments
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<String>,
    },

    /// Pull org secrets to a .env file (requires --org)
    #[command(after_long_help = "Examples:\n  sirr pull .env --org myteam")]
    Pull {
        /// Path to write the .env file [default: .env]
        #[arg(default_value = ".env")]
        path: String,
    },

    /// Manage webhooks
    #[command(subcommand)]
    Webhooks(WebhookCommand),

    /// View audit log
    #[command(
        after_long_help = "Examples:\n  sirr audit --org myteam\n  sirr audit --key DB_PASS --org myteam\n  sirr audit --action secret.read --since 1711900000"
    )]
    Audit {
        /// Filter by secret key or ID
        #[arg(long)]
        key: Option<String>,
        /// Filter by action (e.g. secret.create, secret.read)
        #[arg(long)]
        action: Option<String>,
        /// Filter from timestamp (unix epoch)
        #[arg(long)]
        since: Option<i64>,
        /// Max events [default: 50]
        #[arg(long, default_value = "50")]
        limit: usize,
    },

    /// Manage scoped API keys
    #[command(subcommand)]
    Keys(KeyCommand),
    /// Manage organizations
    #[command(subcommand)]
    Orgs(OrgCommand),
    /// Manage org members
    #[command(subcommand)]
    Principals(PrincipalCommand),

    /// Show current identity & connection info
    ///
    /// Example: sirr me
    #[command(subcommand)]
    Me(MeCommand),

    /// Generate shell completions or man page
    #[command(hide = true)]
    Completions {
        /// Output target: bash, zsh, fish, or man
        #[arg(name = "SHELL_OR_MAN", value_parser = ["bash", "zsh", "fish", "man"])]
        target: String,
    },
}

#[derive(Subcommand)]
enum WebhookCommand {
    /// List registered webhooks
    List,
    /// Register a webhook URL
    Add {
        /// Webhook endpoint URL
        #[arg(name = "URL")]
        url: String,
        /// Comma-separated event types (default: all)
        #[arg(long, value_delimiter = ',')]
        events: Option<Vec<String>>,
    },
    /// Delete a webhook by ID
    Delete {
        /// Webhook ID
        #[arg(name = "ID")]
        id: String,
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
    /// List org members
    List,
    /// Add an org member
    Create {
        /// Principal name
        name: String,
        /// Role [default: writer]
        #[arg(long, default_value = "writer")]
        role: String,
    },
    /// Issue an API key for a principal (master key only)
    CreateKey {
        /// Principal ID
        #[arg(name = "PRINCIPAL_ID")]
        principal_id: String,
        /// Key name/label
        #[arg(long, default_value = "default")]
        name: String,
        /// Validity duration in seconds (default: 86400 = 24h)
        #[arg(long, default_value = "86400")]
        valid_for_seconds: u64,
    },
    /// Remove an org member
    Delete {
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
        let server = server.trim_end_matches('/').to_string();
        // If no scheme, default to https
        let server = if !server.starts_with("http://") && !server.starts_with("https://") {
            format!("https://{server}")
        } else {
            server
        };
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

fn require_org(org: &Option<String>) -> Result<&str> {
    org.as_deref()
        .ok_or_else(|| anyhow::anyhow!("this command requires --org or $SIRR_ORG"))
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    let log_level = std::env::var("SIRR_LOG_LEVEL").unwrap_or_else(|_| "warn".into());
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::new(&log_level))
        .init();

    let ctx = Ctx::new(cli.server, cli.api_key);

    match cli.command {
        Commands::Push { value, ttl, reads } => cmd_push(&ctx, &value, ttl.as_deref(), reads).await,

        Commands::Set {
            target,
            file,
            ttl,
            reads,
            no_delete,
            share,
        } => {
            let org = require_org(&cli.org)?;
            cmd_set(
                &ctx,
                &target,
                file.as_deref(),
                ttl.as_deref(),
                reads,
                !no_delete,
                share,
                org,
            )
            .await
        }

        Commands::Get { id_or_key } => cmd_get(&ctx, &id_or_key, cli.org.as_deref()).await,

        Commands::List => {
            let org = require_org(&cli.org)?;
            cmd_list(&ctx, Some(org)).await
        }

        Commands::Delete { id_or_key } => cmd_delete(&ctx, &id_or_key, cli.org.as_deref()).await,

        Commands::Prune => cmd_prune(&ctx, cli.org.as_deref()).await,

        Commands::Run { command } => {
            let org = require_org(&cli.org)?;
            cmd_run(&ctx, &command, Some(org)).await
        }

        Commands::Pull { path } => {
            let org = require_org(&cli.org)?;
            cmd_pull(&ctx, &path, Some(org)).await
        }

        Commands::Webhooks(sub) => match sub {
            WebhookCommand::List => cmd_webhook_list(&ctx, cli.org.as_deref()).await,
            WebhookCommand::Add { url, events } => {
                cmd_webhook_add(&ctx, &url, events, cli.org.as_deref()).await
            }
            WebhookCommand::Delete { id } => {
                cmd_webhook_remove(&ctx, &id, cli.org.as_deref()).await
            }
        },

        Commands::Audit {
            key,
            action,
            since,
            limit,
        } => {
            cmd_audit(
                &ctx,
                since,
                action.as_deref(),
                key.as_deref(),
                limit,
                cli.org.as_deref(),
            )
            .await
        }

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

        Commands::Principals(sub) => {
            let org = require_org(&cli.org)?;
            match sub {
                PrincipalCommand::List => cmd_principal_list(&ctx, org).await,
                PrincipalCommand::Create { name, role } => {
                    cmd_principal_create(&ctx, org, &name, &role).await
                }
                PrincipalCommand::CreateKey {
                    principal_id,
                    name,
                    valid_for_seconds,
                } => {
                    cmd_principal_create_key(&ctx, org, &principal_id, &name, valid_for_seconds)
                        .await
                }
                PrincipalCommand::Delete { id } => cmd_principal_delete(&ctx, org, &id).await,
            }
        }

        Commands::Me(sub) => match sub {
            MeCommand::Info => cmd_me_info(&ctx).await,
            MeCommand::Keys => cmd_me_keys(&ctx).await,
            MeCommand::CreateKey {
                name,
                valid_for_seconds,
            } => cmd_me_create_key(&ctx, &name, valid_for_seconds).await,
            MeCommand::DeleteKey { id } => cmd_me_delete_key(&ctx, &id).await,
        },

        Commands::Completions { target } => {
            cmd_completions(&target);
            Ok(())
        }
    }
}

fn cmd_completions(target: &str) {
    let mut cmd = Cli::command();
    match target {
        "bash" => clap_complete::generate(Shell::Bash, &mut cmd, "sirr", &mut std::io::stdout()),
        "zsh" => clap_complete::generate(Shell::Zsh, &mut cmd, "sirr", &mut std::io::stdout()),
        "fish" => clap_complete::generate(Shell::Fish, &mut cmd, "sirr", &mut std::io::stdout()),
        "man" => {
            let man = clap_mangen::Man::new(cmd);
            man.render(&mut std::io::stdout())
                .expect("failed to write man page");
        }
        _ => unreachable!("clap validates the value"),
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

async fn cmd_push(ctx: &Ctx, value: &str, ttl: Option<&str>, reads: Option<u32>) -> Result<()> {
    let ttl_seconds = ttl.map(parse_duration).transpose()?;
    let body = serde_json::json!({
        "value": value,
        "ttl_seconds": ttl_seconds,
        "max_reads": reads,
    });

    let resp = require_success(
        ctx.post("secrets")
            .json(&body)
            .send()
            .await
            .context("HTTP request failed")?,
    )
    .await?;

    let json: Value = resp.json().await?;
    let id = json["id"].as_str().unwrap_or("?");
    let url = format!("{}/secrets/{}", ctx.server, id);

    println!("{}", serde_json::json!({"id": id, "url": url}));
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn cmd_set(
    ctx: &Ctx,
    target: &str,
    file: Option<&str>,
    ttl: Option<&str>,
    reads: Option<u32>,
    delete: bool,
    share: bool,
    org: &str,
) -> Result<()> {
    let ttl_seconds = ttl.map(parse_duration).transpose()?;

    // Handle -f (value from file)
    if let Some(file_path) = file {
        if target.contains('=') {
            anyhow::bail!("cannot use -f with KEY=VALUE syntax; use -f with just the KEY name, or omit -f for inline values");
        }

        // Check if file is a .env file (multiple key=value lines)
        if file_path.ends_with(".env") || file_path.starts_with(".env") {
            return set_env_file(ctx, file_path, ttl_seconds, reads, delete, org).await;
        }

        // Single key with value from file
        let value = std::fs::read_to_string(file_path)
            .with_context(|| format!("read file: {file_path}"))?;
        return set_one(ctx, target, &value, ttl_seconds, reads, delete, share, org).await;
    }

    // KEY=VALUE inline
    let (key, value) = target
        .split_once('=')
        .context("expected KEY=VALUE (use -f to read value from a file)")?;

    set_one(ctx, key, value, ttl_seconds, reads, delete, share, org).await
}

async fn set_env_file(
    ctx: &Ctx,
    path: &str,
    ttl_seconds: Option<u64>,
    reads: Option<u32>,
    delete: bool,
    org: &str,
) -> Result<()> {
    let entries =
        dotenvy::from_filename_iter(path).with_context(|| format!("read .env file: {path}"))?;

    let mut count = 0usize;
    for entry in entries {
        let (key, value) = entry.context("parse .env entry")?;
        set_one(ctx, &key, &value, ttl_seconds, reads, delete, false, org).await?;
        count += 1;
    }
    println!("{count} secret(s) set from {path}");
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn set_one(
    ctx: &Ctx,
    key: &str,
    value: &str,
    ttl_seconds: Option<u64>,
    max_reads: Option<u32>,
    delete: bool,
    share: bool,
    org: &str,
) -> Result<()> {
    let body = serde_json::json!({
        "key": key,
        "value": value,
        "ttl_seconds": ttl_seconds,
        "max_reads": max_reads,
        "delete": delete,
    });

    let path = format!("orgs/{org}/secrets");
    let resp = ctx
        .post(&path)
        .json(&body)
        .send()
        .await
        .context("HTTP request failed")?;

    let status = resp.status();
    let json: Value = resp.json().await.context("parse response")?;

    if status == reqwest::StatusCode::CONFLICT {
        let msg = json["message"].as_str().unwrap_or("key already exists");
        anyhow::bail!("✗ {msg}");
    }

    if !status.is_success() {
        let error = json["error"].as_str().unwrap_or("unknown error");
        anyhow::bail!("server returned {status}: {error}");
    }

    let key_name = json["key"].as_str().unwrap_or(key);
    if share {
        println!("{}", serde_json::json!({"key": key_name}));
    } else {
        println!("✓ set {key_name}");
    }
    Ok(())
}

async fn cmd_get(ctx: &Ctx, id_or_key: &str, org: Option<&str>) -> Result<()> {
    let path = match org {
        Some(org_id) => format!("orgs/{org_id}/secrets/{id_or_key}"),
        None => format!("secrets/{id_or_key}"),
    };
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
    key: Option<&str>,
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
    if let Some(k) = key {
        url.push_str(&format!("&key={k}"));
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
                let ekey = e["key"].as_str().unwrap_or("-");
                let ip = e["source_ip"].as_str().unwrap_or("?");
                let ok = if e["success"].as_bool().unwrap_or(false) {
                    "ok"
                } else {
                    "FAIL"
                };
                println!("  [{ts}] {action} key={ekey} ip={ip} {ok}");
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

async fn cmd_principal_create_key(
    ctx: &Ctx,
    org: &str,
    principal_id: &str,
    name: &str,
    valid_for_seconds: u64,
) -> Result<()> {
    let body = serde_json::json!({
        "name": name,
        "valid_for_seconds": valid_for_seconds,
    });

    let resp = require_success(
        ctx.post(&format!("orgs/{org}/principals/{principal_id}/keys"))
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
    let resp = ctx.get("me").send().await.context("HTTP request failed")?;

    if resp.status().is_success() {
        let json: Value = resp.json().await?;
        let name = json["name"].as_str().unwrap_or("?");
        let org_id = json["org_id"].as_str().unwrap_or("?");
        let role = json["role"].as_str().unwrap_or("?");
        let key_count = json["keys"].as_array().map(|a| a.len()).unwrap_or(0);
        println!(
            "{name} · {org_id} · {role} · {key_count} keys · {}",
            ctx.server
        );

        if let Some(keys) = json["keys"].as_array() {
            for k in keys {
                let kid = k["id"].as_str().unwrap_or("?");
                let kname = k["name"].as_str().unwrap_or("?");
                println!("  {kid}  {kname}");
            }
        }
    } else {
        // Anonymous — no valid auth, just show connection info
        println!("anonymous · {}", ctx.server);
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
