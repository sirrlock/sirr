use clap::{Parser, Subcommand};
use serde_json::{json, Value};

// ── TTL parsing ────────────────────────────────────────────────────────────────

fn parse_ttl(s: &str) -> anyhow::Result<u64> {
    let s = s.trim();
    if let Some(n) = s.strip_suffix('s') {
        return Ok(n.parse::<u64>()?);
    }
    if let Some(n) = s.strip_suffix('m') {
        return Ok(n.parse::<u64>()? * 60);
    }
    if let Some(n) = s.strip_suffix('h') {
        return Ok(n.parse::<u64>()? * 3600);
    }
    if let Some(n) = s.strip_suffix('d') {
        return Ok(n.parse::<u64>()? * 86400);
    }
    s.parse::<u64>().map_err(Into::into)
}

// ── CLI structure ──────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(name = "sirr", about = "Sirr CLI — ephemeral secret client", version)]
struct Cli {
    /// Server URL
    #[arg(
        long,
        env = "SIRR_SERVER",
        default_value = "https://sirrlock.com",
        global = true
    )]
    server: String,

    /// Bearer token for authentication
    #[arg(long, env = "SIRR_TOKEN", global = true)]
    token: Option<String>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Push a new secret (returns URL)
    Push {
        value: String,
        #[arg(long)]
        ttl: Option<String>,
        #[arg(long)]
        reads: Option<u32>,
        #[arg(long)]
        prefix: Option<String>,
    },
    /// Read a secret value
    Get { hash: String },
    /// Inspect secret metadata (HEAD)
    Inspect { hash: String },
    /// View audit trail for a secret
    Audit { hash: String },
    /// Update a secret value (owner only)
    Patch {
        hash: String,
        value: String,
        #[arg(long)]
        ttl: Option<String>,
        #[arg(long)]
        reads: Option<u32>,
    },
    /// Burn a secret (delete permanently)
    Burn { hash: String },
    /// Store authentication token
    Login,
}

// ── Token file ────────────────────────────────────────────────────────────────

fn token_file_path() -> anyhow::Result<std::path::PathBuf> {
    let home = std::env::var("HOME").map_err(|_| anyhow::anyhow!("$HOME is not set"))?;
    Ok(std::path::PathBuf::from(home)
        .join(".config")
        .join("sirr")
        .join("token"))
}

fn read_token_file() -> anyhow::Result<String> {
    let path = token_file_path()?;
    Ok(std::fs::read_to_string(path)?.trim().to_string())
}

// ── HTTP helpers ──────────────────────────────────────────────────────────────

fn build_client() -> anyhow::Result<reqwest::Client> {
    Ok(reqwest::Client::builder().build()?)
}

fn auth_header(cli: &Cli) -> Option<String> {
    if let Some(ref token) = cli.token {
        return Some(format!("Bearer {token}"));
    }
    if let Ok(token) = read_token_file() {
        if !token.is_empty() {
            return Some(format!("Bearer {token}"));
        }
    }
    None
}

fn apply_auth(req: reqwest::RequestBuilder, cli: &Cli) -> reqwest::RequestBuilder {
    if let Some(header) = auth_header(cli) {
        req.header("authorization", header)
    } else {
        req
    }
}

// ── Main ──────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let client = build_client()?;

    match &cli.command {
        // ── push ──────────────────────────────────────────────────────────────
        Commands::Push {
            value,
            ttl,
            reads,
            prefix,
        } => {
            let mut body = json!({"value": value});

            if let Some(t) = ttl {
                let secs = parse_ttl(t)?;
                body["ttl_seconds"] = json!(secs);
            }
            if let Some(r) = reads {
                body["reads"] = json!(r);
            }
            if let Some(p) = prefix {
                body["prefix"] = json!(p);
            }

            let url = format!("{}/secret", cli.server);
            let req = apply_auth(client.post(&url).json(&body), &cli);
            let resp = req.send().await?;

            let status = resp.status();
            let text = resp.text().await?;

            if status.is_success() {
                let data: Value = serde_json::from_str(&text)?;
                println!("{}", data["url"].as_str().unwrap_or(&text));
            } else {
                eprintln!("error {status}: {text}");
                std::process::exit(1);
            }
        }

        // ── get ───────────────────────────────────────────────────────────────
        Commands::Get { hash } => {
            let url = format!("{}/secret/{hash}", cli.server);
            let req = apply_auth(client.get(&url), &cli);
            let resp = req.send().await?;

            let status = resp.status();
            if status == reqwest::StatusCode::GONE || status == reqwest::StatusCode::NOT_FOUND {
                eprintln!("secret is gone");
                std::process::exit(1);
            }
            if !status.is_success() {
                let text = resp.text().await?;
                eprintln!("error {status}: {text}");
                std::process::exit(1);
            }

            // Print raw value (text/plain).
            let text = resp.text().await?;
            print!("{text}");
        }

        // ── inspect ───────────────────────────────────────────────────────────
        Commands::Inspect { hash } => {
            let url = format!("{}/secret/{hash}", cli.server);
            let req = apply_auth(client.head(&url), &cli);
            let resp = req.send().await?;

            let status = resp.status();
            if status == reqwest::StatusCode::GONE || status == reqwest::StatusCode::NOT_FOUND {
                eprintln!("secret is gone");
                std::process::exit(1);
            }
            if !status.is_success() {
                eprintln!("error {status}");
                std::process::exit(1);
            }

            // Pretty-print X-Sirr-* headers.
            for (name, value) in resp.headers() {
                let name_str = name.as_str();
                if let Some(label) = name_str.strip_prefix("x-sirr-") {
                    println!("{label}: {}", value.to_str().unwrap_or("?"));
                }
            }
        }

        // ── audit ─────────────────────────────────────────────────────────────
        Commands::Audit { hash } => {
            let url = format!("{}/secret/{hash}/audit", cli.server);
            let req = apply_auth(client.get(&url), &cli);
            let resp = req.send().await?;

            let status = resp.status();
            if status == reqwest::StatusCode::UNAUTHORIZED {
                eprintln!("not authorized — this command requires the owner key");
                std::process::exit(1);
            }
            if status == reqwest::StatusCode::NOT_FOUND {
                eprintln!("no audit available for this secret");
                std::process::exit(1);
            }
            if !status.is_success() {
                let text = resp.text().await?;
                eprintln!("error {status}: {text}");
                std::process::exit(1);
            }

            let data: Value = resp.json().await?;
            if let Some(events) = data["events"].as_array() {
                for e in events {
                    println!(
                        "{} {} {}",
                        e["at"],
                        e["type"].as_str().unwrap_or("-"),
                        e["ip"].as_str().unwrap_or("-"),
                    );
                }
            } else {
                println!("{}", serde_json::to_string_pretty(&data)?);
            }
        }

        // ── patch ─────────────────────────────────────────────────────────────
        Commands::Patch {
            hash,
            value,
            ttl,
            reads,
        } => {
            let mut body = json!({"value": value});
            if let Some(t) = ttl {
                let secs = parse_ttl(t)?;
                body["ttl_seconds"] = json!(secs);
            }
            if let Some(r) = reads {
                body["reads"] = json!(r);
            }

            let url = format!("{}/secret/{hash}", cli.server);
            let req = apply_auth(client.patch(&url).json(&body), &cli);
            let resp = req.send().await?;

            let status = resp.status();
            if status == reqwest::StatusCode::GONE {
                eprintln!("secret is gone");
                std::process::exit(1);
            }
            if !status.is_success() {
                let text = resp.text().await?;
                eprintln!("error {status}: {text}");
                std::process::exit(1);
            }

            let data: Value = resp.json().await?;
            println!("patched: {}", data["hash"].as_str().unwrap_or(hash));
            if let Some(exp) = data["expires_at"].as_i64() {
                println!("expires_at: {exp}");
            }
            if let Some(rem) = data["reads_remaining"].as_u64() {
                println!("reads_remaining: {rem}");
            }
        }

        // ── burn ──────────────────────────────────────────────────────────────
        Commands::Burn { hash } => {
            let url = format!("{}/secret/{hash}", cli.server);
            let req = apply_auth(client.delete(&url), &cli);
            let resp = req.send().await?;

            let status = resp.status();
            if status == reqwest::StatusCode::NO_CONTENT {
                println!("burned");
            } else if status == reqwest::StatusCode::GONE {
                eprintln!("already gone");
            } else {
                let text = resp.text().await?;
                eprintln!("error {status}: {text}");
                std::process::exit(1);
            }
        }

        // ── login ─────────────────────────────────────────────────────────────
        Commands::Login => {
            use std::io::Write;
            eprint!("Enter your sirr token: ");
            std::io::stderr().flush()?;

            let mut token = String::new();
            std::io::stdin().read_line(&mut token)?;
            let token = token.trim().to_string();

            if token.is_empty() {
                eprintln!("no token entered");
                std::process::exit(1);
            }

            let path = token_file_path()?;
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(&path, format!("{token}\n"))?;

            // Set permissions to 0600 on Unix.
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
            }

            eprintln!("token saved to {}", path.display());
        }
    }

    Ok(())
}
