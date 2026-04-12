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
    /// List all secrets owned by your key (requires token)
    List,
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

// ── Request body builders ─────────────────────────────────────────────────────

fn build_push_body(
    value: &str,
    ttl: Option<&str>,
    reads: Option<u32>,
    prefix: Option<&str>,
) -> anyhow::Result<Value> {
    let mut body = json!({"value": value});
    if let Some(t) = ttl {
        body["ttl_seconds"] = json!(parse_ttl(t)?);
    }
    if let Some(r) = reads {
        body["reads"] = json!(r);
    }
    if let Some(p) = prefix {
        body["prefix"] = json!(p);
    }
    Ok(body)
}

fn build_patch_body(value: &str, ttl: Option<&str>, reads: Option<u32>) -> anyhow::Result<Value> {
    let mut body = json!({"value": value});
    if let Some(t) = ttl {
        body["ttl_seconds"] = json!(parse_ttl(t)?);
    }
    if let Some(r) = reads {
        body["reads"] = json!(r);
    }
    Ok(body)
}

// ── HTTP helpers ──────────────────────────────────────────────────────────────

fn build_client() -> anyhow::Result<reqwest::Client> {
    Ok(reqwest::Client::builder().build()?)
}

fn make_bearer(explicit: Option<&str>, file_token: Option<&str>) -> Option<String> {
    if let Some(t) = explicit {
        return Some(format!("Bearer {t}"));
    }
    if let Some(t) = file_token {
        if !t.is_empty() {
            return Some(format!("Bearer {t}"));
        }
    }
    None
}

fn auth_header(cli: &Cli) -> Option<String> {
    let file_token = read_token_file().ok();
    make_bearer(cli.token.as_deref(), file_token.as_deref())
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
            let body = build_push_body(value, ttl.as_deref(), *reads, prefix.as_deref())?;

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
            let body = build_patch_body(value, ttl.as_deref(), *reads)?;

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

        // ── list ──────────────────────────────────────────────────────────────
        Commands::List => {
            let url = format!("{}/secrets", cli.server);
            let req = apply_auth(client.get(&url), &cli);
            let resp = req.send().await?;

            let status = resp.status();
            if status == reqwest::StatusCode::UNAUTHORIZED {
                eprintln!("not authorized — this command requires a token (sirr login or --token)");
                std::process::exit(1);
            }
            if status == reqwest::StatusCode::SERVICE_UNAVAILABLE {
                eprintln!("server is in lockdown mode");
                std::process::exit(1);
            }
            if !status.is_success() {
                let text = resp.text().await?;
                eprintln!("error {status}: {text}");
                std::process::exit(1);
            }

            let items: Vec<Value> = resp.json().await?;
            if items.is_empty() {
                println!("no secrets");
            } else {
                println!(
                    "{:<66}  {:>10}  {:>5}  burned",
                    "hash", "created_at", "reads"
                );
                println!("{}", "-".repeat(100));
                for item in &items {
                    let hash = item["hash"].as_str().unwrap_or("-");
                    let created = item["created_at"].as_i64().unwrap_or(0);
                    let reads = item["reads_remaining"]
                        .as_u64()
                        .map(|n| n.to_string())
                        .unwrap_or_else(|| "∞".to_string());
                    let burned = if item["burned"].as_bool().unwrap_or(false) {
                        "yes"
                    } else {
                        "no"
                    };
                    println!("{hash:<66}  {created:>10}  {reads:>5}  {burned}");
                }
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

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── parse_ttl ─────────────────────────────────────────────────────────────

    #[test]
    fn parse_ttl_seconds_suffix() {
        assert_eq!(parse_ttl("30s").unwrap(), 30);
    }

    #[test]
    fn parse_ttl_minutes_suffix() {
        assert_eq!(parse_ttl("5m").unwrap(), 300);
    }

    #[test]
    fn parse_ttl_hours_suffix() {
        assert_eq!(parse_ttl("1h").unwrap(), 3600);
    }

    #[test]
    fn parse_ttl_days_suffix() {
        assert_eq!(parse_ttl("2d").unwrap(), 172800);
    }

    #[test]
    fn parse_ttl_plain_seconds() {
        assert_eq!(parse_ttl("3600").unwrap(), 3600);
    }

    #[test]
    fn parse_ttl_empty_is_error() {
        assert!(parse_ttl("").is_err());
    }

    #[test]
    fn parse_ttl_alpha_is_error() {
        assert!(parse_ttl("abc").is_err());
    }

    #[test]
    fn parse_ttl_unknown_suffix_is_error() {
        assert!(parse_ttl("5x").is_err());
    }

    // ── build_push_body ───────────────────────────────────────────────────────

    #[test]
    fn push_body_minimal() {
        let body = build_push_body("hello", None, None, None).unwrap();
        assert_eq!(body, json!({"value": "hello"}));
    }

    #[test]
    fn push_body_with_ttl() {
        let body = build_push_body("hello", Some("1h"), None, None).unwrap();
        assert_eq!(body, json!({"value": "hello", "ttl_seconds": 3600u64}));
    }

    #[test]
    fn push_body_with_reads() {
        let body = build_push_body("hello", None, Some(5), None).unwrap();
        assert_eq!(body, json!({"value": "hello", "reads": 5u32}));
    }

    #[test]
    fn push_body_with_prefix() {
        let body = build_push_body("hello", None, None, Some("db1_")).unwrap();
        assert_eq!(body, json!({"value": "hello", "prefix": "db1_"}));
    }

    #[test]
    fn push_body_all_options() {
        let body = build_push_body("hello", Some("5m"), Some(3), Some("pfx_")).unwrap();
        assert_eq!(
            body,
            json!({"value": "hello", "ttl_seconds": 300u64, "reads": 3u32, "prefix": "pfx_"})
        );
    }

    #[test]
    fn push_body_invalid_ttl_is_error() {
        assert!(build_push_body("hello", Some("bad"), None, None).is_err());
    }

    // ── build_patch_body ──────────────────────────────────────────────────────

    #[test]
    fn patch_body_minimal() {
        let body = build_patch_body("new", None, None).unwrap();
        assert_eq!(body, json!({"value": "new"}));
    }

    #[test]
    fn patch_body_with_ttl_and_reads() {
        let body = build_patch_body("new", Some("5m"), Some(1)).unwrap();
        assert_eq!(
            body,
            json!({"value": "new", "ttl_seconds": 300u64, "reads": 1u32})
        );
    }

    #[test]
    fn patch_body_invalid_ttl_is_error() {
        assert!(build_patch_body("new", Some("5x"), None).is_err());
    }

    // ── URL construction ──────────────────────────────────────────────────────

    #[test]
    fn url_push() {
        assert_eq!(
            format!("{}/secret", "https://example.com"),
            "https://example.com/secret"
        );
    }

    #[test]
    fn url_get_and_inspect_and_patch_and_burn() {
        let hash = "abc123";
        let server = "https://example.com";
        assert_eq!(
            format!("{server}/secret/{hash}"),
            "https://example.com/secret/abc123"
        );
    }

    #[test]
    fn url_audit() {
        let hash = "abc123";
        let server = "https://example.com";
        assert_eq!(
            format!("{server}/secret/{hash}/audit"),
            "https://example.com/secret/abc123/audit"
        );
    }

    // ── make_bearer (auth_header helper) ──────────────────────────────────────

    #[test]
    fn bearer_with_explicit_token() {
        let result = make_bearer(Some("mytoken"), None);
        assert_eq!(result, Some("Bearer mytoken".to_string()));
    }

    #[test]
    fn bearer_explicit_token_takes_priority_over_file() {
        let result = make_bearer(Some("explicit"), Some("fromfile"));
        assert_eq!(result, Some("Bearer explicit".to_string()));
    }

    #[test]
    fn bearer_falls_back_to_file_token() {
        let result = make_bearer(None, Some("filetoken"));
        assert_eq!(result, Some("Bearer filetoken".to_string()));
    }

    #[test]
    fn bearer_empty_file_token_returns_none() {
        let result = make_bearer(None, Some(""));
        assert_eq!(result, None);
    }

    #[test]
    fn bearer_no_tokens_returns_none() {
        let result = make_bearer(None, None);
        assert_eq!(result, None);
    }
}
