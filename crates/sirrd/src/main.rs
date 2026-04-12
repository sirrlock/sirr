use std::path::PathBuf;

use clap::{Parser, Subcommand};
use sirr_server::admin::{AdminRequest, AdminResponse};
use sirr_server::store::Visibility;
use sirr_server::ServerConfig;

// ── CLI structure ─────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(
    name = "sirrd",
    about = "Sirr daemon — ephemeral secret server",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the sirrd daemon
    Serve {
        #[arg(long, default_value = "0.0.0.0:7843")]
        bind: String,
        #[arg(long)]
        data_dir: Option<String>,
        #[arg(long)]
        admin_socket: Option<String>,
        /// Initial visibility mode: public | private | both | none (default: public).
        /// Hot-switchable at runtime via `sirrd visibility set <mode>`.
        /// Resets to this value on restart.
        #[arg(long, default_value = "public")]
        visibility: String,
        /// Retention period in days for burned secrets and their audit events (default: 30).
        #[arg(long, default_value = "30")]
        retention_days: i64,
    },
    /// Get or set visibility mode
    Visibility {
        #[command(subcommand)]
        action: VisibilityAction,
    },
    /// Manage API keys
    Keys {
        #[command(subcommand)]
        action: KeysAction,
    },
    /// View audit log
    Audit {
        #[arg(long)]
        since: Option<i64>,
        #[arg(long)]
        until: Option<i64>,
        #[arg(long, default_value = "50")]
        limit: usize,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
enum VisibilityAction {
    Get,
    Set { mode: String },
}

#[derive(Subcommand)]
enum KeysAction {
    Create {
        name: String,
        #[arg(long)]
        valid_after: Option<i64>,
        #[arg(long)]
        valid_before: Option<i64>,
        #[arg(long)]
        webhook: Option<String>,
    },
    List,
    Delete {
        name: String,
    },
    Secrets {
        name: String,
    },
    Purge {
        name: String,
        #[arg(long)]
        yes: bool,
    },
}

// ── Default socket path ───────────────────────────────────────────────────────

fn default_socket_path() -> String {
    std::env::var("SIRR_ADMIN_SOCKET").unwrap_or_else(|_| "/tmp/sirrd.sock".to_string())
}

// ── Admin client ──────────────────────────────────────────────────────────────

async fn send_admin(socket_path: &str, req: &AdminRequest) -> anyhow::Result<AdminResponse> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::UnixStream;

    let stream = UnixStream::connect(socket_path).await.map_err(|e| {
        anyhow::anyhow!("cannot connect to admin socket at {socket_path}: {e}\n(is sirrd running?)")
    })?;

    let (reader, mut writer) = stream.into_split();

    let mut json = serde_json::to_string(req)?;
    json.push('\n');
    writer.write_all(json.as_bytes()).await?;
    writer.shutdown().await?;

    let mut buf = String::new();
    BufReader::new(reader).read_line(&mut buf).await?;

    let resp: AdminResponse = serde_json::from_str(buf.trim())
        .map_err(|e| anyhow::anyhow!("invalid response from daemon: {e}\nraw: {buf}"))?;
    Ok(resp)
}

// ── Main ──────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        // ── serve ─────────────────────────────────────────────────────────────
        Commands::Serve {
            bind,
            data_dir,
            admin_socket,
            visibility,
            retention_days,
        } => {
            let vis: Visibility = visibility
                .parse()
                .map_err(|e| anyhow::anyhow!("invalid visibility: {e}"))?;
            let config = ServerConfig {
                bind_addr: bind
                    .parse()
                    .map_err(|e| anyhow::anyhow!("invalid bind address: {e}"))?,
                data_dir: data_dir.map(PathBuf::from).unwrap_or_else(default_data_dir),
                admin_socket: PathBuf::from(admin_socket.unwrap_or_else(default_socket_path)),
                visibility: vis,
                retention_days,
            };
            sirr_server::server::run(config).await?;
        }

        // ── visibility ────────────────────────────────────────────────────────
        Commands::Visibility { action } => {
            let socket = default_socket_path();
            match action {
                VisibilityAction::Get => {
                    let resp = send_admin(&socket, &AdminRequest::VisibilityGet).await?;
                    match resp {
                        AdminResponse::Ok { data } => {
                            println!("visibility: {}", data["mode"].as_str().unwrap_or("?"))
                        }
                        AdminResponse::Error { message } => {
                            eprintln!("error: {message}");
                            std::process::exit(1);
                        }
                    }
                }
                VisibilityAction::Set { mode } => {
                    let resp =
                        send_admin(&socket, &AdminRequest::VisibilitySet { mode: mode.clone() })
                            .await?;
                    match resp {
                        AdminResponse::Ok { .. } => {
                            println!("visibility set to: {mode}")
                        }
                        AdminResponse::Error { message } => {
                            eprintln!("error: {message}");
                            std::process::exit(1);
                        }
                    }
                }
            }
        }

        // ── keys ──────────────────────────────────────────────────────────────
        Commands::Keys { action } => {
            let socket = default_socket_path();
            match action {
                KeysAction::Create {
                    name,
                    valid_after,
                    valid_before,
                    webhook,
                } => {
                    let resp = send_admin(
                        &socket,
                        &AdminRequest::KeysCreate {
                            name: name.clone(),
                            valid_after,
                            valid_before,
                            webhook_url: webhook,
                        },
                    )
                    .await?;
                    match resp {
                        AdminResponse::Ok { data } => {
                            eprintln!("Store this token — it will not be shown again:");
                            println!("{}", data["token"].as_str().unwrap_or("???"));
                            eprintln!("key name: {name}");
                            eprintln!("key id:   {}", data["id"].as_str().unwrap_or("?"));
                        }
                        AdminResponse::Error { message } => {
                            eprintln!("error: {message}");
                            std::process::exit(1);
                        }
                    }
                }

                KeysAction::List => {
                    let resp = send_admin(&socket, &AdminRequest::KeysList).await?;
                    match resp {
                        AdminResponse::Ok { data } => {
                            if let Some(keys) = data.as_array() {
                                if keys.is_empty() {
                                    println!("no keys");
                                } else {
                                    for k in keys {
                                        println!(
                                            "{:12} {:26} created: {}",
                                            k["name"].as_str().unwrap_or("-"),
                                            k["id"].as_str().unwrap_or("-"),
                                            k["created_at"],
                                        );
                                    }
                                }
                            }
                        }
                        AdminResponse::Error { message } => {
                            eprintln!("error: {message}");
                            std::process::exit(1);
                        }
                    }
                }

                KeysAction::Delete { name } => {
                    let resp =
                        send_admin(&socket, &AdminRequest::KeysDelete { name: name.clone() })
                            .await?;
                    match resp {
                        AdminResponse::Ok { .. } => println!("deleted key: {name}"),
                        AdminResponse::Error { message } => {
                            eprintln!("error: {message}");
                            std::process::exit(1);
                        }
                    }
                }

                KeysAction::Secrets { name } => {
                    let resp = send_admin(&socket, &AdminRequest::KeysSecrets { name }).await?;
                    match resp {
                        AdminResponse::Ok { data } => {
                            println!("{}", serde_json::to_string_pretty(&data)?)
                        }
                        AdminResponse::Error { message } => {
                            eprintln!("error: {message}");
                            std::process::exit(1);
                        }
                    }
                }

                KeysAction::Purge { name, yes } => {
                    if !yes {
                        eprintln!("purge all secrets for key '{name}'?");
                        eprintln!("use --yes to confirm");
                        std::process::exit(1);
                    }
                    let resp = send_admin(&socket, &AdminRequest::KeysPurge { name: name.clone() })
                        .await?;
                    match resp {
                        AdminResponse::Ok { data } => {
                            println!(
                                "burned {} secrets owned by {name}",
                                data["burned"].as_u64().unwrap_or(0)
                            )
                        }
                        AdminResponse::Error { message } => {
                            eprintln!("error: {message}");
                            std::process::exit(1);
                        }
                    }
                }
            }
        }

        // ── audit ─────────────────────────────────────────────────────────────
        Commands::Audit {
            since,
            until,
            limit,
            json,
        } => {
            let socket = default_socket_path();
            let resp = send_admin(
                &socket,
                &AdminRequest::Audit {
                    since,
                    until,
                    limit: Some(limit),
                },
            )
            .await?;
            match resp {
                AdminResponse::Ok { data } => {
                    if json {
                        println!("{}", serde_json::to_string_pretty(&data)?);
                    } else if let Some(events) = data.as_array() {
                        if events.is_empty() {
                            println!("(no audit events)");
                        } else {
                            for e in events {
                                println!(
                                    "{} {} {} {}",
                                    e["timestamp"],
                                    e["action"].as_str().unwrap_or("-"),
                                    e["hash"].as_str().unwrap_or("-"),
                                    e["source_ip"].as_str().unwrap_or("-"),
                                );
                            }
                        }
                    }
                }
                AdminResponse::Error { message } => {
                    eprintln!("error: {message}");
                    std::process::exit(1);
                }
            }
        }
    }

    Ok(())
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn default_data_dir() -> PathBuf {
    // Check SIRR_DATA_DIR env var first.
    if let Ok(d) = std::env::var("SIRR_DATA_DIR") {
        return PathBuf::from(d);
    }
    // Platform data dir via HOME.
    if let Ok(home) = std::env::var("HOME") {
        #[cfg(target_os = "macos")]
        return PathBuf::from(home)
            .join("Library")
            .join("Application Support")
            .join("sirrd");
        #[cfg(not(target_os = "macos"))]
        return PathBuf::from(home)
            .join(".local")
            .join("share")
            .join("sirrd");
    }
    // Fallback.
    PathBuf::from("/var/lib/sirrd")
}
