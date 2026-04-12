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
    version,
    disable_version_flag = true
)]
struct Cli {
    #[arg(short = 'v', long = "version", action = clap::ArgAction::Version)]
    version: (),

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
        /// Base URL for secret URLs in responses (e.g. https://sirr.sirrlock.com).
        /// Defaults to http://<bind-address>.
        #[arg(long)]
        base_url: Option<String>,
        /// Print live audit events to stderr as they happen.
        #[arg(long)]
        verbose: bool,
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
        /// Filter by key name. Shows full (unmasked) hashes for this key's events.
        /// Without this flag, hashes and key IDs are masked.
        #[arg(long)]
        key: Option<String>,
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

// ── Admin request builder ─────────────────────────────────────────────────────

#[cfg_attr(not(test), allow(dead_code))]
fn build_admin_request(command: &Commands) -> Option<AdminRequest> {
    match command {
        Commands::Serve { .. } => None,

        Commands::Visibility { action } => Some(match action {
            VisibilityAction::Get => AdminRequest::VisibilityGet,
            VisibilityAction::Set { mode } => AdminRequest::VisibilitySet { mode: mode.clone() },
        }),

        Commands::Keys { action } => Some(match action {
            KeysAction::Create {
                name,
                valid_after,
                valid_before,
                webhook,
            } => AdminRequest::KeysCreate {
                name: name.clone(),
                valid_after: *valid_after,
                valid_before: *valid_before,
                webhook_url: webhook.clone(),
            },
            KeysAction::List => AdminRequest::KeysList,
            KeysAction::Delete { name } => AdminRequest::KeysDelete { name: name.clone() },
            KeysAction::Secrets { name } => AdminRequest::KeysSecrets { name: name.clone() },
            KeysAction::Purge { name, .. } => AdminRequest::KeysPurge { name: name.clone() },
        }),

        Commands::Audit {
            since,
            until,
            limit,
            key,
            ..
        } => Some(AdminRequest::Audit {
            since: *since,
            until: *until,
            limit: Some(*limit),
            key_name: key.clone(),
        }),
    }
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
            base_url,
            verbose,
        } => {
            let vis: Visibility = visibility
                .parse()
                .map_err(|e| anyhow::anyhow!("invalid visibility: {e}"))?;
            let resolved_base_url = base_url.unwrap_or_else(|| format!("http://{bind}"));
            let config = ServerConfig {
                bind_addr: bind
                    .parse()
                    .map_err(|e| anyhow::anyhow!("invalid bind address: {e}"))?,
                data_dir: data_dir.map(PathBuf::from).unwrap_or_else(default_data_dir),
                admin_socket: PathBuf::from(admin_socket.unwrap_or_else(default_socket_path)),
                visibility: vis,
                retention_days,
                base_url: resolved_base_url,
                verbose,
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
            key,
        } => {
            let socket = default_socket_path();
            let resp = send_admin(
                &socket,
                &AdminRequest::Audit {
                    since,
                    until,
                    limit: Some(limit),
                    key_name: key,
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
                                    "{} {:16} {:>26} {}",
                                    e["timestamp"],
                                    e["action"].as_str().unwrap_or("-"),
                                    e["hash"].as_str().unwrap_or("-"),
                                    e["key_id"].as_str().unwrap_or("-"),
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

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── build_admin_request ───────────────────────────────────────────────────

    #[test]
    fn admin_serve_returns_none() {
        let cmd = Commands::Serve {
            bind: "0.0.0.0:7843".to_string(),
            data_dir: None,
            admin_socket: None,
            visibility: "public".to_string(),
            retention_days: 30,
            base_url: None,
            verbose: false,
        };
        assert!(build_admin_request(&cmd).is_none());
    }

    #[test]
    fn admin_visibility_get() {
        let cmd = Commands::Visibility {
            action: VisibilityAction::Get,
        };
        assert_eq!(build_admin_request(&cmd), Some(AdminRequest::VisibilityGet));
    }

    #[test]
    fn admin_visibility_set() {
        let cmd = Commands::Visibility {
            action: VisibilityAction::Set {
                mode: "private".to_string(),
            },
        };
        assert_eq!(
            build_admin_request(&cmd),
            Some(AdminRequest::VisibilitySet {
                mode: "private".to_string()
            })
        );
    }

    #[test]
    fn admin_keys_create_minimal() {
        let cmd = Commands::Keys {
            action: KeysAction::Create {
                name: "alice".to_string(),
                valid_after: None,
                valid_before: None,
                webhook: None,
            },
        };
        assert_eq!(
            build_admin_request(&cmd),
            Some(AdminRequest::KeysCreate {
                name: "alice".to_string(),
                valid_after: None,
                valid_before: None,
                webhook_url: None,
            })
        );
    }

    #[test]
    fn admin_keys_create_with_webhook() {
        let cmd = Commands::Keys {
            action: KeysAction::Create {
                name: "alice".to_string(),
                valid_after: None,
                valid_before: None,
                webhook: Some("http://example.com".to_string()),
            },
        };
        assert_eq!(
            build_admin_request(&cmd),
            Some(AdminRequest::KeysCreate {
                name: "alice".to_string(),
                valid_after: None,
                valid_before: None,
                webhook_url: Some("http://example.com".to_string()),
            })
        );
    }

    #[test]
    fn admin_keys_list() {
        let cmd = Commands::Keys {
            action: KeysAction::List,
        };
        assert_eq!(build_admin_request(&cmd), Some(AdminRequest::KeysList));
    }

    #[test]
    fn admin_keys_delete() {
        let cmd = Commands::Keys {
            action: KeysAction::Delete {
                name: "bob".to_string(),
            },
        };
        assert_eq!(
            build_admin_request(&cmd),
            Some(AdminRequest::KeysDelete {
                name: "bob".to_string()
            })
        );
    }

    #[test]
    fn admin_keys_secrets() {
        let cmd = Commands::Keys {
            action: KeysAction::Secrets {
                name: "alice".to_string(),
            },
        };
        assert_eq!(
            build_admin_request(&cmd),
            Some(AdminRequest::KeysSecrets {
                name: "alice".to_string()
            })
        );
    }

    #[test]
    fn admin_keys_purge() {
        let cmd = Commands::Keys {
            action: KeysAction::Purge {
                name: "alice".to_string(),
                yes: true,
            },
        };
        assert_eq!(
            build_admin_request(&cmd),
            Some(AdminRequest::KeysPurge {
                name: "alice".to_string()
            })
        );
    }

    #[test]
    fn admin_audit_with_limit() {
        let cmd = Commands::Audit {
            since: None,
            until: None,
            limit: 10,
            json: false,
            key: None,
        };
        assert_eq!(
            build_admin_request(&cmd),
            Some(AdminRequest::Audit {
                since: None,
                until: None,
                limit: Some(10),
                key_name: None,
            })
        );
    }

    #[test]
    fn admin_audit_full() {
        let cmd = Commands::Audit {
            since: Some(100),
            until: Some(200),
            limit: 5,
            json: false,
            key: None,
        };
        assert_eq!(
            build_admin_request(&cmd),
            Some(AdminRequest::Audit {
                since: Some(100),
                until: Some(200),
                limit: Some(5),
                key_name: None,
            })
        );
    }

    #[test]
    fn admin_audit_with_key() {
        let cmd = Commands::Audit {
            since: None,
            until: None,
            limit: 50,
            json: false,
            key: Some("my-key".to_string()),
        };
        assert_eq!(
            build_admin_request(&cmd),
            Some(AdminRequest::Audit {
                since: None,
                until: None,
                limit: Some(50),
                key_name: Some("my-key".to_string()),
            })
        );
    }

    // ── default_socket_path ───────────────────────────────────────────────────

    #[test]
    fn socket_path_default() {
        std::env::remove_var("SIRR_ADMIN_SOCKET");
        assert_eq!(default_socket_path(), "/tmp/sirrd.sock");
    }

    #[test]
    fn socket_path_from_env() {
        std::env::set_var("SIRR_ADMIN_SOCKET", "/custom/path.sock");
        assert_eq!(default_socket_path(), "/custom/path.sock");
        std::env::remove_var("SIRR_ADMIN_SOCKET");
    }

    // ── default_data_dir ──────────────────────────────────────────────────────

    #[test]
    fn data_dir_from_env() {
        std::env::set_var("SIRR_DATA_DIR", "/tmp/test-sirr-data");
        let dir = default_data_dir();
        assert_eq!(dir, std::path::PathBuf::from("/tmp/test-sirr-data"));
        std::env::remove_var("SIRR_DATA_DIR");
    }

    #[test]
    fn data_dir_without_env_is_nonempty_and_contains_sirr() {
        std::env::remove_var("SIRR_DATA_DIR");
        let dir = default_data_dir();
        let s = dir.to_string_lossy();
        assert!(!s.is_empty());
        assert!(s.contains("sirr"), "expected 'sirr' in path, got: {s}");
    }
}
