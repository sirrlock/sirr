//! Unix domain socket admin protocol.
//!
//! Newline-delimited JSON: one request line → one response line → close.
//! Authentication is purely filesystem-level: whoever can connect to the socket
//! has been authenticated by the kernel.

use std::path::PathBuf;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::store::{AuditQuery, Store, Visibility};

type VisibilityLock = Arc<tokio::sync::RwLock<Visibility>>;

// ── Wire types ────────────────────────────────────────────────────────────────

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum AdminRequest {
    VisibilityGet,
    VisibilitySet {
        mode: String,
    },
    KeysCreate {
        name: String,
        valid_after: Option<i64>,
        valid_before: Option<i64>,
        webhook_url: Option<String>,
    },
    KeysList,
    KeysDelete {
        name: String,
    },
    KeysSecrets {
        name: String,
    },
    KeysPurge {
        name: String,
    },
    Audit {
        since: Option<i64>,
        until: Option<i64>,
        limit: Option<usize>,
        /// Filter by key name. When set, only events for this key are returned
        /// and hashes are shown unmasked.
        key_name: Option<String>,
    },
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum AdminResponse {
    Ok { data: Value },
    Error { message: String },
}

impl AdminResponse {
    fn ok(data: Value) -> Self {
        Self::Ok { data }
    }

    fn err(msg: impl Into<String>) -> Self {
        Self::Error {
            message: msg.into(),
        }
    }
}

// ── Masking ───────────────────────────────────────────────────────────────────

/// Mask a string value for audit output. Shows first 4 and last 4 characters,
/// with `…` in between. Strings shorter than 12 chars show first 3 + `…`.
/// When `unmask` is true, returns the full value.
fn mask_value(s: &str, unmask: bool) -> String {
    if unmask {
        return s.to_owned();
    }
    let len = s.len();
    if len <= 8 {
        // Too short to meaningfully mask — show first 3 chars only.
        let show = len.min(3);
        format!("{}…", &s[..show])
    } else {
        format!("{}…{}", &s[..4], &s[len - 4..])
    }
}

/// Mask an optional string, preserving `None` as JSON null.
fn mask_optional(s: Option<&str>, unmask: bool) -> Value {
    match s {
        Some(v) => Value::String(mask_value(v, unmask)),
        None => Value::Null,
    }
}

// ── Socket listener ───────────────────────────────────────────────────────────

pub fn spawn_admin_socket(
    store: Arc<Store>,
    visibility: VisibilityLock,
    path: PathBuf,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        // Remove stale socket file if it exists.
        let _ = std::fs::remove_file(&path);

        // Create parent directory if needed.
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }

        let listener = match tokio::net::UnixListener::bind(&path) {
            Ok(l) => l,
            Err(e) => {
                tracing::error!("failed to bind admin socket at {}: {e}", path.display());
                return;
            }
        };

        // Set socket permissions to 0660.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o660));
        }

        tracing::info!("admin socket listening at {}", path.display());

        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    let store = store.clone();
                    let visibility = visibility.clone();
                    tokio::spawn(async move {
                        handle_admin_connection(stream, store, visibility).await;
                    });
                }
                Err(e) => {
                    tracing::error!("admin socket accept error: {e}");
                }
            }
        }
    })
}

// ── Connection handler ────────────────────────────────────────────────────────

async fn handle_admin_connection(
    stream: tokio::net::UnixStream,
    store: Arc<Store>,
    visibility: VisibilityLock,
) {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    let (reader, mut writer) = stream.into_split();
    let mut line = String::new();

    if let Err(e) = BufReader::new(reader).read_line(&mut line).await {
        tracing::warn!("admin: failed to read request: {e}");
        return;
    }

    let resp = match serde_json::from_str::<AdminRequest>(line.trim()) {
        Ok(req) => dispatch(req, &store, &visibility).await,
        Err(e) => AdminResponse::err(format!("invalid request: {e}")),
    };

    let mut out = match serde_json::to_string(&resp) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("admin: failed to serialize response: {e}");
            return;
        }
    };
    out.push('\n');

    if let Err(e) = writer.write_all(out.as_bytes()).await {
        tracing::warn!("admin: failed to write response: {e}");
    }
}

// ── Command dispatch ──────────────────────────────────────────────────────────

async fn dispatch(req: AdminRequest, store: &Store, visibility: &VisibilityLock) -> AdminResponse {
    match req {
        // ── Visibility ────────────────────────────────────────────────────────
        AdminRequest::VisibilityGet => {
            let v = *visibility.read().await;
            AdminResponse::ok(json!({"mode": v.to_string()}))
        }

        AdminRequest::VisibilitySet { mode } => {
            let vis: Visibility = match mode.parse() {
                Ok(v) => v,
                Err(e) => return AdminResponse::err(e.to_string()),
            };
            *visibility.write().await = vis;
            AdminResponse::ok(json!({"mode": vis.to_string()}))
        }

        // ── Keys ──────────────────────────────────────────────────────────────
        AdminRequest::KeysCreate {
            name,
            valid_after,
            valid_before,
            webhook_url,
        } => match store.create_key(&name, valid_after, valid_before, webhook_url) {
            Ok((record, token)) => AdminResponse::ok(json!({
                "id":         record.id,
                "name":       record.name,
                "token":      token,
                "created_at": record.created_at,
                "valid_after":  record.valid_after,
                "valid_before": record.valid_before,
                "webhook_url":  record.webhook_url,
            })),
            Err(e) => AdminResponse::err(e.to_string()),
        },

        AdminRequest::KeysList => match store.list_keys() {
            Ok(keys) => {
                let arr: Vec<Value> = keys
                    .into_iter()
                    .map(|k| {
                        json!({
                            "id":         k.id,
                            "name":       k.name,
                            "created_at": k.created_at,
                            "valid_after":  k.valid_after,
                            "valid_before": k.valid_before,
                            "webhook_url":  k.webhook_url,
                            // hash intentionally omitted
                        })
                    })
                    .collect();
                AdminResponse::ok(Value::Array(arr))
            }
            Err(e) => AdminResponse::err(e.to_string()),
        },

        AdminRequest::KeysDelete { name } => match store.delete_key(&name) {
            Ok(()) => AdminResponse::ok(json!({"deleted": name})),
            Err(e) => AdminResponse::err(e.to_string()),
        },

        AdminRequest::KeysSecrets { name } => {
            let key = match store.find_key_by_name(&name) {
                Ok(Some(k)) => k,
                Ok(None) => return AdminResponse::err(format!("key not found: {name}")),
                Err(e) => return AdminResponse::err(e.to_string()),
            };
            match store.secrets_owned_by(&key.id) {
                Ok((count, histogram)) => AdminResponse::ok(json!({
                    "key_name": name,
                    "active_count": count,
                    "prefix_histogram": histogram,
                })),
                Err(e) => AdminResponse::err(e.to_string()),
            }
        }

        AdminRequest::KeysPurge { name } => {
            let key = match store.find_key_by_name(&name) {
                Ok(Some(k)) => k,
                Ok(None) => return AdminResponse::err(format!("key not found: {name}")),
                Err(e) => return AdminResponse::err(e.to_string()),
            };
            match store.purge_secrets_for_key(&key.id) {
                Ok(count) => AdminResponse::ok(json!({"burned": count})),
                Err(e) => AdminResponse::err(e.to_string()),
            }
        }

        // ── Audit ─────────────────────────────────────────────────────────────
        AdminRequest::Audit {
            since,
            until,
            limit,
            key_name,
        } => {
            // If --key was provided, resolve name → key_id for filtering + unmasking.
            let owner_key_id = match &key_name {
                Some(name) => match store.find_key_by_name(name) {
                    Ok(Some(k)) => Some(k.id),
                    Ok(None) => return AdminResponse::err(format!("key not found: {name}")),
                    Err(e) => return AdminResponse::err(e.to_string()),
                },
                None => None,
            };

            let query = AuditQuery {
                since,
                until,
                limit: limit.unwrap_or(50),
                key_id: owner_key_id.clone(),
                ..Default::default()
            };
            match store.query_audit(&query) {
                Ok(events) => {
                    let unmask = owner_key_id.is_some();
                    let arr: Vec<Value> = events
                        .into_iter()
                        .map(|ev| {
                            json!({
                                "id":        ev.id,
                                "timestamp": ev.timestamp,
                                "action":    ev.action,
                                "key_id":    mask_optional(ev.key_id.as_deref(), unmask),
                                "hash":      mask_optional(ev.hash.as_deref(), unmask),
                                "source_ip": ev.source_ip,
                                "success":   ev.success,
                                "detail":    ev.detail,
                            })
                        })
                        .collect();
                    AdminResponse::ok(Value::Array(arr))
                }
                Err(e) => AdminResponse::err(e.to_string()),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mask_long_hash() {
        assert_eq!(mask_value("abcdef123456789xyz", false), "abcd…9xyz");
    }

    #[test]
    fn mask_short_string() {
        assert_eq!(mask_value("abc", false), "abc…");
    }

    #[test]
    fn mask_exactly_eight_chars() {
        assert_eq!(mask_value("12345678", false), "123…");
    }

    #[test]
    fn mask_nine_chars_shows_ends() {
        assert_eq!(mask_value("123456789", false), "1234…6789");
    }

    #[test]
    fn unmask_returns_full() {
        assert_eq!(mask_value("abcdef123456789xyz", true), "abcdef123456789xyz");
    }

    #[test]
    fn mask_optional_none_is_null() {
        assert_eq!(mask_optional(None, false), Value::Null);
        assert_eq!(mask_optional(None, true), Value::Null);
    }

    #[test]
    fn mask_optional_some_masks() {
        assert_eq!(
            mask_optional(Some("abcdef123456"), false),
            Value::String("abcd…3456".to_string())
        );
    }

    #[test]
    fn mask_optional_some_unmasks() {
        assert_eq!(
            mask_optional(Some("abcdef123456"), true),
            Value::String("abcdef123456".to_string())
        );
    }
}
