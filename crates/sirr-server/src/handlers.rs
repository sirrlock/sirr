//! HTTP handlers for the Sirr secret API.
//!
//! Five endpoints over one resource:
//!   POST   /secret              — create
//!   GET    /secret/{hash}       — read value (consumes a read)
//!   HEAD   /secret/{hash}       — metadata only (does NOT consume a read)
//!   GET    /secret/{hash}/audit — audit trail (owner only)
//!   PATCH  /secret/{hash}       — update value (owner only)
//!   DELETE /secret/{hash}       — burn

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    extract::{Path, State},
    http::{HeaderMap, HeaderName, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::authz::{authorize, Action, AuthDecision, Caller};
use crate::store::audit::{
    AuditEvent, AuditQuery, ACTION_SECRET_BURN, ACTION_SECRET_CREATE, ACTION_SECRET_PATCH,
    ACTION_SECRET_READ,
};
use crate::store::crypto::EncryptionKey;
use crate::store::{SecretRecord, Store, Visibility};

// ── AppState ──────────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct AppState {
    pub store: Arc<Store>,
    pub encryption_key: Arc<EncryptionKey>,
    pub visibility: Arc<tokio::sync::RwLock<Visibility>>,
}

// ── Router ────────────────────────────────────────────────────────────────────

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/secret", post(create_secret))
        .route(
            "/secret/{hash}",
            get(read_secret)
                .head(inspect_secret)
                .patch(patch_secret)
                .delete(burn_secret),
        )
        .route("/secret/{hash}/audit", get(audit_secret))
        .with_state(state)
}

// ── Time helper ───────────────────────────────────────────────────────────────

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

// ── Bearer token extraction ───────────────────────────────────────────────────

/// Extract a `Caller` from the HTTP request headers.
///
/// Looks for `Authorization: Bearer <token>`. Any other scheme or a
/// malformed header silently falls back to `Caller::Anonymous` (not 400).
fn extract_caller(headers: &HeaderMap, store: &Store) -> Caller {
    let token = match extract_bearer_token(headers) {
        Some(t) => t,
        None => return Caller::Anonymous,
    };

    match store.find_key_by_token(&token) {
        Ok(Some(key)) => {
            // Only honour the key if it is within its validity window.
            if key.is_active(now_secs()) {
                Caller::Keyed(key)
            } else {
                Caller::Anonymous
            }
        }
        _ => Caller::Anonymous,
    }
}

/// Pull the bearer token string out of the Authorization header, if present
/// and correctly formed. Returns `None` for any other scheme or malformed input.
fn extract_bearer_token(headers: &HeaderMap) -> Option<String> {
    let value = headers.get(axum::http::header::AUTHORIZATION)?;
    let s = value.to_str().ok()?;
    let token = s.strip_prefix("Bearer ")?;
    if token.is_empty() {
        return None;
    }
    Some(token.to_string())
}

// ── Error response helpers ────────────────────────────────────────────────────

fn decision_to_response(decision: &AuthDecision) -> Response {
    match decision {
        AuthDecision::Allow => unreachable!("Allow should not be converted to an error response"),
        AuthDecision::Unauthorized => (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "authentication required"})),
        )
            .into_response(),
        AuthDecision::BadRequest(msg) => {
            (StatusCode::BAD_REQUEST, Json(json!({"error": msg}))).into_response()
        }
        AuthDecision::MethodNotAllowed => (
            StatusCode::METHOD_NOT_ALLOWED,
            Json(json!({"error": "method not allowed"})),
        )
            .into_response(),
        AuthDecision::NotFound => {
            (StatusCode::NOT_FOUND, Json(json!({"error": "not found"}))).into_response()
        }
        AuthDecision::Gone => {
            (StatusCode::GONE, Json(json!({"error": "secret is gone"}))).into_response()
        }
        AuthDecision::Unavailable => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": "server is in lockdown mode (visibility=none)"})),
        )
            .into_response(),
    }
}

// ── POST /secret ──────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct CreateRequest {
    pub value: String,
    pub ttl_seconds: Option<u64>,
    pub reads: Option<u32>,
    /// Optional short prefix prepended to the random hash. Must match [a-z0-9_-]{1,16}.
    pub prefix: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct CreateResponse {
    pub hash: String,
    pub url: String,
    pub expires_at: Option<i64>,
    pub reads_remaining: Option<u32>,
    pub owned: bool,
}

pub async fn create_secret(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<CreateRequest>,
) -> Response {
    let caller = extract_caller(&headers, &state.store);

    let visibility = *state.visibility.read().await;

    let now = now_secs();
    let decision = authorize(Action::Create, None, &caller, visibility, now);
    if decision != AuthDecision::Allow {
        return decision_to_response(&decision);
    }

    // Validate prefix if supplied.
    if let Some(ref prefix) = body.prefix {
        if !is_valid_prefix(prefix) {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "prefix must match [a-z0-9_-]{1,16}"})),
            )
                .into_response();
        }
    }

    // Generate hash: optional_prefix + 64 hex chars (32 random bytes).
    let mut random_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut random_bytes);
    let hash = format!(
        "{}{}",
        body.prefix.as_deref().unwrap_or(""),
        hex::encode(random_bytes)
    );

    // Encrypt the value.
    let (ciphertext, nonce) =
        match crate::store::crypto::encrypt(&state.encryption_key, body.value.as_bytes()) {
            Ok(pair) => pair,
            Err(e) => {
                tracing::error!("encryption failed: {e}");
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
        };

    let ttl_expires_at = body.ttl_seconds.map(|secs| now + secs as i64);
    let owner_key_id = match &caller {
        Caller::Keyed(key) => Some(key.id.clone()),
        Caller::Anonymous => None,
    };
    let owned = owner_key_id.is_some();

    let record = SecretRecord {
        hash: hash.clone(),
        value_ciphertext: ciphertext,
        nonce,
        created_at: now,
        ttl_expires_at,
        reads_remaining: body.reads,
        burned: false,
        burned_at: None,
        owner_key_id,
        created_by_ip: None, // IP extraction added in Phase 4 with ConnectInfo
    };

    if let Err(e) = state.store.create_secret(&record) {
        tracing::error!("failed to create secret: {e}");
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }

    // Record audit event.
    let key_id = match &caller {
        Caller::Keyed(k) => Some(k.id.clone()),
        Caller::Anonymous => None,
    };
    let event = AuditEvent::new(
        ACTION_SECRET_CREATE,
        key_id,
        Some(hash.clone()),
        String::new(),
        true,
        None,
    );
    let _ = state.store.record_audit(event);

    let url = format!("http://localhost:7843/secret/{hash}");
    (
        StatusCode::CREATED,
        Json(CreateResponse {
            hash,
            url,
            expires_at: ttl_expires_at,
            reads_remaining: body.reads,
            owned,
        }),
    )
        .into_response()
}

// ── GET /secret/{hash} ────────────────────────────────────────────────────────

pub async fn read_secret(
    State(state): State<AppState>,
    Path(hash): Path<String>,
    headers: HeaderMap,
) -> Response {
    let visibility = *state.visibility.read().await;

    if !visibility.allows_any_request() {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }

    let now = now_secs();

    match state.store.consume_read(&hash, now, &state.encryption_key) {
        Ok((plaintext, _burned)) => {
            // Record audit event for the successful read.
            let event = AuditEvent::new(
                ACTION_SECRET_READ,
                None,
                Some(hash.clone()),
                String::new(),
                true,
                None,
            );
            let _ = state.store.record_audit(event);

            // Decide response format based on Accept header.
            let wants_json = headers
                .get(axum::http::header::ACCEPT)
                .and_then(|v| v.to_str().ok())
                .map(|s| s.contains("application/json"))
                .unwrap_or(false);

            if wants_json {
                let value_str = String::from_utf8_lossy(&plaintext).into_owned();
                Json(json!({"value": value_str})).into_response()
            } else {
                let value_str = String::from_utf8_lossy(&plaintext).into_owned();
                (
                    StatusCode::OK,
                    [(
                        axum::http::header::CONTENT_TYPE,
                        "text/plain; charset=utf-8",
                    )],
                    value_str,
                )
                    .into_response()
            }
        }
        Err(crate::store::StoreError::NotFound)
        | Err(crate::store::StoreError::Burned)
        | Err(crate::store::StoreError::Expired) => StatusCode::GONE.into_response(),
        Err(e) => {
            tracing::error!("consume_read failed: {e}");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

// ── HEAD /secret/{hash} ───────────────────────────────────────────────────────

/// Metadata inspection. Does NOT consume a read.
pub async fn inspect_secret(State(state): State<AppState>, Path(hash): Path<String>) -> Response {
    let visibility = *state.visibility.read().await;

    if !visibility.allows_any_request() {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }

    let now = now_secs();

    let secret = match state.store.get_secret(&hash) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("get_secret failed: {e}");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    match secret {
        None => StatusCode::GONE.into_response(),
        Some(s) if s.burned || s.is_expired(now) => StatusCode::GONE.into_response(),
        Some(s) => {
            let mut response_headers = HeaderMap::new();

            // X-Sirr-Created
            let created_str = unix_to_rfc3339(s.created_at);
            if let Ok(v) = HeaderValue::from_str(&created_str) {
                response_headers.insert(HeaderName::from_static("x-sirr-created"), v);
            }

            // X-Sirr-TTL-Expires (if set)
            if let Some(exp) = s.ttl_expires_at {
                let exp_str = unix_to_rfc3339(exp);
                if let Ok(v) = HeaderValue::from_str(&exp_str) {
                    response_headers.insert(HeaderName::from_static("x-sirr-ttl-expires"), v);
                }
            }

            // X-Sirr-Reads-Remaining (if set)
            // Note: spec also calls this X-Sirr-Read-Count but we use reads_remaining.
            // Using reads_remaining as-is (YAGNI — no separate read_count field).
            if let Some(rem) = s.reads_remaining {
                if let Ok(v) = HeaderValue::from_str(&rem.to_string()) {
                    response_headers.insert(HeaderName::from_static("x-sirr-reads-remaining"), v);
                    // X-Sirr-Read-Count mirrors reads_remaining for now.
                    if let Ok(v2) = HeaderValue::from_str(&rem.to_string()) {
                        response_headers.insert(HeaderName::from_static("x-sirr-read-count"), v2);
                    }
                }
            }

            // X-Sirr-Owned
            let owned_str = if s.owner_key_id.is_some() {
                "true"
            } else {
                "false"
            };
            if let Ok(v) = HeaderValue::from_str(owned_str) {
                response_headers.insert(HeaderName::from_static("x-sirr-owned"), v);
            }

            (StatusCode::OK, response_headers).into_response()
        }
    }
}

// ── GET /secret/{hash}/audit ──────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct AuditEventResponse {
    #[serde(rename = "type")]
    pub event_type: String,
    pub at: i64,
    pub ip: String,
}

#[derive(Debug, Serialize)]
pub struct AuditResponse {
    pub hash: String,
    pub created_at: i64,
    pub events: Vec<AuditEventResponse>,
}

pub async fn audit_secret(
    State(state): State<AppState>,
    Path(hash): Path<String>,
    headers: HeaderMap,
) -> Response {
    let caller = extract_caller(&headers, &state.store);

    let visibility = *state.visibility.read().await;

    if !visibility.allows_any_request() {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }

    let now = now_secs();

    let secret = match state.store.get_secret(&hash) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("get_secret failed: {e}");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let decision = authorize(Action::Audit, secret.as_ref(), &caller, visibility, now);
    if decision != AuthDecision::Allow {
        return decision_to_response(&decision);
    }

    // secret is Some and caller is owner (guaranteed by authorize returning Allow).
    let secret = secret.unwrap();

    let query = AuditQuery {
        hash: Some(hash.clone()),
        limit: 0, // unlimited
        ..Default::default()
    };

    let events = match state.store.query_audit(&query) {
        Ok(evs) => evs,
        Err(e) => {
            tracing::error!("query_audit failed: {e}");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let event_responses: Vec<AuditEventResponse> = events
        .into_iter()
        .map(|ev| AuditEventResponse {
            event_type: ev.action,
            at: ev.timestamp,
            ip: ev.source_ip,
        })
        .collect();

    Json(AuditResponse {
        hash,
        created_at: secret.created_at,
        events: event_responses,
    })
    .into_response()
}

// ── PATCH /secret/{hash} ──────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct PatchRequest {
    pub value: String,
    pub ttl_seconds: Option<u64>,
    pub reads: Option<u32>,
}

pub async fn patch_secret(
    State(state): State<AppState>,
    Path(hash): Path<String>,
    headers: HeaderMap,
    Json(body): Json<PatchRequest>,
) -> Response {
    let caller = extract_caller(&headers, &state.store);

    let visibility = *state.visibility.read().await;

    if !visibility.allows_any_request() {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }

    let now = now_secs();

    let secret = match state.store.get_secret(&hash) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("get_secret failed: {e}");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let decision = authorize(Action::Patch, secret.as_ref(), &caller, visibility, now);
    if decision != AuthDecision::Allow {
        return decision_to_response(&decision);
    }

    // caller is Keyed and is owner (guaranteed by authorize returning Allow).
    let owner_key_id = match &caller {
        Caller::Keyed(k) => k.id.clone(),
        Caller::Anonymous => unreachable!("authorize returned Allow for anonymous patch"),
    };

    // Optional resets: ttl_seconds translates to an absolute timestamp.
    let new_ttl = body.ttl_seconds.map(|secs| now + secs as i64);
    let new_reads = body.reads;

    match state.store.patch_secret(
        &hash,
        body.value.as_bytes(),
        &owner_key_id,
        new_ttl,
        new_reads,
        &state.encryption_key,
    ) {
        Ok(updated) => {
            // Record audit event.
            let event = AuditEvent::new(
                ACTION_SECRET_PATCH,
                Some(owner_key_id),
                Some(hash),
                String::new(),
                true,
                None,
            );
            let _ = state.store.record_audit(event);

            let owned = updated.owner_key_id.is_some();
            let url = format!("http://localhost:7843/secret/{}", updated.hash);
            (
                StatusCode::OK,
                Json(CreateResponse {
                    hash: updated.hash,
                    url,
                    expires_at: updated.ttl_expires_at,
                    reads_remaining: updated.reads_remaining,
                    owned,
                }),
            )
                .into_response()
        }
        Err(crate::store::StoreError::NotFound) => StatusCode::NOT_FOUND.into_response(),
        Err(crate::store::StoreError::Burned) | Err(crate::store::StoreError::Expired) => {
            StatusCode::GONE.into_response()
        }
        Err(crate::store::StoreError::WrongOwner) => StatusCode::NOT_FOUND.into_response(),
        Err(e) => {
            tracing::error!("patch_secret failed: {e}");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

// ── DELETE /secret/{hash} ─────────────────────────────────────────────────────

pub async fn burn_secret(
    State(state): State<AppState>,
    Path(hash): Path<String>,
    headers: HeaderMap,
) -> Response {
    let caller = extract_caller(&headers, &state.store);

    let visibility = *state.visibility.read().await;

    if !visibility.allows_any_request() {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }

    let now = now_secs();

    let secret = match state.store.get_secret(&hash) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("get_secret failed: {e}");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let decision = authorize(Action::Burn, secret.as_ref(), &caller, visibility, now);
    if decision != AuthDecision::Allow {
        return decision_to_response(&decision);
    }

    // Determine the owner_key_id to pass to burn_secret (None for anonymous).
    let owner_key_id_opt = match &caller {
        Caller::Keyed(k) => Some(k.id.clone()),
        Caller::Anonymous => None, // anonymous secret — anyone can burn
    };

    match state
        .store
        .burn_secret(&hash, owner_key_id_opt.as_deref(), now)
    {
        Ok(()) => {
            let event = AuditEvent::new(
                ACTION_SECRET_BURN,
                owner_key_id_opt,
                Some(hash),
                String::new(),
                true,
                None,
            );
            let _ = state.store.record_audit(event);

            StatusCode::NO_CONTENT.into_response()
        }
        Err(crate::store::StoreError::NotFound) => StatusCode::NOT_FOUND.into_response(),
        Err(crate::store::StoreError::Burned) => StatusCode::GONE.into_response(),
        Err(crate::store::StoreError::WrongOwner) => StatusCode::NOT_FOUND.into_response(),
        Err(e) => {
            tracing::error!("burn_secret failed: {e}");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Validate a prefix: [a-z0-9_-]{1,16}.
fn is_valid_prefix(prefix: &str) -> bool {
    !prefix.is_empty()
        && prefix.len() <= 16
        && prefix
            .bytes()
            .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'_' | b'-'))
}

/// Format a unix timestamp as RFC 3339 (UTC). Falls back to epoch on overflow.
fn unix_to_rfc3339(unix_secs: i64) -> String {
    use std::time::{Duration, UNIX_EPOCH};
    let d = Duration::from_secs(unix_secs.max(0) as u64);
    let sys = UNIX_EPOCH + d;
    // Format manually: YYYY-MM-DDTHH:MM:SSZ using SystemTime arithmetic.
    // We use a simple approach: convert to seconds and format using time math.
    let total_secs = sys.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    seconds_to_rfc3339(total_secs)
}

fn seconds_to_rfc3339(secs: u64) -> String {
    // Compute date/time components from unix epoch.
    let s = secs % 60;
    let m = (secs / 60) % 60;
    let h = (secs / 3600) % 24;
    let days = secs / 86400;

    // Gregorian calendar computation.
    let (year, month, day) = days_to_date(days);

    format!("{year:04}-{month:02}-{day:02}T{h:02}:{m:02}:{s:02}Z")
}

fn days_to_date(days: u64) -> (u64, u64, u64) {
    // Days since 1970-01-01 to proleptic Gregorian date.
    // Uses the algorithm from https://howardhinnant.github.io/date_algorithms.html
    let z = days + 719468;
    let era = z / 146097;
    let doe = z % 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}
