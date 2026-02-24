use std::net::SocketAddr;

use axum::{
    extract::{ConnectInfo, Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::info;

use crate::{
    license::{LicenseStatus, FREE_TIER_LIMIT},
    store::{
        audit::{
            AuditEvent, ACTION_SECRET_BURNED, ACTION_SECRET_CREATE, ACTION_SECRET_DELETE,
            ACTION_SECRET_LIST, ACTION_SECRET_PATCH, ACTION_SECRET_PRUNE, ACTION_SECRET_READ,
        },
        AuditQuery, GetResult,
    },
    AppState,
};

// ── IP extraction ────────────────────────────────────────────────────────────

fn extract_ip(headers: &HeaderMap, addr: &SocketAddr) -> String {
    if let Some(xff) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
        if let Some(first) = xff.split(',').next() {
            let trimmed = first.trim();
            if !trimmed.is_empty() {
                return trimmed.to_owned();
            }
        }
    }
    if let Some(real_ip) = headers.get("x-real-ip").and_then(|v| v.to_str().ok()) {
        let trimmed = real_ip.trim();
        if !trimmed.is_empty() {
            return trimmed.to_owned();
        }
    }
    addr.ip().to_string()
}

// ── Health ────────────────────────────────────────────────────────────────────

pub async fn health() -> impl IntoResponse {
    Json(json!({"status": "ok"}))
}

// ── Audit query ──────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct AuditQueryParams {
    pub since: Option<i64>,
    pub until: Option<i64>,
    pub action: Option<String>,
    pub limit: Option<usize>,
}

pub async fn audit_events(
    State(state): State<AppState>,
    Query(params): Query<AuditQueryParams>,
) -> Response {
    let limit = params.limit.unwrap_or(100).min(1000);
    let query = AuditQuery {
        since: params.since,
        until: params.until,
        action: params.action,
        limit,
    };
    match state.store.list_audit(&query) {
        Ok(events) => Json(json!({ "events": events })).into_response(),
        Err(e) => internal_error(e),
    }
}

// ── List ──────────────────────────────────────────────────────────────────────

pub async fn list_secrets(
    State(state): State<AppState>,
    headers: HeaderMap,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> Response {
    let ip = extract_ip(&headers, &addr);
    match state.store.list() {
        Ok(metas) => {
            info!(count = metas.len(), "audit: secret.list");
            let _ = state.store.record_audit(AuditEvent::new(
                ACTION_SECRET_LIST,
                None,
                ip,
                true,
                Some(format!("count={}", metas.len())),
            ));
            Json(json!({ "secrets": metas })).into_response()
        }
        Err(e) => internal_error(e),
    }
}

// ── Create ────────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct CreateRequest {
    pub key: String,
    pub value: String,
    pub ttl_seconds: Option<u64>,
    pub max_reads: Option<u32>,
    pub delete: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct CreateResponse {
    pub key: String,
}

pub async fn create_secret(
    State(state): State<AppState>,
    headers: HeaderMap,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(body): Json<CreateRequest>,
) -> Response {
    let ip = extract_ip(&headers, &addr);

    if body.key.is_empty() || body.key.len() > 256 {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "key must be 1–256 characters"})),
        )
            .into_response();
    }
    if body.value.len() > 1_048_576 {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "value exceeds 1 MiB limit"})),
        )
            .into_response();
    }

    // License check: free tier capped at FREE_TIER_LIMIT active secrets.
    // Licensed users are validated online when exceeding the free tier threshold.
    match state.store.list() {
        Ok(metas) if metas.len() >= FREE_TIER_LIMIT => {
            if state.license == LicenseStatus::Free {
                let _ = state.store.record_audit(AuditEvent::new(
                    ACTION_SECRET_CREATE,
                    Some(body.key.clone()),
                    ip,
                    false,
                    Some("free tier limit reached".into()),
                ));
                return (
                    StatusCode::PAYMENT_REQUIRED,
                    Json(json!({
                        "error": format!(
                            "free tier limit of {FREE_TIER_LIMIT} secrets reached — \
                             add SIRR_LICENSE_KEY to continue. \
                             Get a license at https://secretdrop.app/sirr"
                        )
                    })),
                )
                    .into_response();
            }

            // Licensed — verify online if a validator is configured.
            if let Some(ref validator) = state.validator {
                if !validator.is_valid(&state.store).await {
                    let _ = state.store.record_audit(AuditEvent::new(
                        ACTION_SECRET_CREATE,
                        Some(body.key.clone()),
                        ip,
                        false,
                        Some("license validation failed".into()),
                    ));
                    return (
                        StatusCode::PAYMENT_REQUIRED,
                        Json(json!({
                            "error": "license validation failed — \
                                      please check your SIRR_LICENSE_KEY or contact support"
                        })),
                    )
                        .into_response();
                }
            }
        }
        Err(e) => return internal_error(e),
        _ => {}
    }

    match state
        .store
        .put(&body.key, &body.value, body.ttl_seconds, body.max_reads, body.delete.unwrap_or(true))
    {
        Ok(()) => {
            info!(
                key = %body.key,
                ttl_seconds = ?body.ttl_seconds,
                max_reads = ?body.max_reads,
                "audit: secret.create"
            );
            let _ = state.store.record_audit(AuditEvent::new(
                ACTION_SECRET_CREATE,
                Some(body.key.clone()),
                ip,
                true,
                None,
            ));
            (StatusCode::CREATED, Json(CreateResponse { key: body.key })).into_response()
        }
        Err(e) => internal_error(e),
    }
}

// ── Get ───────────────────────────────────────────────────────────────────────

pub async fn get_secret(
    State(state): State<AppState>,
    headers: HeaderMap,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Path(key): Path<String>,
) -> Response {
    let ip = extract_ip(&headers, &addr);
    match state.store.get(&key) {
        Ok(GetResult::Value(value)) => {
            let _ = state.store.record_audit(AuditEvent::new(
                ACTION_SECRET_READ,
                Some(key.clone()),
                ip,
                true,
                None,
            ));
            Json(json!({ "key": key, "value": value })).into_response()
        }
        Ok(GetResult::Burned(value)) => {
            let _ = state.store.record_audit(AuditEvent::new(
                ACTION_SECRET_BURNED,
                Some(key.clone()),
                ip,
                true,
                None,
            ));
            Json(json!({ "key": key, "value": value })).into_response()
        }
        Ok(GetResult::Sealed) => {
            let _ = state.store.record_audit(AuditEvent::new(
                ACTION_SECRET_READ,
                Some(key.clone()),
                ip,
                false,
                Some("sealed".into()),
            ));
            (
                StatusCode::GONE,
                Json(json!({"error": "secret is sealed — reads exhausted"})),
            )
                .into_response()
        }
        Ok(GetResult::NotFound) => {
            let _ = state.store.record_audit(AuditEvent::new(
                ACTION_SECRET_READ,
                Some(key.clone()),
                ip,
                false,
                Some("not found or expired".into()),
            ));
            (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "not found or expired"})),
            )
                .into_response()
        }
        Err(e) => internal_error(e),
    }
}

// ── Head ──────────────────────────────────────────────────────────────────────

pub async fn head_secret(
    State(state): State<AppState>,
    headers: HeaderMap,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Path(key): Path<String>,
) -> Response {
    let ip = extract_ip(&headers, &addr);
    match state.store.head(&key) {
        Ok(Some((meta, sealed))) => {
            let detail = if sealed { "head;sealed" } else { "head" };
            let _ = state.store.record_audit(AuditEvent::new(
                ACTION_SECRET_READ,
                Some(key.clone()),
                ip,
                true,
                Some(detail.into()),
            ));

            let status = if sealed {
                StatusCode::GONE
            } else {
                StatusCode::OK
            };

            let reads_remaining = match meta.max_reads {
                Some(max) => (max.saturating_sub(meta.read_count)).to_string(),
                None => "unlimited".to_string(),
            };

            let mut builder = Response::builder()
                .status(status)
                .header("X-Sirr-Read-Count", meta.read_count.to_string())
                .header("X-Sirr-Reads-Remaining", reads_remaining)
                .header("X-Sirr-Delete", meta.delete.to_string())
                .header("X-Sirr-Created-At", meta.created_at.to_string());

            if let Some(exp) = meta.expires_at {
                builder = builder.header("X-Sirr-Expires-At", exp.to_string());
            }

            if sealed {
                builder = builder.header("X-Sirr-Status", "sealed");
            } else {
                builder = builder.header("X-Sirr-Status", "active");
            }

            builder.body(axum::body::Body::empty()).unwrap()
        }
        Ok(None) => {
            let _ = state.store.record_audit(AuditEvent::new(
                ACTION_SECRET_READ,
                Some(key.clone()),
                ip,
                false,
                Some("head;not found or expired".into()),
            ));
            (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "not found or expired"})),
            )
                .into_response()
        }
        Err(e) => internal_error(e),
    }
}

// ── Patch ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct PatchRequest {
    pub value: Option<String>,
    pub max_reads: Option<u32>,
    pub ttl_seconds: Option<u64>,
}

pub async fn patch_secret(
    State(state): State<AppState>,
    headers: HeaderMap,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Path(key): Path<String>,
    Json(body): Json<PatchRequest>,
) -> Response {
    let ip = extract_ip(&headers, &addr);

    if let Some(ref v) = body.value {
        if v.len() > 1_048_576 {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "value exceeds 1 MiB limit"})),
            )
                .into_response();
        }
    }

    match state.store.patch(
        &key,
        body.value.as_deref(),
        body.max_reads,
        body.ttl_seconds,
    ) {
        Ok(Some(meta)) => {
            let _ = state.store.record_audit(AuditEvent::new(
                ACTION_SECRET_PATCH,
                Some(key.clone()),
                ip,
                true,
                None,
            ));
            Json(meta).into_response()
        }
        Ok(None) => {
            let _ = state.store.record_audit(AuditEvent::new(
                ACTION_SECRET_PATCH,
                Some(key.clone()),
                ip,
                false,
                Some("not found or expired".into()),
            ));
            (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "not found or expired"})),
            )
                .into_response()
        }
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("cannot patch") {
                let _ = state.store.record_audit(AuditEvent::new(
                    ACTION_SECRET_PATCH,
                    Some(key.clone()),
                    ip,
                    false,
                    Some("conflict: delete=true".into()),
                ));
                (
                    StatusCode::CONFLICT,
                    Json(json!({"error": msg})),
                )
                    .into_response()
            } else {
                internal_error(e)
            }
        }
    }
}

// ── Delete ────────────────────────────────────────────────────────────────────

pub async fn delete_secret(
    State(state): State<AppState>,
    headers: HeaderMap,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Path(key): Path<String>,
) -> Response {
    let ip = extract_ip(&headers, &addr);
    match state.store.delete(&key) {
        Ok(true) => {
            info!(key = %key, "audit: secret.delete");
            let _ = state.store.record_audit(AuditEvent::new(
                ACTION_SECRET_DELETE,
                Some(key.clone()),
                ip,
                true,
                None,
            ));
            Json(json!({"deleted": true})).into_response()
        }
        Ok(false) => {
            info!(key = %key, "audit: secret.delete.not_found");
            let _ = state.store.record_audit(AuditEvent::new(
                ACTION_SECRET_DELETE,
                Some(key.clone()),
                ip,
                false,
                Some("not found".into()),
            ));
            (StatusCode::NOT_FOUND, Json(json!({"error": "not found"}))).into_response()
        }
        Err(e) => internal_error(e),
    }
}

// ── Prune ─────────────────────────────────────────────────────────────────────

pub async fn prune_secrets(
    State(state): State<AppState>,
    headers: HeaderMap,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> Response {
    let ip = extract_ip(&headers, &addr);
    match state.store.prune() {
        Ok(n) => {
            info!(pruned = n, "audit: secret.prune");
            let _ = state.store.record_audit(AuditEvent::new(
                ACTION_SECRET_PRUNE,
                None,
                ip,
                true,
                Some(format!("pruned={n}")),
            ));
            Json(json!({"pruned": n})).into_response()
        }
        Err(e) => internal_error(e),
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn internal_error(e: anyhow::Error) -> Response {
    tracing::error!(error = %e, "internal error");
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({"error": "internal server error"})),
    )
        .into_response()
}
