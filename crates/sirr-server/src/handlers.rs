use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::info;

use crate::{
    license::{LicenseStatus, FREE_TIER_LIMIT},
    AppState,
};

// ── Health ────────────────────────────────────────────────────────────────────

pub async fn health() -> impl IntoResponse {
    Json(json!({"status": "ok"}))
}

// ── List ──────────────────────────────────────────────────────────────────────

pub async fn list_secrets(State(state): State<AppState>) -> Response {
    match state.store.list() {
        Ok(metas) => {
            info!(count = metas.len(), "audit: secret.list");
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
}

#[derive(Debug, Serialize)]
pub struct CreateResponse {
    pub key: String,
}

pub async fn create_secret(
    State(state): State<AppState>,
    Json(body): Json<CreateRequest>,
) -> Response {
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
    if state.license == LicenseStatus::Free {
        match state.store.list() {
            Ok(metas) if metas.len() >= FREE_TIER_LIMIT => {
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
            Err(e) => return internal_error(e),
            _ => {}
        }
    }

    match state
        .store
        .put(&body.key, &body.value, body.ttl_seconds, body.max_reads)
    {
        Ok(()) => {
            info!(
                key = %body.key,
                ttl_seconds = ?body.ttl_seconds,
                max_reads = ?body.max_reads,
                "audit: secret.create"
            );
            (StatusCode::CREATED, Json(CreateResponse { key: body.key })).into_response()
        }
        Err(e) => internal_error(e),
    }
}

// ── Get ───────────────────────────────────────────────────────────────────────

pub async fn get_secret(State(state): State<AppState>, Path(key): Path<String>) -> Response {
    match state.store.get(&key) {
        Ok(Some(value)) => {
            info!(key = %key, "audit: secret.read");
            Json(json!({ "key": key, "value": value })).into_response()
        }
        Ok(None) => {
            info!(key = %key, "audit: secret.read.not_found");
            (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "not found or expired"})),
            )
                .into_response()
        }
        Err(e) => internal_error(e),
    }
}

// ── Delete ────────────────────────────────────────────────────────────────────

pub async fn delete_secret(State(state): State<AppState>, Path(key): Path<String>) -> Response {
    match state.store.delete(&key) {
        Ok(true) => {
            info!(key = %key, "audit: secret.delete");
            Json(json!({"deleted": true})).into_response()
        }
        Ok(false) => {
            info!(key = %key, "audit: secret.delete.not_found");
            (StatusCode::NOT_FOUND, Json(json!({"error": "not found"}))).into_response()
        }
        Err(e) => internal_error(e),
    }
}

// ── Prune ─────────────────────────────────────────────────────────────────────

pub async fn prune_secrets(State(state): State<AppState>) -> Response {
    match state.store.prune() {
        Ok(n) => {
            info!(pruned = n, "audit: secret.prune");
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
