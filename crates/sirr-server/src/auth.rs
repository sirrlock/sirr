use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use constant_time_eq::constant_time_eq;
use serde_json::json;

use crate::AppState;

/// Axum middleware that validates `Authorization: Bearer <token>`.
pub async fn require_auth(State(state): State<AppState>, request: Request, next: Next) -> Response {
    let token = request
        .headers()
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));

    match token {
        Some(t) if constant_time_eq(t.as_bytes(), state.master_key.as_bytes()) => {
            next.run(request).await
        }
        _ => (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "unauthorized"})),
        )
            .into_response(),
    }
}
