use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use constant_time_eq::constant_time_eq;
use serde_json::json;

use crate::store::api_keys::{hash_key, Permission};
use crate::AppState;

/// Resolved permissions for the current request, inserted into request extensions.
#[derive(Debug, Clone)]
pub struct ResolvedPermissions {
    pub permissions: Vec<Permission>,
    pub prefix: Option<String>,
    /// True when authenticated via the root SIRR_API_KEY (full admin).
    pub is_admin: bool,
}

impl ResolvedPermissions {
    pub fn full_admin() -> Self {
        Self {
            permissions: vec![],
            prefix: None,
            is_admin: true,
        }
    }

    pub fn can_read(&self) -> bool {
        self.is_admin
            || self
                .permissions
                .iter()
                .any(|p| matches!(p, Permission::Read | Permission::Admin))
    }

    pub fn can_write(&self) -> bool {
        self.is_admin
            || self
                .permissions
                .iter()
                .any(|p| matches!(p, Permission::Write | Permission::Admin))
    }

    pub fn can_delete(&self) -> bool {
        self.is_admin
            || self
                .permissions
                .iter()
                .any(|p| matches!(p, Permission::Delete | Permission::Admin))
    }

    pub fn can_admin(&self) -> bool {
        self.is_admin
            || self
                .permissions
                .iter()
                .any(|p| matches!(p, Permission::Admin))
    }

    /// Check if the given secret key matches this key's prefix scope.
    pub fn matches_prefix(&self, key: &str) -> bool {
        self.is_admin
            || match &self.prefix {
                None => true,
                Some(p) => key.starts_with(p.as_str()),
            }
    }
}

/// Axum middleware that validates authentication and resolves permissions.
///
/// Auth flow:
/// 1. No SIRR_API_KEY configured AND no stored scoped keys → open mode (full admin)
/// 2. Extract Bearer token from Authorization header
/// 3. Check against SIRR_API_KEY (constant-time) → full admin
/// 4. Hash token, look up in store → scoped permissions
/// 5. Not found → 401
pub async fn require_api_key(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Response {
    let has_admin_key = state.api_key.is_some();
    let has_scoped_keys = state.store.has_api_keys().unwrap_or(false);

    // Open mode: no auth configured at all.
    if !has_admin_key && !has_scoped_keys {
        request
            .extensions_mut()
            .insert(ResolvedPermissions::full_admin());
        return next.run(request).await;
    }

    let token = request
        .headers()
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));

    let Some(token) = token else {
        return unauthorized();
    };

    // Check against root admin key first (constant-time).
    if let Some(ref expected) = state.api_key {
        if constant_time_eq(token.as_bytes(), expected.as_bytes()) {
            request
                .extensions_mut()
                .insert(ResolvedPermissions::full_admin());
            return next.run(request).await;
        }
    }

    // Check against scoped API keys.
    let token_hash = hash_key(token);
    match state.store.find_api_key_by_hash(&token_hash) {
        Ok(Some(record)) => {
            let perms = ResolvedPermissions {
                permissions: record.permissions,
                prefix: record.prefix,
                is_admin: false,
            };
            request.extensions_mut().insert(perms);
            next.run(request).await
        }
        _ => unauthorized(),
    }
}

fn unauthorized() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(json!({"error": "unauthorized — valid API key required for this endpoint"})),
    )
        .into_response()
}
