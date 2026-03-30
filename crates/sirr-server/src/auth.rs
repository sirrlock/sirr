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

// ── ResolvedAuth ────────────────────────────────────────────────────────────

use crate::store::permissions::{PermBit, Permissions};

/// Authenticated identity for the current request.
///
/// During the transition period both `ResolvedPermissions` (old) and
/// `ResolvedAuth` (new) may coexist in request extensions. Handlers being
/// migrated will switch to extracting `ResolvedAuth`.
#[derive(Debug, Clone)]
pub enum ResolvedAuth {
    /// Authenticated via the root `SIRR_MASTER_API_KEY`. Has no org/principal
    /// context — used for instance-wide admin operations.
    Master,
    /// Authenticated via a principal key. Carries the resolved identity
    /// and the permission bitflag from the principal's role.
    Principal {
        principal_id: String,
        org_id: String,
        key_id: String,
        key_name: String,
        permissions: Permissions,
    },
}

impl ResolvedAuth {
    // ── identity helpers ──

    pub fn is_master(&self) -> bool {
        matches!(self, Self::Master)
    }

    pub fn org_id(&self) -> Option<&str> {
        match self {
            Self::Master => None,
            Self::Principal { org_id, .. } => Some(org_id.as_str()),
        }
    }

    pub fn principal_id(&self) -> Option<&str> {
        match self {
            Self::Master => None,
            Self::Principal { principal_id, .. } => Some(principal_id.as_str()),
        }
    }

    pub fn key_name(&self) -> Option<&str> {
        match self {
            Self::Master => None,
            Self::Principal { key_name, .. } => Some(key_name.as_str()),
        }
    }

    // ── permission checks ──

    /// Master only has SirrAdmin; principals delegate to their role permissions.
    pub fn has(&self, bit: PermBit) -> bool {
        match self {
            Self::Master => bit == PermBit::SirrAdmin,
            Self::Principal { permissions, .. } => permissions.has(bit),
        }
    }

    pub fn can_read_my(&self) -> bool {
        self.has(PermBit::ReadMy)
    }
    pub fn can_read_org(&self) -> bool {
        self.has(PermBit::ReadOrg)
    }
    pub fn can_list_my(&self) -> bool {
        self.has(PermBit::ListMy)
    }
    pub fn can_list_org(&self) -> bool {
        self.has(PermBit::ListOrg)
    }
    pub fn can_create(&self) -> bool {
        self.has(PermBit::Create)
    }
    pub fn can_create_on_behalf(&self) -> bool {
        self.has(PermBit::CreateOnBehalf)
    }
    pub fn can_patch_my(&self) -> bool {
        self.has(PermBit::PatchMy)
    }
    pub fn can_patch_org(&self) -> bool {
        self.has(PermBit::PatchOrg)
    }
    pub fn can_account_read(&self) -> bool {
        self.has(PermBit::AccountRead)
    }
    pub fn can_account_read_org(&self) -> bool {
        self.has(PermBit::AccountReadOrg)
    }
    pub fn can_account_manage(&self) -> bool {
        self.has(PermBit::AccountManage)
    }
    pub fn can_manage_org(&self) -> bool {
        self.has(PermBit::ManageOrg)
    }
    pub fn can_sirr_admin(&self) -> bool {
        self.has(PermBit::SirrAdmin)
    }
    pub fn can_delete_my(&self) -> bool {
        self.has(PermBit::DeleteMy)
    }
    pub fn can_delete_org(&self) -> bool {
        self.has(PermBit::DeleteOrg)
    }

    /// Check if the caller can access a secret owned by `secret_owner_id`.
    ///
    /// Returns `true` if the caller owns the secret (checked via `my_bit`) or
    /// has org-wide access (checked via `org_bit`).
    /// Master always returns `false` — master key has no org/principal context.
    pub fn can_access_secret(
        &self,
        secret_owner_id: Option<&str>,
        my_bit: PermBit,
        org_bit: PermBit,
    ) -> bool {
        match self {
            Self::Master => false,
            Self::Principal {
                principal_id,
                permissions,
                ..
            } => {
                if permissions.has(org_bit) {
                    return true;
                }
                if permissions.has(my_bit) {
                    if let Some(owner) = secret_owner_id {
                        return owner == principal_id.as_str();
                    }
                }
                false
            }
        }
    }
}

fn unauthorized() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(json!({"error": "unauthorized — valid API key required for this endpoint"})),
    )
        .into_response()
}

/// Axum middleware that resolves a `ResolvedAuth` from the request.
///
/// Auth flow:
/// 1. Extract Bearer token from Authorization header
/// 2. Check against SIRR_MASTER_API_KEY (constant-time) → `ResolvedAuth::Master`
/// 3. SHA-256 hash the token, look up in `find_principal_key_by_hash()`
/// 4. Validate `valid_after` / `valid_before` window
/// 5. Resolve principal → role → permissions
/// 6. Insert `ResolvedAuth::Principal` as extension
/// 7. No SIRR_MASTER_API_KEY and no keys at all → open mode (Master)
pub async fn require_auth(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Response {
    let has_admin_key = state.api_key.is_some();

    // Extract Bearer token.
    let token = request
        .headers()
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));

    // Open mode: no admin key configured and no token provided.
    if !has_admin_key && token.is_none() {
        request.extensions_mut().insert(ResolvedAuth::Master);
        return next.run(request).await;
    }

    let Some(token) = token else {
        return unauthorized();
    };

    // Check against root admin key first (constant-time).
    if let Some(ref expected) = state.api_key {
        if constant_time_eq(token.as_bytes(), expected.as_bytes()) {
            request.extensions_mut().insert(ResolvedAuth::Master);
            return next.run(request).await;
        }
    }

    // Check against principal keys (SHA-256 hash lookup).
    let token_hash = {
        use sha2::{Digest, Sha256};
        Sha256::digest(token.as_bytes()).to_vec()
    };

    if let Ok(Some(key_record)) = state.store.find_principal_key_by_hash(&token_hash) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        // Validate time window.
        if now < key_record.valid_after || now >= key_record.valid_before {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "principal key expired or not yet valid"})),
            )
                .into_response();
        }

        // Resolve principal → role → permissions.
        let principal = match state
            .store
            .get_principal(&key_record.org_id, &key_record.principal_id)
        {
            Ok(Some(p)) => p,
            _ => {
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(json!({"error": "principal not found for key"})),
                )
                    .into_response();
            }
        };

        // Look up role: try org-scoped first, then built-in.
        let permissions = match state
            .store
            .get_role(Some(&key_record.org_id), &principal.role)
        {
            Ok(Some(role)) => role.permissions,
            _ => {
                // Fallback to built-in role.
                match state.store.get_role(None, &principal.role) {
                    Ok(Some(role)) => role.permissions,
                    _ => {
                        return (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            Json(json!({"error": "role not found for principal"})),
                        )
                            .into_response();
                    }
                }
            }
        };

        request.extensions_mut().insert(ResolvedAuth::Principal {
            principal_id: key_record.principal_id.clone(),
            org_id: key_record.org_id.clone(),
            key_id: key_record.id.clone(),
            key_name: key_record.name.clone(),
            permissions,
        });
        return next.run(request).await;
    }

    unauthorized()
}

/// Axum middleware that only accepts the root `SIRR_MASTER_API_KEY`.
///
/// Produces `ResolvedAuth::Master`. Keeps open-mode behavior: if no key
/// is configured, all requests are allowed through as Master.
pub async fn require_master_key(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Response {
    // Open mode: no admin key configured.
    if state.api_key.is_none() {
        request.extensions_mut().insert(ResolvedAuth::Master);
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

    if let Some(ref expected) = state.api_key {
        if constant_time_eq(token.as_bytes(), expected.as_bytes()) {
            request.extensions_mut().insert(ResolvedAuth::Master);
            return next.run(request).await;
        }
    }

    unauthorized()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolved_auth_master_has_no_secret_perms() {
        let auth = ResolvedAuth::Master;
        assert!(auth.is_master());
        assert!(auth.can_sirr_admin());
        // Master should NOT have secret-level permissions.
        assert!(!auth.can_read_my());
        assert!(!auth.can_read_org());
        assert!(!auth.can_create());
        assert!(!auth.can_list_my());
        assert!(!auth.can_list_org());
        assert!(!auth.can_delete_my());
        assert!(!auth.can_delete_org());
        assert!(!auth.can_patch_my());
        assert!(!auth.can_patch_org());
        assert!(!auth.can_manage_org());
        // org_id / principal_id are None for master.
        assert!(auth.org_id().is_none());
        assert!(auth.principal_id().is_none());
        assert!(auth.key_name().is_none());
        // can_access_secret always false for master.
        assert!(!auth.can_access_secret(Some("p1"), PermBit::ReadMy, PermBit::ReadOrg));
    }

    #[test]
    fn resolved_auth_principal_checks() {
        let writer_perms = Permissions::parse("rlcpdam").unwrap();
        let auth = ResolvedAuth::Principal {
            principal_id: "p_1".into(),
            org_id: "org_1".into(),
            key_id: "pk_1".into(),
            key_name: "default".into(),
            permissions: writer_perms,
        };

        assert!(!auth.is_master());
        assert_eq!(auth.org_id(), Some("org_1"));
        assert_eq!(auth.principal_id(), Some("p_1"));
        assert_eq!(auth.key_name(), Some("default"));

        // writer has: r, l, c, p, d, a, m
        assert!(auth.can_read_my());
        assert!(auth.can_list_my());
        assert!(auth.can_create());
        assert!(auth.can_patch_my());
        assert!(auth.can_delete_my());
        assert!(auth.can_account_read());
        assert!(auth.can_account_manage());

        // writer does NOT have: R, L, C, P, M, S, D
        assert!(!auth.can_read_org());
        assert!(!auth.can_list_org());
        assert!(!auth.can_create_on_behalf());
        assert!(!auth.can_patch_org());
        assert!(!auth.can_manage_org());
        assert!(!auth.can_sirr_admin());
        assert!(!auth.can_delete_org());

        // can_access_secret: owns the secret
        assert!(auth.can_access_secret(Some("p_1"), PermBit::ReadMy, PermBit::ReadOrg));
        // can_access_secret: doesn't own, no org-wide read
        assert!(!auth.can_access_secret(Some("p_2"), PermBit::ReadMy, PermBit::ReadOrg));
        // can_access_secret: no owner on secret
        assert!(!auth.can_access_secret(None, PermBit::ReadMy, PermBit::ReadOrg));
    }

    #[test]
    fn resolved_auth_admin_has_org_access() {
        let admin_perms = Permissions::parse("rRlLcCpPaAmMdD").unwrap();
        let auth = ResolvedAuth::Principal {
            principal_id: "p_admin".into(),
            org_id: "org_1".into(),
            key_id: "pk_admin".into(),
            key_name: "admin-key".into(),
            permissions: admin_perms,
        };

        // Admin can access any org secret regardless of ownership.
        assert!(auth.can_access_secret(Some("p_other"), PermBit::ReadMy, PermBit::ReadOrg));
        assert!(auth.can_access_secret(None, PermBit::ReadMy, PermBit::ReadOrg));
        assert!(auth.can_read_org());
        assert!(auth.can_list_org());
        assert!(auth.can_delete_org());
        assert!(auth.can_patch_org());
        assert!(auth.can_manage_org());
        // Admin does NOT have SirrAdmin.
        assert!(!auth.can_sirr_admin());
    }
}
