use std::collections::HashMap;
use std::net::SocketAddr;

use axum::{
    extract::{ConnectInfo, Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Extension, Json,
};
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use tracing::info;

use crate::{
    auth::ResolvedAuth,
    license,
    store::{
        audit::{
            AuditEvent, ACTION_KEY_CREATE, ACTION_KEY_DELETE, ACTION_ORG_CREATE, ACTION_ORG_DELETE,
            ACTION_PRINCIPAL_CREATE, ACTION_PRINCIPAL_DELETE, ACTION_ROLE_CREATE,
            ACTION_ROLE_DELETE, ACTION_SECRET_BURNED, ACTION_SECRET_CREATE, ACTION_SECRET_DELETE,
            ACTION_SECRET_LIST, ACTION_SECRET_PATCH, ACTION_SECRET_PRUNE, ACTION_SECRET_READ,
            ACTION_WEBHOOK_CREATE, ACTION_WEBHOOK_DELETE,
        },
        org::{validate_metadata, OrgRecord, PrincipalKeyRecord, PrincipalRecord, RoleRecord},
        permissions::{PermBit, Permissions},
        AuditQuery, GetResult,
    },
    webhooks::{self, MAX_WEBHOOKS},
    AppState,
};

// ── Constants ─────────────────────────────────────────────────────────────────

const MAX_TTL_SECS: u64 = 315_360_000;

// ── Shared helpers ──────────────────────────────────────────────────────────

fn forbidden() -> Response {
    (
        StatusCode::FORBIDDEN,
        Json(json!({"error": "insufficient permissions"})),
    )
        .into_response()
}

fn internal_error(e: anyhow::Error) -> Response {
    tracing::error!(error = %e, "internal error");
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({"error": "internal server error"})),
    )
        .into_response()
}

fn not_found(msg: &str) -> Response {
    (StatusCode::NOT_FOUND, Json(json!({"error": msg}))).into_response()
}

fn bad_request(msg: &str) -> Response {
    (StatusCode::BAD_REQUEST, Json(json!({"error": msg}))).into_response()
}

fn validate_key_name(key: &str) -> bool {
    !key.is_empty()
        && key.len() <= 256
        && key
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
}

fn bad_key_name() -> Response {
    bad_request("key must be 1-256 characters: alphanumeric, -, _, . only")
}

fn extract_ip(headers: &HeaderMap, addr: &SocketAddr, trusted_proxies: &[ipnet::IpNet]) -> String {
    let peer = addr.ip();
    if !trusted_proxies.is_empty() && trusted_proxies.iter().any(|net| net.contains(&peer)) {
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
    }
    peer.to_string()
}

fn now_epoch() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

fn generate_id() -> String {
    format!("{:032x}", rand::random::<u128>())
}

// ── Org CRUD ────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct CreateOrgRequest {
    pub name: String,
    #[serde(default)]
    pub metadata: HashMap<String, String>,
}

pub async fn create_org(
    State(state): State<AppState>,
    Extension(auth): Extension<ResolvedAuth>,
    headers: HeaderMap,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(body): Json<CreateOrgRequest>,
) -> Response {
    if !auth.is_master() && !auth.can_sirr_admin() {
        return forbidden();
    }

    if body.name.is_empty() || body.name.len() > 128 {
        return bad_request("name must be 1-128 characters");
    }

    if let Err(e) = validate_metadata(&body.metadata) {
        return bad_request(&e);
    }

    // License tier check: enforce max orgs.
    let tier = license::effective_tier(&state.license);
    if let Some(max) = tier.max_orgs() {
        match state.store.list_orgs() {
            Ok(orgs) if orgs.len() >= max => {
                return (
                    StatusCode::PAYMENT_REQUIRED,
                    Json(json!({
                        "error": format!(
                            "tier limit: max {max} org(s) — upgrade at https://sirrlock.com/pricing"
                        )
                    })),
                )
                    .into_response();
            }
            Err(e) => return internal_error(e),
            _ => {}
        }
    }

    let ip = extract_ip(&headers, &addr, &state.trusted_proxies);
    let id = generate_id();

    let org = OrgRecord {
        id: id.clone(),
        name: body.name.clone(),
        metadata: body.metadata,
        created_at: now_epoch(),
    };

    match state.store.put_org(&org) {
        Ok(()) => {
            info!(org_id = %id, name = %body.name, "audit: org.create");
            let _ = state.store.record_audit(AuditEvent::new(
                ACTION_ORG_CREATE,
                None,
                ip,
                true,
                Some(format!("org_id={id}")),
                Some(id.clone()),
                auth.principal_id().map(|s| s.to_owned()),
            ));
            (
                StatusCode::CREATED,
                Json(json!({"id": id, "name": org.name})),
            )
                .into_response()
        }
        Err(e) => internal_error(e),
    }
}

pub async fn list_orgs(
    State(state): State<AppState>,
    Extension(auth): Extension<ResolvedAuth>,
) -> Response {
    if !auth.is_master() {
        return forbidden();
    }

    match state.store.list_orgs() {
        Ok(orgs) => Json(json!({"orgs": orgs})).into_response(),
        Err(e) => internal_error(e),
    }
}

pub async fn delete_org(
    State(state): State<AppState>,
    Extension(auth): Extension<ResolvedAuth>,
    headers: HeaderMap,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Path(org_id): Path<String>,
) -> Response {
    if !auth.is_master() {
        return forbidden();
    }

    let ip = extract_ip(&headers, &addr, &state.trusted_proxies);

    match state.store.delete_org(&org_id) {
        Ok(true) => {
            info!(org_id = %org_id, "audit: org.delete");
            let _ = state.store.record_audit(AuditEvent::new(
                ACTION_ORG_DELETE,
                None,
                ip,
                true,
                Some(format!("org_id={org_id}")),
                Some(org_id),
                auth.principal_id().map(|s| s.to_owned()),
            ));
            Json(json!({"deleted": true})).into_response()
        }
        Ok(false) => not_found("org not found"),
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("still has principals") {
                (StatusCode::CONFLICT, Json(json!({"error": msg}))).into_response()
            } else {
                internal_error(e)
            }
        }
    }
}

// ── Principal CRUD ──────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct CreatePrincipalRequest {
    pub name: String,
    pub role: String,
    #[serde(default)]
    pub metadata: HashMap<String, String>,
}

pub async fn create_principal(
    State(state): State<AppState>,
    Extension(auth): Extension<ResolvedAuth>,
    headers: HeaderMap,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Path(org_id): Path<String>,
    Json(body): Json<CreatePrincipalRequest>,
) -> Response {
    if !(auth.is_master() || auth.can_manage_org() && auth.org_id() == Some(&org_id)) {
        return forbidden();
    }

    if body.name.is_empty() || body.name.len() > 128 {
        return bad_request("name must be 1-128 characters");
    }

    if let Err(e) = validate_metadata(&body.metadata) {
        return bad_request(&e);
    }

    // Verify the org exists.
    match state.store.get_org(&org_id) {
        Ok(None) => return not_found("org not found"),
        Err(e) => return internal_error(e),
        Ok(Some(_)) => {}
    }

    // Validate role exists: check org-specific first, then built-in.
    let role_exists = match state.store.get_role(Some(&org_id), &body.role) {
        Ok(Some(_)) => true,
        Ok(None) => matches!(state.store.get_role(None, &body.role), Ok(Some(_))),
        Err(e) => return internal_error(e),
    };

    if !role_exists {
        return bad_request(&format!("role \"{}\" not found", body.role));
    }

    // License tier check: enforce max principals per org.
    let tier = license::effective_tier(&state.license);
    if let Some(max) = tier.max_principals_per_org() {
        match state.store.list_principals(&org_id) {
            Ok(principals) if principals.len() >= max => {
                return (
                    StatusCode::PAYMENT_REQUIRED,
                    Json(json!({
                        "error": format!(
                            "tier limit: max {max} principal(s) per org — upgrade at https://sirrlock.com/pricing"
                        )
                    })),
                )
                    .into_response();
            }
            Err(e) => return internal_error(e),
            _ => {}
        }
    }

    let ip = extract_ip(&headers, &addr, &state.trusted_proxies);
    let id = generate_id();

    let principal = PrincipalRecord {
        id: id.clone(),
        org_id: org_id.clone(),
        name: body.name.clone(),
        role: body.role.clone(),
        metadata: body.metadata,
        created_at: now_epoch(),
    };

    match state.store.put_principal(&principal) {
        Ok(()) => {
            info!(principal_id = %id, org_id = %org_id, "audit: principal.create");
            let _ = state.store.record_audit(AuditEvent::new(
                ACTION_PRINCIPAL_CREATE,
                None,
                ip,
                true,
                Some(format!("principal_id={id}")),
                Some(org_id.clone()),
                auth.principal_id().map(|s| s.to_owned()),
            ));
            (
                StatusCode::CREATED,
                Json(json!({
                    "id": id,
                    "name": principal.name,
                    "role": principal.role,
                    "org_id": org_id,
                })),
            )
                .into_response()
        }
        Err(e) => internal_error(e),
    }
}

pub async fn list_principals(
    State(state): State<AppState>,
    Extension(auth): Extension<ResolvedAuth>,
    Path(org_id): Path<String>,
) -> Response {
    if !(auth.is_master() || auth.can_account_read_org() && auth.org_id() == Some(&org_id)) {
        return forbidden();
    }

    match state.store.list_principals(&org_id) {
        Ok(principals) => {
            let result: Vec<_> = principals
                .iter()
                .map(|p| {
                    json!({
                        "id": p.id,
                        "name": p.name,
                        "role": p.role,
                        "org_id": p.org_id,
                        "metadata": p.metadata,
                        "created_at": p.created_at,
                    })
                })
                .collect();
            Json(json!({"principals": result})).into_response()
        }
        Err(e) => internal_error(e),
    }
}

pub async fn delete_principal(
    State(state): State<AppState>,
    Extension(auth): Extension<ResolvedAuth>,
    headers: HeaderMap,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Path((org_id, id)): Path<(String, String)>,
) -> Response {
    if !(auth.is_master() || auth.can_manage_org() && auth.org_id() == Some(&org_id)) {
        return forbidden();
    }

    let ip = extract_ip(&headers, &addr, &state.trusted_proxies);

    match state.store.delete_principal(&org_id, &id) {
        Ok(true) => {
            info!(principal_id = %id, org_id = %org_id, "audit: principal.delete");
            let _ = state.store.record_audit(AuditEvent::new(
                ACTION_PRINCIPAL_DELETE,
                None,
                ip,
                true,
                Some(format!("principal_id={id}")),
                Some(org_id),
                auth.principal_id().map(|s| s.to_owned()),
            ));
            Json(json!({"deleted": true})).into_response()
        }
        Ok(false) => not_found("principal not found"),
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("has active keys") {
                (StatusCode::CONFLICT, Json(json!({"error": msg}))).into_response()
            } else {
                internal_error(e)
            }
        }
    }
}

// ── Role CRUD ───────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct CreateRoleRequest {
    pub name: String,
    pub permissions: String,
}

pub async fn create_role(
    State(state): State<AppState>,
    Extension(auth): Extension<ResolvedAuth>,
    headers: HeaderMap,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Path(org_id): Path<String>,
    Json(body): Json<CreateRoleRequest>,
) -> Response {
    if !(auth.is_master() || auth.can_manage_org() && auth.org_id() == Some(&org_id)) {
        return forbidden();
    }

    if body.name.is_empty() || body.name.len() > 64 {
        return bad_request("role name must be 1-64 characters");
    }

    // Parse and validate permissions.
    let permissions = match Permissions::parse(&body.permissions) {
        Ok(p) => p,
        Err(e) => return bad_request(&format!("invalid permissions: {e}")),
    };

    // Reject S (SirrAdmin) bit in org-scoped roles.
    if permissions.has(PermBit::SirrAdmin) {
        return bad_request("org-scoped roles cannot include the S (SirrAdmin) permission");
    }

    let ip = extract_ip(&headers, &addr, &state.trusted_proxies);

    let role = RoleRecord {
        name: body.name.clone(),
        org_id: Some(org_id.clone()),
        permissions,
        built_in: false,
        created_at: now_epoch(),
    };

    match state.store.put_role(&role) {
        Ok(()) => {
            info!(role = %body.name, org_id = %org_id, "audit: role.create");
            let _ = state.store.record_audit(AuditEvent::new(
                ACTION_ROLE_CREATE,
                None,
                ip,
                true,
                Some(format!("role={}", body.name)),
                Some(org_id),
                auth.principal_id().map(|s| s.to_owned()),
            ));
            (
                StatusCode::CREATED,
                Json(json!({
                    "name": role.name,
                    "permissions": role.permissions.to_letter_string(),
                    "org_id": role.org_id,
                })),
            )
                .into_response()
        }
        Err(e) => internal_error(e),
    }
}

pub async fn list_roles(
    State(state): State<AppState>,
    Extension(auth): Extension<ResolvedAuth>,
    Path(org_id): Path<String>,
) -> Response {
    if !(auth.is_master() || auth.can_account_read_org() && auth.org_id() == Some(&org_id)) {
        return forbidden();
    }

    match state.store.list_roles(Some(&org_id)) {
        Ok(roles) => {
            let result: Vec<_> = roles
                .iter()
                .map(|r| {
                    json!({
                        "name": r.name,
                        "permissions": r.permissions.to_letter_string(),
                        "built_in": r.built_in,
                        "org_id": r.org_id,
                        "created_at": r.created_at,
                    })
                })
                .collect();
            Json(json!({"roles": result})).into_response()
        }
        Err(e) => internal_error(e),
    }
}

pub async fn delete_role(
    State(state): State<AppState>,
    Extension(auth): Extension<ResolvedAuth>,
    headers: HeaderMap,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Path((org_id, name)): Path<(String, String)>,
) -> Response {
    if !(auth.is_master() || auth.can_manage_org() && auth.org_id() == Some(&org_id)) {
        return forbidden();
    }

    let ip = extract_ip(&headers, &addr, &state.trusted_proxies);

    match state.store.delete_role(Some(&org_id), &name) {
        Ok(true) => {
            info!(role = %name, org_id = %org_id, "audit: role.delete");
            let _ = state.store.record_audit(AuditEvent::new(
                ACTION_ROLE_DELETE,
                None,
                ip,
                true,
                Some(format!("role={name}")),
                Some(org_id),
                auth.principal_id().map(|s| s.to_owned()),
            ));
            Json(json!({"deleted": true})).into_response()
        }
        Ok(false) => not_found("role not found"),
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("cannot delete") {
                (StatusCode::CONFLICT, Json(json!({"error": msg}))).into_response()
            } else {
                internal_error(e)
            }
        }
    }
}

// ── Principal self-service ──────────────────────────────────────────────────

pub async fn get_me(
    State(state): State<AppState>,
    Extension(auth): Extension<ResolvedAuth>,
) -> Response {
    if !auth.can_account_read() {
        return forbidden();
    }

    let (principal_id, org_id) = match &auth {
        ResolvedAuth::Principal {
            principal_id,
            org_id,
            ..
        } => (principal_id.clone(), org_id.clone()),
        ResolvedAuth::Master => return forbidden(),
    };

    let principal = match state.store.get_principal(&org_id, &principal_id) {
        Ok(Some(p)) => p,
        Ok(None) => return not_found("principal not found"),
        Err(e) => return internal_error(e),
    };

    let keys = match state.store.list_principal_keys(&principal_id) {
        Ok(k) => k,
        Err(e) => return internal_error(e),
    };

    let key_list: Vec<_> = keys
        .iter()
        .map(|k| {
            json!({
                "id": k.id,
                "name": k.name,
                "valid_after": k.valid_after,
                "valid_before": k.valid_before,
                "created_at": k.created_at,
            })
        })
        .collect();

    Json(json!({
        "id": principal.id,
        "name": principal.name,
        "role": principal.role,
        "org_id": principal.org_id,
        "metadata": principal.metadata,
        "created_at": principal.created_at,
        "keys": key_list,
    }))
    .into_response()
}

#[derive(Debug, Deserialize)]
pub struct PatchMeRequest {
    #[serde(default)]
    pub metadata: HashMap<String, String>,
}

pub async fn patch_me(
    State(state): State<AppState>,
    Extension(auth): Extension<ResolvedAuth>,
    Json(body): Json<PatchMeRequest>,
) -> Response {
    if !auth.can_account_manage() {
        return forbidden();
    }

    let (principal_id, org_id) = match &auth {
        ResolvedAuth::Principal {
            principal_id,
            org_id,
            ..
        } => (principal_id.clone(), org_id.clone()),
        ResolvedAuth::Master => return forbidden(),
    };

    if let Err(e) = validate_metadata(&body.metadata) {
        return bad_request(&e);
    }

    let mut principal = match state.store.get_principal(&org_id, &principal_id) {
        Ok(Some(p)) => p,
        Ok(None) => return not_found("principal not found"),
        Err(e) => return internal_error(e),
    };

    principal.metadata = body.metadata;

    match state.store.put_principal(&principal) {
        Ok(()) => Json(json!({
            "id": principal.id,
            "name": principal.name,
            "role": principal.role,
            "org_id": principal.org_id,
            "metadata": principal.metadata,
        }))
        .into_response(),
        Err(e) => internal_error(e),
    }
}

// ── Principal key management ────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct CreateKeyRequest {
    pub name: String,
    pub valid_for_seconds: Option<i64>,
    pub valid_before: Option<i64>,
}

pub async fn create_key(
    State(state): State<AppState>,
    Extension(auth): Extension<ResolvedAuth>,
    headers: HeaderMap,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(body): Json<CreateKeyRequest>,
) -> Response {
    if !auth.can_account_manage() {
        return forbidden();
    }

    let (principal_id, org_id) = match &auth {
        ResolvedAuth::Principal {
            principal_id,
            org_id,
            ..
        } => (principal_id.clone(), org_id.clone()),
        ResolvedAuth::Master => return forbidden(),
    };

    if body.name.is_empty() || body.name.len() > 128 {
        return bad_request("key name must be 1-128 characters");
    }

    let ip = extract_ip(&headers, &addr, &state.trusted_proxies);
    let now = now_epoch();

    // Generate the raw key.
    let mut bytes = [0u8; 16];
    rand::Rng::fill(&mut rand::thread_rng(), &mut bytes);
    let raw_key = format!("sirr_key_{}", hex::encode(bytes));

    // SHA-256 hash for storage.
    let key_hash = Sha256::digest(raw_key.as_bytes()).to_vec();

    let id = generate_id();

    // Determine validity window.
    let valid_after = now;
    let valid_before = if let Some(vb) = body.valid_before {
        vb
    } else if let Some(vfs) = body.valid_for_seconds {
        now + vfs
    } else {
        // Default: 1 year.
        now + 365 * 86400
    };

    let key_record = PrincipalKeyRecord {
        id: id.clone(),
        principal_id: principal_id.clone(),
        org_id: org_id.clone(),
        name: body.name.clone(),
        key_hash,
        valid_after,
        valid_before,
        created_at: now,
    };

    match state.store.put_principal_key(&key_record) {
        Ok(()) => {
            info!(key_id = %id, principal_id = %principal_id, "audit: key.create");
            let _ = state.store.record_audit(AuditEvent::new(
                ACTION_KEY_CREATE,
                None,
                ip,
                true,
                Some(format!("key_id={id}")),
                Some(org_id),
                Some(principal_id),
            ));
            (
                StatusCode::CREATED,
                Json(json!({
                    "id": id,
                    "name": body.name,
                    "key": raw_key,
                    "valid_after": valid_after,
                    "valid_before": valid_before,
                })),
            )
                .into_response()
        }
        Err(e) => internal_error(e),
    }
}

/// Master-auth endpoint: create a key for a specific principal.
/// Used by sirrlock.com for org provisioning (creating the first owner key).
pub async fn create_principal_key(
    State(state): State<AppState>,
    Extension(auth): Extension<ResolvedAuth>,
    headers: HeaderMap,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Path((org_id, principal_id)): Path<(String, String)>,
    Json(body): Json<CreateKeyRequest>,
) -> Response {
    if !matches!(auth, ResolvedAuth::Master) {
        return forbidden();
    }

    // Verify the principal exists and belongs to this org.
    let principals = match state.store.list_principals(&org_id) {
        Ok(ps) => ps,
        Err(e) => return internal_error(e),
    };
    if !principals.iter().any(|p| p.id == principal_id) {
        return not_found("principal not found in this org");
    }

    if body.name.is_empty() || body.name.len() > 128 {
        return bad_request("key name must be 1-128 characters");
    }

    let ip = extract_ip(&headers, &addr, &state.trusted_proxies);
    let now = now_epoch();

    let mut bytes = [0u8; 16];
    rand::Rng::fill(&mut rand::thread_rng(), &mut bytes);
    let raw_key = format!("sirr_key_{}", hex::encode(bytes));
    let key_hash = Sha256::digest(raw_key.as_bytes()).to_vec();
    let id = generate_id();

    let valid_after = now;
    let valid_before = if let Some(vb) = body.valid_before {
        vb
    } else if let Some(vfs) = body.valid_for_seconds {
        now + vfs
    } else {
        now + 365 * 86400
    };

    let key_record = PrincipalKeyRecord {
        id: id.clone(),
        principal_id: principal_id.clone(),
        org_id: org_id.clone(),
        name: body.name.clone(),
        key_hash,
        valid_after,
        valid_before,
        created_at: now,
    };

    match state.store.put_principal_key(&key_record) {
        Ok(()) => {
            info!(key_id = %id, principal_id = %principal_id, "audit: key.create (master)");
            let _ = state.store.record_audit(AuditEvent::new(
                ACTION_KEY_CREATE,
                None,
                ip,
                true,
                Some(format!("key_id={id}")),
                Some(org_id),
                Some(principal_id),
            ));
            (
                StatusCode::CREATED,
                Json(json!({
                    "id": id,
                    "name": body.name,
                    "key": raw_key,
                    "valid_after": valid_after,
                    "valid_before": valid_before,
                })),
            )
                .into_response()
        }
        Err(e) => internal_error(e),
    }
}

pub async fn delete_key(
    State(state): State<AppState>,
    Extension(auth): Extension<ResolvedAuth>,
    headers: HeaderMap,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Path(key_id): Path<String>,
) -> Response {
    if !auth.can_account_manage() {
        return forbidden();
    }

    let (principal_id, org_id) = match &auth {
        ResolvedAuth::Principal {
            principal_id,
            org_id,
            ..
        } => (principal_id.clone(), org_id.clone()),
        ResolvedAuth::Master => return forbidden(),
    };

    let ip = extract_ip(&headers, &addr, &state.trusted_proxies);

    match state.store.delete_principal_key(&principal_id, &key_id) {
        Ok(true) => {
            info!(key_id = %key_id, principal_id = %principal_id, "audit: key.delete");
            let _ = state.store.record_audit(AuditEvent::new(
                ACTION_KEY_DELETE,
                None,
                ip,
                true,
                Some(format!("key_id={key_id}")),
                Some(org_id),
                Some(principal_id),
            ));
            Json(json!({"deleted": true})).into_response()
        }
        Ok(false) => not_found("key not found"),
        Err(e) => internal_error(e),
    }
}

// ── Org secrets ─────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct CreateOrgSecretRequest {
    pub key: String,
    pub value: String,
    pub ttl_seconds: Option<u64>,
    pub max_reads: Option<u32>,
    pub delete: Option<bool>,
    pub webhook_url: Option<String>,
    pub allowed_keys: Option<Vec<String>>,
}

pub async fn create_org_secret(
    State(state): State<AppState>,
    Extension(auth): Extension<ResolvedAuth>,
    headers: HeaderMap,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Path(org_id): Path<String>,
    Json(body): Json<CreateOrgSecretRequest>,
) -> Response {
    if !auth.can_create() || auth.org_id() != Some(&org_id) {
        return forbidden();
    }

    if !validate_key_name(&body.key) {
        return bad_key_name();
    }
    if body.max_reads == Some(0) {
        return bad_request("max_reads must be >= 1; omit to allow unlimited reads");
    }
    if body.value.len() > 1_048_576 {
        return bad_request("value exceeds 1 MiB limit");
    }
    if let Some(ttl) = body.ttl_seconds {
        if ttl > MAX_TTL_SECS {
            return bad_request(&format!(
                "ttl_seconds exceeds maximum of {MAX_TTL_SECS} (10 years)"
            ));
        }
    }
    if let Some(ref wurl) = body.webhook_url {
        if let Err(reason) = webhooks::validate_webhook_url(wurl, &state.webhook_allowed_origins) {
            return bad_request(&format!("webhook_url: {reason}"));
        }
    }

    let ip = extract_ip(&headers, &addr, &state.trusted_proxies);

    let expires_at = body.ttl_seconds.map(|ttl| now_epoch() + ttl as i64);

    let max_reads = body.max_reads.or(Some(1));

    match state.store.put_org_secret(
        &org_id,
        &body.key,
        &body.value,
        expires_at,
        max_reads,
        body.delete.unwrap_or(true),
        body.webhook_url.clone(),
        auth.principal_id(),
        body.allowed_keys.clone(),
    ) {
        Ok(()) => {
            info!(key = %body.key, org_id = %org_id, "audit: secret.create");
            let _ = state.store.record_audit(AuditEvent::new(
                ACTION_SECRET_CREATE,
                Some(body.key.clone()),
                ip,
                true,
                None,
                Some(org_id.clone()),
                auth.principal_id().map(|s| s.to_owned()),
            ));
            if let Some(ref sender) = state.webhook_sender {
                sender.fire("secret.created", &body.key, json!({}));
            }
            (StatusCode::CREATED, Json(json!({"key": body.key}))).into_response()
        }
        Err(e) => internal_error(e),
    }
}

pub async fn list_org_secrets(
    State(state): State<AppState>,
    Extension(auth): Extension<ResolvedAuth>,
    headers: HeaderMap,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Path(org_id): Path<String>,
) -> Response {
    if auth.org_id() != Some(&org_id) {
        return forbidden();
    }

    let owner_filter = if auth.can_list_org() {
        None // list all org secrets
    } else if auth.can_list_my() {
        auth.principal_id().map(|s| s.to_owned())
    } else {
        return forbidden();
    };

    let ip = extract_ip(&headers, &addr, &state.trusted_proxies);

    match state
        .store
        .list_org_secrets(&org_id, owner_filter.as_deref())
    {
        Ok(metas) => {
            info!(count = metas.len(), org_id = %org_id, "audit: secret.list");
            let _ = state.store.record_audit(AuditEvent::new(
                ACTION_SECRET_LIST,
                None,
                ip,
                true,
                Some(format!("count={}", metas.len())),
                Some(org_id),
                auth.principal_id().map(|s| s.to_owned()),
            ));
            Json(json!({"secrets": metas})).into_response()
        }
        Err(e) => internal_error(e),
    }
}

pub async fn get_org_secret(
    State(state): State<AppState>,
    Extension(auth): Extension<ResolvedAuth>,
    headers: HeaderMap,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Path((org_id, key)): Path<(String, String)>,
) -> Response {
    if auth.org_id() != Some(&org_id) {
        return forbidden();
    }
    if !auth.can_read_my() && !auth.can_read_org() {
        return forbidden();
    }
    if !validate_key_name(&key) {
        return bad_key_name();
    }

    // Pre-flight: check key binding and ownership via metadata.
    match state.store.head_org_secret(&org_id, &key) {
        Ok(Some((meta, _sealed))) => {
            // Ownership check: ReadMy only grants access to own secrets.
            if !auth.can_access_secret(meta.owner_id.as_deref(), PermBit::ReadMy, PermBit::ReadOrg)
            {
                return forbidden();
            }
            // Key binding check.
            if let Some(key_name) = auth.key_name() {
                match state.store.check_key_binding(&org_id, &key, key_name) {
                    Ok(false) => {
                        return (
                            StatusCode::FORBIDDEN,
                            Json(json!({"error": "key not authorized for this secret"})),
                        )
                            .into_response();
                    }
                    Err(e) => return internal_error(e),
                    Ok(true) => {}
                }
            }
        }
        Ok(None) => return not_found("not found or expired"),
        Err(e) => return internal_error(e),
    }

    let ip = extract_ip(&headers, &addr, &state.trusted_proxies);

    match state.store.get_org_secret(&org_id, &key) {
        Ok(GetResult::Value(value, webhook_url)) => {
            let _ = state.store.record_audit(AuditEvent::new(
                ACTION_SECRET_READ,
                Some(key.clone()),
                ip,
                true,
                None,
                Some(org_id.clone()),
                auth.principal_id().map(|s| s.to_owned()),
            ));
            if let Some(ref sender) = state.webhook_sender {
                sender.fire("secret.read", &key, json!({}));
                if let Some(ref url) = webhook_url {
                    sender.fire_for_url(url, "secret.read", &key, json!({}));
                }
            }
            Json(json!({"key": key, "value": value})).into_response()
        }
        Ok(GetResult::Burned(value, webhook_url)) => {
            let _ = state.store.record_audit(AuditEvent::new(
                ACTION_SECRET_BURNED,
                Some(key.clone()),
                ip,
                true,
                None,
                Some(org_id.clone()),
                auth.principal_id().map(|s| s.to_owned()),
            ));
            if let Some(ref sender) = state.webhook_sender {
                sender.fire("secret.burned", &key, json!({}));
                if let Some(ref url) = webhook_url {
                    sender.fire_for_url(url, "secret.burned", &key, json!({}));
                }
            }
            Json(json!({"key": key, "value": value})).into_response()
        }
        Ok(GetResult::Sealed) => {
            let _ = state.store.record_audit(AuditEvent::new(
                ACTION_SECRET_READ,
                Some(key.clone()),
                ip,
                false,
                Some("sealed".into()),
                Some(org_id),
                auth.principal_id().map(|s| s.to_owned()),
            ));
            (
                StatusCode::GONE,
                Json(json!({"error": "secret is sealed - reads exhausted"})),
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
                Some(org_id),
                auth.principal_id().map(|s| s.to_owned()),
            ));
            not_found("not found or expired")
        }
        Err(e) => internal_error(e),
    }
}

pub async fn head_org_secret(
    State(state): State<AppState>,
    Extension(auth): Extension<ResolvedAuth>,
    Path((org_id, key)): Path<(String, String)>,
) -> Response {
    if auth.org_id() != Some(&org_id) {
        return forbidden();
    }
    if !auth.can_read_my() && !auth.can_read_org() {
        return forbidden();
    }
    if !validate_key_name(&key) {
        return bad_key_name();
    }

    // Key binding check (GB-01 fix).
    if let Some(key_name) = auth.key_name() {
        match state.store.check_key_binding(&org_id, &key, key_name) {
            Ok(false) => {
                return (
                    StatusCode::FORBIDDEN,
                    Json(json!({"error": "key not authorized for this secret"})),
                )
                    .into_response();
            }
            Err(e) => {
                let msg = e.to_string();
                if msg.contains("not found") {
                    return not_found("not found or expired");
                }
                return internal_error(e);
            }
            Ok(true) => {}
        }
    }

    match state.store.head_org_secret(&org_id, &key) {
        Ok(Some((meta, sealed))) => {
            // Ownership check: ReadMy only grants access to own secrets.
            if !auth.can_access_secret(meta.owner_id.as_deref(), PermBit::ReadMy, PermBit::ReadOrg)
            {
                return forbidden();
            }
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
        Ok(None) => not_found("not found or expired"),
        Err(e) => internal_error(e),
    }
}

#[derive(Debug, Deserialize)]
pub struct PatchOrgSecretRequest {
    pub value: Option<String>,
    pub max_reads: Option<u32>,
    pub ttl_seconds: Option<u64>,
}

pub async fn patch_org_secret(
    State(state): State<AppState>,
    Extension(auth): Extension<ResolvedAuth>,
    headers: HeaderMap,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Path((org_id, key)): Path<(String, String)>,
    Json(body): Json<PatchOrgSecretRequest>,
) -> Response {
    if auth.org_id() != Some(&org_id) {
        return forbidden();
    }
    if !auth.can_patch_my() && !auth.can_patch_org() {
        return forbidden();
    }
    if !validate_key_name(&key) {
        return bad_key_name();
    }
    if body.max_reads == Some(0) {
        return bad_request("max_reads must be >= 1; omit to allow unlimited reads");
    }
    if let Some(ref v) = body.value {
        if v.len() > 1_048_576 {
            return bad_request("value exceeds 1 MiB limit");
        }
    }
    if let Some(ttl) = body.ttl_seconds {
        if ttl > MAX_TTL_SECS {
            return bad_request(&format!(
                "ttl_seconds exceeds maximum of {MAX_TTL_SECS} (10 years)"
            ));
        }
    }

    // Ownership check: PatchMy only grants access to own secrets (GB-04 fix).
    if !auth.can_patch_org() {
        match state.store.head_org_secret(&org_id, &key) {
            Ok(Some((meta, _))) => {
                if !auth.can_access_secret(
                    meta.owner_id.as_deref(),
                    PermBit::PatchMy,
                    PermBit::PatchOrg,
                ) {
                    return forbidden();
                }
            }
            Ok(None) => return not_found("not found or expired"),
            Err(e) => return internal_error(e),
        }
    }

    let ip = extract_ip(&headers, &addr, &state.trusted_proxies);

    let new_expires_at = body.ttl_seconds.map(|ttl| now_epoch() + ttl as i64);

    match state.store.patch_org_secret(
        &org_id,
        &key,
        body.value.as_deref(),
        body.max_reads,
        new_expires_at,
    ) {
        Ok(Some(meta)) => {
            let _ = state.store.record_audit(AuditEvent::new(
                ACTION_SECRET_PATCH,
                Some(key.clone()),
                ip,
                true,
                None,
                Some(org_id),
                auth.principal_id().map(|s| s.to_owned()),
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
                Some(org_id),
                auth.principal_id().map(|s| s.to_owned()),
            ));
            not_found("not found or expired")
        }
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("cannot patch") {
                (StatusCode::CONFLICT, Json(json!({"error": msg}))).into_response()
            } else if msg.starts_with("sealed:") {
                (
                    StatusCode::GONE,
                    Json(json!({"error": "secret read limit exhausted"})),
                )
                    .into_response()
            } else {
                internal_error(e)
            }
        }
    }
}

pub async fn delete_org_secret(
    State(state): State<AppState>,
    Extension(auth): Extension<ResolvedAuth>,
    headers: HeaderMap,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Path((org_id, key)): Path<(String, String)>,
) -> Response {
    if auth.org_id() != Some(&org_id) {
        return forbidden();
    }
    if !auth.can_delete_my() && !auth.can_delete_org() {
        return forbidden();
    }
    if !validate_key_name(&key) {
        return bad_key_name();
    }

    // Ownership check: DeleteMy only grants access to own secrets (GB-03 fix).
    if !auth.can_delete_org() {
        match state.store.head_org_secret(&org_id, &key) {
            Ok(Some((meta, _))) => {
                if !auth.can_access_secret(
                    meta.owner_id.as_deref(),
                    PermBit::DeleteMy,
                    PermBit::DeleteOrg,
                ) {
                    return forbidden();
                }
            }
            Ok(None) => return not_found("not found or expired"),
            Err(e) => return internal_error(e),
        }
    }

    let ip = extract_ip(&headers, &addr, &state.trusted_proxies);

    match state.store.delete_org_secret(&org_id, &key) {
        Ok(true) => {
            info!(key = %key, org_id = %org_id, "audit: secret.delete");
            let _ = state.store.record_audit(AuditEvent::new(
                ACTION_SECRET_DELETE,
                Some(key.clone()),
                ip,
                true,
                None,
                Some(org_id),
                auth.principal_id().map(|s| s.to_owned()),
            ));
            if let Some(ref sender) = state.webhook_sender {
                sender.fire("secret.deleted", &key, json!({}));
            }
            Json(json!({"deleted": true})).into_response()
        }
        Ok(false) => not_found("not found"),
        Err(e) => internal_error(e),
    }
}

pub async fn prune_org_secrets(
    State(state): State<AppState>,
    Extension(auth): Extension<ResolvedAuth>,
    headers: HeaderMap,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Path(org_id): Path<String>,
) -> Response {
    if auth.org_id() != Some(&org_id) {
        return forbidden();
    }
    if !auth.can_manage_org() && !auth.can_delete_org() {
        return forbidden();
    }

    let ip = extract_ip(&headers, &addr, &state.trusted_proxies);

    match state.store.prune_org_secrets(&org_id) {
        Ok(pruned_keys) => {
            let n = pruned_keys.len();
            info!(pruned = n, org_id = %org_id, "audit: secret.prune");
            let _ = state.store.record_audit(AuditEvent::new(
                ACTION_SECRET_PRUNE,
                None,
                ip,
                true,
                Some(format!("pruned={n}")),
                Some(org_id),
                auth.principal_id().map(|s| s.to_owned()),
            ));
            if let Some(ref sender) = state.webhook_sender {
                for key in &pruned_keys {
                    sender.fire("secret.expired", key, json!({"reason": "manual_prune"}));
                }
            }
            Json(json!({"pruned": n})).into_response()
        }
        Err(e) => internal_error(e),
    }
}

// ── Org audit + webhooks ────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct OrgAuditQueryParams {
    pub since: Option<i64>,
    pub until: Option<i64>,
    pub action: Option<String>,
    pub limit: Option<usize>,
}

pub async fn org_audit_events(
    State(state): State<AppState>,
    Extension(auth): Extension<ResolvedAuth>,
    Path(org_id): Path<String>,
    Query(params): Query<OrgAuditQueryParams>,
) -> Response {
    if auth.org_id() != Some(&org_id) && !auth.is_master() {
        return forbidden();
    }
    if !auth.is_master() && !auth.can_manage_org() {
        return forbidden();
    }

    let limit = params.limit.unwrap_or(100).min(1000);
    let query = AuditQuery {
        since: params.since,
        until: params.until,
        action: params.action,
        limit,
        org_id: Some(org_id),
    };
    match state.store.list_audit(&query) {
        Ok(events) => {
            if state.redact_audit_keys {
                let redacted: Vec<_> = events
                    .into_iter()
                    .map(|mut e| {
                        if let Some(ref k) = e.key {
                            let hash = Sha256::digest(k.as_bytes());
                            e.key = Some(format!("sha256:{}", &hex::encode(hash)[..8]));
                        }
                        e
                    })
                    .collect();
                Json(json!({"events": redacted})).into_response()
            } else {
                Json(json!({"events": events})).into_response()
            }
        }
        Err(e) => internal_error(e),
    }
}

#[derive(Debug, Deserialize)]
pub struct CreateOrgWebhookRequest {
    pub url: String,
    pub events: Option<Vec<String>>,
}

pub async fn create_org_webhook(
    State(state): State<AppState>,
    Extension(auth): Extension<ResolvedAuth>,
    headers: HeaderMap,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Path(org_id): Path<String>,
    Json(body): Json<CreateOrgWebhookRequest>,
) -> Response {
    if auth.org_id() != Some(&org_id) && !auth.is_master() {
        return forbidden();
    }
    if !auth.is_master() && !auth.can_manage_org() {
        return forbidden();
    }

    let ip = extract_ip(&headers, &addr, &state.trusted_proxies);

    if !body.url.starts_with("http://") && !body.url.starts_with("https://") {
        return bad_request("webhook URL must start with http:// or https://");
    }

    // Check count limit per org.
    match state.store.count_webhooks_for_org(&org_id) {
        Ok(count) if count >= MAX_WEBHOOKS => {
            return (
                StatusCode::CONFLICT,
                Json(
                    json!({"error": format!("maximum of {MAX_WEBHOOKS} webhooks reached for org")}),
                ),
            )
                .into_response();
        }
        Err(e) => return internal_error(e),
        _ => {}
    }

    let events = body.events.unwrap_or_else(|| vec!["*".to_string()]);
    let id = webhooks::generate_webhook_id();
    let secret = webhooks::generate_signing_secret();

    let reg = webhooks::WebhookRegistration {
        id: id.clone(),
        url: body.url.clone(),
        secret: secret.clone(),
        events,
        created_at: now_epoch(),
        org_id: Some(org_id.clone()),
    };

    match state.store.put_webhook(&reg) {
        Ok(()) => {
            let _ = state.store.record_audit(AuditEvent::new(
                ACTION_WEBHOOK_CREATE,
                None,
                ip,
                true,
                Some(format!("id={id}")),
                Some(org_id),
                auth.principal_id().map(|s| s.to_owned()),
            ));
            (
                StatusCode::CREATED,
                Json(json!({"id": id, "secret": secret})),
            )
                .into_response()
        }
        Err(e) => internal_error(e),
    }
}

pub async fn list_org_webhooks(
    State(state): State<AppState>,
    Extension(auth): Extension<ResolvedAuth>,
    Path(org_id): Path<String>,
) -> Response {
    if auth.org_id() != Some(&org_id) && !auth.is_master() {
        return forbidden();
    }
    if !auth.is_master() && !auth.can_manage_org() {
        return forbidden();
    }

    match state.store.list_webhooks_for_org(&org_id) {
        Ok(regs) => {
            let redacted: Vec<_> = regs
                .iter()
                .map(|r| {
                    json!({
                        "id": r.id,
                        "url": r.url,
                        "events": r.events,
                        "created_at": r.created_at,
                    })
                })
                .collect();
            Json(json!({"webhooks": redacted})).into_response()
        }
        Err(e) => internal_error(e),
    }
}

pub async fn delete_org_webhook(
    State(state): State<AppState>,
    Extension(auth): Extension<ResolvedAuth>,
    headers: HeaderMap,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Path((org_id, id)): Path<(String, String)>,
) -> Response {
    if auth.org_id() != Some(&org_id) && !auth.is_master() {
        return forbidden();
    }
    if !auth.is_master() && !auth.can_manage_org() {
        return forbidden();
    }

    let ip = extract_ip(&headers, &addr, &state.trusted_proxies);

    match state.store.delete_webhook(&id) {
        Ok(true) => {
            let _ = state.store.record_audit(AuditEvent::new(
                ACTION_WEBHOOK_DELETE,
                None,
                ip,
                true,
                Some(format!("id={id}")),
                Some(org_id),
                auth.principal_id().map(|s| s.to_owned()),
            ));
            Json(json!({"deleted": true})).into_response()
        }
        Ok(false) => not_found("webhook not found"),
        Err(e) => internal_error(e),
    }
}
