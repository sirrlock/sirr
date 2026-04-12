use crate::store::{KeyRecord, SecretRecord, Visibility};
use axum::http::StatusCode;

/// The action a caller is attempting to perform.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Create,
    Read,
    Inspect, // HEAD — metadata only
    Audit,   // GET /secret/:hash/audit
    Patch,
    Burn,
}

/// Who is making the request.
#[derive(Debug, Clone)]
pub enum Caller {
    Anonymous,
    Keyed(KeyRecord),
}

/// The authorization decision returned by `authorize()`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthDecision {
    Allow,
    Unauthorized,       // 401
    BadRequest(String), // 400
    MethodNotAllowed,   // 405
    NotFound,           // 404 — used for "wrong key" AND "hash doesn't exist"
    Gone,               // 410
    Unavailable,        // 503
}

impl AuthDecision {
    /// Map the decision to the corresponding HTTP status code.
    pub fn into_status_code(&self) -> StatusCode {
        match self {
            AuthDecision::Allow => StatusCode::OK,
            AuthDecision::Unauthorized => StatusCode::UNAUTHORIZED,
            AuthDecision::BadRequest(_) => StatusCode::BAD_REQUEST,
            AuthDecision::MethodNotAllowed => StatusCode::METHOD_NOT_ALLOWED,
            AuthDecision::NotFound => StatusCode::NOT_FOUND,
            AuthDecision::Gone => StatusCode::GONE,
            AuthDecision::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
        }
    }
}

/// The single authorization function for the entire Sirr access control model.
///
/// This function is pure: no IO, no store access, no side effects.
/// It implements the full decision table from spec §6.
///
/// # Parameters
/// - `action`: What the caller wants to do.
/// - `secret`: The secret record, if the hash exists (None for Create or if hash not found).
/// - `caller`: Who is making the request.
/// - `visibility`: Current server-wide visibility mode.
/// - `now`: Current unix timestamp (seconds). Used to check secret expiry.
///
/// # Security invariant
/// The only signals an unauthorized caller ever sees about a hash they don't own
/// are `NotFound` (404) and `Unavailable` (503). Hash existence is privileged information.
pub fn authorize(
    action: Action,
    secret: Option<&SecretRecord>,
    caller: &Caller,
    visibility: Visibility,
    now: i64,
) -> AuthDecision {
    // Row 1: visibility=none rejects everything.
    if visibility == Visibility::None {
        return AuthDecision::Unavailable;
    }

    match action {
        // ── Create ────────────────────────────────────────────────────────────
        Action::Create => match (visibility, caller) {
            // public: anonymous allowed, keyed rejected
            (Visibility::Public, Caller::Anonymous) => AuthDecision::Allow,
            (Visibility::Public, Caller::Keyed(_)) => AuthDecision::BadRequest(
                "server in public mode does not accept keyed writes".to_string(),
            ),
            // private: keyed allowed, anonymous rejected
            (Visibility::Private, Caller::Anonymous) => AuthDecision::Unauthorized,
            (Visibility::Private, Caller::Keyed(_)) => AuthDecision::Allow,
            // both: either works
            (Visibility::Both, _) => AuthDecision::Allow,
            // none already handled above
            (Visibility::None, _) => unreachable!(),
        },

        // ── Read ──────────────────────────────────────────────────────────────
        Action::Read => match secret {
            Some(s) if is_active(s, now) => AuthDecision::Allow,
            Some(_) => AuthDecision::Gone,
            // Hash doesn't exist: treat as Gone (see spec §13 open question — lean 410)
            None => AuthDecision::Gone,
        },

        // ── Inspect (HEAD) ────────────────────────────────────────────────────
        Action::Inspect => match secret {
            Some(s) if is_active(s, now) => AuthDecision::Allow,
            Some(_) => AuthDecision::Gone,
            None => AuthDecision::Gone,
        },

        // ── Audit ─────────────────────────────────────────────────────────────
        Action::Audit => match secret {
            None => AuthDecision::NotFound,
            Some(s) => {
                // Anonymous secrets have no audit endpoint — return 404 regardless of caller.
                if s.owner_key_id.is_none() {
                    return AuthDecision::NotFound;
                }
                // Keyed secret: check caller.
                match caller {
                    Caller::Anonymous => AuthDecision::Unauthorized,
                    Caller::Keyed(_) if is_owner(s, caller) => AuthDecision::Allow,
                    // Wrong key: oracle defense — return 404, not 401/403.
                    Caller::Keyed(_) => AuthDecision::NotFound,
                }
            }
        },

        // ── Patch ─────────────────────────────────────────────────────────────
        Action::Patch => match secret {
            None => AuthDecision::NotFound,
            Some(s) => {
                // Burned/expired secrets cannot be patched.
                if !is_active(s, now) {
                    return AuthDecision::Gone;
                }
                // Anonymous secrets are immutable.
                if s.owner_key_id.is_none() {
                    return AuthDecision::MethodNotAllowed;
                }
                // Keyed secret: only owner may patch.
                match caller {
                    Caller::Anonymous => AuthDecision::Unauthorized,
                    Caller::Keyed(_) if is_owner(s, caller) => AuthDecision::Allow,
                    // Wrong key: oracle defense — return 404.
                    Caller::Keyed(_) => AuthDecision::NotFound,
                }
            }
        },

        // ── Burn ──────────────────────────────────────────────────────────────
        Action::Burn => match secret {
            None => AuthDecision::NotFound,
            Some(s) => {
                // Already burned/expired.
                if !is_active(s, now) {
                    return AuthDecision::Gone;
                }
                // Anonymous secrets: capability model — anyone with the hash can burn.
                if s.owner_key_id.is_none() {
                    return AuthDecision::Allow;
                }
                // Keyed secret: only owner may burn.
                match caller {
                    Caller::Anonymous => AuthDecision::Unauthorized,
                    Caller::Keyed(_) if is_owner(s, caller) => AuthDecision::Allow,
                    // Wrong key: oracle defense — return 404.
                    Caller::Keyed(_) => AuthDecision::NotFound,
                }
            }
        },
    }
}

/// Returns true when `caller` is the owning key of `secret`.
fn is_owner(secret: &SecretRecord, caller: &Caller) -> bool {
    match (secret.owner_key_id.as_deref(), caller) {
        (Some(owner_id), Caller::Keyed(key)) => owner_id == key.id,
        _ => false,
    }
}

/// Returns true when the secret is neither burned nor expired.
fn is_active(secret: &SecretRecord, now: i64) -> bool {
    !secret.burned && !secret.is_expired(now)
}
