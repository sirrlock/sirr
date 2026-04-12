/// Authorization decision matrix tests.
///
/// Every row from spec §6 is covered. Each test case is a tuple of:
///   (name, action, secret, caller, visibility, now, expected_decision)
///
/// The `full_authorization_matrix` test runs all cases sequentially and reports
/// the failing case name on mismatch.
use sirr_server::store::{KeyRecord, SecretRecord, Visibility};
use sirr_server::{authorize, Action, AuthDecision, Caller};

const NOW: i64 = 1_712_846_400; // 2024-04-11T12:00:00Z

// ── Fixture helpers ──────────────────────────────────────────────────────────

fn make_key_with_id(id: &str) -> KeyRecord {
    KeyRecord {
        id: id.to_string(),
        name: format!("key-{id}"),
        hash: [0u8; 32],
        created_at: NOW,
        valid_after: None,
        valid_before: None,
        webhook_url: None,
    }
}

fn make_key() -> KeyRecord {
    make_key_with_id("key-alice")
}

/// Active anonymous secret (no owner key).
fn active_anon() -> SecretRecord {
    SecretRecord {
        hash: "anon_abc123".to_string(),
        value_ciphertext: vec![1, 2, 3],
        nonce: [0u8; 12],
        created_at: NOW,
        ttl_expires_at: None,
        reads_remaining: None,
        burned: false,
        burned_at: None,
        owner_key_id: None,
        created_by_ip: None,
    }
}

/// Active keyed secret owned by the given key.
fn active_keyed(owner: &KeyRecord) -> SecretRecord {
    SecretRecord {
        hash: "keyed_def456".to_string(),
        value_ciphertext: vec![4, 5, 6],
        nonce: [0u8; 12],
        created_at: NOW,
        ttl_expires_at: None,
        reads_remaining: None,
        burned: false,
        burned_at: None,
        owner_key_id: Some(owner.id.clone()),
        created_by_ip: None,
    }
}

/// Burned secret (tombstone).
fn burned_secret() -> SecretRecord {
    SecretRecord {
        hash: "burned_ghi789".to_string(),
        value_ciphertext: vec![0u8; 3],
        nonce: [0u8; 12],
        created_at: NOW - 3600,
        ttl_expires_at: None,
        reads_remaining: None,
        burned: true,
        burned_at: Some(NOW - 3600),
        owner_key_id: None,
        created_by_ip: None,
    }
}

/// Expired secret (TTL elapsed).
fn expired_secret() -> SecretRecord {
    SecretRecord {
        hash: "expired_jkl012".to_string(),
        value_ciphertext: vec![7, 8, 9],
        nonce: [0u8; 12],
        created_at: NOW - 7200,
        ttl_expires_at: Some(NOW - 3600), // expired 1 hour ago
        reads_remaining: None,
        burned: false,
        burned_at: None,
        owner_key_id: None,
        created_by_ip: None,
    }
}

/// Burned keyed secret.
fn burned_keyed(owner: &KeyRecord) -> SecretRecord {
    SecretRecord {
        hash: "burnedkeyed_mno345".to_string(),
        value_ciphertext: vec![0u8; 3],
        nonce: [0u8; 12],
        created_at: NOW - 3600,
        ttl_expires_at: None,
        reads_remaining: None,
        burned: true,
        burned_at: Some(NOW - 3600),
        owner_key_id: Some(owner.id.clone()),
        created_by_ip: None,
    }
}

// ── Full decision matrix ─────────────────────────────────────────────────────

#[test]
fn full_authorization_matrix() {
    let owner_key = make_key_with_id("owner");
    let other_key = make_key_with_id("other");

    // Precompute fixtures so we can reference them in the table.
    let anon_secret = active_anon();
    let keyed_secret = active_keyed(&owner_key);
    let burned_anon = burned_secret();
    let expired_anon = expired_secret();
    let burned_kd = burned_keyed(&owner_key);

    // Each row: (name, action, secret, caller, visibility, now, expected)
    type Row<'a> = (
        &'static str,
        Action,
        Option<&'a SecretRecord>,
        Caller,
        Visibility,
        i64,
        AuthDecision,
    );

    let cases: Vec<Row<'_>> = vec![
        // ── visibility=none blocks everything ──────────────────────────────
        (
            "none: read anon secret → unavailable",
            Action::Read,
            Some(&anon_secret),
            Caller::Anonymous,
            Visibility::None,
            NOW,
            AuthDecision::Unavailable,
        ),
        (
            "none: create anonymous → unavailable",
            Action::Create,
            None,
            Caller::Anonymous,
            Visibility::None,
            NOW,
            AuthDecision::Unavailable,
        ),
        (
            "none: create keyed → unavailable",
            Action::Create,
            None,
            Caller::Keyed(make_key()),
            Visibility::None,
            NOW,
            AuthDecision::Unavailable,
        ),
        (
            "none: burn keyed secret → unavailable",
            Action::Burn,
            Some(&keyed_secret),
            Caller::Keyed(owner_key.clone()),
            Visibility::None,
            NOW,
            AuthDecision::Unavailable,
        ),
        // ── Create / public ────────────────────────────────────────────────
        (
            "public: anonymous create → allow",
            Action::Create,
            None,
            Caller::Anonymous,
            Visibility::Public,
            NOW,
            AuthDecision::Allow,
        ),
        (
            "public: keyed create → bad request",
            Action::Create,
            None,
            Caller::Keyed(make_key()),
            Visibility::Public,
            NOW,
            AuthDecision::BadRequest(
                "server in public mode does not accept keyed writes".to_string(),
            ),
        ),
        // ── Create / private ───────────────────────────────────────────────
        (
            "private: anonymous create → unauthorized",
            Action::Create,
            None,
            Caller::Anonymous,
            Visibility::Private,
            NOW,
            AuthDecision::Unauthorized,
        ),
        (
            "private: keyed create → allow",
            Action::Create,
            None,
            Caller::Keyed(make_key()),
            Visibility::Private,
            NOW,
            AuthDecision::Allow,
        ),
        // ── Create / both ──────────────────────────────────────────────────
        (
            "both: anonymous create → allow",
            Action::Create,
            None,
            Caller::Anonymous,
            Visibility::Both,
            NOW,
            AuthDecision::Allow,
        ),
        (
            "both: keyed create → allow",
            Action::Create,
            None,
            Caller::Keyed(make_key()),
            Visibility::Both,
            NOW,
            AuthDecision::Allow,
        ),
        // ── Read / active ──────────────────────────────────────────────────
        (
            "read active anon secret anonymous → allow",
            Action::Read,
            Some(&anon_secret),
            Caller::Anonymous,
            Visibility::Public,
            NOW,
            AuthDecision::Allow,
        ),
        (
            "read active keyed secret anonymous → allow",
            Action::Read,
            Some(&keyed_secret),
            Caller::Anonymous,
            Visibility::Private,
            NOW,
            AuthDecision::Allow,
        ),
        (
            "read active keyed secret with owner key → allow",
            Action::Read,
            Some(&keyed_secret),
            Caller::Keyed(owner_key.clone()),
            Visibility::Private,
            NOW,
            AuthDecision::Allow,
        ),
        (
            "read active keyed secret with non-owner key → allow (reads are universal)",
            Action::Read,
            Some(&keyed_secret),
            Caller::Keyed(other_key.clone()),
            Visibility::Private,
            NOW,
            AuthDecision::Allow,
        ),
        // ── Read / burned/expired ──────────────────────────────────────────
        (
            "read burned anon secret → gone",
            Action::Read,
            Some(&burned_anon),
            Caller::Anonymous,
            Visibility::Public,
            NOW,
            AuthDecision::Gone,
        ),
        (
            "read expired anon secret → gone",
            Action::Read,
            Some(&expired_anon),
            Caller::Anonymous,
            Visibility::Public,
            NOW,
            AuthDecision::Gone,
        ),
        // ── Inspect / active ───────────────────────────────────────────────
        (
            "inspect active anon secret → allow",
            Action::Inspect,
            Some(&anon_secret),
            Caller::Anonymous,
            Visibility::Public,
            NOW,
            AuthDecision::Allow,
        ),
        (
            "inspect active keyed secret any caller → allow",
            Action::Inspect,
            Some(&keyed_secret),
            Caller::Keyed(other_key.clone()),
            Visibility::Private,
            NOW,
            AuthDecision::Allow,
        ),
        // ── Inspect / burned/expired ───────────────────────────────────────
        (
            "inspect burned secret → gone",
            Action::Inspect,
            Some(&burned_anon),
            Caller::Anonymous,
            Visibility::Public,
            NOW,
            AuthDecision::Gone,
        ),
        (
            "inspect expired secret → gone",
            Action::Inspect,
            Some(&expired_anon),
            Caller::Anonymous,
            Visibility::Both,
            NOW,
            AuthDecision::Gone,
        ),
        // ── Audit / anonymous secret ───────────────────────────────────────
        (
            "audit anonymous secret → not found",
            Action::Audit,
            Some(&anon_secret),
            Caller::Anonymous,
            Visibility::Public,
            NOW,
            AuthDecision::NotFound,
        ),
        (
            "audit anonymous secret with key → not found",
            Action::Audit,
            Some(&anon_secret),
            Caller::Keyed(make_key()),
            Visibility::Public,
            NOW,
            AuthDecision::NotFound,
        ),
        // ── Audit / keyed secret ───────────────────────────────────────────
        (
            "audit keyed secret anonymous → unauthorized",
            Action::Audit,
            Some(&keyed_secret),
            Caller::Anonymous,
            Visibility::Private,
            NOW,
            AuthDecision::Unauthorized,
        ),
        (
            "audit keyed secret owner → allow",
            Action::Audit,
            Some(&keyed_secret),
            Caller::Keyed(owner_key.clone()),
            Visibility::Private,
            NOW,
            AuthDecision::Allow,
        ),
        (
            "audit keyed secret wrong key → not found (oracle defense)",
            Action::Audit,
            Some(&keyed_secret),
            Caller::Keyed(other_key.clone()),
            Visibility::Private,
            NOW,
            AuthDecision::NotFound,
        ),
        // ── Patch / anonymous secret ───────────────────────────────────────
        (
            "patch anonymous secret → method not allowed",
            Action::Patch,
            Some(&anon_secret),
            Caller::Anonymous,
            Visibility::Public,
            NOW,
            AuthDecision::MethodNotAllowed,
        ),
        (
            "patch anonymous secret with key → method not allowed",
            Action::Patch,
            Some(&anon_secret),
            Caller::Keyed(make_key()),
            Visibility::Both,
            NOW,
            AuthDecision::MethodNotAllowed,
        ),
        // ── Patch / keyed secret ───────────────────────────────────────────
        (
            "patch keyed secret anonymous → unauthorized",
            Action::Patch,
            Some(&keyed_secret),
            Caller::Anonymous,
            Visibility::Private,
            NOW,
            AuthDecision::Unauthorized,
        ),
        (
            "patch keyed secret owner → allow",
            Action::Patch,
            Some(&keyed_secret),
            Caller::Keyed(owner_key.clone()),
            Visibility::Private,
            NOW,
            AuthDecision::Allow,
        ),
        (
            "patch keyed secret wrong key → not found (oracle defense)",
            Action::Patch,
            Some(&keyed_secret),
            Caller::Keyed(other_key.clone()),
            Visibility::Private,
            NOW,
            AuthDecision::NotFound,
        ),
        // ── Patch / burned/expired ─────────────────────────────────────────
        (
            "patch burned keyed secret → gone",
            Action::Patch,
            Some(&burned_kd),
            Caller::Keyed(owner_key.clone()),
            Visibility::Private,
            NOW,
            AuthDecision::Gone,
        ),
        (
            "patch burned anon secret → gone (burned check before anon check)",
            Action::Patch,
            Some(&burned_anon),
            Caller::Anonymous,
            Visibility::Public,
            NOW,
            AuthDecision::Gone,
        ),
        // ── Burn / anonymous secret ────────────────────────────────────────
        (
            "burn anonymous secret anonymous → allow (capability model)",
            Action::Burn,
            Some(&anon_secret),
            Caller::Anonymous,
            Visibility::Public,
            NOW,
            AuthDecision::Allow,
        ),
        (
            "burn anonymous secret with any key → allow (capability model)",
            Action::Burn,
            Some(&anon_secret),
            Caller::Keyed(other_key.clone()),
            Visibility::Both,
            NOW,
            AuthDecision::Allow,
        ),
        // ── Burn / keyed secret ────────────────────────────────────────────
        (
            "burn keyed secret anonymous → unauthorized",
            Action::Burn,
            Some(&keyed_secret),
            Caller::Anonymous,
            Visibility::Private,
            NOW,
            AuthDecision::Unauthorized,
        ),
        (
            "burn keyed secret owner → allow",
            Action::Burn,
            Some(&keyed_secret),
            Caller::Keyed(owner_key.clone()),
            Visibility::Private,
            NOW,
            AuthDecision::Allow,
        ),
        (
            "burn keyed secret wrong key → not found (oracle defense)",
            Action::Burn,
            Some(&keyed_secret),
            Caller::Keyed(other_key.clone()),
            Visibility::Private,
            NOW,
            AuthDecision::NotFound,
        ),
        // ── Burn / burned ──────────────────────────────────────────────────
        (
            "burn already-burned secret → gone",
            Action::Burn,
            Some(&burned_anon),
            Caller::Anonymous,
            Visibility::Public,
            NOW,
            AuthDecision::Gone,
        ),
        (
            "burn already-burned keyed secret → gone",
            Action::Burn,
            Some(&burned_kd),
            Caller::Keyed(owner_key.clone()),
            Visibility::Private,
            NOW,
            AuthDecision::Gone,
        ),
    ];

    for (name, action, secret, caller, vis, now, expected) in &cases {
        let actual = authorize(*action, *secret, caller, *vis, *now);
        assert_eq!(&actual, expected, "FAILED: {name}");
    }
}

// ── Oracle defense test ──────────────────────────────────────────────────────

/// Every action that requires ownership must return NotFound for a wrong key,
/// never Unauthorized or Forbidden. This enforces the hash-existence oracle defense.
#[test]
fn wrong_key_always_returns_not_found() {
    let owner_key = make_key_with_id("owner");
    let other_key = make_key_with_id("other");
    let secret = active_keyed(&owner_key);

    for action in [Action::Audit, Action::Patch, Action::Burn] {
        let result = authorize(
            action,
            Some(&secret),
            &Caller::Keyed(other_key.clone()),
            Visibility::Private,
            NOW,
        );
        assert_eq!(
            result,
            AuthDecision::NotFound,
            "action {action:?} should return NotFound for wrong key, got {result:?}"
        );
    }
}

// ── status code mapping ──────────────────────────────────────────────────────

#[test]
fn auth_decision_status_codes() {
    use axum::http::StatusCode;

    assert_eq!(AuthDecision::Allow.into_status_code(), StatusCode::OK);
    assert_eq!(
        AuthDecision::Unauthorized.into_status_code(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        AuthDecision::BadRequest("x".to_string()).into_status_code(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        AuthDecision::MethodNotAllowed.into_status_code(),
        StatusCode::METHOD_NOT_ALLOWED
    );
    assert_eq!(
        AuthDecision::NotFound.into_status_code(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(AuthDecision::Gone.into_status_code(), StatusCode::GONE);
    assert_eq!(
        AuthDecision::Unavailable.into_status_code(),
        StatusCode::SERVICE_UNAVAILABLE
    );
}
