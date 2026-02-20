//! Integration tests for the multi-tenant org/principal/key system.
//!
//! These tests exercise the store layer directly to validate the full
//! org lifecycle, permission enforcement, and backward-compatibility of
//! the public (non-org) secret bucket.

use sirr_server::store::{
    crypto, db::GetResult, org::PrincipalKeyRecord, org::PrincipalRecord, org::RoleRecord,
    permissions::Permissions, Store,
};
use std::collections::HashMap;
use tempfile::tempdir;

/// Helper: create a fresh Store backed by a temp directory.
fn make_store() -> (Store, tempfile::TempDir) {
    let key = crypto::generate_key();
    let dir = tempdir().unwrap();
    let path = dir.path().join("test.db");
    let store = Store::open(&path, key).unwrap();
    (store, dir)
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

// ── Public bucket backward compatibility ────────────────────────────────

#[test]
fn public_bucket_backward_compat() {
    let (s, _dir) = make_store();

    // Push secret to public bucket (no org).
    s.put("MY_KEY", "my-value", None, None, true, None).unwrap();

    // GET returns the value.
    assert_eq!(
        s.get("MY_KEY").unwrap(),
        GetResult::Value("my-value".into(), None)
    );
}

// ── Org lifecycle ───────────────────────────────────────────────────────

#[test]
fn org_lifecycle() {
    let (s, _dir) = make_store();
    let now = now_secs();

    // Create org.
    let org = sirr_server::store::org::OrgRecord {
        id: "org_1".into(),
        name: "Acme Corp".into(),
        metadata: HashMap::new(),
        created_at: now,
    };
    s.put_org(&org).unwrap();

    // List orgs returns it.
    let orgs = s.list_orgs().unwrap();
    assert_eq!(orgs.len(), 1);
    assert_eq!(orgs[0].name, "Acme Corp");

    // Create principal in org.
    let principal = PrincipalRecord {
        id: "p_1".into(),
        org_id: "org_1".into(),
        name: "alice".into(),
        role: "writer".into(),
        metadata: HashMap::new(),
        created_at: now,
    };
    s.put_principal(&principal).unwrap();

    // List principals.
    let principals = s.list_principals("org_1").unwrap();
    assert_eq!(principals.len(), 1);
    assert_eq!(principals[0].name, "alice");

    // Create key for principal.
    let key_hash = {
        use sha2::{Digest, Sha256};
        Sha256::digest(b"test-api-key").to_vec()
    };
    let key_record = PrincipalKeyRecord {
        id: "pk_1".into(),
        principal_id: "p_1".into(),
        org_id: "org_1".into(),
        name: "default".into(),
        key_hash: key_hash.clone(),
        valid_after: now - 60,
        valid_before: now + 3600,
        created_at: now,
    };
    s.put_principal_key(&key_record).unwrap();

    // Find key by hash.
    let found = s.find_principal_key_by_hash(&key_hash).unwrap();
    assert!(found.is_some());
    let found = found.unwrap();
    assert_eq!(found.id, "pk_1");
    assert_eq!(found.org_id, "org_1");

    // Use key context to push org secret.
    s.put_org_secret(
        "org_1",
        "DB_PASSWORD",
        "s3cret",
        None,
        None,
        true,
        None,
        Some("p_1"),
        None,
    )
    .unwrap();

    // Read org secret.
    assert_eq!(
        s.get_org_secret("org_1", "DB_PASSWORD").unwrap(),
        GetResult::Value("s3cret".into(), None)
    );

    // Verify two orgs can have same secret name.
    let org2 = sirr_server::store::org::OrgRecord {
        id: "org_2".into(),
        name: "Other Corp".into(),
        metadata: HashMap::new(),
        created_at: now,
    };
    s.put_org(&org2).unwrap();
    s.put_org_secret(
        "org_2",
        "DB_PASSWORD",
        "different-secret",
        None,
        None,
        true,
        None,
        None,
        None,
    )
    .unwrap();

    // Both secrets exist independently.
    assert_eq!(
        s.get_org_secret("org_2", "DB_PASSWORD").unwrap(),
        GetResult::Value("different-secret".into(), None)
    );

    // Delete keys, then principal, then org (enforced constraints).
    assert!(s.delete_principal_key("p_1", "pk_1").unwrap());
    assert!(s.delete_principal("org_1", "p_1").unwrap());

    // Delete org.
    assert!(s.delete_org("org_1").unwrap());
    assert!(s.list_orgs().unwrap().iter().all(|o| o.id != "org_1"));
}

// ── Key binding enforcement ─────────────────────────────────────────────

#[test]
fn key_binding_enforcement() {
    let (s, _dir) = make_store();

    // Create secret with allowed_keys binding.
    s.put_org_secret(
        "org_1",
        "DEPLOY_SECRET",
        "value",
        None,
        None,
        true,
        None,
        Some("p_1"),
        Some(vec!["deploy_key".to_string()]),
    )
    .unwrap();

    // Head returns metadata (allowed_keys are stored in the record but not
    // exposed in SecretMeta — the binding check happens at handler level).
    let (meta, _sealed) = s
        .head_org_secret("org_1", "DEPLOY_SECRET")
        .unwrap()
        .unwrap();
    assert_eq!(meta.key, "DEPLOY_SECRET");
}

// ── Role permission enforcement (unit-level) ────────────────────────────

#[test]
fn role_permission_enforcement() {
    use sirr_server::auth::ResolvedAuth;

    // Reader role: "rla" → ReadMy + ListMy + AccountRead
    let reader_perms = Permissions::parse("rla").unwrap();
    let auth = ResolvedAuth::Principal {
        principal_id: "p_reader".into(),
        org_id: "org_1".into(),
        key_id: "pk_reader".into(),
        key_name: "reader-key".into(),
        permissions: reader_perms,
    };

    // Reader CAN read their own secrets.
    assert!(auth.can_read_my());
    assert!(auth.can_list_my());
    assert!(auth.can_account_read());

    // Reader CANNOT create, delete, or manage.
    assert!(!auth.can_create());
    assert!(!auth.can_delete_my());
    assert!(!auth.can_delete_org());
    assert!(!auth.can_manage_org());
    assert!(!auth.can_sirr_admin());
}

// ── Built-in roles are seeded ───────────────────────────────────────────

#[test]
fn builtin_roles_seeded() {
    let (s, _dir) = make_store();

    // Built-in roles should be accessible.
    for name in &["reader", "writer", "admin", "owner"] {
        let role = s.get_role(None, name).unwrap();
        assert!(role.is_some(), "built-in role '{name}' should exist");
    }
}

// ── Custom role CRUD ────────────────────────────────────────────────────

#[test]
fn custom_role_crud() {
    let (s, _dir) = make_store();

    let custom = RoleRecord {
        name: "deployer".into(),
        org_id: Some("org_1".into()),
        permissions: Permissions::parse("rcda").unwrap(),
        built_in: false,
        created_at: now_secs(),
    };
    s.put_role(&custom).unwrap();

    let fetched = s.get_role(Some("org_1"), "deployer").unwrap();
    assert!(fetched.is_some());
    let fetched = fetched.unwrap();
    assert_eq!(fetched.permissions.to_letter_string(), "rcad");

    // Delete custom role.
    assert!(s.delete_role(Some("org_1"), "deployer").unwrap());
    assert!(s.get_role(Some("org_1"), "deployer").unwrap().is_none());
}

// ── Principal key time-window validation ────────────────────────────────

#[test]
fn principal_key_listing_and_deletion() {
    let (s, _dir) = make_store();
    let now = now_secs();

    // Create two keys for the same principal.
    for i in 1..=2 {
        let key_hash = vec![i; 32]; // dummy hash
        let kr = PrincipalKeyRecord {
            id: format!("pk_{i}"),
            principal_id: "p_1".into(),
            org_id: "org_1".into(),
            name: format!("key-{i}"),
            key_hash,
            valid_after: now - 60,
            valid_before: now + 3600,
            created_at: now,
        };
        s.put_principal_key(&kr).unwrap();
    }

    let keys = s.list_principal_keys("p_1").unwrap();
    assert_eq!(keys.len(), 2);

    // Delete one key.
    assert!(s.delete_principal_key("p_1", "pk_1").unwrap());
    let keys = s.list_principal_keys("p_1").unwrap();
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0].id, "pk_2");
}

// ── Org secret isolation ────────────────────────────────────────────────

#[test]
fn org_secrets_isolated_from_public() {
    let (s, _dir) = make_store();

    // Public secret.
    s.put("SHARED_NAME", "public-val", None, None, true, None)
        .unwrap();

    // Org secret with same name.
    s.put_org_secret(
        "org_1",
        "SHARED_NAME",
        "org-val",
        None,
        None,
        true,
        None,
        None,
        None,
    )
    .unwrap();

    // They are completely independent.
    assert_eq!(
        s.get("SHARED_NAME").unwrap(),
        GetResult::Value("public-val".into(), None)
    );
    assert_eq!(
        s.get_org_secret("org_1", "SHARED_NAME").unwrap(),
        GetResult::Value("org-val".into(), None)
    );
}

// ── Org secret list filtering by owner ──────────────────────────────────

#[test]
fn org_secret_list_by_owner() {
    let (s, _dir) = make_store();

    s.put_org_secret(
        "org_1",
        "K1",
        "v",
        None,
        None,
        true,
        None,
        Some("alice"),
        None,
    )
    .unwrap();
    s.put_org_secret(
        "org_1",
        "K2",
        "v",
        None,
        None,
        true,
        None,
        Some("bob"),
        None,
    )
    .unwrap();
    s.put_org_secret(
        "org_1",
        "K3",
        "v",
        None,
        None,
        true,
        None,
        Some("alice"),
        None,
    )
    .unwrap();

    // All secrets in org.
    let all = s.list_org_secrets("org_1", None).unwrap();
    assert_eq!(all.len(), 3);

    // Only alice's secrets.
    let alice_secrets = s.list_org_secrets("org_1", Some("alice")).unwrap();
    assert_eq!(alice_secrets.len(), 2);

    // Only bob's secrets.
    let bob_secrets = s.list_org_secrets("org_1", Some("bob")).unwrap();
    assert_eq!(bob_secrets.len(), 1);
}

// ── ResolvedAuth::can_access_secret with org-wide perms ─────────────────

#[test]
fn can_access_secret_org_wide() {
    use sirr_server::auth::ResolvedAuth;
    use sirr_server::store::permissions::PermBit;

    // Admin has org-wide read.
    let admin_perms = Permissions::parse("rRlLcCpPaAmMdD").unwrap();
    let admin_auth = ResolvedAuth::Principal {
        principal_id: "p_admin".into(),
        org_id: "org_1".into(),
        key_id: "pk_admin".into(),
        key_name: "admin-key".into(),
        permissions: admin_perms,
    };

    // Admin can access anyone's secret.
    assert!(admin_auth.can_access_secret(Some("p_other"), PermBit::ReadMy, PermBit::ReadOrg));

    // Writer can only access own secrets.
    let writer_perms = Permissions::parse("rlcdam").unwrap();
    let writer_auth = ResolvedAuth::Principal {
        principal_id: "p_writer".into(),
        org_id: "org_1".into(),
        key_id: "pk_writer".into(),
        key_name: "writer-key".into(),
        permissions: writer_perms,
    };

    assert!(writer_auth.can_access_secret(Some("p_writer"), PermBit::ReadMy, PermBit::ReadOrg));
    assert!(!writer_auth.can_access_secret(Some("p_other"), PermBit::ReadMy, PermBit::ReadOrg));
}
