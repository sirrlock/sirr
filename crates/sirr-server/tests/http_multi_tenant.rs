//! HTTP-level integration tests for the multi-tenant system.
//!
//! These tests exercise the actual HTTP endpoints (via `axum_test::TestServer`)
//! instead of just the store layer, covering authentication, authorization,
//! routing, and org isolation.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use axum::{
    extract::{ConnectInfo, Request},
    middleware::{self, Next},
    response::Response,
    routing::{delete, get, patch, post},
    Router,
};
use axum_test::TestServer;
use http::Method;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tempfile::{tempdir, TempDir};

use sirr_server::{
    auth::{require_auth, require_master_key},
    handlers::*,
    license::LicenseStatus,
    org_handlers::*,
    store::{
        crypto,
        org::{OrgRecord, PrincipalKeyRecord, PrincipalRecord},
        Store,
    },
    AppState,
};

const MASTER_KEY: &str = "test-master-key-12345";

/// Middleware that injects a fake `ConnectInfo<SocketAddr>` for test environments
/// where we don't have a real TCP connection.
async fn inject_connect_info(mut req: Request, next: Next) -> Response {
    req.extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 12345))));
    next.run(req).await
}

/// Build a test app with all routes wired, returning the server, store, and
/// temp dir (kept alive so the db file is not deleted).
fn build_test_app() -> (TestServer, Store, TempDir) {
    let dir = tempdir().unwrap();
    let key = crypto::generate_key();
    let store = Store::open(&dir.path().join("test.db"), key).unwrap();

    let state = AppState {
        store: store.clone(),
        api_key: Some(MASTER_KEY.to_string()),
        license: LicenseStatus::Free,
        validator: None,
        webhook_sender: None,
        trusted_proxies: Arc::new(vec![]),
        redact_audit_keys: false,
        webhook_allowed_origins: Arc::new(vec![]),
        enable_public_bucket: true,
    };

    // Public bucket: read routes (no auth).
    let secret_read = Router::new().route("/secrets/{key}", get(get_secret).head(head_secret));

    // Public bucket: write routes (master key required).
    let protected_public = Router::new()
        .route("/secrets", get(list_secrets).post(create_secret))
        .route("/secrets/{key}", patch(patch_secret).delete(delete_secret))
        .route("/prune", post(prune_secrets))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            require_master_key,
        ));

    // Org routes (principal auth required).
    let org_protected = Router::new()
        .route("/orgs", post(create_org).get(list_orgs))
        .route("/orgs/{org_id}", delete(delete_org))
        .route(
            "/orgs/{org_id}/principals",
            post(create_principal).get(list_principals),
        )
        .route("/orgs/{org_id}/principals/{id}", delete(delete_principal))
        .route("/orgs/{org_id}/roles", post(create_role).get(list_roles))
        .route("/orgs/{org_id}/roles/{name}", delete(delete_role))
        .route("/me", get(get_me).patch(patch_me))
        .route("/me/keys", post(create_key))
        .route("/me/keys/{key_id}", delete(delete_key))
        .route(
            "/orgs/{org_id}/secrets",
            post(create_org_secret).get(list_org_secrets),
        )
        .route(
            "/orgs/{org_id}/secrets/{key}",
            get(get_org_secret)
                .head(head_org_secret)
                .patch(patch_org_secret)
                .delete(delete_org_secret),
        )
        .route("/orgs/{org_id}/prune", post(prune_org_secrets))
        .route("/orgs/{org_id}/audit", get(org_audit_events))
        .route(
            "/orgs/{org_id}/webhooks",
            post(create_org_webhook).get(list_org_webhooks),
        )
        .route("/orgs/{org_id}/webhooks/{id}", delete(delete_org_webhook))
        .layer(middleware::from_fn_with_state(state.clone(), require_auth));

    // The outermost layer injects ConnectInfo<SocketAddr> which handlers
    // extract via `ConnectInfo(addr): ConnectInfo<SocketAddr>`. In production
    // this comes from `into_make_service_with_connect_info`; in tests we
    // inject it as a request extension.
    let app: Router<()> = Router::new()
        .merge(secret_read)
        .merge(protected_public)
        .merge(org_protected)
        .with_state(state)
        .layer(middleware::from_fn(inject_connect_info));

    let server = TestServer::new(app);
    (server, store, dir)
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

/// Bootstrap an org + principal + key directly via the store.
/// Returns (org_id, principal_id, raw_api_key).
fn bootstrap_org_with_key(
    store: &Store,
    org_name: &str,
    principal_name: &str,
    role: &str,
) -> (String, String, String) {
    let now = now_secs();
    let org_id = format!("org_{org_name}");
    let principal_id = format!("p_{principal_name}");

    let raw_key = format!("sirr_key_{}", hex::encode(rand::random::<[u8; 16]>()));
    let key_hash = Sha256::digest(raw_key.as_bytes()).to_vec();

    store
        .put_org(&OrgRecord {
            id: org_id.clone(),
            name: org_name.into(),
            metadata: HashMap::new(),
            created_at: now,
        })
        .unwrap();

    store
        .put_principal(&PrincipalRecord {
            id: principal_id.clone(),
            org_id: org_id.clone(),
            name: principal_name.into(),
            role: role.into(),
            metadata: HashMap::new(),
            created_at: now,
        })
        .unwrap();

    store
        .put_principal_key(&PrincipalKeyRecord {
            id: format!("pk_{principal_name}"),
            principal_id: principal_id.clone(),
            org_id: org_id.clone(),
            name: "default_key".into(),
            key_hash,
            valid_after: now - 60,
            valid_before: now + 3600,
            created_at: now,
        })
        .unwrap();

    (org_id, principal_id, raw_key)
}

/// Same as bootstrap_org_with_key but creates a second key with a specific name.
fn add_named_key(
    store: &Store,
    org_id: &str,
    principal_id: &str,
    key_id: &str,
    key_name: &str,
) -> String {
    let now = now_secs();
    let raw_key = format!("sirr_key_{}", hex::encode(rand::random::<[u8; 16]>()));
    let key_hash = Sha256::digest(raw_key.as_bytes()).to_vec();

    store
        .put_principal_key(&PrincipalKeyRecord {
            id: key_id.into(),
            principal_id: principal_id.into(),
            org_id: org_id.into(),
            name: key_name.into(),
            key_hash,
            valid_after: now - 60,
            valid_before: now + 3600,
            created_at: now,
        })
        .unwrap();

    raw_key
}

// ── Test 1: Public bucket push and read ─────────────────────────────────────

#[tokio::test]
async fn public_bucket_push_and_read() {
    let (server, _store, _dir) = build_test_app();

    // POST /secrets — value-only, server generates random ID → 201
    let resp = server
        .post("/secrets")
        .authorization_bearer(MASTER_KEY)
        .json(&json!({"value": "abc123", "max_reads": 3}))
        .await;
    resp.assert_status(axum::http::StatusCode::CREATED);
    let body: Value = resp.json();
    let id = body["id"].as_str().expect("response should contain 'id'");
    assert_eq!(id.len(), 64, "ID should be 256-bit hex (64 chars)");

    // GET /secrets/{id} without auth → 200
    let resp = server.get(&format!("/secrets/{id}")).await;
    resp.assert_status(axum::http::StatusCode::OK);
    let body: Value = resp.json();
    assert_eq!(body["value"], "abc123");
    assert_eq!(body["id"], id);

    // HEAD /secrets/{id} → 200 with X-Sirr headers
    let resp = server.method(Method::HEAD, &format!("/secrets/{id}")).await;
    resp.assert_status(axum::http::StatusCode::OK);
    assert!(resp.headers().get("x-sirr-read-count").is_some());
    assert!(resp.headers().get("x-sirr-status").is_some());

    // GET /secrets without auth → 401 (list requires master key)
    let resp = server.get("/secrets").await;
    resp.assert_status(axum::http::StatusCode::UNAUTHORIZED);
}

// ── Test 2: Org full lifecycle ──────────────────────────────────────────────

#[tokio::test]
async fn org_full_lifecycle() {
    let (server, store, _dir) = build_test_app();

    // Bootstrap org + principal + key directly in store.
    let (org_id, _principal_id, raw_key) =
        bootstrap_org_with_key(&store, "acme", "ci-bot", "writer");

    // POST org secret with principal key → 201
    let resp = server
        .post(&format!("/orgs/{org_id}/secrets"))
        .authorization_bearer(&raw_key)
        .json(&json!({"key": "DB_URL", "value": "postgres://localhost/db"}))
        .await;
    resp.assert_status(axum::http::StatusCode::CREATED);

    // GET org secret with principal key → 200
    let resp = server
        .get(&format!("/orgs/{org_id}/secrets/DB_URL"))
        .authorization_bearer(&raw_key)
        .await;
    resp.assert_status(axum::http::StatusCode::OK);
    let body: Value = resp.json();
    assert_eq!(body["value"], "postgres://localhost/db");

    // GET org secrets list without auth → 401
    let resp = server.get(&format!("/orgs/{org_id}/secrets")).await;
    resp.assert_status(axum::http::StatusCode::UNAUTHORIZED);

    // GET /secrets/DB_URL (public bucket) → 404 (not in public bucket)
    let resp = server.get("/secrets/DB_URL").await;
    resp.assert_status(axum::http::StatusCode::NOT_FOUND);
}

// ── Test 2b: Org duplicate key returns 409 ─────────────────────────────────

#[tokio::test]
async fn org_duplicate_key_returns_409() {
    let (server, store, _dir) = build_test_app();

    let (org_id, _principal_id, raw_key) =
        bootstrap_org_with_key(&store, "dupes", "alice", "writer");

    // First push → 201
    let resp = server
        .post(&format!("/orgs/{org_id}/secrets"))
        .authorization_bearer(&raw_key)
        .json(&json!({"key": "TOKEN", "value": "first"}))
        .await;
    resp.assert_status(axum::http::StatusCode::CREATED);

    // Second push with same key → 409 Conflict
    let resp = server
        .post(&format!("/orgs/{org_id}/secrets"))
        .authorization_bearer(&raw_key)
        .json(&json!({"key": "TOKEN", "value": "second"}))
        .await;
    resp.assert_status(axum::http::StatusCode::CONFLICT);
    let body: Value = resp.json();
    assert_eq!(body["error"], "secret_exists");

    // Original value should still be intact
    let resp = server
        .get(&format!("/orgs/{org_id}/secrets/TOKEN"))
        .authorization_bearer(&raw_key)
        .await;
    resp.assert_status(axum::http::StatusCode::OK);
    assert_eq!(resp.json::<Value>()["value"], "first");
}

// ── Test 3: Org isolation between orgs ──────────────────────────────────────

#[tokio::test]
async fn org_isolation_between_orgs() {
    let (server, store, _dir) = build_test_app();

    let (org_a, _pa, key_a) = bootstrap_org_with_key(&store, "alpha", "alice", "writer");
    let (org_b, _pb, key_b) = bootstrap_org_with_key(&store, "beta", "bob", "writer");

    // Push "SECRET" to org_a
    let resp = server
        .post(&format!("/orgs/{org_a}/secrets"))
        .authorization_bearer(&key_a)
        .json(&json!({"key": "SECRET", "value": "value_a"}))
        .await;
    resp.assert_status(axum::http::StatusCode::CREATED);

    // Push "SECRET" to org_b
    let resp = server
        .post(&format!("/orgs/{org_b}/secrets"))
        .authorization_bearer(&key_b)
        .json(&json!({"key": "SECRET", "value": "value_b"}))
        .await;
    resp.assert_status(axum::http::StatusCode::CREATED);

    // GET with correct keys
    let resp = server
        .get(&format!("/orgs/{org_a}/secrets/SECRET"))
        .authorization_bearer(&key_a)
        .await;
    resp.assert_status(axum::http::StatusCode::OK);
    assert_eq!(resp.json::<Value>()["value"], "value_a");

    let resp = server
        .get(&format!("/orgs/{org_b}/secrets/SECRET"))
        .authorization_bearer(&key_b)
        .await;
    resp.assert_status(axum::http::StatusCode::OK);
    assert_eq!(resp.json::<Value>()["value"], "value_b");

    // Cross-org access: key_b tries to read org_a → 403
    let resp = server
        .get(&format!("/orgs/{org_a}/secrets/SECRET"))
        .authorization_bearer(&key_b)
        .await;
    resp.assert_status(axum::http::StatusCode::FORBIDDEN);
}

// ── Test 4: Public and org secrets coexist ──────────────────────────────────

#[tokio::test]
async fn public_and_org_secrets_coexist() {
    let (server, store, _dir) = build_test_app();

    let (org_id, _pid, raw_key) = bootstrap_org_with_key(&store, "coexist", "agent", "writer");

    // Push to public bucket (value-only; server returns random id)
    let resp = server
        .post("/secrets")
        .authorization_bearer(MASTER_KEY)
        .json(&json!({"value": "public_value"}))
        .await;
    resp.assert_status(axum::http::StatusCode::CREATED);
    let public_id = resp.json::<Value>()["id"].as_str().unwrap().to_owned();
    assert!(!public_id.is_empty());

    // Push SHARED to org
    let resp = server
        .post(&format!("/orgs/{org_id}/secrets"))
        .authorization_bearer(&raw_key)
        .json(&json!({"key": "SHARED", "value": "org_value"}))
        .await;
    resp.assert_status(axum::http::StatusCode::CREATED);

    // GET public by id → public_value
    let resp = server.get(&format!("/secrets/{public_id}")).await;
    resp.assert_status(axum::http::StatusCode::OK);
    assert_eq!(resp.json::<Value>()["value"], "public_value");

    // GET org → org_value
    let resp = server
        .get(&format!("/orgs/{org_id}/secrets/SHARED"))
        .authorization_bearer(&raw_key)
        .await;
    resp.assert_status(axum::http::StatusCode::OK);
    assert_eq!(resp.json::<Value>()["value"], "org_value");
}

// ── Test 5: Key binding via HTTP ────────────────────────────────────────────

#[tokio::test]
async fn key_binding_via_http() {
    let (server, store, _dir) = build_test_app();

    let (org_id, principal_id, _default_key) =
        bootstrap_org_with_key(&store, "keybind", "deployer", "writer");

    // Create two named keys for the same principal.
    let deploy_key = add_named_key(&store, &org_id, &principal_id, "pk_deploy", "deploy_key");
    let ci_key = add_named_key(&store, &org_id, &principal_id, "pk_ci", "ci_key");

    // Push secret with allowed_keys: ["deploy_key"]
    let resp = server
        .post(&format!("/orgs/{org_id}/secrets"))
        .authorization_bearer(&deploy_key)
        .json(&json!({
            "key": "DEPLOY_TOKEN",
            "value": "secret-deploy-value",
            "allowed_keys": ["deploy_key"]
        }))
        .await;
    resp.assert_status(axum::http::StatusCode::CREATED);

    // GET with deploy_key → 200
    let resp = server
        .get(&format!("/orgs/{org_id}/secrets/DEPLOY_TOKEN"))
        .authorization_bearer(&deploy_key)
        .await;
    resp.assert_status(axum::http::StatusCode::OK);
    assert_eq!(resp.json::<Value>()["value"], "secret-deploy-value");

    // GET with ci_key → 403 (key not authorized)
    let resp = server
        .get(&format!("/orgs/{org_id}/secrets/DEPLOY_TOKEN"))
        .authorization_bearer(&ci_key)
        .await;
    resp.assert_status(axum::http::StatusCode::FORBIDDEN);
}

// ── Test 6: Role enforcement via HTTP ───────────────────────────────────────

#[tokio::test]
async fn role_enforcement_via_http() {
    let (server, store, _dir) = build_test_app();

    // Create an org with a writer who can push secrets.
    let (org_id, _writer_pid, writer_key) =
        bootstrap_org_with_key(&store, "roles", "writer-user", "writer");

    // Create a reader principal in the same org.
    let reader_pid = "p_reader_user";
    let now = now_secs();
    store
        .put_principal(&PrincipalRecord {
            id: reader_pid.into(),
            org_id: org_id.clone(),
            name: "reader-user".into(),
            role: "reader".into(),
            metadata: HashMap::new(),
            created_at: now,
        })
        .unwrap();

    let reader_key = add_named_key(&store, &org_id, reader_pid, "pk_reader", "reader_key");

    // Writer pushes a secret.
    let resp = server
        .post(&format!("/orgs/{org_id}/secrets"))
        .authorization_bearer(&writer_key)
        .json(&json!({"key": "READABLE", "value": "hello-reader"}))
        .await;
    resp.assert_status(axum::http::StatusCode::CREATED);

    // Reader tries to create a secret → 403 (no create permission).
    let resp = server
        .post(&format!("/orgs/{org_id}/secrets"))
        .authorization_bearer(&reader_key)
        .json(&json!({"key": "NOPE", "value": "denied"}))
        .await;
    resp.assert_status(axum::http::StatusCode::FORBIDDEN);

    // Reader (ReadMy only, no ReadOrg) tries to read writer's secret.
    // The ownership check blocks this — reader doesn't own it.
    let resp = server
        .get(&format!("/orgs/{org_id}/secrets/READABLE"))
        .authorization_bearer(&reader_key)
        .await;
    resp.assert_status(axum::http::StatusCode::FORBIDDEN);
}

// ── Test: Master key can manage orgs via HTTP ───────────────────────────────

#[tokio::test]
async fn master_key_creates_and_lists_orgs() {
    let (server, _store, _dir) = build_test_app();

    // Create org via master key
    let resp = server
        .post("/orgs")
        .authorization_bearer(MASTER_KEY)
        .json(&json!({"name": "test-org"}))
        .await;
    resp.assert_status(axum::http::StatusCode::CREATED);
    let body: Value = resp.json();
    let org_id = body["id"].as_str().unwrap().to_string();
    assert_eq!(body["name"], "test-org");

    // List orgs via master key
    let resp = server.get("/orgs").authorization_bearer(MASTER_KEY).await;
    resp.assert_status(axum::http::StatusCode::OK);
    let body: Value = resp.json();
    let orgs = body["orgs"].as_array().unwrap();
    assert!(orgs.iter().any(|o| o["id"].as_str() == Some(&org_id)));

    // Create principal via master key
    let resp = server
        .post(&format!("/orgs/{org_id}/principals"))
        .authorization_bearer(MASTER_KEY)
        .json(&json!({"name": "new-principal", "role": "writer"}))
        .await;
    resp.assert_status(axum::http::StatusCode::CREATED);
    let body: Value = resp.json();
    assert_eq!(body["name"], "new-principal");
    assert_eq!(body["role"], "writer");
}

// ── Test: Unauthenticated requests to protected endpoints ───────────────────

#[tokio::test]
async fn unauthenticated_requests_rejected() {
    let (server, _store, _dir) = build_test_app();

    // Org endpoints without auth → 401
    let resp = server.get("/orgs").await;
    resp.assert_status(axum::http::StatusCode::UNAUTHORIZED);

    let resp = server.post("/orgs").json(&json!({"name": "nope"})).await;
    resp.assert_status(axum::http::StatusCode::UNAUTHORIZED);

    // Public bucket write without auth → 401
    let resp = server
        .post("/secrets")
        .json(&json!({"key": "X", "value": "Y"}))
        .await;
    resp.assert_status(axum::http::StatusCode::UNAUTHORIZED);

    // Public bucket read without auth → works (404 because key doesn't exist)
    let resp = server.get("/secrets/NONEXISTENT").await;
    resp.assert_status(axum::http::StatusCode::NOT_FOUND);
}

// ── Test: Wrong key for wrong org returns 403 ───────────────────────────────

#[tokio::test]
async fn wrong_org_key_returns_forbidden() {
    let (server, store, _dir) = build_test_app();

    let (org_a, _pa, _key_a) = bootstrap_org_with_key(&store, "orgA", "userA", "writer");
    let (_org_b, _pb, key_b) = bootstrap_org_with_key(&store, "orgB", "userB", "writer");

    // key_b tries to push to org_a → 403
    let resp = server
        .post(&format!("/orgs/{org_a}/secrets"))
        .authorization_bearer(&key_b)
        .json(&json!({"key": "CROSS", "value": "nope"}))
        .await;
    resp.assert_status(axum::http::StatusCode::FORBIDDEN);

    // key_b tries to list org_a secrets → 403
    let resp = server
        .get(&format!("/orgs/{org_a}/secrets"))
        .authorization_bearer(&key_b)
        .await;
    resp.assert_status(axum::http::StatusCode::FORBIDDEN);
}
