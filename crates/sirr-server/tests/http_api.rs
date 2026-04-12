//! Integration tests for the Sirr HTTP API — Phase 3.
//!
//! Each endpoint has multiple test cases covering the authorization matrix
//! from spec §6. Uses `axum_test::TestServer` against the real router.

use std::sync::Arc;

use axum::http::{header, Method, StatusCode};
use axum_test::TestServer;
use serde_json::{json, Value};
use sirr_server::{
    router,
    store::{crypto, Store, Visibility},
    AppState, WebhookSender,
};
use tempfile::tempdir;

// ── Test helpers ──────────────────────────────────────────────────────────────

struct Setup {
    server: TestServer,
    store: Arc<Store>,
}

fn setup() -> Setup {
    setup_with_visibility(Visibility::Public)
}

fn setup_with_visibility(vis: Visibility) -> Setup {
    let dir = tempdir().unwrap();
    let store = Arc::new(Store::open(dir.path().join("test.db")).unwrap());

    let key = Arc::new(crypto::generate_key());
    let visibility = Arc::new(tokio::sync::RwLock::new(vis));
    let state = AppState {
        store: store.clone(),
        encryption_key: key,
        visibility,
        webhook_sender: WebhookSender::new(),
        base_url: "http://test".to_string(),
    };
    let server = TestServer::new(router(state));
    Setup { server, store }
}

/// Create an API key in the store and return (record, bearer token hex).
fn create_key(store: &Store) -> (sirr_server::KeyRecord, String) {
    store.create_key("test-key", None, None, None).unwrap()
}

// Helper to add a Bearer token to a request.
fn auth_header(token: &str) -> (header::HeaderName, header::HeaderValue) {
    (
        header::AUTHORIZATION,
        format!("Bearer {token}").parse().unwrap(),
    )
}

// ── POST /secret ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn post_public_anon_creates_ok() {
    let s = setup();
    let resp = s
        .server
        .post("/secret")
        .json(&json!({"value": "hello"}))
        .await;
    resp.assert_status_success();
    let body: Value = resp.json();
    assert!(!body["hash"].as_str().unwrap().is_empty());
    assert!(body["url"].as_str().unwrap().contains("/secret/"));
    assert_eq!(body["owned"], json!(false));
}

#[tokio::test]
async fn post_public_keyed_returns_400() {
    let s = setup(); // public mode
    let (_key_record, token) = create_key(&s.store);
    let (name, value) = auth_header(&token);
    let resp = s
        .server
        .post("/secret")
        .add_header(name, value)
        .json(&json!({"value": "hello"}))
        .await;
    resp.assert_status(StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn post_private_anon_returns_401() {
    let s = setup_with_visibility(Visibility::Private);
    let resp = s
        .server
        .post("/secret")
        .json(&json!({"value": "hello"}))
        .await;
    resp.assert_status(StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn post_private_keyed_creates_ok_with_owned_true() {
    let s = setup_with_visibility(Visibility::Private);
    let (_key_record, token) = create_key(&s.store);
    let (name, value) = auth_header(&token);
    let resp = s
        .server
        .post("/secret")
        .add_header(name, value)
        .json(&json!({"value": "owned-secret"}))
        .await;
    resp.assert_status_success();
    let body: Value = resp.json();
    assert_eq!(body["owned"], json!(true));
}

#[tokio::test]
async fn post_both_anon_ok() {
    let s = setup_with_visibility(Visibility::Both);
    let resp = s
        .server
        .post("/secret")
        .json(&json!({"value": "anon-in-both"}))
        .await;
    resp.assert_status_success();
    let body: Value = resp.json();
    assert_eq!(body["owned"], json!(false));
}

#[tokio::test]
async fn post_both_keyed_ok() {
    let s = setup_with_visibility(Visibility::Both);
    let (_key_record, token) = create_key(&s.store);
    let (name, value) = auth_header(&token);
    let resp = s
        .server
        .post("/secret")
        .add_header(name, value)
        .json(&json!({"value": "keyed-in-both"}))
        .await;
    resp.assert_status_success();
    let body: Value = resp.json();
    assert_eq!(body["owned"], json!(true));
}

#[tokio::test]
async fn post_none_returns_503() {
    let s = setup_with_visibility(Visibility::None);
    let resp = s
        .server
        .post("/secret")
        .json(&json!({"value": "blocked"}))
        .await;
    resp.assert_status(StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn post_with_prefix_hash_starts_with_prefix() {
    let s = setup();
    let resp = s
        .server
        .post("/secret")
        .json(&json!({"value": "hi", "prefix": "db1_"}))
        .await;
    resp.assert_status_success();
    let body: Value = resp.json();
    let hash = body["hash"].as_str().unwrap();
    assert!(
        hash.starts_with("db1_"),
        "hash should start with prefix: {hash}"
    );
}

#[tokio::test]
async fn post_with_ttl_sets_expires_at() {
    let s = setup();
    let resp = s
        .server
        .post("/secret")
        .json(&json!({"value": "ttl-secret", "ttl_seconds": 3600}))
        .await;
    resp.assert_status_success();
    let body: Value = resp.json();
    assert!(
        body["expires_at"].is_number(),
        "expires_at should be a number"
    );
}

#[tokio::test]
async fn post_with_reads_sets_reads_remaining() {
    let s = setup();
    let resp = s
        .server
        .post("/secret")
        .json(&json!({"value": "read-limit", "reads": 3}))
        .await;
    resp.assert_status_success();
    let body: Value = resp.json();
    assert_eq!(body["reads_remaining"], json!(3));
}

#[tokio::test]
async fn post_invalid_prefix_returns_400() {
    let s = setup();
    // Prefix with uppercase — invalid per [a-z0-9_-]{1,16}
    let resp = s
        .server
        .post("/secret")
        .json(&json!({"value": "hi", "prefix": "DB1_"}))
        .await;
    resp.assert_status(StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn post_prefix_length_boundary() {
    let s = setup();
    // 15 chars — valid
    let resp = s
        .server
        .post("/secret")
        .json(&json!({"value": "hi", "prefix": "aaaaaaaaaaaaa__"}))
        .await;
    resp.assert_status_success();

    // 16 chars — at the limit, valid
    let resp2 = s
        .server
        .post("/secret")
        .json(&json!({"value": "hi", "prefix": "aaaaaaaaaaaaa___"}))
        .await;
    resp2.assert_status_success();

    // 17 chars — over limit
    let resp3 = s
        .server
        .post("/secret")
        .json(&json!({"value": "hi", "prefix": "aaaaaaaaaaaaa____"}))
        .await;
    resp3.assert_status(StatusCode::BAD_REQUEST);
}

// ── GET /secret/{hash} ────────────────────────────────────────────────────────

async fn create_and_get_hash(setup: &Setup, value: &str) -> String {
    let resp = setup
        .server
        .post("/secret")
        .json(&json!({"value": value}))
        .await;
    resp.assert_status_success();
    resp.json::<Value>()["hash"].as_str().unwrap().to_string()
}

#[tokio::test]
async fn get_returns_value_as_plain_text() {
    let s = setup();
    let hash = create_and_get_hash(&s, "my-secret-value").await;
    let resp = s.server.get(&format!("/secret/{hash}")).await;
    resp.assert_status_success();
    assert_eq!(resp.text(), "my-secret-value");
}

#[tokio::test]
async fn get_with_accept_json_returns_json() {
    let s = setup();
    let hash = create_and_get_hash(&s, "json-value").await;
    let resp = s
        .server
        .get(&format!("/secret/{hash}"))
        .add_header(
            header::ACCEPT,
            "application/json".parse::<header::HeaderValue>().unwrap(),
        )
        .await;
    resp.assert_status_success();
    let body: Value = resp.json();
    assert_eq!(body["value"], json!("json-value"));
}

#[tokio::test]
async fn get_consumes_read_counter() {
    let s = setup();
    let resp = s
        .server
        .post("/secret")
        .json(&json!({"value": "countable", "reads": 3}))
        .await;
    resp.assert_status_success();
    let hash = resp.json::<Value>()["hash"].as_str().unwrap().to_string();

    for _ in 0..3 {
        s.server
            .get(&format!("/secret/{hash}"))
            .await
            .assert_status_success();
    }
    // Fourth read — burned.
    s.server
        .get(&format!("/secret/{hash}"))
        .await
        .assert_status(StatusCode::GONE);
}

#[tokio::test]
async fn get_last_read_burns_secret() {
    let s = setup();
    let resp = s
        .server
        .post("/secret")
        .json(&json!({"value": "burn-me", "reads": 1}))
        .await;
    resp.assert_status_success();
    let hash = resp.json::<Value>()["hash"].as_str().unwrap().to_string();

    s.server
        .get(&format!("/secret/{hash}"))
        .await
        .assert_status_success();
    s.server
        .get(&format!("/secret/{hash}"))
        .await
        .assert_status(StatusCode::GONE);
}

#[tokio::test]
async fn get_nonexistent_hash_returns_410() {
    let s = setup();
    // Existence oracle defense: hashes that never existed also return 410.
    s.server
        .get("/secret/deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
        .await
        .assert_status(StatusCode::GONE);
}

#[tokio::test]
async fn get_none_visibility_returns_503() {
    let s = setup_with_visibility(Visibility::None);
    s.server
        .get("/secret/deadbeef")
        .await
        .assert_status(StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn get_unlimited_reads_does_not_burn() {
    let s = setup();
    let hash = create_and_get_hash(&s, "unlimited").await;
    for _ in 0..5 {
        s.server
            .get(&format!("/secret/{hash}"))
            .await
            .assert_status_success();
    }
}

// ── HEAD /secret/{hash} ───────────────────────────────────────────────────────

#[tokio::test]
async fn head_returns_200_with_sirr_headers() {
    let s = setup();
    let resp = s
        .server
        .post("/secret")
        .json(&json!({"value": "head-me", "reads": 5, "ttl_seconds": 3600}))
        .await;
    resp.assert_status_success();
    let hash = resp.json::<Value>()["hash"].as_str().unwrap().to_string();

    let resp = s
        .server
        .method(Method::HEAD, &format!("/secret/{hash}"))
        .await;
    resp.assert_status_success();

    let headers = resp.headers();
    assert!(
        headers.contains_key("x-sirr-created"),
        "missing x-sirr-created"
    );
    assert!(
        headers.contains_key("x-sirr-ttl-expires"),
        "missing x-sirr-ttl-expires"
    );
    assert!(
        headers.contains_key("x-sirr-reads-remaining"),
        "missing x-sirr-reads-remaining"
    );
    assert!(headers.contains_key("x-sirr-owned"), "missing x-sirr-owned");
}

#[tokio::test]
async fn head_does_not_consume_read() {
    let s = setup();
    let resp = s
        .server
        .post("/secret")
        .json(&json!({"value": "headonly", "reads": 1}))
        .await;
    resp.assert_status_success();
    let hash = resp.json::<Value>()["hash"].as_str().unwrap().to_string();

    // HEAD three times — should never burn the secret.
    for _ in 0..3 {
        s.server
            .method(Method::HEAD, &format!("/secret/{hash}"))
            .await
            .assert_status_success();
    }
    // GET should still work (reads=1 not consumed by HEAD).
    s.server
        .get(&format!("/secret/{hash}"))
        .await
        .assert_status_success();
    // Now burned.
    s.server
        .get(&format!("/secret/{hash}"))
        .await
        .assert_status(StatusCode::GONE);
}

#[tokio::test]
async fn head_burned_returns_410_no_sirr_headers() {
    let s = setup();
    let resp = s
        .server
        .post("/secret")
        .json(&json!({"value": "burnme", "reads": 1}))
        .await;
    resp.assert_status_success();
    let hash = resp.json::<Value>()["hash"].as_str().unwrap().to_string();

    // Burn via GET.
    s.server
        .get(&format!("/secret/{hash}"))
        .await
        .assert_status_success();

    // HEAD should now 410 with no X-Sirr-* headers.
    let resp = s
        .server
        .method(Method::HEAD, &format!("/secret/{hash}"))
        .await;
    resp.assert_status(StatusCode::GONE);
    assert!(
        !resp.headers().contains_key("x-sirr-created"),
        "tombstone should not leak x-sirr-created"
    );
}

#[tokio::test]
async fn head_nonexistent_returns_410() {
    let s = setup();
    s.server
        .method(
            Method::HEAD,
            "/secret/0000000000000000000000000000000000000000000000000000000000000000",
        )
        .await
        .assert_status(StatusCode::GONE);
}

#[tokio::test]
async fn head_anonymous_secret_shows_owned_false() {
    let s = setup();
    let hash = create_and_get_hash(&s, "anon-head").await;
    let resp = s
        .server
        .method(Method::HEAD, &format!("/secret/{hash}"))
        .await;
    resp.assert_status_success();
    let owned_header = resp.headers().get("x-sirr-owned").unwrap();
    assert_eq!(owned_header, "false");
}

// ── GET /secret/{hash}/audit ──────────────────────────────────────────────────

async fn create_keyed_secret(setup: &Setup, value: &str, token: &str) -> String {
    let (name, val) = auth_header(token);
    let resp = setup
        .server
        .post("/secret")
        .add_header(name, val)
        .json(&json!({"value": value}))
        .await;
    resp.assert_status_success();
    resp.json::<Value>()["hash"].as_str().unwrap().to_string()
}

#[tokio::test]
async fn audit_owner_gets_200_with_events() {
    let s = setup_with_visibility(Visibility::Private);
    let (_key, token) = create_key(&s.store);
    let hash = create_keyed_secret(&s, "audit-me", &token).await;

    let (name, val) = auth_header(&token);
    let resp = s
        .server
        .get(&format!("/secret/{hash}/audit"))
        .add_header(name, val)
        .await;
    resp.assert_status_success();
    let body: Value = resp.json();
    assert_eq!(body["hash"], json!(hash));
    assert!(body["events"].is_array());
    assert!(!body["events"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn audit_anonymous_secret_returns_404() {
    let s = setup(); // public mode
    let hash = create_and_get_hash(&s, "anon-secret").await;

    let resp = s.server.get(&format!("/secret/{hash}/audit")).await;
    resp.assert_status(StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn audit_keyed_no_auth_returns_401() {
    let s = setup_with_visibility(Visibility::Private);
    let (_key, token) = create_key(&s.store);
    let hash = create_keyed_secret(&s, "auth-required", &token).await;

    let resp = s.server.get(&format!("/secret/{hash}/audit")).await;
    resp.assert_status(StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn audit_keyed_wrong_key_returns_404() {
    let s = setup_with_visibility(Visibility::Both);
    let (_key, token) = create_key(&s.store);
    let hash = create_keyed_secret(&s, "mine", &token).await;

    // Second key — doesn't own the secret.
    let (_key2, token2) = s.store.create_key("other-key", None, None, None).unwrap();
    let (name, val) = auth_header(&token2);
    let resp = s
        .server
        .get(&format!("/secret/{hash}/audit"))
        .add_header(name, val)
        .await;
    resp.assert_status(StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn audit_events_include_read_event_after_get() {
    let s = setup_with_visibility(Visibility::Private);
    let (_key, token) = create_key(&s.store);
    let hash = create_keyed_secret(&s, "readable", &token).await;

    // Trigger a read.
    s.server
        .get(&format!("/secret/{hash}"))
        .await
        .assert_status_success();

    let (name, val) = auth_header(&token);
    let resp = s
        .server
        .get(&format!("/secret/{hash}/audit"))
        .add_header(name, val)
        .await;
    resp.assert_status_success();
    let body: Value = resp.json();
    let events = body["events"].as_array().unwrap();
    let types: Vec<&str> = events.iter().map(|e| e["type"].as_str().unwrap()).collect();
    assert!(
        types.contains(&"secret.read"),
        "should include read event: {types:?}"
    );
}

// ── PATCH /secret/{hash} ──────────────────────────────────────────────────────

#[tokio::test]
async fn patch_owner_succeeds_and_value_updates() {
    let s = setup_with_visibility(Visibility::Private);
    let (_key, token) = create_key(&s.store);
    let hash = create_keyed_secret(&s, "original", &token).await;

    let (name, val) = auth_header(&token);
    let resp = s
        .server
        .patch(&format!("/secret/{hash}"))
        .add_header(name, val)
        .json(&json!({"value": "updated"}))
        .await;
    resp.assert_status_success();

    // Read back the updated value.
    assert_eq!(
        s.server.get(&format!("/secret/{hash}")).await.text(),
        "updated"
    );
}

#[tokio::test]
async fn patch_frozen_ttl_and_reads_unchanged_by_default() {
    let s = setup_with_visibility(Visibility::Private);
    let (_key, token) = create_key(&s.store);

    let (name, val) = auth_header(&token);
    let create_resp = s
        .server
        .post("/secret")
        .add_header(name, val)
        .json(&json!({"value": "v1", "reads": 5, "ttl_seconds": 9999}))
        .await;
    create_resp.assert_status_success();
    let hash = create_resp.json::<Value>()["hash"]
        .as_str()
        .unwrap()
        .to_string();

    // Patch value only.
    let (name2, val2) = auth_header(&token);
    let patch_resp = s
        .server
        .patch(&format!("/secret/{hash}"))
        .add_header(name2, val2)
        .json(&json!({"value": "v2"}))
        .await;
    patch_resp.assert_status_success();
    let body: Value = patch_resp.json();
    assert_eq!(body["reads_remaining"], json!(5));
    assert!(body["expires_at"].is_number());
}

#[tokio::test]
async fn patch_with_new_reads_resets_counter() {
    let s = setup_with_visibility(Visibility::Private);
    let (_key, token) = create_key(&s.store);
    let hash = create_keyed_secret(&s, "resetme", &token).await;

    let (name, val) = auth_header(&token);
    let resp = s
        .server
        .patch(&format!("/secret/{hash}"))
        .add_header(name, val)
        .json(&json!({"value": "newval", "reads": 2}))
        .await;
    resp.assert_status_success();
    assert_eq!(resp.json::<Value>()["reads_remaining"], json!(2));
}

#[tokio::test]
async fn patch_wrong_key_returns_404() {
    let s = setup_with_visibility(Visibility::Both);
    let (_key, token) = create_key(&s.store);
    let hash = create_keyed_secret(&s, "notmine", &token).await;
    let (_key2, token2) = s.store.create_key("attacker", None, None, None).unwrap();

    let (name, val) = auth_header(&token2);
    let resp = s
        .server
        .patch(&format!("/secret/{hash}"))
        .add_header(name, val)
        .json(&json!({"value": "hack"}))
        .await;
    resp.assert_status(StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn patch_anonymous_secret_returns_405() {
    let s = setup(); // public mode — anonymous secrets
    let hash = create_and_get_hash(&s, "anon-immutable").await;

    let resp = s
        .server
        .patch(&format!("/secret/{hash}"))
        .json(&json!({"value": "nope"}))
        .await;
    resp.assert_status(StatusCode::METHOD_NOT_ALLOWED);
}

#[tokio::test]
async fn patch_no_auth_on_keyed_secret_returns_401() {
    let s = setup_with_visibility(Visibility::Private);
    let (_key, token) = create_key(&s.store);
    let hash = create_keyed_secret(&s, "needsauth", &token).await;

    let resp = s
        .server
        .patch(&format!("/secret/{hash}"))
        .json(&json!({"value": "nope"}))
        .await;
    resp.assert_status(StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn patch_burned_secret_returns_410() {
    let s = setup_with_visibility(Visibility::Private);
    let (_key, token) = create_key(&s.store);

    let (name, val) = auth_header(&token);
    let create_resp = s
        .server
        .post("/secret")
        .add_header(name, val)
        .json(&json!({"value": "burnable", "reads": 1}))
        .await;
    create_resp.assert_status_success();
    let hash = create_resp.json::<Value>()["hash"]
        .as_str()
        .unwrap()
        .to_string();

    // Burn by reading.
    s.server
        .get(&format!("/secret/{hash}"))
        .await
        .assert_status_success();

    let (name2, val2) = auth_header(&token);
    let resp = s
        .server
        .patch(&format!("/secret/{hash}"))
        .add_header(name2, val2)
        .json(&json!({"value": "too-late"}))
        .await;
    resp.assert_status(StatusCode::GONE);
}

// ── DELETE /secret/{hash} ─────────────────────────────────────────────────────

#[tokio::test]
async fn delete_anonymous_secret_returns_204() {
    let s = setup();
    let hash = create_and_get_hash(&s, "anon-delete").await;
    s.server
        .method(Method::DELETE, &format!("/secret/{hash}"))
        .await
        .assert_status(StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn delete_anonymous_anyone_can_burn() {
    // Capability model: anyone with the hash can burn an anonymous secret.
    let s = setup();
    let hash = create_and_get_hash(&s, "cap-burn").await;

    // No auth header.
    s.server
        .method(Method::DELETE, &format!("/secret/{hash}"))
        .await
        .assert_status(StatusCode::NO_CONTENT);

    // Confirm gone.
    s.server
        .get(&format!("/secret/{hash}"))
        .await
        .assert_status(StatusCode::GONE);
}

#[tokio::test]
async fn delete_keyed_owner_ok() {
    let s = setup_with_visibility(Visibility::Private);
    let (_key, token) = create_key(&s.store);
    let hash = create_keyed_secret(&s, "mine", &token).await;

    let (name, val) = auth_header(&token);
    s.server
        .method(Method::DELETE, &format!("/secret/{hash}"))
        .add_header(name, val)
        .await
        .assert_status(StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn delete_keyed_no_auth_returns_401() {
    let s = setup_with_visibility(Visibility::Private);
    let (_key, token) = create_key(&s.store);
    let hash = create_keyed_secret(&s, "locked", &token).await;

    s.server
        .method(Method::DELETE, &format!("/secret/{hash}"))
        .await
        .assert_status(StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn delete_keyed_wrong_key_returns_404() {
    let s = setup_with_visibility(Visibility::Both);
    let (_key, token) = create_key(&s.store);
    let hash = create_keyed_secret(&s, "notmine", &token).await;
    let (_key2, token2) = s.store.create_key("intruder", None, None, None).unwrap();

    let (name, val) = auth_header(&token2);
    s.server
        .method(Method::DELETE, &format!("/secret/{hash}"))
        .add_header(name, val)
        .await
        .assert_status(StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn delete_already_burned_returns_410() {
    let s = setup();
    let hash = create_and_get_hash(&s, "burn-twice").await;

    // First delete.
    s.server
        .method(Method::DELETE, &format!("/secret/{hash}"))
        .await
        .assert_status(StatusCode::NO_CONTENT);

    // Second delete — already gone.
    s.server
        .method(Method::DELETE, &format!("/secret/{hash}"))
        .await
        .assert_status(StatusCode::GONE);
}

#[tokio::test]
async fn delete_confirmed_via_subsequent_get() {
    let s = setup();
    let hash = create_and_get_hash(&s, "confirm-burn").await;

    s.server
        .method(Method::DELETE, &format!("/secret/{hash}"))
        .await
        .assert_status(StatusCode::NO_CONTENT);

    s.server
        .get(&format!("/secret/{hash}"))
        .await
        .assert_status(StatusCode::GONE);
}

// ── Cross-endpoint invariants ─────────────────────────────────────────────────

#[tokio::test]
async fn get_head_return_410_for_nonexistent_hash() {
    let s = setup_with_visibility(Visibility::Both);
    let fake = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    // GET → 410
    s.server
        .get(&format!("/secret/{fake}"))
        .await
        .assert_status(StatusCode::GONE);

    // HEAD → 410
    s.server
        .method(Method::HEAD, &format!("/secret/{fake}"))
        .await
        .assert_status(StatusCode::GONE);
}

#[tokio::test]
async fn patch_delete_return_404_for_nonexistent_hash() {
    let s = setup_with_visibility(Visibility::Both);
    let fake = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    // PATCH → 404 (authorize returns NotFound for None secret + Patch)
    s.server
        .patch(&format!("/secret/{fake}"))
        .json(&json!({"value": "x"}))
        .await
        .assert_status(StatusCode::NOT_FOUND);

    // DELETE → 404 (authorize returns NotFound for None secret + Burn)
    s.server
        .method(Method::DELETE, &format!("/secret/{fake}"))
        .await
        .assert_status(StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn bearer_token_wrong_scheme_falls_back_to_anon() {
    // "Basic ..." should silently fall back to anonymous, not 400.
    // In public mode, anonymous creates succeed.
    let s = setup();
    let resp = s
        .server
        .post("/secret")
        .add_header(
            header::AUTHORIZATION,
            "Basic dXNlcjpwYXNz".parse::<header::HeaderValue>().unwrap(),
        )
        .json(&json!({"value": "basic-auth-fallback"}))
        .await;
    // Falls back to anonymous — succeeds in public mode.
    resp.assert_status_success();
}

#[tokio::test]
async fn two_keys_have_different_tokens() {
    let s = setup_with_visibility(Visibility::Both);
    let (_k1, t1) = s.store.create_key("alice", None, None, None).unwrap();
    let (_k2, t2) = s.store.create_key("bob", None, None, None).unwrap();
    assert_ne!(t1, t2);
}

#[tokio::test]
async fn url_in_create_response_contains_hash() {
    let s = setup();
    let resp = s
        .server
        .post("/secret")
        .json(&json!({"value": "url-check"}))
        .await;
    resp.assert_status_success();
    let body: Value = resp.json();
    let hash = body["hash"].as_str().unwrap();
    let url = body["url"].as_str().unwrap();
    assert!(url.contains(hash), "url should contain the hash");
}

// ── GET /secrets ──────────────────────────────────────────────────────────────

/// Helper: create a secret in the store via POST and return its hash.
async fn create_owned_secret(s: &Setup, token: &str) -> String {
    let (name, value) = auth_header(token);
    let resp = s
        .server
        .post("/secret")
        .add_header(name, value)
        .json(&json!({"value": "owned-secret"}))
        .await;
    resp.assert_status_success();
    resp.json::<Value>()["hash"].as_str().unwrap().to_string()
}

#[tokio::test]
async fn list_my_secrets_returns_owned_only() {
    let s = setup_with_visibility(Visibility::Both);
    let (_k_a, tok_a) = s.store.create_key("alice", None, None, None).unwrap();
    let (_k_b, tok_b) = s.store.create_key("bob", None, None, None).unwrap();

    let hash_a1 = create_owned_secret(&s, &tok_a).await;
    let hash_a2 = create_owned_secret(&s, &tok_a).await;
    let _hash_b = create_owned_secret(&s, &tok_b).await;

    let (name, value) = auth_header(&tok_a);
    let resp = s.server.get("/secrets").add_header(name, value).await;
    resp.assert_status_success();

    let items: Vec<Value> = resp.json();
    assert_eq!(items.len(), 2, "should only see Alice's secrets");
    let returned_hashes: Vec<&str> = items.iter().map(|v| v["hash"].as_str().unwrap()).collect();
    assert!(returned_hashes.contains(&hash_a1.as_str()));
    assert!(returned_hashes.contains(&hash_a2.as_str()));
}

#[tokio::test]
async fn list_my_secrets_requires_auth() {
    let s = setup_with_visibility(Visibility::Both);
    let resp = s.server.get("/secrets").await;
    resp.assert_status(StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn list_my_secrets_includes_burned() {
    let s = setup_with_visibility(Visibility::Both);
    let (_k, tok) = s.store.create_key("owner", None, None, None).unwrap();

    let hash = create_owned_secret(&s, &tok).await;

    // Burn the secret.
    let (name, value) = auth_header(&tok);
    s.server
        .method(Method::DELETE, &format!("/secret/{hash}"))
        .add_header(name, value)
        .await
        .assert_status(StatusCode::NO_CONTENT);

    // List should still include the burned tombstone.
    let (name, value) = auth_header(&tok);
    let resp = s.server.get("/secrets").add_header(name, value).await;
    resp.assert_status_success();

    let items: Vec<Value> = resp.json();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["burned"], json!(true));
    assert!(items[0]["burned_at"].is_number());
}

#[tokio::test]
async fn list_my_secrets_excludes_values() {
    let s = setup_with_visibility(Visibility::Both);
    let (_k, tok) = s.store.create_key("owner", None, None, None).unwrap();

    create_owned_secret(&s, &tok).await;

    let (name, value) = auth_header(&tok);
    let resp = s.server.get("/secrets").add_header(name, value).await;
    resp.assert_status_success();

    let items: Vec<Value> = resp.json();
    assert_eq!(items.len(), 1);
    // Must not contain any value-related fields.
    assert!(items[0].get("value_ciphertext").is_none());
    assert!(items[0].get("value").is_none());
    assert!(items[0].get("nonce").is_none());
    assert!(items[0].get("owner_key_id").is_none());
    assert!(items[0].get("created_by_ip").is_none());
    // Must contain expected metadata fields.
    assert!(items[0]["hash"].is_string());
    assert!(items[0]["created_at"].is_number());
    assert_eq!(items[0]["owned"], json!(true));
}

#[tokio::test]
async fn list_my_secrets_empty_for_new_key() {
    let s = setup_with_visibility(Visibility::Both);
    let (_k, tok) = s.store.create_key("fresh", None, None, None).unwrap();

    let (name, value) = auth_header(&tok);
    let resp = s.server.get("/secrets").add_header(name, value).await;
    resp.assert_status_success();

    let items: Vec<Value> = resp.json();
    assert!(items.is_empty(), "new key should have no secrets");
}

#[tokio::test]
async fn list_my_secrets_503_when_locked() {
    let s = setup_with_visibility(Visibility::None);
    let resp = s.server.get("/secrets").await;
    resp.assert_status(StatusCode::SERVICE_UNAVAILABLE);
}
