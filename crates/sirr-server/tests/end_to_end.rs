//! End-to-end integration tests for the Sirr server.
//!
//! These tests exercise full lifecycle paths through the real axum router
//! with a real redb store, verifying that all layers (authz, store, handlers)
//! work together correctly.

use std::sync::Arc;

use axum::http::{header, Method, StatusCode};
use axum_test::TestServer;
use serde_json::{json, Value};
use sirr_server::{
    router,
    store::{crypto, AuditQuery, Store, Visibility},
    AppState, WebhookSender,
};
use tempfile::tempdir;

// ── Test helpers ──────────────────────────────────────────────────────────────

fn make_server(vis: Visibility) -> (TestServer, Arc<Store>) {
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
    (TestServer::new(router(state)), store)
}

fn bearer(token: &str) -> (header::HeaderName, header::HeaderValue) {
    (
        header::AUTHORIZATION,
        format!("Bearer {token}").parse().unwrap(),
    )
}

// ── Test 1: Full lifecycle ─────────────────────────────────────────────────────

/// Creates a key, pushes a secret, reads it, patches it, inspects metadata,
/// checks audit trail, then burns it and verifies it's gone.
#[tokio::test]
async fn full_lifecycle() {
    let (server, store) = make_server(Visibility::Both);

    // Create alice's key.
    let (_alice_key, alice_token) = store.create_key("alice", None, None, None).unwrap();

    // POST /secret with alice's auth → owned secret.
    let create_resp = server
        .post("/secret")
        .add_header(bearer(&alice_token).0, bearer(&alice_token).1)
        .json(&json!({"value": "my-secret-value", "reads": 5}))
        .await;
    create_resp.assert_status(StatusCode::CREATED);
    let body: Value = create_resp.json();
    let hash = body["hash"].as_str().unwrap().to_string();
    assert_eq!(body["owned"], json!(true));

    // GET the secret without auth — reads are universal.
    let read_resp = server.get(&format!("/secret/{hash}")).await;
    read_resp.assert_status_ok();

    // PATCH from alice — should succeed.
    let patch_resp = server
        .patch(&format!("/secret/{hash}"))
        .add_header(bearer(&alice_token).0, bearer(&alice_token).1)
        .json(&json!({"value": "updated-value"}))
        .await;
    patch_resp.assert_status_ok();

    // HEAD → shows metadata, does NOT consume a read.
    let head_resp = server
        .method(Method::HEAD, &format!("/secret/{hash}"))
        .await;
    head_resp.assert_status_ok();

    // GET /audit with alice's token → shows events.
    let audit_resp = server
        .get(&format!("/secret/{hash}/audit"))
        .add_header(bearer(&alice_token).0, bearer(&alice_token).1)
        .await;
    audit_resp.assert_status_ok();
    let audit_body: Value = audit_resp.json();
    let events = audit_body["events"].as_array().unwrap();
    assert!(!events.is_empty(), "audit trail should have events");

    // DELETE from alice → 204 No Content.
    let burn_resp = server
        .delete(&format!("/secret/{hash}"))
        .add_header(bearer(&alice_token).0, bearer(&alice_token).1)
        .await;
    burn_resp.assert_status(StatusCode::NO_CONTENT);

    // GET again → 410 Gone.
    let gone_resp = server.get(&format!("/secret/{hash}")).await;
    gone_resp.assert_status(StatusCode::GONE);
}

// ── Test 2: Visibility transition ─────────────────────────────────────────────

/// Starts in Public mode, creates an anonymous secret.
/// Switches to Private — the existing anonymous secret is still readable.
/// New anonymous creates return 401.
#[tokio::test]
async fn visibility_transition() {
    let dir = tempdir().unwrap();
    let store = Arc::new(Store::open(dir.path().join("test.db")).unwrap());
    let key = Arc::new(crypto::generate_key());
    let visibility = Arc::new(tokio::sync::RwLock::new(Visibility::Public));
    let state = AppState {
        store: store.clone(),
        encryption_key: key,
        visibility: visibility.clone(),
        webhook_sender: WebhookSender::new(),
        base_url: "http://test".to_string(),
    };
    let server = TestServer::new(router(state));

    // Create an anonymous secret in Public mode.
    let resp = server
        .post("/secret")
        .json(&json!({"value": "public-anon"}))
        .await;
    resp.assert_status(StatusCode::CREATED);
    let hash = resp.json::<Value>()["hash"].as_str().unwrap().to_string();

    // Switch visibility to Private.
    *visibility.write().await = Visibility::Private;

    // The existing anonymous secret is still readable.
    let read_resp = server.get(&format!("/secret/{hash}")).await;
    read_resp.assert_status_ok();

    // New anonymous create returns 401 in Private mode.
    let anon_create = server
        .post("/secret")
        .json(&json!({"value": "should-fail"}))
        .await;
    anon_create.assert_status(StatusCode::UNAUTHORIZED);
}

// ── Test 3: Lockdown test ─────────────────────────────────────────────────────

/// Sets visibility to None → all endpoints return 503.
/// Restores to Public → server recovers.
#[tokio::test]
async fn lockdown_and_recovery() {
    let dir = tempdir().unwrap();
    let store = Arc::new(Store::open(dir.path().join("test.db")).unwrap());
    let key = Arc::new(crypto::generate_key());
    let visibility = Arc::new(tokio::sync::RwLock::new(Visibility::None));
    let state = AppState {
        store: store.clone(),
        encryption_key: key,
        visibility: visibility.clone(),
        webhook_sender: WebhookSender::new(),
        base_url: "http://test".to_string(),
    };
    let server = TestServer::new(router(state));

    // All endpoints should return 503 in None mode.
    server
        .post("/secret")
        .json(&json!({"value": "x"}))
        .await
        .assert_status(StatusCode::SERVICE_UNAVAILABLE);
    server
        .get("/secret/fakehash")
        .await
        .assert_status(StatusCode::SERVICE_UNAVAILABLE);
    server
        .method(Method::HEAD, "/secret/fakehash")
        .await
        .assert_status(StatusCode::SERVICE_UNAVAILABLE);

    // Restore to Public mode.
    *visibility.write().await = Visibility::Public;

    // Server should now accept requests normally.
    let resp = server
        .post("/secret")
        .json(&json!({"value": "recovered"}))
        .await;
    resp.assert_status(StatusCode::CREATED);
}

// ── Test 4: Wrong-key probe test ──────────────────────────────────────────────

/// Creates a secret with key A. Key B attempting PATCH, GET /audit, or DELETE
/// should all return 404, NOT 403 (security: don't reveal ownership).
#[tokio::test]
async fn wrong_key_gets_not_found() {
    let (server, store) = make_server(Visibility::Both);

    let (_key_a, token_a) = store.create_key("key-a", None, None, None).unwrap();
    let (_key_b, token_b) = store.create_key("key-b", None, None, None).unwrap();

    // Create secret with key A.
    let resp = server
        .post("/secret")
        .add_header(bearer(&token_a).0, bearer(&token_a).1)
        .json(&json!({"value": "alice-secret"}))
        .await;
    resp.assert_status(StatusCode::CREATED);
    let hash = resp.json::<Value>()["hash"].as_str().unwrap().to_string();

    // Key B: PATCH → 404.
    server
        .patch(&format!("/secret/{hash}"))
        .add_header(bearer(&token_b).0, bearer(&token_b).1)
        .json(&json!({"value": "hack"}))
        .await
        .assert_status(StatusCode::NOT_FOUND);

    // Key B: GET /audit → 404.
    server
        .get(&format!("/secret/{hash}/audit"))
        .add_header(bearer(&token_b).0, bearer(&token_b).1)
        .await
        .assert_status(StatusCode::NOT_FOUND);

    // Key B: DELETE → 404.
    server
        .delete(&format!("/secret/{hash}"))
        .add_header(bearer(&token_b).0, bearer(&token_b).1)
        .await
        .assert_status(StatusCode::NOT_FOUND);
}

// ── Test 5: Prune test ────────────────────────────────────────────────────────

/// Creates and burns secrets, then calls prune with a large time offset.
/// Verifies that tombstones AND their audit events are deleted.
#[tokio::test]
async fn prune_removes_tombstones_and_audit() {
    let (server, store) = make_server(Visibility::Public);

    // Create and immediately read-burn a secret (reads: 1).
    let resp = server
        .post("/secret")
        .json(&json!({"value": "burn-me", "reads": 1}))
        .await;
    resp.assert_status(StatusCode::CREATED);
    let hash = resp.json::<Value>()["hash"].as_str().unwrap().to_string();

    // Read it — this burns it (reads_remaining drops to 0).
    server
        .get(&format!("/secret/{hash}"))
        .await
        .assert_status_ok();

    // Verify it's gone (burned).
    server
        .get(&format!("/secret/{hash}"))
        .await
        .assert_status(StatusCode::GONE);

    // Verify audit events exist before pruning.
    let query = AuditQuery {
        hash: Some(hash.clone()),
        limit: 0,
        ..Default::default()
    };
    let events_before = store.query_audit(&query).unwrap();
    assert!(
        !events_before.is_empty(),
        "audit events should exist before prune"
    );

    // Prune with a huge future timestamp so retention_days = 0 covers our tombstone.
    let far_future = 9_999_999_999i64;
    let pruned = store.prune(far_future, 0).unwrap();
    assert!(pruned >= 1, "at least one secret should be pruned");

    // Verify tombstone is gone from store.
    let secret_after = store.get_secret(&hash).unwrap();
    assert!(
        secret_after.is_none(),
        "tombstone should be deleted after prune"
    );

    // Verify audit events for this hash are also gone.
    let events_after = store.query_audit(&query).unwrap();
    assert!(
        events_after.is_empty(),
        "audit events should be deleted after prune"
    );
}
