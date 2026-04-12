//! Webhook delivery tests using wiremock for a real HTTP mock server.

use std::sync::Arc;

use axum_test::TestServer;
use serde_json::{json, Value};
use sirr_server::{
    router,
    store::{crypto, Store, Visibility},
    AppState, WebhookSender,
};
use tempfile::tempdir;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

// ── Helpers ───────────────────────────────────────────────────────────────────

fn make_state(store: Arc<Store>) -> AppState {
    let key = Arc::new(crypto::generate_key());
    let visibility = Arc::new(tokio::sync::RwLock::new(Visibility::Both));
    AppState {
        store,
        encryption_key: key,
        visibility,
        webhook_sender: WebhookSender::new(),
    }
}

fn auth_header(
    token: &str,
) -> (
    axum::http::header::HeaderName,
    axum::http::header::HeaderValue,
) {
    (
        axum::http::header::AUTHORIZATION,
        format!("Bearer {token}").parse().unwrap(),
    )
}

// ── Tests ─────────────────────────────────────────────────────────────────────

/// Creating a keyed secret fires a `secret.created` webhook.
#[tokio::test]
async fn webhook_fires_on_create() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/hook"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&mock_server)
        .await;

    let dir = tempdir().unwrap();
    let store = Arc::new(Store::open(dir.path().join("test.db")).unwrap());

    // Create a key with the mock server as webhook URL.
    let webhook_url = format!("{}/hook", mock_server.uri());
    let (_key, token) = store
        .create_key("alice", None, None, Some(webhook_url))
        .unwrap();

    let state = make_state(store);
    let server = TestServer::new(router(state));

    let resp = server
        .post("/secret")
        .add_header(auth_header(&token).0, auth_header(&token).1)
        .json(&json!({"value": "top-secret"}))
        .await;

    resp.assert_status_success();

    // Give the background task a moment to fire.
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    mock_server.verify().await;
}

/// Reading a keyed secret fires a `secret.read` webhook.
#[tokio::test]
async fn webhook_fires_on_read() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/hook"))
        .respond_with(ResponseTemplate::new(200))
        .expect(2) // created + read
        .mount(&mock_server)
        .await;

    let dir = tempdir().unwrap();
    let store = Arc::new(Store::open(dir.path().join("test.db")).unwrap());

    let webhook_url = format!("{}/hook", mock_server.uri());
    let (_key, token) = store
        .create_key("bob", None, None, Some(webhook_url))
        .unwrap();

    let state = make_state(store);
    let server = TestServer::new(router(state));

    // Create the secret with auth.
    let resp = server
        .post("/secret")
        .add_header(auth_header(&token).0, auth_header(&token).1)
        .json(&json!({"value": "read-me"}))
        .await;
    resp.assert_status_success();
    let hash = resp.json::<Value>()["hash"].as_str().unwrap().to_string();

    // Read the secret (no auth needed for reads).
    let _read_resp = server.get(&format!("/secret/{hash}")).await;

    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    mock_server.verify().await;
}

/// Anonymous secrets do NOT trigger webhooks (no key to attach a webhook to).
#[tokio::test]
async fn webhook_does_not_fire_for_anonymous_secrets() {
    let mock_server = MockServer::start().await;

    // We explicitly expect ZERO webhook calls for anonymous secrets.
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&mock_server)
        .await;

    let dir = tempdir().unwrap();
    let store = Arc::new(Store::open(dir.path().join("test.db")).unwrap());
    let state = make_state(store);
    let server = TestServer::new(router(state));

    // Anonymous create in Both mode (anonymous allowed).
    let resp = server
        .post("/secret")
        .json(&json!({"value": "anon-secret"}))
        .await;
    resp.assert_status_success();
    let hash = resp.json::<Value>()["hash"].as_str().unwrap().to_string();

    // Anonymous read.
    let _read_resp = server.get(&format!("/secret/{hash}")).await;

    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    mock_server.verify().await;
}

/// Keys without a webhook_url configured do not fire any webhooks.
#[tokio::test]
async fn webhook_does_not_fire_when_no_url_configured() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&mock_server)
        .await;

    let dir = tempdir().unwrap();
    let store = Arc::new(Store::open(dir.path().join("test.db")).unwrap());

    // Create a key WITHOUT a webhook URL.
    let (_key, token) = store.create_key("carol", None, None, None).unwrap();

    let state = make_state(store);
    let server = TestServer::new(router(state));

    let resp = server
        .post("/secret")
        .add_header(auth_header(&token).0, auth_header(&token).1)
        .json(&json!({"value": "no-webhook"}))
        .await;
    resp.assert_status_success();

    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    mock_server.verify().await;
}

/// The webhook payload contains the expected fields.
#[tokio::test]
async fn webhook_payload_shape() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/hook"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&mock_server)
        .await;

    let dir = tempdir().unwrap();
    let store = Arc::new(Store::open(dir.path().join("test.db")).unwrap());

    let webhook_url = format!("{}/hook", mock_server.uri());
    let (_key, token) = store
        .create_key("dave", None, None, Some(webhook_url))
        .unwrap();

    let state = make_state(store);
    let server = TestServer::new(router(state));

    let resp = server
        .post("/secret")
        .add_header(auth_header(&token).0, auth_header(&token).1)
        .json(&json!({"value": "payload-check"}))
        .await;
    resp.assert_status_success();
    let hash = resp.json::<Value>()["hash"].as_str().unwrap().to_string();

    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    // Inspect the captured request bodies.
    let received = mock_server.received_requests().await.unwrap();
    assert!(
        !received.is_empty(),
        "expected at least one webhook request"
    );

    let body: Value =
        serde_json::from_slice(&received[0].body).expect("webhook body should be JSON");

    assert_eq!(body["type"], json!("secret.created"));
    assert_eq!(body["hash"], json!(hash));
    assert!(
        body["at"].as_i64().is_some(),
        "at should be a unix timestamp"
    );
    assert!(body["ip"].is_string(), "ip field should be present");
}
