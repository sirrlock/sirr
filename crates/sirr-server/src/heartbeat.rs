//! Instance heartbeat — periodic phone-home to SecretDrop so customers
//! can see which Sirr instances are running, their versions, and health.

use std::time::{Duration, Instant};

use serde::Serialize;
use tracing::warn;

use crate::store::Store;

/// Configuration for the background heartbeat task.
pub struct HeartbeatConfig {
    /// Full URL, e.g. `https://secretdrop.app/api/instances/heartbeat`.
    pub endpoint: String,
    /// The `SIRR_LICENSE_KEY` value (sent as Bearer token).
    pub license_key: String,
    /// Stable identifier derived from the encryption key.
    pub instance_id: String,
    /// Store handle — used to read secret count.
    pub store: Store,
}

#[derive(Serialize)]
struct HeartbeatPayload {
    instance_id: String,
    version: String,
    uptime_secs: u64,
    secret_count: usize,
}

/// Derive a stable 16-hex-char instance ID from the raw encryption key bytes.
pub fn instance_id_from_key(key_bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(key_bytes);
    hex::encode(&hash[..8]) // first 16 hex chars
}

/// Spawn a background tokio task that sends a heartbeat every 5 minutes.
///
/// The first heartbeat fires immediately. Failures are logged at `warn`
/// level and never retried — the next interval tick will try again.
pub fn spawn_heartbeat(config: HeartbeatConfig) {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .expect("build heartbeat reqwest client");

    tokio::spawn(async move {
        let started = Instant::now();
        let mut interval = tokio::time::interval(Duration::from_secs(300));

        loop {
            interval.tick().await;

            let secret_count = config.store.list().map(|v| v.len()).unwrap_or(0);

            let payload = HeartbeatPayload {
                instance_id: config.instance_id.clone(),
                version: env!("CARGO_PKG_VERSION").to_string(),
                uptime_secs: started.elapsed().as_secs(),
                secret_count,
            };

            let result = client
                .post(&config.endpoint)
                .bearer_auth(&config.license_key)
                .json(&payload)
                .send()
                .await;

            match result {
                Ok(resp) if resp.status().is_success() => {
                    tracing::debug!("heartbeat sent successfully");
                }
                Ok(resp) => {
                    warn!(status = %resp.status(), "heartbeat rejected by server");
                }
                Err(e) => {
                    warn!(error = %e, "heartbeat failed");
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn instance_id_consistent_and_correct_length() {
        let key = [42u8; 32];
        let id1 = instance_id_from_key(&key);
        let id2 = instance_id_from_key(&key);
        assert_eq!(id1, id2, "same key should produce same ID");
        assert_eq!(id1.len(), 16, "instance ID should be 16 hex chars");
        assert!(id1.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn different_keys_produce_different_ids() {
        let id1 = instance_id_from_key(&[1u8; 32]);
        let id2 = instance_id_from_key(&[2u8; 32]);
        assert_ne!(id1, id2);
    }

    #[tokio::test]
    async fn heartbeat_sends_correct_payload_and_auth() {
        use wiremock::matchers::{bearer_token, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/instances/heartbeat"))
            .and(bearer_token("sirr_lic_testkey"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ok": true
            })))
            .expect(1..)
            .mount(&mock)
            .await;

        let key = crate::store::crypto::generate_key();
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let store = Store::open(&db_path, key).unwrap();

        let config = HeartbeatConfig {
            endpoint: format!("{}/api/instances/heartbeat", mock.uri()),
            license_key: "sirr_lic_testkey".into(),
            instance_id: instance_id_from_key(&[42u8; 32]),
            store,
        };

        spawn_heartbeat(config);

        // Give the first tick time to fire and complete.
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}
