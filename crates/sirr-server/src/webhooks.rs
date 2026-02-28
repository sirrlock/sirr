use std::time::{Duration, SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use tracing::{debug, warn};

use crate::store::Store;

type HmacSha256 = Hmac<Sha256>;

// ── Data types ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookRegistration {
    pub id: String,
    pub url: String,
    pub secret: String,
    pub events: Vec<String>,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct WebhookEvent {
    pub event: String,
    pub key: String,
    pub timestamp: i64,
    pub instance_id: String,
    pub detail: serde_json::Value,
}

/// Maximum number of global webhooks per instance.
pub const MAX_WEBHOOKS: usize = 10;

// ── WebhookSender ────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct WebhookSender {
    client: reqwest::Client,
    store: Store,
    instance_id: String,
    /// Signing key for per-secret webhook URLs (from SIRR_WEBHOOK_SECRET).
    per_secret_signing_key: Option<String>,
}

impl WebhookSender {
    pub fn new(store: Store, instance_id: String, per_secret_signing_key: Option<String>) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .expect("build webhook reqwest client");

        Self {
            client,
            store,
            instance_id,
            per_secret_signing_key,
        }
    }

    /// Fire webhook events to all matching global registrations.
    pub fn fire(&self, event_type: &str, key: &str, detail: serde_json::Value) {
        let event = WebhookEvent {
            event: event_type.to_owned(),
            key: key.to_owned(),
            timestamp: now(),
            instance_id: self.instance_id.clone(),
            detail,
        };

        let registrations = match self.store.list_webhooks() {
            Ok(regs) => regs,
            Err(e) => {
                warn!(error = %e, "failed to list webhooks for delivery");
                return;
            }
        };

        for reg in registrations {
            if matches_event(&reg.events, event_type) {
                let sender = self.clone();
                let event = event.clone();
                let url = reg.url.clone();
                let secret = reg.secret.clone();
                tokio::spawn(async move {
                    sender.deliver(&url, &event, &secret).await;
                });
            }
        }
    }

    /// Fire a webhook to a specific per-secret URL.
    pub fn fire_for_url(&self, url: &str, event_type: &str, key: &str, detail: serde_json::Value) {
        let signing_key = match &self.per_secret_signing_key {
            Some(k) => k.clone(),
            None => {
                debug!(
                    "per-secret webhook URL set but no SIRR_WEBHOOK_SECRET configured; skipping"
                );
                return;
            }
        };

        let event = WebhookEvent {
            event: event_type.to_owned(),
            key: key.to_owned(),
            timestamp: now(),
            instance_id: self.instance_id.clone(),
            detail,
        };

        let sender = self.clone();
        let url = url.to_owned();
        tokio::spawn(async move {
            sender.deliver(&url, &event, &signing_key).await;
        });
    }

    /// POST the event payload to the given URL with HMAC signature.
    async fn deliver(&self, url: &str, event: &WebhookEvent, hmac_secret: &str) {
        let body = match serde_json::to_string(event) {
            Ok(b) => b,
            Err(e) => {
                warn!(error = %e, url, "failed to serialize webhook event");
                return;
            }
        };

        let signature = compute_signature(hmac_secret, &body);

        let result = self
            .client
            .post(url)
            .header("Content-Type", "application/json")
            .header("X-Sirr-Signature", format!("sha256={signature}"))
            .body(body)
            .send()
            .await;

        match result {
            Ok(resp) => {
                debug!(url, status = %resp.status(), "webhook delivered");
            }
            Err(e) => {
                warn!(url, error = %e, "webhook delivery failed");
            }
        }
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────────

fn matches_event(subscribed: &[String], event_type: &str) -> bool {
    subscribed.iter().any(|e| e == "*" || e == event_type)
}

/// Compute HMAC-SHA256 hex digest.
pub fn compute_signature(secret: &str, body: &str) -> String {
    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key length");
    mac.update(body.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

/// Generate a webhook signing secret: "whsec_" + 32 random hex chars.
pub fn generate_signing_secret() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let bytes: [u8; 16] = rng.gen();
    format!("whsec_{}", hex::encode(bytes))
}

/// Generate a webhook registration ID: 16 random hex chars.
pub fn generate_webhook_id() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let bytes: [u8; 8] = rng.gen();
    hex::encode(bytes)
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hmac_signature_is_deterministic() {
        let sig1 = compute_signature("my-secret", r#"{"event":"test"}"#);
        let sig2 = compute_signature("my-secret", r#"{"event":"test"}"#);
        assert_eq!(sig1, sig2);
        assert!(!sig1.is_empty());
    }

    #[test]
    fn different_secrets_produce_different_signatures() {
        let sig1 = compute_signature("secret-a", "body");
        let sig2 = compute_signature("secret-b", "body");
        assert_ne!(sig1, sig2);
    }

    #[test]
    fn matches_event_wildcard() {
        let events = vec!["*".to_string()];
        assert!(matches_event(&events, "secret.created"));
        assert!(matches_event(&events, "secret.burned"));
    }

    #[test]
    fn matches_event_specific() {
        let events = vec!["secret.created".to_string(), "secret.deleted".to_string()];
        assert!(matches_event(&events, "secret.created"));
        assert!(matches_event(&events, "secret.deleted"));
        assert!(!matches_event(&events, "secret.read"));
    }

    #[test]
    fn generate_signing_secret_format() {
        let secret = generate_signing_secret();
        assert!(secret.starts_with("whsec_"));
        assert_eq!(secret.len(), 6 + 32); // "whsec_" + 32 hex chars
    }

    #[test]
    fn generate_webhook_id_format() {
        let id = generate_webhook_id();
        assert_eq!(id.len(), 16); // 8 bytes = 16 hex chars
    }
}
