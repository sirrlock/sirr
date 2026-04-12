//! Per-key, fire-and-forget webhook delivery.
//!
//! When a key has a `webhook_url` set, the server POSTs a `WebhookEvent` JSON
//! payload to that URL after each successful secret lifecycle event. The POST
//! is dispatched in a background tokio task — it never blocks the HTTP response.
//! No retries, no queue, no acknowledgement required.

use reqwest::Client;
use serde::Serialize;

/// The JSON body sent to a webhook URL.
#[derive(Debug, Clone, Serialize)]
pub struct WebhookEvent {
    /// Lifecycle event type. One of:
    /// `secret.created`, `secret.read`, `secret.patched`, `secret.burned`, `secret.expired`.
    #[serde(rename = "type")]
    pub event_type: String,
    /// The secret hash that triggered the event.
    pub hash: String,
    /// Unix seconds when the event occurred.
    pub at: i64,
    /// IP address of the caller (empty string if unknown).
    pub ip: String,
}

/// Shared HTTP client for webhook delivery. Clone-cheap (Arc internally).
#[derive(Clone)]
pub struct WebhookSender {
    client: Client,
}

impl WebhookSender {
    /// Build a sender with a 10-second timeout per request.
    pub fn new() -> Self {
        Self {
            client: Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .build()
                .unwrap_or_default(),
        }
    }

    /// Fire-and-forget: spawn a tokio task, POST `event` to `url`, never block.
    pub fn fire(&self, url: String, event: WebhookEvent) {
        let client = self.client.clone();
        tokio::spawn(async move {
            match client.post(&url).json(&event).send().await {
                Ok(resp) => {
                    tracing::debug!("webhook {} → {}", url, resp.status());
                }
                Err(e) => {
                    tracing::warn!("webhook {} failed: {}", url, e);
                }
            }
        });
    }
}

impl Default for WebhookSender {
    fn default() -> Self {
        Self::new()
    }
}
