use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac};
use ipnet::IpNet;
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

// ── SSRF guard ───────────────────────────────────────────────────────────────

/// Private, loopback, and link-local ranges that must never be webhook targets.
static BLOCKED_RANGES: &[&str] = &[
    "127.0.0.0/8",    // IPv4 loopback
    "10.0.0.0/8",     // RFC-1918 private
    "172.16.0.0/12",  // RFC-1918 private
    "192.168.0.0/16", // RFC-1918 private
    "169.254.0.0/16", // link-local / cloud metadata (AWS IMDSv1, GCP, Azure)
    "::1/128",        // IPv6 loopback
    "fc00::/7",       // IPv6 unique-local
    "fe80::/10",      // IPv6 link-local
];

fn is_private_ip(ip: IpAddr) -> bool {
    BLOCKED_RANGES.iter().any(|r| {
        r.parse::<IpNet>()
            .map(|net| net.contains(&ip))
            .unwrap_or(false)
    })
}

/// Validates a per-secret webhook URL against SSRF risks.
///
/// Rules (in order):
/// 1. Must be a syntactically valid URL.
/// 2. Scheme must be `https`.
/// 3. If the host is a bare IP address, it must not be in a private/loopback/
///    link-local range.  (Hostname-based targets are not resolved here; the
///    allowlist is the primary protection against those.)
/// 4. If `allowed_origins` is non-empty, the URL must start with one of them.
///    If `allowed_origins` is **empty**, per-secret webhook URLs are disabled
///    entirely — operators must set `SIRR_WEBHOOK_ALLOWED_ORIGINS` to opt in.
///
/// Returns `Ok(())` when safe, `Err(human-readable reason)` otherwise.
pub fn validate_webhook_url(url: &str, allowed_origins: &[String]) -> Result<(), String> {
    let uri: http::Uri = url
        .parse()
        .map_err(|_| "webhook_url is not a valid URL".to_string())?;

    if uri.scheme_str() != Some("https") {
        return Err("webhook_url must use https://".to_string());
    }

    let host = uri
        .host()
        .ok_or_else(|| "webhook_url is missing a host".to_string())?;

    // Strip IPv6 brackets before parsing.
    let bare = host.trim_matches(|c| c == '[' || c == ']');
    if let Ok(ip) = bare.parse::<IpAddr>() {
        if is_private_ip(ip) {
            return Err(
                "webhook_url must not target private, loopback, or link-local addresses"
                    .to_string(),
            );
        }
    }

    if allowed_origins.is_empty() {
        return Err(
            "per-secret webhook_url requires SIRR_WEBHOOK_ALLOWED_ORIGINS to be configured"
                .to_string(),
        );
    }

    if !allowed_origins.iter().any(|o| url.starts_with(o.as_str())) {
        return Err(
            "webhook_url does not match any allowed origin in SIRR_WEBHOOK_ALLOWED_ORIGINS"
                .to_string(),
        );
    }

    Ok(())
}

// ── WebhookSender ────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct WebhookSender {
    client: reqwest::Client,
    store: Store,
    instance_id: String,
    /// Signing key for per-secret webhook URLs (from SIRR_WEBHOOK_SECRET).
    per_secret_signing_key: Option<String>,
    /// Allowlist of URL prefixes for per-secret webhook URLs
    /// (from SIRR_WEBHOOK_ALLOWED_ORIGINS).  Empty = disabled.
    pub allowed_origins: Arc<Vec<String>>,
}

impl WebhookSender {
    pub fn new(
        store: Store,
        instance_id: String,
        per_secret_signing_key: Option<String>,
        allowed_origins: Arc<Vec<String>>,
    ) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .expect("build webhook reqwest client");

        Self {
            client,
            store,
            instance_id,
            per_secret_signing_key,
            allowed_origins,
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

        // Defense-in-depth: re-validate at delivery time in case a URL was stored
        // before the SSRF guard existed or the allowlist was changed.
        if let Err(reason) = validate_webhook_url(url, &self.allowed_origins) {
            warn!(url, %reason, "dropping per-secret webhook: SSRF guard rejected URL");
            return;
        }

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

    // ── validate_webhook_url ─────────────────────────────────────────────

    fn origins(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn valid_https_url_with_matching_origin() {
        let allowed = origins(&["https://hooks.example.com"]);
        assert!(validate_webhook_url("https://hooks.example.com/events", &allowed).is_ok());
    }

    #[test]
    fn rejects_http_scheme() {
        let allowed = origins(&["http://hooks.example.com"]);
        let err = validate_webhook_url("http://hooks.example.com/events", &allowed).unwrap_err();
        assert!(err.contains("https"), "expected https error, got: {err}");
    }

    #[test]
    fn rejects_private_ipv4() {
        let allowed = origins(&["https://10.0.0.1"]);
        let err = validate_webhook_url("https://10.0.0.1/hook", &allowed).unwrap_err();
        assert!(
            err.contains("private"),
            "expected private IP error, got: {err}"
        );
    }

    #[test]
    fn rejects_loopback() {
        let allowed = origins(&["https://127.0.0.1"]);
        let err = validate_webhook_url("https://127.0.0.1/hook", &allowed).unwrap_err();
        assert!(err.contains("private") || err.contains("loopback"), "{err}");
    }

    #[test]
    fn rejects_metadata_endpoint() {
        let allowed = origins(&["https://169.254.169.254"]);
        let err = validate_webhook_url("https://169.254.169.254/latest/meta-data/", &allowed)
            .unwrap_err();
        assert!(
            err.contains("private") || err.contains("link-local"),
            "{err}"
        );
    }

    #[test]
    fn rejects_when_no_allowlist() {
        let err = validate_webhook_url("https://hooks.example.com/events", &[]).unwrap_err();
        assert!(err.contains("SIRR_WEBHOOK_ALLOWED_ORIGINS"), "{err}");
    }

    #[test]
    fn rejects_url_not_in_allowlist() {
        let allowed = origins(&["https://hooks.example.com"]);
        let err = validate_webhook_url("https://attacker.example.org/hook", &allowed).unwrap_err();
        assert!(err.contains("allowed origin"), "{err}");
    }

    #[test]
    fn rejects_ipv6_loopback() {
        let allowed = origins(&["https://[::1]"]);
        let err = validate_webhook_url("https://[::1]/hook", &allowed).unwrap_err();
        assert!(err.contains("private") || err.contains("loopback"), "{err}");
    }

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
