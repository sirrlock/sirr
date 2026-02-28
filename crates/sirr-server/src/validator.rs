//! Online license validation against SecretDrop.
//!
//! Cached with background revalidation so `create_secret` is never blocked
//! on HTTP after startup. A 72-hour grace period allows operation if
//! SecretDrop is temporarily unreachable.

use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::Deserialize;
use tokio::sync::RwLock;
use tracing::{info, warn};

use crate::store::audit::AuditEvent;
use crate::store::Store;

const ACTION_LICENSE_VALIDATE: &str = "license.validate";

/// JSON response from `GET /api/validate?key=...`.
#[derive(Debug, Deserialize)]
pub struct ValidationResponse {
    pub valid: bool,
    pub plan: Option<String>,
    pub limit: Option<u64>,
    pub reason: Option<String>,
}

/// Locally cached validation result.
#[derive(Debug, Clone)]
struct CachedValidation {
    valid: bool,
    plan: Option<String>,
    limit: Option<u64>,
    checked_at: Instant,
    /// Last time a *successful* (valid=true) response was received.
    last_success_at: Option<Instant>,
}

/// Online license validator with HTTP cache + grace period.
#[derive(Clone)]
pub struct OnlineValidator {
    client: reqwest::Client,
    license_key: String,
    validation_url: String,
    cache: Arc<RwLock<Option<CachedValidation>>>,
    cache_ttl: Duration,
    grace_period: Duration,
}

impl OnlineValidator {
    pub fn new(
        license_key: String,
        validation_url: String,
        cache_ttl_secs: u64,
        grace_period_secs: u64,
    ) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .expect("build reqwest client");

        Self {
            client,
            license_key,
            validation_url,
            cache: Arc::new(RwLock::new(None)),
            cache_ttl: Duration::from_secs(cache_ttl_secs),
            grace_period: Duration::from_secs(grace_period_secs),
        }
    }

    /// Call the SecretDrop validation endpoint.
    async fn validate_remote(&self) -> Result<ValidationResponse, reqwest::Error> {
        let url = format!("{}?key={}", self.validation_url, self.license_key);
        self.client.get(&url).send().await?.json().await
    }

    /// Run at server startup. Awaits the first validation; if unreachable, warns
    /// but allows the server to start (backward compatibility).
    pub async fn validate_startup(&self, store: &Store) -> bool {
        match self.validate_remote().await {
            Ok(resp) => {
                let valid = resp.valid;
                let now = Instant::now();

                let cached = CachedValidation {
                    valid,
                    plan: resp.plan.clone(),
                    limit: resp.limit,
                    checked_at: now,
                    last_success_at: if valid { Some(now) } else { None },
                };
                *self.cache.write().await = Some(cached);

                let detail = if valid {
                    format!("startup;plan={}", resp.plan.as_deref().unwrap_or("unknown"))
                } else {
                    format!(
                        "startup;denied;reason={}",
                        resp.reason.as_deref().unwrap_or("unknown")
                    )
                };

                let _ = store.record_audit(AuditEvent::new(
                    ACTION_LICENSE_VALIDATE,
                    None,
                    "server".into(),
                    valid,
                    Some(detail),
                ));

                if valid {
                    info!(
                        plan = resp.plan.as_deref().unwrap_or("unknown"),
                        "license validated online"
                    );
                } else {
                    warn!(
                        reason = resp.reason.as_deref().unwrap_or("unknown"),
                        "license rejected by SecretDrop"
                    );
                }
                valid
            }
            Err(e) => {
                warn!(error = %e, "SecretDrop unreachable at startup — allowing degraded mode");
                let _ = store.record_audit(AuditEvent::new(
                    ACTION_LICENSE_VALIDATE,
                    None,
                    "server".into(),
                    true,
                    Some(format!("startup;unreachable;error={e}")),
                ));
                // Seed cache with a "valid but unchecked" entry so grace period begins.
                let now = Instant::now();
                *self.cache.write().await = Some(CachedValidation {
                    valid: true,
                    plan: None,
                    limit: None,
                    checked_at: now,
                    last_success_at: Some(now),
                });
                true
            }
        }
    }

    /// Non-blocking check used by `create_secret`. Returns `true` if the
    /// license is currently considered valid.
    ///
    /// - Fresh cache (< cache_ttl) → use cached result
    /// - Stale cache → spawn background revalidation, use cached result
    /// - Grace period expired (> 72h since last success) → deny
    pub async fn is_valid(&self, store: &Store) -> bool {
        let cache = self.cache.read().await.clone();

        match cache {
            Some(c) => {
                let age = c.checked_at.elapsed();

                if age < self.cache_ttl {
                    // Fresh — use as-is.
                    return c.valid;
                }

                // Stale — spawn background revalidation.
                self.spawn_revalidate(store.clone());

                // Check grace period: if we've had a success within the grace window, allow.
                if let Some(last_ok) = c.last_success_at {
                    if last_ok.elapsed() < self.grace_period {
                        return true;
                    }
                }

                // Grace period expired — use last known result (which may be false).
                c.valid
            }
            None => {
                // No cache at all — shouldn't happen after startup, but deny to be safe.
                false
            }
        }
    }

    /// Spawn a background task to revalidate and update the cache.
    fn spawn_revalidate(&self, store: Store) {
        let this = self.clone();
        tokio::spawn(async move {
            match this.validate_remote().await {
                Ok(resp) => {
                    let valid = resp.valid;
                    let now = Instant::now();
                    let mut guard = this.cache.write().await;
                    let prev_success = guard.as_ref().and_then(|c| c.last_success_at);

                    *guard = Some(CachedValidation {
                        valid,
                        plan: resp.plan.clone(),
                        limit: resp.limit,
                        checked_at: now,
                        last_success_at: if valid { Some(now) } else { prev_success },
                    });

                    let detail = if valid {
                        format!(
                            "revalidate;plan={}",
                            resp.plan.as_deref().unwrap_or("unknown")
                        )
                    } else {
                        format!(
                            "revalidate;denied;reason={}",
                            resp.reason.as_deref().unwrap_or("unknown")
                        )
                    };

                    let _ = store.record_audit(AuditEvent::new(
                        ACTION_LICENSE_VALIDATE,
                        None,
                        "server".into(),
                        valid,
                        Some(detail),
                    ));
                }
                Err(e) => {
                    warn!(error = %e, "background license revalidation failed");
                    // Update checked_at so we don't spam revalidation on every request.
                    let mut guard = this.cache.write().await;
                    if let Some(ref mut c) = *guard {
                        c.checked_at = Instant::now();
                    }

                    let _ = store.record_audit(AuditEvent::new(
                        ACTION_LICENSE_VALIDATE,
                        None,
                        "server".into(),
                        false,
                        Some(format!("revalidate;unreachable;error={e}")),
                    ));
                }
            }
        });
    }

    /// Return the cached plan name, if available.
    pub async fn cached_plan(&self) -> Option<String> {
        self.cache
            .read()
            .await
            .as_ref()
            .and_then(|c| c.plan.clone())
    }

    /// Return the cached secret limit, if available.
    pub async fn cached_limit(&self) -> Option<u64> {
        self.cache.read().await.as_ref().and_then(|c| c.limit)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::audit::AuditQuery;
    use tempfile::tempdir;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn make_store() -> (Store, tempfile::TempDir) {
        let key = crate::store::crypto::generate_key();
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let store = Store::open(&db_path, key).unwrap();
        (store, dir)
    }

    #[tokio::test]
    async fn valid_license_caches_result() {
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/validate"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "valid": true,
                "plan": "pro",
                "limit": null
            })))
            .mount(&mock)
            .await;

        let (store, _dir) = make_store();
        let v = OnlineValidator::new(
            "sirr_lic_test".into(),
            format!("{}/api/validate", mock.uri()),
            3600,
            259200, // 72h
        );

        let result = v.validate_startup(&store).await;
        assert!(result);
        assert_eq!(v.cached_plan().await, Some("pro".into()));

        // Should use cache (no HTTP call).
        assert!(v.is_valid(&store).await);

        // Audit log should have the startup event.
        let events = store
            .list_audit(&AuditQuery {
                since: None,
                until: None,
                action: Some("license.validate".into()),
                limit: 100,
            })
            .unwrap();
        assert!(!events.is_empty());
        assert!(events[0].success);
    }

    #[tokio::test]
    async fn invalid_license_denied() {
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/validate"))
            .respond_with(ResponseTemplate::new(402).set_body_json(serde_json::json!({
                "valid": false,
                "reason": "expired"
            })))
            .mount(&mock)
            .await;

        let (store, _dir) = make_store();
        let v = OnlineValidator::new(
            "sirr_lic_test".into(),
            format!("{}/api/validate", mock.uri()),
            3600,
            259200,
        );

        let result = v.validate_startup(&store).await;
        assert!(!result);
        assert!(!v.is_valid(&store).await);
    }

    #[tokio::test]
    async fn unreachable_allows_degraded_mode() {
        // Use a URL that will definitely fail.
        let (store, _dir) = make_store();
        let v = OnlineValidator::new(
            "sirr_lic_test".into(),
            "http://127.0.0.1:1/api/validate".into(),
            3600,
            259200,
        );

        // Startup should succeed (degraded mode).
        let result = v.validate_startup(&store).await;
        assert!(result);

        // Cache should be seeded — is_valid should return true (within grace period).
        assert!(v.is_valid(&store).await);
    }

    #[tokio::test]
    async fn stale_cache_triggers_revalidation() {
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/validate"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "valid": true,
                "plan": "pro",
                "limit": null
            })))
            .expect(2..) // startup + revalidation
            .mount(&mock)
            .await;

        let (store, _dir) = make_store();
        // Cache TTL of 0 means immediately stale.
        let v = OnlineValidator::new(
            "sirr_lic_test".into(),
            format!("{}/api/validate", mock.uri()),
            0, // immediately stale
            259200,
        );

        v.validate_startup(&store).await;

        // This should trigger background revalidation due to stale cache,
        // but still return true (grace period).
        assert!(v.is_valid(&store).await);

        // Give background task time to complete.
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}
