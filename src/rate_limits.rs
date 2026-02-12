use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use thiserror::Error;
use tokio::sync::Mutex;

use crate::api_keys::parse_presented_key;

#[derive(Debug, Clone)]
pub struct ApiKeyRateLimitConfig {
    pub max_failures: u32,
    pub failure_window: Duration,
    pub block_duration: Duration,
    pub cleanup_after_requests: u64,
}

impl Default for ApiKeyRateLimitConfig {
    fn default() -> Self {
        Self {
            max_failures: 5,
            failure_window: Duration::from_secs(60),
            block_duration: Duration::from_secs(300),
            cleanup_after_requests: 100,
        }
    }
}

#[derive(Debug, Error)]
pub enum ApiKeyRateLimitError {
    #[error("Rate limit backend error: {0}")]
    Backend(String),
}

#[async_trait]
pub trait ApiKeyRateLimitStore: Send + Sync + 'static {
    async fn is_blocked(&self, key: &str) -> Result<bool, ApiKeyRateLimitError>;
    async fn record_success(&self, key: &str) -> Result<(), ApiKeyRateLimitError>;
    async fn record_failure(
        &self,
        key: &str,
        config: &ApiKeyRateLimitConfig,
    ) -> Result<(), ApiKeyRateLimitError>;
    async fn cleanup_expired(
        &self,
        config: &ApiKeyRateLimitConfig,
    ) -> Result<(), ApiKeyRateLimitError>;
}

#[derive(Debug, Clone)]
pub struct InMemoryApiKeyRateLimitStore {
    state: Arc<Mutex<HashMap<String, AuthFailureRecord>>>,
}

impl InMemoryApiKeyRateLimitStore {
    pub fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl Default for InMemoryApiKeyRateLimitStore {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
struct AuthFailureRecord {
    failures: u32,
    window_started_at: Instant,
    blocked_until: Option<Instant>,
}

#[async_trait]
impl ApiKeyRateLimitStore for InMemoryApiKeyRateLimitStore {
    async fn is_blocked(&self, key: &str) -> Result<bool, ApiKeyRateLimitError> {
        let now = Instant::now();
        let guard = self.state.lock().await;
        Ok(guard
            .get(key)
            .and_then(|record| record.blocked_until)
            .is_some_and(|blocked_until| blocked_until > now))
    }

    async fn record_success(&self, key: &str) -> Result<(), ApiKeyRateLimitError> {
        self.state.lock().await.remove(key);
        Ok(())
    }

    async fn record_failure(
        &self,
        key: &str,
        config: &ApiKeyRateLimitConfig,
    ) -> Result<(), ApiKeyRateLimitError> {
        let now = Instant::now();
        let mut guard = self.state.lock().await;
        prune_stale_records(&mut guard, now, config);

        let record = guard.entry(key.to_string()).or_insert(AuthFailureRecord {
            failures: 0,
            window_started_at: now,
            blocked_until: None,
        });

        if now.duration_since(record.window_started_at) > config.failure_window {
            record.failures = 0;
            record.window_started_at = now;
            record.blocked_until = None;
        }

        record.failures = record.failures.saturating_add(1);
        if record.failures >= config.max_failures {
            record.blocked_until = Some(now + config.block_duration);
        }

        Ok(())
    }

    async fn cleanup_expired(
        &self,
        config: &ApiKeyRateLimitConfig,
    ) -> Result<(), ApiKeyRateLimitError> {
        let now = Instant::now();
        let mut guard = self.state.lock().await;
        prune_stale_records(&mut guard, now, config);
        Ok(())
    }
}

fn prune_stale_records(
    records: &mut HashMap<String, AuthFailureRecord>,
    now: Instant,
    config: &ApiKeyRateLimitConfig,
) {
    records.retain(|_, record| {
        if record
            .blocked_until
            .is_some_and(|blocked_until| blocked_until > now)
        {
            return true;
        }
        now.duration_since(record.window_started_at) <= config.failure_window
    });
}

pub fn rate_limit_key(presented_key: &str) -> String {
    if let Some((id, _secret)) = parse_presented_key(presented_key) {
        return id.to_string();
    }

    "invalid_format".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn in_memory_rate_limiter_blocks_after_threshold() {
        let store = InMemoryApiKeyRateLimitStore::new();
        let config = ApiKeyRateLimitConfig {
            max_failures: 2,
            failure_window: Duration::from_secs(60),
            block_duration: Duration::from_secs(60),
            cleanup_after_requests: 100,
        };

        store
            .record_failure("invalid_format", &config)
            .await
            .expect("record first failure");
        assert!(
            !store
                .is_blocked("invalid_format")
                .await
                .expect("read blocked state")
        );

        store
            .record_failure("invalid_format", &config)
            .await
            .expect("record second failure");
        assert!(
            store
                .is_blocked("invalid_format")
                .await
                .expect("read blocked state")
        );
    }
}
