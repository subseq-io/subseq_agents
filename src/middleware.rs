use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::{Request, State};
use axum::http::header::{AUTHORIZATION, HeaderMap};
use axum::http::{HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use serde_json::json;
use tokio::sync::Mutex;

use crate::api_keys::{ApiKeyStore, parse_presented_key};

#[derive(Clone)]
pub struct ApiKeyMiddlewareState {
    pub key_store: Arc<dyn ApiKeyStore>,
    pub mount_name: String,
    pub rate_limiter: Arc<ApiKeyRateLimiter>,
}

#[derive(Debug, Clone)]
pub struct ApiKeyRateLimitConfig {
    pub max_failures: u32,
    pub failure_window: Duration,
    pub block_duration: Duration,
}

impl Default for ApiKeyRateLimitConfig {
    fn default() -> Self {
        Self {
            max_failures: 5,
            failure_window: Duration::from_secs(60),
            block_duration: Duration::from_secs(300),
        }
    }
}

#[derive(Debug)]
struct AuthFailureRecord {
    failures: u32,
    window_started_at: Instant,
    blocked_until: Option<Instant>,
}

#[derive(Debug)]
pub struct ApiKeyRateLimiter {
    config: ApiKeyRateLimitConfig,
    state: Mutex<HashMap<String, AuthFailureRecord>>,
}

impl ApiKeyRateLimiter {
    pub fn new(config: ApiKeyRateLimitConfig) -> Self {
        Self {
            config,
            state: Mutex::new(HashMap::new()),
        }
    }

    async fn is_blocked(&self, key: &str) -> bool {
        let now = Instant::now();
        let mut guard = self.state.lock().await;
        prune_stale_records(&mut guard, now, &self.config);

        guard
            .get(key)
            .and_then(|record| record.blocked_until)
            .is_some_and(|blocked_until| blocked_until > now)
    }

    async fn record_success(&self, key: &str) {
        self.state.lock().await.remove(key);
    }

    async fn record_failure(&self, key: String) {
        let now = Instant::now();
        let mut guard = self.state.lock().await;
        prune_stale_records(&mut guard, now, &self.config);

        let record = guard.entry(key).or_insert(AuthFailureRecord {
            failures: 0,
            window_started_at: now,
            blocked_until: None,
        });

        if now.duration_since(record.window_started_at) > self.config.failure_window {
            record.failures = 0;
            record.window_started_at = now;
            record.blocked_until = None;
        }

        record.failures = record.failures.saturating_add(1);
        if record.failures >= self.config.max_failures {
            record.blocked_until = Some(now + self.config.block_duration);
        }
    }
}

impl Default for ApiKeyRateLimiter {
    fn default() -> Self {
        Self::new(ApiKeyRateLimitConfig::default())
    }
}

pub async fn api_key_auth_middleware(
    State(state): State<ApiKeyMiddlewareState>,
    mut request: Request,
    next: Next,
) -> Response {
    let Some(presented_key) = extract_api_key(request.headers()) else {
        return unauthorized_response("missing_api_key");
    };
    let rate_limit_key = rate_limit_key(presented_key);

    if state.rate_limiter.is_blocked(&rate_limit_key).await {
        return too_many_requests_response();
    }

    let actor = match state
        .key_store
        .authenticate_key(&state.mount_name, presented_key)
        .await
    {
        Ok(Some(actor)) => {
            state.rate_limiter.record_success(&rate_limit_key).await;
            actor
        }
        Ok(None) => {
            state.rate_limiter.record_failure(rate_limit_key).await;
            return unauthorized_response("invalid_api_key");
        }
        Err(err) => {
            tracing::error!("api key auth lookup failed: {err}");
            return internal_error_response();
        }
    };

    request.extensions_mut().insert(actor);
    next.run(request).await
}

fn extract_api_key(headers: &HeaderMap) -> Option<&str> {
    if let Some(header) = headers.get("x-api-key").and_then(value_to_trimmed_str) {
        return Some(header);
    }

    let authorization = headers.get(AUTHORIZATION)?.to_str().ok()?.trim();
    if let Some(token) = authorization.strip_prefix("Bearer ") {
        let token = token.trim();
        if !token.is_empty() {
            return Some(token);
        }
    }
    None
}

fn value_to_trimmed_str(value: &HeaderValue) -> Option<&str> {
    let value = value.to_str().ok()?.trim();
    if value.is_empty() {
        return None;
    }
    Some(value)
}

fn rate_limit_key(presented_key: &str) -> String {
    if let Some((id, _secret)) = parse_presented_key(presented_key) {
        return id.to_string();
    }

    "invalid_format".to_string()
}

fn unauthorized_response(code: &'static str) -> Response {
    (
        StatusCode::UNAUTHORIZED,
        axum::Json(json!({
            "error": {
                "code": code,
                "message": "Unauthorized",
            }
        })),
    )
        .into_response()
}

fn internal_error_response() -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        axum::Json(json!({
            "error": {
                "code": "internal_error",
                "message": "Internal server error",
            }
        })),
    )
        .into_response()
}

fn too_many_requests_response() -> Response {
    (
        StatusCode::TOO_MANY_REQUESTS,
        axum::Json(json!({
            "error": {
                "code": "rate_limited",
                "message": "Too many invalid API key attempts",
            }
        })),
    )
        .into_response()
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

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use axum::http::header::AUTHORIZATION;
    use axum::http::{HeaderMap, HeaderValue};

    use super::{ApiKeyRateLimitConfig, ApiKeyRateLimiter, extract_api_key, rate_limit_key};

    #[test]
    fn parses_x_api_key_first() {
        let mut headers = HeaderMap::new();
        headers.insert("x-api-key", HeaderValue::from_static("abc"));
        headers.insert(AUTHORIZATION, HeaderValue::from_static("Bearer def"));
        assert_eq!(extract_api_key(&headers), Some("abc"));
    }

    #[test]
    fn parses_bearer_fallback() {
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, HeaderValue::from_static("Bearer def"));
        assert_eq!(extract_api_key(&headers), Some("def"));
    }

    #[tokio::test]
    async fn rate_limiter_blocks_after_repeated_failures() {
        let limiter = ApiKeyRateLimiter::new(ApiKeyRateLimitConfig {
            max_failures: 2,
            failure_window: Duration::from_secs(60),
            block_duration: Duration::from_secs(60),
        });

        let key = "invalid_format".to_string();
        limiter.record_failure(key.clone()).await;
        assert!(!limiter.is_blocked(&key).await);

        limiter.record_failure(key.clone()).await;
        assert!(limiter.is_blocked(&key).await);
    }

    #[test]
    fn rate_limit_uses_key_id_when_present() {
        let key = "mcpk_123e4567-e89b-12d3-a456-426614174000.secret";
        assert_eq!(rate_limit_key(key), "123e4567-e89b-12d3-a456-426614174000");
    }
}
