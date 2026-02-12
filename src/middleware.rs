use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use axum::extract::{Request, State};
use axum::http::header::{AUTHORIZATION, HeaderMap};
use axum::http::{HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use serde_json::json;

use crate::api_keys::ApiKeyStore;
use crate::rate_limits::{ApiKeyRateLimitConfig, ApiKeyRateLimitStore, rate_limit_key};

#[derive(Clone)]
pub struct ApiKeyMiddlewareState {
    pub key_store: Arc<dyn ApiKeyStore>,
    pub mount_name: String,
    pub rate_limit_store: Arc<dyn ApiKeyRateLimitStore>,
    pub rate_limit_config: ApiKeyRateLimitConfig,
    pub cleanup_counter: Arc<AtomicU64>,
}

pub async fn api_key_auth_middleware(
    State(state): State<ApiKeyMiddlewareState>,
    mut request: Request,
    next: Next,
) -> Response {
    maybe_run_cleanup(&state).await;

    let Some(presented_key) = extract_api_key(request.headers()) else {
        return unauthorized_response("missing_api_key");
    };
    let rate_key = rate_limit_key(presented_key);

    match state.rate_limit_store.is_blocked(&rate_key).await {
        Ok(true) => return too_many_requests_response(),
        Ok(false) => {}
        Err(err) => {
            tracing::error!("api key rate limit check failed: {err}");
            return internal_error_response();
        }
    }

    let actor = match state
        .key_store
        .authenticate_key(&state.mount_name, presented_key)
        .await
    {
        Ok(Some(actor)) => {
            if let Err(err) = state.rate_limit_store.record_success(&rate_key).await {
                tracing::error!("api key rate limit success update failed: {err}");
                return internal_error_response();
            }
            actor
        }
        Ok(None) => {
            if let Err(err) = state
                .rate_limit_store
                .record_failure(&rate_key, &state.rate_limit_config)
                .await
            {
                tracing::error!("api key rate limit failure update failed: {err}");
                return internal_error_response();
            }
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

async fn maybe_run_cleanup(state: &ApiKeyMiddlewareState) {
    let cleanup_every = state.rate_limit_config.cleanup_after_requests.max(1);
    let count = state.cleanup_counter.fetch_add(1, Ordering::Relaxed);
    if count % cleanup_every != 0 {
        return;
    }

    if let Err(err) = state
        .rate_limit_store
        .cleanup_expired(&state.rate_limit_config)
        .await
    {
        tracing::warn!("api key rate limit cleanup failed: {err}");
    }
}

#[cfg(test)]
mod tests {
    use axum::http::header::AUTHORIZATION;
    use axum::http::{HeaderMap, HeaderValue};

    use crate::rate_limits::rate_limit_key;

    use super::extract_api_key;

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

    #[test]
    fn rate_limit_uses_key_id_when_present() {
        let key = "mcpk_123e4567-e89b-12d3-a456-426614174000.secret";
        assert_eq!(rate_limit_key(key), "123e4567-e89b-12d3-a456-426614174000");
    }
}
