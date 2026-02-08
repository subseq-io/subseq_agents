use std::sync::Arc;

use axum::extract::{Request, State};
use axum::http::header::{AUTHORIZATION, HeaderMap};
use axum::http::{HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use serde_json::json;

use crate::api_keys::ApiKeyStore;

#[derive(Clone)]
pub struct ApiKeyMiddlewareState {
    pub key_store: Arc<dyn ApiKeyStore>,
    pub mount_name: String,
}

pub async fn api_key_auth_middleware(
    State(state): State<ApiKeyMiddlewareState>,
    mut request: Request,
    next: Next,
) -> Response {
    let Some(presented_key) = extract_api_key(request.headers()) else {
        return unauthorized_response("missing_api_key");
    };

    let actor = match state
        .key_store
        .authenticate_key(&state.mount_name, presented_key)
        .await
    {
        Ok(Some(actor)) => actor,
        Ok(None) => return unauthorized_response("invalid_api_key"),
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

#[cfg(test)]
mod tests {
    use axum::http::header::AUTHORIZATION;
    use axum::http::{HeaderMap, HeaderValue};

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
}
