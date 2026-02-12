use std::sync::Arc;
use std::sync::atomic::AtomicU64;

use axum::extract::{Extension, Path, Request, State};
use axum::http::StatusCode;
use axum::middleware;
use axum::response::{IntoResponse, Response};
use axum::routing::{any, get, post};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use rmcp::RoleServer;
use rmcp::Service as RmcpService;
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use rmcp::transport::streamable_http_server::{StreamableHttpServerConfig, StreamableHttpService};
use serde::{Deserialize, Serialize};

use subseq_auth::prelude::{AuthenticatedUser, UserId};

use crate::api_keys::{ApiKeyMetadata, ApiKeyStore, ApiKeyStoreError, CreatedApiKey};
use crate::key_management::{
    AllowAllKeyManagementAuthorizer, DynKeyManagementAuthorizer,
    KeyManagementAuthorizationDecision, KeyManagementOperation,
};
use crate::middleware::{ApiKeyMiddlewareState, api_key_auth_middleware};
use crate::rate_limits::{
    ApiKeyRateLimitConfig, ApiKeyRateLimitStore, InMemoryApiKeyRateLimitStore,
};

#[derive(Debug, Clone)]
pub struct McpMountProfile {
    pub name: &'static str,
}

impl McpMountProfile {
    pub fn new(name: &'static str) -> Self {
        Self { name }
    }

    fn base_path(&self) -> String {
        format!("/mcp/{}", self.name)
    }
}

#[derive(Clone)]
struct KeyRouteState {
    key_store: Arc<dyn ApiKeyStore>,
    mount_name: String,
    key_management_authorizer: DynKeyManagementAuthorizer,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateApiKeyRequest {
    expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ListApiKeysResponse {
    keys: Vec<ApiKeyMetadata>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct CreateApiKeyResponse {
    key: CreatedApiKey,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct RevokeApiKeyResponse {
    key: ApiKeyMetadata,
}

pub fn mcp_mount_router<S>(
    profile: McpMountProfile,
    service: S,
    key_store: Arc<dyn ApiKeyStore>,
) -> Router
where
    S: RmcpService<RoleServer> + Clone + Send + Sync + 'static,
{
    mcp_mount_router_with_controls(
        profile,
        service,
        key_store,
        Arc::new(InMemoryApiKeyRateLimitStore::default()),
        ApiKeyRateLimitConfig::default(),
        Arc::new(AllowAllKeyManagementAuthorizer),
    )
}

pub fn mcp_mount_router_with_rate_limits<S>(
    profile: McpMountProfile,
    service: S,
    key_store: Arc<dyn ApiKeyStore>,
    rate_limit_store: Arc<dyn ApiKeyRateLimitStore>,
    rate_limit_config: ApiKeyRateLimitConfig,
) -> Router
where
    S: RmcpService<RoleServer> + Clone + Send + Sync + 'static,
{
    mcp_mount_router_with_controls(
        profile,
        service,
        key_store,
        rate_limit_store,
        rate_limit_config,
        Arc::new(AllowAllKeyManagementAuthorizer),
    )
}

pub fn mcp_mount_router_with_controls<S>(
    profile: McpMountProfile,
    service: S,
    key_store: Arc<dyn ApiKeyStore>,
    rate_limit_store: Arc<dyn ApiKeyRateLimitStore>,
    rate_limit_config: ApiKeyRateLimitConfig,
    key_management_authorizer: DynKeyManagementAuthorizer,
) -> Router
where
    S: RmcpService<RoleServer> + Clone + Send + Sync + 'static,
{
    let base_path = profile.base_path();
    let key_list_path = format!("{base_path}/key");
    let key_named_path = format!("{base_path}/key/{{key_name}}");

    let streamable_service = StreamableHttpService::new(
        move || Ok(service.clone()),
        Arc::new(LocalSessionManager::default()),
        StreamableHttpServerConfig::default(),
    );

    let key_state = KeyRouteState {
        key_store: Arc::clone(&key_store),
        mount_name: profile.name.to_string(),
        key_management_authorizer,
    };

    let auth_state = ApiKeyMiddlewareState {
        key_store,
        mount_name: profile.name.to_string(),
        rate_limit_store,
        rate_limit_config,
        cleanup_counter: Arc::new(AtomicU64::new(0)),
    };

    let mcp_handler = {
        let streamable_service = streamable_service.clone();
        move |request: Request| {
            let streamable_service = streamable_service.clone();
            async move { streamable_service.handle(request).await }
        }
    };

    Router::new()
        .route(
            &base_path,
            any(mcp_handler).layer(middleware::from_fn_with_state(
                auth_state,
                api_key_auth_middleware,
            )),
        )
        .route(&key_list_path, get(list_api_keys_handler))
        .route(
            &key_named_path,
            post(create_api_key_handler).delete(revoke_api_key_handler),
        )
        .with_state(key_state)
}

async fn list_api_keys_handler(
    State(state): State<KeyRouteState>,
    auth_user: Option<Extension<AuthenticatedUser>>,
) -> Response {
    let user_id =
        match require_management_user(auth_user, &state, KeyManagementOperation::List).await {
            Ok(user_id) => user_id,
            Err(response) => return response,
        };
    match state.key_store.list_keys(user_id, &state.mount_name).await {
        Ok(keys) => Json(ListApiKeysResponse { keys }).into_response(),
        Err(err) => map_store_error(err),
    }
}

async fn create_api_key_handler(
    State(state): State<KeyRouteState>,
    Path(key_name): Path<String>,
    auth_user: Option<Extension<AuthenticatedUser>>,
    payload: Option<Json<CreateApiKeyRequest>>,
) -> Response {
    let user_id =
        match require_management_user(auth_user, &state, KeyManagementOperation::Create).await {
            Ok(user_id) => user_id,
            Err(response) => return response,
        };
    let expires_at = payload.and_then(|value| value.0.expires_at);
    match state
        .key_store
        .create_key(user_id, &state.mount_name, &key_name, expires_at)
        .await
    {
        Ok(key) => (StatusCode::CREATED, Json(CreateApiKeyResponse { key })).into_response(),
        Err(err) => map_store_error(err),
    }
}

async fn revoke_api_key_handler(
    State(state): State<KeyRouteState>,
    Path(key_name): Path<String>,
    auth_user: Option<Extension<AuthenticatedUser>>,
) -> Response {
    let user_id =
        match require_management_user(auth_user, &state, KeyManagementOperation::Revoke).await {
            Ok(user_id) => user_id,
            Err(response) => return response,
        };
    match state
        .key_store
        .revoke_key(user_id, &state.mount_name, &key_name)
        .await
    {
        Ok(key) => Json(RevokeApiKeyResponse { key }).into_response(),
        Err(err) => map_store_error(err),
    }
}

fn map_store_error(err: ApiKeyStoreError) -> Response {
    let (status, code, message) = match err {
        ApiKeyStoreError::InvalidKeyName => (
            StatusCode::BAD_REQUEST,
            "invalid_key_name",
            "Invalid key name",
        ),
        ApiKeyStoreError::InvalidExpiry => (
            StatusCode::BAD_REQUEST,
            "invalid_expires_at",
            "expiresAt must be in the future",
        ),
        ApiKeyStoreError::Conflict => (StatusCode::CONFLICT, "key_conflict", "Key already exists"),
        ApiKeyStoreError::NotFound => (StatusCode::NOT_FOUND, "key_not_found", "Key not found"),
        ApiKeyStoreError::Internal(msg) => {
            tracing::error!("api key store failure: {msg}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "Internal server error",
            )
        }
    };

    (
        status,
        Json(serde_json::json!({
            "error": {
                "code": code,
                "message": message,
            }
        })),
    )
        .into_response()
}

async fn require_management_user(
    auth_user: Option<Extension<AuthenticatedUser>>,
    state: &KeyRouteState,
    operation: KeyManagementOperation,
) -> Result<UserId, Response> {
    match auth_user {
        Some(Extension(auth_user)) => {
            let user_id = auth_user.id();
            match state
                .key_management_authorizer
                .authorize(user_id, &state.mount_name, operation)
                .await
            {
                Ok(KeyManagementAuthorizationDecision::Allow) => Ok(user_id),
                Ok(KeyManagementAuthorizationDecision::Deny(deny)) => Err((
                    deny.status,
                    Json(serde_json::json!({
                        "error": {
                            "code": deny.code,
                            "message": deny.message,
                        }
                    })),
                )
                    .into_response()),
                Err(err) => {
                    tracing::error!("key management authorization failed: {err}");
                    Err((
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(serde_json::json!({
                            "error": {
                                "code": "internal_error",
                                "message": "Internal server error",
                            }
                        })),
                    )
                        .into_response())
                }
            }
        }
        None => Err((
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({
                "error": {
                    "code": "unauthorized",
                    "message": "Unauthorized",
                }
            })),
        )
            .into_response()),
    }
}
