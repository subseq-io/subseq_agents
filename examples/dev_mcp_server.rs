use std::env;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;

use anyhow::Context;
use axum::extract::{Request, State};
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::{Next, from_fn_with_state};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use chrono::Utc;
use rmcp::ServerHandler;
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::tool::Extension;
use rmcp::{tool, tool_handler, tool_router};
use serde_json::json;
use subseq_agents::{InMemoryApiKeyStore, McpMountProfile, ToolActor, mcp_mount_router};
use subseq_auth::prelude::{
    AuthenticatedUser, ClaimsVerificationError, CoreIdToken, CoreIdTokenClaims, OidcToken, UserId,
    ValidatesIdentity,
};
use uuid::Uuid;

const DEV_ID_TOKEN: &str = concat!(
    "eyJhbGciOiJSUzI1NiJ9.",
    "eyJpc3MiOiJodHRwczovL3NlcnZlci5leGFtcGxlLmNvbSIsImF1ZCI6WyJzNkJoZ",
    "FJrcXQzIl0sImV4cCI6MTMxMTI4MTk3MCwiaWF0IjoxMzExMjgwOTcwLCJzdWIiOi",
    "IyNDQwMDMyMCIsInRmYV9tZXRob2QiOiJ1MmYifQ.",
    "aW52YWxpZF9zaWduYXR1cmU"
);

#[derive(Clone)]
struct DevAuthConfig {
    default_user_id: Uuid,
    default_username: String,
    default_email: String,
    require_dev_header: bool,
}

#[derive(Clone)]
struct ExampleApp {
    auth: DevAuthConfig,
}

impl ValidatesIdentity for ExampleApp {
    fn validate_bearer(
        &self,
        _token: &str,
    ) -> Result<(CoreIdToken, CoreIdTokenClaims), ClaimsVerificationError> {
        Err(ClaimsVerificationError::Unsupported(
            "dev server uses x-dev-user-id auth shim".to_string(),
        ))
    }

    fn validate_token(
        &self,
        _token: &OidcToken,
    ) -> Result<(CoreIdToken, CoreIdTokenClaims), ClaimsVerificationError> {
        Err(ClaimsVerificationError::Unsupported(
            "dev server does not use OIDC sessions".to_string(),
        ))
    }

    fn refresh_token(
        &self,
        _token: OidcToken,
    ) -> impl std::future::Future<Output = anyhow::Result<OidcToken>> + Send {
        async { Err(anyhow::anyhow!("token refresh unsupported in dev server")) }
    }
}

#[derive(Debug, Clone)]
struct DevMcpService {
    tool_router: ToolRouter<Self>,
}

impl DevMcpService {
    fn new() -> Self {
        Self {
            tool_router: Self::tool_router(),
        }
    }
}

impl Default for DevMcpService {
    fn default() -> Self {
        Self::new()
    }
}

#[tool_router]
impl DevMcpService {
    #[tool(
        name = "whoami",
        description = "Return the authenticated actor resolved from API key auth."
    )]
    async fn whoami(&self, Extension(actor): Extension<ToolActor>) -> String {
        format!(
            "user_id={} mount={} api_key_id={} api_key_name={}",
            actor.user_id, actor.mcp_mount_name, actor.api_key_id, actor.api_key_name
        )
    }

    #[tool(name = "ping", description = "Simple health tool.")]
    async fn ping(&self) -> String {
        "pong".to_string()
    }
}

#[tool_handler]
impl ServerHandler for DevMcpService {}

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    let bind = env::var("SUBSEQ_AGENTS_EXAMPLE_BIND").unwrap_or_else(|_| "127.0.0.1:4020".into());
    let bind_addr: SocketAddr = bind
        .parse()
        .with_context(|| format!("invalid SUBSEQ_AGENTS_EXAMPLE_BIND '{bind}'"))?;

    let default_user_id = env::var("SUBSEQ_AGENTS_EXAMPLE_DEFAULT_USER_ID")
        .unwrap_or_else(|_| "00000000-0000-0000-0000-000000000001".to_string());
    let default_user_id = Uuid::parse_str(&default_user_id).with_context(|| {
        format!(
            "invalid SUBSEQ_AGENTS_EXAMPLE_DEFAULT_USER_ID '{}'",
            default_user_id
        )
    })?;

    let app_state = ExampleApp {
        auth: DevAuthConfig {
            default_user_id,
            default_username: env::var("SUBSEQ_AGENTS_EXAMPLE_DEFAULT_USERNAME")
                .unwrap_or_else(|_| "agents-example".to_string()),
            default_email: env::var("SUBSEQ_AGENTS_EXAMPLE_DEFAULT_EMAIL")
                .unwrap_or_else(|_| "agents-example@example.local".to_string()),
            require_dev_header: env_flag("SUBSEQ_AGENTS_EXAMPLE_REQUIRE_DEV_HEADER"),
        },
    };

    let key_store = Arc::new(InMemoryApiKeyStore::new());
    let mcp_router = mcp_mount_router(McpMountProfile::new("dev"), DevMcpService::new(), key_store);

    let protected_api_v1 = Router::new()
        .route("/dev/whoami", get(whoami_handler))
        .merge(mcp_router)
        .layer(from_fn_with_state(
            app_state.clone(),
            dev_identity_middleware,
        ));

    let app = Router::new()
        .nest(
            "/api/v1",
            Router::new().route("/healthz", get(health_handler)),
        )
        .nest("/api/v1", protected_api_v1);

    let listener = tokio::net::TcpListener::bind(bind_addr)
        .await
        .with_context(|| format!("failed to bind listener on {}", bind_addr))?;

    println!("subseq_agents dev example listening on http://{bind_addr}");
    println!("base path: /api/v1");
    println!("management auth shim headers: x-dev-user-id, x-dev-email, x-dev-username");
    println!("mcp mount path: /api/v1/mcp/dev");
    println!();
    println!("Quickstart:");
    println!("1) Create key:");
    println!("   curl -sS -X POST http://{bind_addr}/api/v1/mcp/dev/key/local");
    println!("2) Initialize MCP with key in x-api-key header");
    println!("3) Call tools/list and tools/call (whoami, ping)");

    axum::serve(listener, app)
        .await
        .context("dev server failed")
}

fn env_flag(name: &str) -> bool {
    match env::var(name) {
        Ok(value) => {
            let normalized = value.trim().to_ascii_lowercase();
            normalized == "1" || normalized == "true" || normalized == "yes"
        }
        Err(_) => false,
    }
}

async fn health_handler() -> Json<serde_json::Value> {
    Json(json!({
        "ok": true,
    }))
}

async fn whoami_handler(req: Request) -> Response {
    let Some(auth_user) = req.extensions().get::<AuthenticatedUser>() else {
        return json_error(StatusCode::UNAUTHORIZED, "unauthorized", "Unauthorized");
    };
    Json(json!({
        "userId": auth_user.id().to_string(),
        "username": auth_user.username(),
        "email": auth_user.email(),
    }))
    .into_response()
}

async fn dev_identity_middleware(
    State(app): State<ExampleApp>,
    mut req: Request,
    next: Next,
) -> Response {
    let headers = req.headers();
    let user_id = match parse_user_id(headers, &app.auth) {
        Ok(user_id) => user_id,
        Err(response) => return response,
    };
    let username = header_or_default(headers, "x-dev-username", &app.auth.default_username);
    let email = header_or_default(headers, "x-dev-email", &app.auth.default_email);

    let auth_user = match build_auth_user(user_id, &username, &email).await {
        Ok(user) => user,
        Err(message) => return json_error(StatusCode::BAD_REQUEST, "invalid_dev_auth", &message),
    };

    req.extensions_mut().insert(auth_user);
    next.run(req).await
}

fn parse_user_id(headers: &HeaderMap, auth: &DevAuthConfig) -> Result<UserId, Response> {
    let Some(raw_user_id) = header_value(headers, "x-dev-user-id") else {
        if auth.require_dev_header {
            return Err(json_error(
                StatusCode::UNAUTHORIZED,
                "missing_dev_user_id",
                "x-dev-user-id header is required",
            ));
        }
        return Ok(UserId(auth.default_user_id));
    };

    Uuid::parse_str(raw_user_id).map(UserId).map_err(|_| {
        json_error(
            StatusCode::BAD_REQUEST,
            "invalid_dev_user_id",
            "invalid UUID",
        )
    })
}

fn header_or_default(headers: &HeaderMap, key: &str, default: &str) -> String {
    header_value(headers, key)
        .filter(|value| !value.trim().is_empty())
        .map(|value| value.to_string())
        .unwrap_or_else(|| default.to_string())
}

fn header_value<'a>(headers: &'a HeaderMap, key: &str) -> Option<&'a str> {
    headers.get(key).and_then(|value| value.to_str().ok())
}

async fn build_auth_user(
    user_id: UserId,
    username: &str,
    email: &str,
) -> Result<AuthenticatedUser, String> {
    let now = Utc::now().timestamp();
    let token = CoreIdToken::from_str(DEV_ID_TOKEN)
        .map_err(|_| "failed to parse built-in dev token".to_string())?;
    let claims: CoreIdTokenClaims = serde_json::from_value(json!({
        "iss": "https://subseq-agents-example.local",
        "sub": user_id.to_string(),
        "aud": ["subseq_agents_example"],
        "exp": now + 3600,
        "iat": now,
        "email": email,
        "preferred_username": username
    }))
    .map_err(|err| format!("failed to build claims: {err}"))?;

    AuthenticatedUser::from_claims(token, claims)
        .await
        .map_err(|err| format!("invalid dev auth user: {err}"))
}

fn json_error(status: StatusCode, code: &'static str, message: &str) -> Response {
    (
        status,
        Json(json!({
            "error": {
                "code": code,
                "message": message,
            }
        })),
    )
        .into_response()
}
