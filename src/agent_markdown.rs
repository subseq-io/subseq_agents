use std::collections::HashMap;
use std::fs;
use std::future::Future;
use std::path::{Component, Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use axum::http::{HeaderMap, HeaderValue, Method, Request, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use thiserror::Error;
use tower::{Layer, Service};
use tower_http::services::ServeDir;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MarkdownMissBehavior {
    HtmlFallback,
    NotAcceptable,
    NotFound,
}

impl Default for MarkdownMissBehavior {
    fn default() -> Self {
        Self::HtmlFallback
    }
}

#[derive(Debug, Clone)]
pub struct AgentMarkdownConfig {
    pub frontend_root: PathBuf,
    pub manifest_rel_path: PathBuf,
    pub markdown_prefix: String,
    pub miss_behavior: MarkdownMissBehavior,
}

impl Default for AgentMarkdownConfig {
    fn default() -> Self {
        Self {
            frontend_root: PathBuf::from("dist"),
            manifest_rel_path: PathBuf::from("__agent/routes.json"),
            markdown_prefix: "/__agent/".to_string(),
            miss_behavior: MarkdownMissBehavior::HtmlFallback,
        }
    }
}

impl AgentMarkdownConfig {
    pub fn default_for(frontend_root: PathBuf) -> Self {
        Self {
            frontend_root,
            ..Self::default()
        }
    }

    fn manifest_path(&self) -> PathBuf {
        self.frontend_root.join(&self.manifest_rel_path)
    }
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RouteVisibility {
    Public,
    PrivateMetadata,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentRouteEntry {
    pub path: String,
    pub visibility: RouteVisibility,
    pub markdown_path: String,
    pub title: Option<String>,
    pub summary: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct AgentManifest {
    pub schema_version: u32,
    pub app: Option<String>,
    pub generated_at: Option<String>,
    routes: HashMap<String, AgentRouteEntry>,
}

impl AgentManifest {
    pub fn empty() -> Self {
        Self::default()
    }

    pub fn is_empty(&self) -> bool {
        self.routes.is_empty()
    }

    pub fn route_for_path(&self, path: &str) -> Option<&AgentRouteEntry> {
        let normalized = normalize_runtime_path(path);
        self.routes.get(&normalized)
    }

    pub fn routes(&self) -> impl Iterator<Item = &AgentRouteEntry> {
        self.routes.values()
    }
}

#[derive(Debug, Error)]
pub enum ManifestError {
    #[error("failed to read manifest at {path}: {source}")]
    ReadManifest {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("failed to parse manifest at {path}: {source}")]
    ParseManifest {
        path: PathBuf,
        source: serde_json::Error,
    },
    #[error("unsupported schemaVersion {found}; expected 1")]
    UnsupportedSchemaVersion { found: u32 },
    #[error("route[{index}] has invalid path: {reason}")]
    InvalidRoutePath { index: usize, reason: String },
    #[error("route[{index}] has invalid markdownPath `{path}`: {reason}")]
    InvalidMarkdownPath {
        index: usize,
        path: String,
        reason: String,
    },
    #[error("duplicate route path `{path}` in manifest")]
    DuplicateRoutePath { path: String },
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawAgentManifest {
    schema_version: u32,
    app: Option<String>,
    generated_at: Option<String>,
    #[serde(default)]
    routes: Vec<RawAgentRouteEntry>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawAgentRouteEntry {
    path: String,
    visibility: RouteVisibility,
    markdown_path: String,
    title: Option<String>,
    summary: Option<String>,
    #[allow(dead_code)]
    source_pattern: Option<String>,
}

pub fn load_manifest(config: &AgentMarkdownConfig) -> Result<AgentManifest, ManifestError> {
    let manifest_path = config.manifest_path();
    let bytes = fs::read(&manifest_path).map_err(|source| ManifestError::ReadManifest {
        path: manifest_path.clone(),
        source,
    })?;
    let raw: RawAgentManifest =
        serde_json::from_slice(&bytes).map_err(|source| ManifestError::ParseManifest {
            path: manifest_path,
            source,
        })?;

    if raw.schema_version != 1 {
        return Err(ManifestError::UnsupportedSchemaVersion {
            found: raw.schema_version,
        });
    }

    let mut routes = HashMap::with_capacity(raw.routes.len());
    for (index, route) in raw.routes.into_iter().enumerate() {
        let normalized_path = normalize_manifest_path(&route.path)
            .map_err(|reason| ManifestError::InvalidRoutePath { index, reason })?;
        let markdown_path =
            validate_markdown_path(&route.markdown_path, config).map_err(|reason| {
                ManifestError::InvalidMarkdownPath {
                    index,
                    path: route.markdown_path.clone(),
                    reason,
                }
            })?;
        let entry = AgentRouteEntry {
            path: normalized_path.clone(),
            visibility: route.visibility,
            markdown_path,
            title: route.title,
            summary: route.summary,
        };

        if routes.insert(normalized_path.clone(), entry).is_some() {
            return Err(ManifestError::DuplicateRoutePath {
                path: normalized_path,
            });
        }
    }

    Ok(AgentManifest {
        schema_version: raw.schema_version,
        app: raw.app,
        generated_at: raw.generated_at,
        routes,
    })
}

#[derive(Debug, Clone)]
struct MarkdownNegotiationState {
    manifest: Arc<AgentManifest>,
    config: AgentMarkdownConfig,
}

#[derive(Debug, Clone)]
pub struct MarkdownNegotiationLayer {
    state: MarkdownNegotiationState,
}

#[derive(Clone)]
pub struct MarkdownNegotiationService<S> {
    inner: S,
    state: MarkdownNegotiationState,
}

pub fn markdown_negotiation_layer(
    manifest: Arc<AgentManifest>,
    config: AgentMarkdownConfig,
) -> MarkdownNegotiationLayer {
    MarkdownNegotiationLayer {
        state: MarkdownNegotiationState { manifest, config },
    }
}

pub fn markdown_static_service(frontend_root: &Path) -> ServeDir {
    ServeDir::new(frontend_root)
}

impl<S> Layer<S> for MarkdownNegotiationLayer {
    type Service = MarkdownNegotiationService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        MarkdownNegotiationService {
            inner,
            state: self.state.clone(),
        }
    }
}

impl<S, B> Service<Request<B>> for MarkdownNegotiationService<S>
where
    S: Service<Request<B>, Response = Response> + Clone + Send + 'static,
    S::Future: Send + 'static,
    B: Send + 'static,
{
    type Response = Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: Request<B>) -> Self::Future {
        let state = self.state.clone();
        let mut inner = self.inner.clone();

        Box::pin(async move { handle_markdown_negotiation(state, request, &mut inner).await })
    }
}

async fn handle_markdown_negotiation<S, B>(
    state: MarkdownNegotiationState,
    mut request: Request<B>,
    inner: &mut S,
) -> Result<Response, S::Error>
where
    S: Service<Request<B>, Response = Response>,
{
    let method = request.method().clone();
    let request_path = request.uri().path().to_string();
    let is_eligible_method = method == Method::GET || method == Method::HEAD;
    let is_api_path = path_is_api(&request_path);
    let negotiated_markdown =
        is_eligible_method && !is_api_path && accepts_markdown(request.headers());

    let mut rewritten_to_markdown = false;

    if negotiated_markdown {
        match state.manifest.route_for_path(&request_path) {
            Some(route) => {
                rewritten_to_markdown = true;
                rewrite_request_path(&mut request, &route.markdown_path);
                tracing::debug!(
                    markdown_hit = true,
                    path = %request_path,
                    markdown_path = %route.markdown_path,
                    "agent markdown route matched"
                );
            }
            None => {
                tracing::debug!(
                    markdown_hit = false,
                    path = %request_path,
                    "agent markdown route miss"
                );
                match state.config.miss_behavior {
                    MarkdownMissBehavior::HtmlFallback => {}
                    MarkdownMissBehavior::NotAcceptable => {
                        let mut response = (
                            StatusCode::NOT_ACCEPTABLE,
                            "No markdown representation for this route",
                        )
                            .into_response();
                        append_vary_accept(response.headers_mut());
                        return Ok(response);
                    }
                    MarkdownMissBehavior::NotFound => {
                        let mut response = (
                            StatusCode::NOT_FOUND,
                            "No markdown representation for this route",
                        )
                            .into_response();
                        append_vary_accept(response.headers_mut());
                        return Ok(response);
                    }
                }
            }
        }
    }

    let mut response = inner.call(request).await?;

    if is_eligible_method && !is_api_path {
        append_vary_accept(response.headers_mut());
    }
    if rewritten_to_markdown && response.status().is_success() {
        response.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/markdown; charset=utf-8"),
        );
    }

    Ok(response)
}

fn normalize_manifest_path(path: &str) -> Result<String, String> {
    let trimmed = path.trim();
    if trimmed.is_empty() {
        return Err("path cannot be empty".to_string());
    }
    if !trimmed.starts_with('/') {
        return Err("path must start with `/`".to_string());
    }
    if trimmed.contains('?') || trimmed.contains('#') {
        return Err("path cannot include query or hash".to_string());
    }

    Ok(normalize_runtime_path(trimmed))
}

fn normalize_runtime_path(path: &str) -> String {
    if path == "/" {
        return "/".to_string();
    }
    let normalized = path.trim_end_matches('/');
    if normalized.is_empty() {
        "/".to_string()
    } else {
        normalized.to_string()
    }
}

fn validate_markdown_path(path: &str, config: &AgentMarkdownConfig) -> Result<String, String> {
    let trimmed = path.trim();
    if trimmed.is_empty() {
        return Err("markdownPath cannot be empty".to_string());
    }
    if !trimmed.starts_with('/') {
        return Err("markdownPath must start with `/`".to_string());
    }
    if !trimmed.starts_with(&config.markdown_prefix) {
        return Err(format!(
            "markdownPath must start with `{}`",
            config.markdown_prefix
        ));
    }
    if trimmed.contains('?') || trimmed.contains('#') {
        return Err("markdownPath cannot include query or hash".to_string());
    }
    if trimmed.ends_with('/') {
        return Err("markdownPath must reference a file, not a directory".to_string());
    }

    let relative = trimmed.trim_start_matches('/');
    let relative_path = Path::new(relative);
    for component in relative_path.components() {
        match component {
            Component::Normal(_) | Component::CurDir => {}
            Component::ParentDir => {
                return Err("markdownPath cannot contain `..`".to_string());
            }
            Component::RootDir | Component::Prefix(_) => {
                return Err("markdownPath must be relative to frontend root".to_string());
            }
        }
    }

    Ok(trimmed.to_string())
}

fn rewrite_request_path<B>(request: &mut Request<B>, new_path: &str) {
    let current = request.uri().clone();
    let rewritten = rewrite_uri_path(&current, new_path);
    *request.uri_mut() = rewritten;
}

fn rewrite_uri_path(current: &Uri, new_path: &str) -> Uri {
    let mut parts = current.clone().into_parts();
    let query = parts
        .path_and_query
        .as_ref()
        .and_then(|path_and_query| path_and_query.query());
    let new_path_and_query = match query {
        Some(query) => format!("{new_path}?{query}"),
        None => new_path.to_string(),
    };

    let Ok(parsed_path_and_query) = new_path_and_query.parse() else {
        return current.clone();
    };
    parts.path_and_query = Some(parsed_path_and_query);
    Uri::from_parts(parts).unwrap_or_else(|_| current.clone())
}

fn path_is_api(path: &str) -> bool {
    path == "/api" || path.starts_with("/api/")
}

fn accepts_markdown(headers: &HeaderMap) -> bool {
    headers
        .get_all(header::ACCEPT)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .any(accept_header_mentions_markdown)
}

fn accept_header_mentions_markdown(value: &str) -> bool {
    value
        .split(',')
        .any(|media_range| media_range_allows_markdown(media_range.trim()))
}

fn media_range_allows_markdown(media_range: &str) -> bool {
    let mut parts = media_range.split(';');
    let media_type = parts
        .next()
        .map(str::trim)
        .map(str::to_ascii_lowercase)
        .unwrap_or_default();
    if media_type != "text/markdown" {
        return false;
    }

    let mut q = 1.0_f32;
    for parameter in parts {
        let mut split = parameter.splitn(2, '=');
        let name = split.next().map(str::trim).unwrap_or_default();
        if !name.eq_ignore_ascii_case("q") {
            continue;
        }
        let value = split.next().map(str::trim).unwrap_or_default();
        q = value.trim_matches('"').parse::<f32>().unwrap_or(0.0);
    }

    q > 0.0
}

fn append_vary_accept(headers: &mut HeaderMap) {
    let mut vary_values = Vec::new();
    for header_value in headers.get_all(header::VARY).iter() {
        if let Ok(value) = header_value.to_str() {
            vary_values.extend(
                value
                    .split(',')
                    .map(|part| part.trim())
                    .filter(|part| !part.is_empty()),
            );
        }
    }

    if vary_values
        .iter()
        .any(|part| part.eq_ignore_ascii_case("accept"))
    {
        return;
    }

    vary_values.push("Accept");
    let combined = vary_values.join(", ");
    if let Ok(value) = HeaderValue::from_str(&combined) {
        headers.insert(header::VARY, value);
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::sync::Arc;

    use axum::Router;
    use axum::body::{Body, to_bytes};
    use axum::http::{Request, StatusCode, header};
    use axum::routing::get;
    use serde_json::json;
    use tempfile::TempDir;
    use tower::ServiceExt;
    use tower_http::services::{ServeDir, ServeFile};

    use super::{
        AgentMarkdownConfig, ManifestError, MarkdownMissBehavior, load_manifest,
        markdown_negotiation_layer, markdown_static_service,
    };

    #[test]
    fn load_manifest_rejects_duplicate_route_paths() {
        let dir = TempDir::new().expect("create temp dir");
        write_routes(
            dir.path(),
            json!({
                "schemaVersion": 1,
                "app": "test-app",
                "generatedAt": "2026-02-22T01:00:00.000Z",
                "routes": [
                    {
                        "path": "/",
                        "visibility": "public",
                        "markdownPath": "/__agent/pages/index.md"
                    },
                    {
                        "path": "/",
                        "visibility": "public",
                        "markdownPath": "/__agent/pages/other.md"
                    }
                ]
            }),
        );

        let config = AgentMarkdownConfig::default_for(dir.path().to_path_buf());
        let err = load_manifest(&config).expect_err("manifest should fail");
        assert!(matches!(err, ManifestError::DuplicateRoutePath { .. }));
    }

    #[test]
    fn load_manifest_requires_prefix_confined_markdown_paths() {
        let dir = TempDir::new().expect("create temp dir");
        write_routes(
            dir.path(),
            json!({
                "schemaVersion": 1,
                "app": "test-app",
                "generatedAt": "2026-02-22T01:00:00.000Z",
                "routes": [
                    {
                        "path": "/",
                        "visibility": "public",
                        "markdownPath": "/outside/index.md"
                    }
                ]
            }),
        );

        let config = AgentMarkdownConfig::default_for(dir.path().to_path_buf());
        let err = load_manifest(&config).expect_err("manifest should fail");
        assert!(matches!(err, ManifestError::InvalidMarkdownPath { .. }));
    }

    #[tokio::test]
    async fn markdown_accept_serves_markdown_file_and_sets_vary() {
        let (dir, config, manifest) = fixture();
        let app = build_app(dir.path(), config, manifest);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header(header::ACCEPT, "text/markdown")
                    .body(Body::empty())
                    .expect("build request"),
            )
            .await
            .expect("serve request");

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()),
            Some("text/markdown; charset=utf-8")
        );
        assert_eq!(
            response
                .headers()
                .get(header::VARY)
                .and_then(|value| value.to_str().ok()),
            Some("Accept")
        );

        let body = response_to_string(response).await;
        assert!(body.contains("# Home"));
    }

    #[tokio::test]
    async fn markdown_miss_falls_back_to_html_when_configured() {
        let (dir, config, manifest) = fixture();
        let app = build_app(dir.path(), config, manifest);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/missing")
                    .header(header::ACCEPT, "text/markdown")
                    .body(Body::empty())
                    .expect("build request"),
            )
            .await
            .expect("serve request");

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get(header::VARY)
                .and_then(|value| value.to_str().ok()),
            Some("Accept")
        );
        let body = response_to_string(response).await;
        assert!(body.contains("<html>"));
    }

    #[tokio::test]
    async fn markdown_never_rewrites_api_routes() {
        let (dir, config, manifest) = fixture();
        let app = build_app(dir.path(), config, manifest);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/echo")
                    .header(header::ACCEPT, "text/markdown")
                    .body(Body::empty())
                    .expect("build request"),
            )
            .await
            .expect("serve request");

        assert_eq!(response.status(), StatusCode::OK);
        assert_ne!(
            response
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()),
            Some("text/markdown; charset=utf-8")
        );
        let body = response_to_string(response).await;
        assert!(body.contains("ok"));
    }

    #[tokio::test]
    async fn markdown_miss_not_acceptable_returns_406() {
        let (dir, mut config, manifest) = fixture();
        config.miss_behavior = MarkdownMissBehavior::NotAcceptable;
        let app = build_app(dir.path(), config, manifest);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/missing")
                    .header(header::ACCEPT, "text/markdown")
                    .body(Body::empty())
                    .expect("build request"),
            )
            .await
            .expect("serve request");

        assert_eq!(response.status(), StatusCode::NOT_ACCEPTABLE);
        assert_eq!(
            response
                .headers()
                .get(header::VARY)
                .and_then(|value| value.to_str().ok()),
            Some("Accept")
        );
    }

    fn build_app(
        root: &std::path::Path,
        config: AgentMarkdownConfig,
        manifest: super::AgentManifest,
    ) -> Router {
        let spa = ServeDir::new(root).fallback(ServeFile::new(root.join("index.html")));

        Router::new()
            .route(
                "/api/v1/echo",
                get(|| async { axum::Json(json!({ "ok": true })) }),
            )
            .route_service("/__agent/{*path}", markdown_static_service(root))
            .fallback_service(spa)
            .layer(markdown_negotiation_layer(Arc::new(manifest), config))
    }

    fn fixture() -> (TempDir, AgentMarkdownConfig, super::AgentManifest) {
        let dir = TempDir::new().expect("create temp dir");
        fs::create_dir_all(dir.path().join("__agent/pages/private"))
            .expect("create markdown directory");
        fs::write(
            dir.path().join("index.html"),
            "<html><body>SPA</body></html>",
        )
        .expect("write index");
        fs::write(dir.path().join("__agent/pages/index.md"), "# Home\n").expect("write markdown");
        fs::write(
            dir.path().join("__agent/pages/private/portal-sessions.md"),
            "# Portal Sessions\nContent omitted. Authentication required.\n",
        )
        .expect("write private markdown");

        write_routes(
            dir.path(),
            json!({
                "schemaVersion": 1,
                "app": "test-app",
                "generatedAt": "2026-02-22T01:00:00.000Z",
                "routes": [
                    {
                        "path": "/",
                        "visibility": "public",
                        "markdownPath": "/__agent/pages/index.md",
                        "title": "Home",
                        "summary": "Public home page."
                    },
                    {
                        "path": "/portal/sessions",
                        "visibility": "private_metadata",
                        "markdownPath": "/__agent/pages/private/portal-sessions.md",
                        "title": "Portal Sessions",
                        "summary": "Private metadata only."
                    }
                ]
            }),
        );

        let config = AgentMarkdownConfig::default_for(dir.path().to_path_buf());
        let manifest = load_manifest(&config).expect("load manifest");
        (dir, config, manifest)
    }

    fn write_routes(root: &std::path::Path, routes_json: serde_json::Value) {
        fs::create_dir_all(root.join("__agent")).expect("create __agent");
        fs::write(
            root.join("__agent/routes.json"),
            serde_json::to_vec(&routes_json).expect("serialize routes"),
        )
        .expect("write routes");
    }

    async fn response_to_string(response: axum::response::Response) -> String {
        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("read response body");
        String::from_utf8(body.to_vec()).expect("utf8 body")
    }
}
