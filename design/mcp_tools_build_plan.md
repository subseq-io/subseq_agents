# subseq_agents Build Plan (rmcp + axum + subseq_auth)

## Goals

1. Provide an MCP server in this repo with a high-level `tool_router` surface (`rmcp`).
2. Run over `axum` transport with JWT authentication middleware.
3. Derive trusted `AuthenticatedUser -> UserId` from request auth, never from tool arguments.
4. Keep room for deferred components:
   - agent-scoped token IdP flow
   - agent runner that brokers user auth and MCP calls

## Non-Goals (for initial delivery)

1. Full implementation of IdP token exchange.
2. Full implementation of the external agent runner.
3. Domain-complete tool set on day 1.

## Core Architecture

### 1) Crate Layout

- `src/lib.rs`: public crate entry points and prelude exports.
- `src/server/mod.rs`: `axum` app builder and MCP route mounting.
- `src/auth/mod.rs`: JWT validation, claim mapping, auth context types.
- `src/auth/middleware.rs`: request middleware that validates bearer token and injects actor context.
- `src/tools/mod.rs`: `rmcp` tool registration and router composition.
- `src/tools/policy.rs`: tool auth policy registry (`public` vs `authenticated`, future scopes).
- `src/tools/extract.rs`: helper extractors to read actor context inside tool handlers.
- `src/error.rs`: transport-safe error mapping (`401`, `403`, structured auth failures).

### 2) Trust Boundaries

1. `Authorization: Bearer <jwt>` enters at `axum` middleware.
2. Middleware validates signature/issuer/audience/expiry and maps `sub -> UserId`.
3. Middleware injects a trusted actor into request extensions.
4. Tool execution reads actor only from trusted context.
5. Tool params are untrusted input only.

## Answer To Open Question: Auth Requirement + user_id Propagation

Use an explicit tool-policy registry wrapped around `rmcp` router.

### Pattern

1. Define `ToolAuthPolicy`:
   - `Public`
   - `Authenticated` (later: `AuthenticatedWithScopes(Vec<String>)`)
2. Register each tool with both:
   - `rmcp` handler/route
   - required `ToolAuthPolicy`
3. On each tool call:
   - resolve tool name
   - enforce policy before handler execution
   - reject with `401/403` if policy fails
4. Pass user identity via trusted context:
   - middleware inserts `AuthenticatedActor { user_id, claims }`
   - tool handlers extract `AuthenticatedActor` from request context/extensions

This guarantees auth requirements are explicit, testable, and not dependent on model-provided fields.

## Generalized Calling Contract (Trusted Actor First)

Every internal tool function should implement a common actor-first signature:

```rust
async fn run_tool(
    deps: &ToolDeps,
    actor: &ToolActor,
    input: ToolInput,
) -> Result<ToolOutput, ToolError>;
```

Where:

- `ToolActor` is created only by auth middleware (never deserialized from tool args).
- `ToolInput` is tool-specific untrusted payload.
- `ToolDeps` carries shared dependencies (db pools, domain operation structs, config).

### Contract Types

```rust
pub struct ToolActor {
    pub user_id: subseq_auth::user_id::UserId,
    pub issuer: String,
    pub audience: String,
    pub scopes: Vec<String>,
    pub jwt_id: Option<String>,
}

pub enum ToolAuthPolicy {
    Public,
    Authenticated,
}

pub struct ToolDescriptor<I, O> {
    pub name: &'static str,
    pub policy: ToolAuthPolicy,
    pub run: fn(&ToolDeps, &ToolActor, I) -> ToolFuture<O>,
}
```

### rmcp Adapter Rule

`rmcp` handlers should be thin adapters only:

1. Extract `ToolActor` from trusted context/extensions (for example `Extension<ToolActor>`).
2. Parse tool args into `ToolInput`.
3. Call descriptor `run(&deps, &actor, input)`.
4. Convert result/error back to MCP response shape.

This keeps all domain tools on one generalized calling contract while still integrating with
`rmcp` router mechanics.

## Phased Delivery

## Phase 0: Bootstrap

Deliverables:

1. Add dependencies (`rmcp`, `axum`, `tower`, `serde`, `tracing`, `subseq_auth`, etc.).
2. Replace template code in `src/lib.rs` with crate module skeleton.
3. Add basic README section for running the MCP server.

Acceptance:

1. `cargo check` passes.
2. Crate exports app builder and server startup entry points.

## Phase 1: MCP Server Skeleton

Deliverables:

1. Stand up `axum` router and mount MCP endpoint (streamable HTTP transport).
2. Create a minimal tool set (`health`/`ping`) through `tool_router`.
3. Add structured error responses and tracing spans.

Acceptance:

1. MCP handshake/list-tools works without auth for explicitly `Public` tool(s).
2. Logs include request id/tool name/status.

## Phase 2: Auth Middleware + Context Injection

Deliverables:

1. Add JWT bearer middleware using `subseq_auth`-compatible validation patterns.
2. Introduce `AuthenticatedActor` in request extensions.
3. Build policy enforcement layer for tool calls.

Acceptance:

1. Missing/invalid token returns `401`.
2. Auth-required tool executes with trusted `user_id` from claims.
3. Tool args containing fake `user_id` are ignored/rejected.

## Phase 3: Domain Tool Surfaces

Deliverables:

1. Add first real tool modules backed by domain libs (for example `subseq_graph::operations`).
2. Ensure all domain calls require explicit `actor: UserId`.
3. Return machine-readable permission errors compatible with `subseq_auth` response shape.

Acceptance:

1. End-to-end authorized/unauthorized tests for each tool.
2. No domain tool accepts trusted identity through input payload.

## Phase 4: IdP + Agent Runner Interface Stubs (Deferred Integration)

Deliverables:

1. Define token contract doc for agent-issued MCP JWTs:
   - required claims (`iss`, `aud`, `sub`, `exp`, `iat`, `scope`)
   - optional (`jti`, `thread_id`, `azp`)
2. Add placeholder endpoints/interfaces for token verification config rotation (JWKS or equivalent).
3. Define runner-to-MCP protocol expectations (headers, retry rules, correlation ids).

Acceptance:

1. Contract docs checked in.
2. Validation code can be switched from forwarded-user-token to delegated-token without API break.

## Phase 5: Hardening + Operations

Deliverables:

1. Audit logs for tool call auth decisions.
2. Metrics for auth failures, permission denials, and per-tool latency.
3. Negative tests for replay/expired/wrong-audience tokens.

Acceptance:

1. CI includes unit + integration test suites for auth and tool dispatch.
2. Observability confirms actor and tool-level authorization outcomes.

## Testing Strategy

1. Unit tests:
   - bearer parsing
   - claim-to-`UserId` mapping
   - tool policy matching and enforcement
2. Integration tests:
   - list tools, call tool with/without token
   - permission denied paths returning structured errors
3. Abuse tests:
   - forged `user_id` in payload
   - wrong `aud`/`iss`
   - expired token

## CI/Deployment Notes

1. Keep server stateless for auth decisions; no mutable in-memory trust source.
2. Keep container-safe defaults:
   - bind address/port/env configurable
   - timeouts for inbound requests
3. Ensure healthcheck endpoint remains available and cheap.

## Immediate Next Build Steps

1. Implement Phase 0 + Phase 1 skeleton.
2. Implement Phase 2 auth middleware and one authenticated tool.
3. Integrate first domain tool via `subseq_graph::operations` for end-to-end verification.
