# subseq_agents Build Plan (rmcp + axum + API-key auth)

## Goals

1. Provide an MCP server in this repo with a high-level `tool_router` surface (`rmcp`).
2. Expose per-mount API keys for MCP requests instead of JWT-bearing MCP calls.
3. Keep key management authenticated via existing `subseq_auth` user JWT/session flows.
4. Preserve trusted `UserId` propagation to domain permission checks through a generalized actor-first tool contract.
5. Keep room for deferred components:
   - an external agent runner that stores per-user per-mount keys
   - automatic key rotation using authenticated management calls

## Package Layering

To avoid circular dependencies between tool libraries and server composition:

1. Keep this crate as the shared MCP core layer:
   - exported traits and shared types for tool integrations
   - API-key contract types and store interfaces
   - DB migrations + migration runner function (`create_agent_tables`)
2. Put the concrete MCP server wiring in a separate server-only package:
   - axum startup/runtime assembly
   - rmcp transport mounting
   - composition of concrete tool implementations from callee libraries
3. Callee libraries should depend only on the shared core layer (not server package).

## Non-Goals (for initial delivery)

1. Replacing `subseq_auth` identity flows.
2. Building a full external agent runner.
3. Domain-complete tool coverage on day 1.

## Route Profile

The route builder should emit an `axum::Router` for one MCP mount profile.

```rust
pub struct McpMountProfile {
    pub name: &'static str, // used in /mcp/{name}
}

pub fn mcp_mount_router<S>(
    profile: McpMountProfile,
    tool_router: rmcp::handler::server::router::tool::ToolRouter<S>,
) -> axum::Router<S>;
```

Mounted routes:

1. `POST /mcp/{name}` (or transport-specific MCP route) for tool execution/listing over rmcp.
2. `GET /mcp/{name}/key` list active keys for current authenticated user + mount (metadata only).
3. `POST /mcp/{name}/key/{key_name}` create key for current authenticated user + mount.
4. `DELETE /mcp/{name}/key/{key_name}` revoke key for current authenticated user + mount.

## Auth Model

Two auth lanes:

1. MCP lane (`/mcp/{name}`):
   - authenticate via API key only
   - resolve key -> trusted `UserId`
2. Management lane (`/mcp/{name}/key*`):
   - authenticate via `subseq_auth::prelude::AuthenticatedUser`
   - create/list/delete keys for that user

### API Key Scope

Each key is scoped to:

1. `user_id` (owner)
2. `mcp_mount_name`
3. `key_name` (human label)

The lookup must enforce all three as applicable and only return `UserId` from DB state.

## Generalized Calling Contract (Trusted Actor First)

Every internal tool function should implement one actor-first shape:

```rust
async fn run_tool(
    deps: &ToolDeps,
    actor: &ToolActor,
    input: ToolInput,
) -> Result<ToolOutput, ToolError>;
```

```rust
pub struct ToolActor {
    pub user_id: subseq_auth::user_id::UserId,
    pub mcp_mount_name: String,
    pub api_key_id: uuid::Uuid,
    pub api_key_name: String,
}
```

Rules:

1. `ToolActor` is only middleware-generated from a validated API key lookup.
2. `ToolInput` is untrusted user/model payload.
3. Tool/domain functions do not accept trusted `user_id` in payload.
4. rmcp handlers are thin adapters: extract actor, parse input, call `run_tool`.

## Key Storage Contract

Recommended table (example):

- `agent.mcp_api_keys`
  - `id uuid pk`
  - `user_id uuid not null`
  - `mcp_mount_name text not null`
  - `key_name text not null`
  - `secret_hash text not null` // salted password-hash string (e.g., argon2id encoded hash)
  - `secret_prefix text not null`
  - `created_at timestamptz not null default now()`
  - `last_used_at timestamptz null`
  - `revoked_at timestamptz null`
  - `expires_at timestamptz null`

Constraints:

1. Unique active key by `(user_id, mcp_mount_name, key_name)` (partial index where `revoked_at is null`).
2. No plaintext secret storage.
3. Secret verification must compare against stored salted hash only (never decrypt).

Token format recommendation:

1. Return only once on create.
2. Embed key id in presented token to enable direct row lookup.
3. Verify secret with constant-time salted-hash verification (for example argon2id verify).

Key management response contract:

1. `GET /mcp/{name}/key` returns key metadata only:
   - `key_name`
   - `created_at`
   - `last_used_at`
   - `expires_at`
   - `revoked_at`
2. `POST /mcp/{name}/key/{key_name}` returns secret exactly once and never again.
3. `DELETE /mcp/{name}/key/{key_name}` returns revocation status/metadata only.

## Security Requirements

1. `GET /mcp/{name}/key` must return metadata only, never secret values.
2. `POST /mcp/{name}/key/{key_name}` returns plaintext secret once.
3. `DELETE` is revocation (soft delete), not hard row deletion.
4. Tool request logging must avoid secret leakage.
5. Rate-limit failed key auth attempts per source.
6. Keep TLS required for all inbound traffic.

## Phased Delivery

## Phase 0: Bootstrap

Deliverables:

1. Add dependencies (`rmcp`, `axum`, `tower`, `serde`, `tracing`, `subseq_auth`, `sqlx`).
2. Replace template code in `src/lib.rs` with module skeleton.
3. Add migration for `agent.mcp_api_keys`.

Acceptance:

1. `cargo check` passes.
2. Migration applies on clean database.

## Phase 1: Route Profile + MCP Skeleton

Deliverables:

1. Implement `mcp_mount_router(profile, tool_router)`.
2. Mount one MCP profile with a public health/ping tool.
3. Add transport-safe error mapping and request tracing.

Acceptance:

1. MCP list-tools/calls work on mount.
2. Route mount path matches `/mcp/{name}` contract.

## Phase 2: API Key Middleware + Management Routes

Deliverables:

1. Add API key middleware for MCP lane.
2. Add key list/create/delete handlers (JWT/session-authenticated via `AuthenticatedUser`).
3. Inject `ToolActor` into MCP request context from key lookup.

Acceptance:

1. Missing/invalid key returns `401`.
2. Valid key resolves expected `ToolActor.user_id`.
3. Key endpoints are inaccessible without authenticated user.

## Phase 3: Domain Tool Surfaces

Deliverables:

1. Add first real tool module (for example `subseq_graph::operations`).
2. Pass `actor.user_id` into domain operations.
3. Preserve machine-readable permission-denied shape.

Acceptance:

1. Allowed/denied authorization paths tested end-to-end.
2. Payload-supplied identity fields are ignored/rejected.

## Phase 4: Rotation + Runner Contracts (Deferred)

Deliverables:

1. Document runner key lifecycle:
   - create new key via authenticated management endpoint
   - atomically swap in runner
   - revoke old key
2. Add optional expiration/rotation policy defaults.
3. Add endpoint contract docs for agent integration.

Acceptance:

1. Rotation flow can run without MCP downtime.
2. Revoked keys fail immediately.

## Phase 5: Hardening + Operations

Deliverables:

1. Audit logs for key create/revoke and MCP auth decisions.
2. Metrics for key auth success/fail, per-mount throughput, denial codes.
3. Negative tests for replayed/revoked/expired keys.

Acceptance:

1. CI covers unit + integration + abuse tests.
2. No plaintext key material in logs.

## Testing Strategy

1. Unit tests:
   - key parser and lookup
   - secret hash verification
   - actor context injection
2. Integration tests:
   - list/create/delete keys with authenticated user
   - call MCP route with valid vs invalid key
3. Abuse tests:
   - forged payload identity
   - revoked key replay
   - expired key

## Immediate Next Build Steps

1. Implement migration + key repository interface.
2. Implement `mcp_mount_router` with one mount and one tool.
3. Implement key management endpoints and API key auth middleware.
