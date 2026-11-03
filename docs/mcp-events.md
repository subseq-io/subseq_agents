# Shared MCP Events core

`subseq_agents::events` provides reusable event protocol, signing/encryption, callback verification, subscription state, and durable delivery. It does not assemble a server, load environment variables, define a harness catalog, accept producer credentials, spawn workers, or decide agent actions.

## Modules and responsibilities

- `EventService`: list/subscribe/unsubscribe lifecycle, staged renewal, callback challenges, key rotation, idempotent publication, one leased delivery attempt, and maintenance. Construct it with a pool, `EventServiceConfig`, `Arc<dyn EventPolicy>`, and `Arc<dyn WebhookTransport>`.
- `EventPolicy`: consumer-provided event catalog, subscription and payload validation, resource identifier extraction, and asynchronous access checks. Implementations must reject unsupported event names/fields and enforce the advertised schemas. Empty authorization arguments mean catalog discovery; delivery rechecks both subscription scope and the event's specific resource scope.
- `store`: SQLx persistence, transactional quotas, deduplication and generation-fenced lifecycle operations. Raw store methods are trusted infrastructure APIs, not authorization endpoints.
- `crypto`: Standard Webhooks HMAC signing, deterministic IDs, encrypted signing-secret storage, and constant-time comparisons.
- `webhooks`: outbound callback abstraction and `SafeWebhookClient`, which verifies public HTTPS destination addresses on every connection, pins DNS results, rejects redirects/proxies, and limits time/body size. Use this implementation for production; injected alternatives are responsible for equivalent security.
- `protocol::advertise_sse`: pure initialization-response adaptation for rmcp 0.14's capability model. Consumers apply it only to the bounded finite initialization response; do not buffer normal tool or GET streams.
- `tool_actor_from_extensions`: resolves the authenticated actor from direct or HTTP-transport nested extensions. Never take user identity from event arguments.

Concrete HTTP routing, authentication middleware composition, env/config parsing, producer authentication, source-specific filters, tool schemas, worker task lifetime, and shutdown stay in the consuming server. Existing `mcp_mount_router*` APIs and key-management contracts are unchanged.

## Identity and storage

Each service is configured with its actual API-key `mount_name`; authentication checks, producer deduplication, fanout and worker claims are isolated by mount. Filters match JSONB containment of the event data. Policies should advertise supported containment filters and reject unsupported operators. `tests/events_core.rs` demonstrates a `queue.changed` event with `queue_id`, independent of harness/project/run concepts.

Identity hashes recursively sort object keys, including when a downstream crate enables `serde_json/preserve_order`; array order remains significant. The reserved legacy mount `router` preserves prior subscription IDs and encryption associated data. Other mounts use a distinct deterministic identity namespace. The original event migration was moved byte-for-byte from the router; a second additive migration assigns existing rows to `router` and extends uniqueness with mount scope. The migration entrypoint remains `create_agent_tables` / `db::MIGRATOR`. Existing encrypted secrets, pending deliveries, event IDs, and SQLx migration checksums remain valid.

The library retains the original implementation's operational policy: 100 active subscriptions per owner/mount, 10,000 queued deliveries (plus boundary fanout), finite 1-minute minimum/24-hour maximum lifetimes, 60-second leases, eight bounded retry attempts, and five-minute signing-key overlap. Terminal event records are retained for deduplication; consumers own capacity/retention planning. It has no protocol replay and returns null cursors. Sources must expose authoritative read tools for reconciliation.

## Consumption sequence

The extraction is a coordinated two-repository change. Before changing a consuming server's production lockfile:

1. Review and merge/publish this library commit through the normal authorized Git workflow.
2. Update the consumer's existing Git dependency resolution to the published revision. Do not change the dependency to a local path or fabricate a remotely available revision.
3. Verify the lockfile's Git source/revision and run locked checks plus integration tests.

Local integration before publication uses a disposable copy of the consumer and a Cargo `[patch]` in that copy, pointing at the library worktree. That copy's lockfile is allowed to resolve a path; never commit it as the production lockfile. See the router's `scripts/check-local-events-library.sh`.

## Tests

Unit tests cover signing vectors, AEAD ownership binding, callback address policy, SSE adaptation, and actor extraction. PostgreSQL tests use `tests/support/test_harness.rs` and create/drop isolated databases. Set `POSTGRES_TEST_BASE_URL` explicitly to the isolated test server; do not use a production database.

```sh
POSTGRES_TEST_BASE_URL=postgres://postgres@127.0.0.1:55439 cargo test --locked
cargo fmt --check
cargo check --locked
```

New integration tests verify non-harness catalogs/filters, mount isolation for keys/identities/producer IDs/worker claims, signed delivery, and migration preservation of legacy ciphertext. Router tests retain the full protocol/harness lifecycle regressions.

Verification for this extraction: 20 unit tests and 8 integration tests passed against an isolated PostgreSQL instance, along with formatting and locked compilation. The paired router passed 6 unit tests and 5 database/HTTP lifecycle tests with a disposable local dependency patch. Independent review identified the key-order portability issue; the feature-enabled regression failed before explicit canonicalization and passed afterward. No library publication, production migration, or real callback subscription was performed.
