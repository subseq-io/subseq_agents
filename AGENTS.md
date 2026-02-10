# Agent Guidelines (subseq_agents)

This file stores durable, repo-specific guardrails for subseq_agents.

## Packaging and Runtime Boundaries
- Keep subseq_agents as shared core for traits/types/auth-key contracts/migrations.
- Keep concrete MCP server runtime assembly in a separate server-only package to avoid circular composition dependencies.

## Routing and Auth
- Keep mounts built through `mcp_mount_router(profile, service, key_store)`.
- Guard `/mcp/{name}` tool routes with API-key auth middleware that injects actor context (`ToolActor`) for tool handlers.
- Keep `/mcp/{name}/key*` management routes on authenticated user context (not API-key actor context).

## API Key Contract
- GET key endpoints return metadata only.
- POST key creation returns plaintext key once.
- Persist only salted/hash material in DB; never persist plaintext API keys.
- API-key validation must compare presented key against stored hash.

## Persistence
- Keep SQLx-backed API-key storage (`SqlxApiKeyStore`) and migrations under this crate.
- Keep migration entrypoint (`create_agent_tables`) wired and used by consuming services.
