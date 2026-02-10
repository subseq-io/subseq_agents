# subseq_agents examples

## `dev_mcp_server`

A manually runnable dev server wiring:

- `mcp_mount_router(McpMountProfile::new("dev"), ...)`
- API-key auth middleware on `/mcp/dev`
- key management routes under `/mcp/dev/key*`
- mocked authenticated user via `x-dev-*` headers for key management endpoints

No database is required for this example; it uses `InMemoryApiKeyStore`.

### Run

```bash
cargo run --example dev_mcp_server
```

Default bind: `127.0.0.1:4020`

### 1) Create an API key

```bash
curl -sS -X POST \
  http://127.0.0.1:4020/api/v1/mcp/dev/key/local
```

Extract `key.plaintextKey` from the JSON response and save it as `API_KEY`.

### 2) Initialize MCP session

```bash
curl -i -sS -X POST \
  http://127.0.0.1:4020/api/v1/mcp/dev \
  -H 'content-type: application/json' \
  -H 'accept: application/json, text/event-stream' \
  -H "x-api-key: $API_KEY" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"manual","version":"0.1"}}}'
```

Capture `mcp-session-id` from response headers as `SESSION_ID`.

### 3) List tools

```bash
curl -sS -X POST \
  http://127.0.0.1:4020/api/v1/mcp/dev \
  -H 'content-type: application/json' \
  -H 'accept: application/json, text/event-stream' \
  -H "x-api-key: $API_KEY" \
  -H "mcp-session-id: $SESSION_ID" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}'
```

### 4) Call tools

```bash
curl -sS -X POST \
  http://127.0.0.1:4020/api/v1/mcp/dev \
  -H 'content-type: application/json' \
  -H 'accept: application/json, text/event-stream' \
  -H "x-api-key: $API_KEY" \
  -H "mcp-session-id: $SESSION_ID" \
  -d '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"ping","arguments":{}}}'
```

```bash
curl -sS -X POST \
  http://127.0.0.1:4020/api/v1/mcp/dev \
  -H 'content-type: application/json' \
  -H 'accept: application/json, text/event-stream' \
  -H "x-api-key: $API_KEY" \
  -H "mcp-session-id: $SESSION_ID" \
  -d '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"whoami","arguments":{}}}'
```
