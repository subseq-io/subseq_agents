CREATE TABLE IF NOT EXISTS agent.mcp_api_key_rate_limits (
    rate_limit_key text PRIMARY KEY,
    failures integer NOT NULL,
    window_started_at timestamptz NOT NULL,
    blocked_until timestamptz NULL,
    updated_at timestamptz NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS mcp_api_key_rate_limits_blocked_until_idx
    ON agent.mcp_api_key_rate_limits (blocked_until);

CREATE INDEX IF NOT EXISTS mcp_api_key_rate_limits_updated_at_idx
    ON agent.mcp_api_key_rate_limits (updated_at);
