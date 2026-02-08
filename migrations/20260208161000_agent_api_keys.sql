CREATE SCHEMA IF NOT EXISTS agent;

CREATE TABLE IF NOT EXISTS agent.mcp_api_keys (
    id uuid PRIMARY KEY,
    user_id uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    mcp_mount_name text NOT NULL,
    key_name text NOT NULL,
    secret_hash text NOT NULL,
    secret_prefix text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT NOW(),
    last_used_at timestamptz NULL,
    expires_at timestamptz NULL,
    revoked_at timestamptz NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS mcp_api_keys_user_mount_key_name_active_idx
    ON agent.mcp_api_keys (user_id, mcp_mount_name, key_name)
    WHERE revoked_at IS NULL;

CREATE INDEX IF NOT EXISTS mcp_api_keys_lookup_idx
    ON agent.mcp_api_keys (id, mcp_mount_name);
