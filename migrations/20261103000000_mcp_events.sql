-- Additive migration. Deliberately separate from tool metering and app_data.
CREATE TABLE IF NOT EXISTS mcp_event_subscriptions (
    id TEXT PRIMARY KEY,
    owner_id UUID NOT NULL,
    api_key_id UUID NOT NULL,
    name TEXT NOT NULL,
    arguments JSONB NOT NULL,
    callback_url TEXT NOT NULL,
    secret TEXT NOT NULL,
    secret_fingerprint TEXT NOT NULL,
    pending_secret TEXT,
    pending_fingerprint TEXT,
    pending_expires_at TIMESTAMPTZ,
    pending_api_key_id UUID,
    previous_secret TEXT,
    rotate_until TIMESTAMPTZ,
    expires_at TIMESTAMPTZ NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('verifying','active','stopped','failed')),
    generation BIGINT NOT NULL DEFAULT 1,
    verify_until TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(owner_id, name, arguments, callback_url)
);
CREATE INDEX IF NOT EXISTS mcp_event_subscriptions_owner ON mcp_event_subscriptions(owner_id, name);
CREATE TABLE IF NOT EXISTS mcp_event_records (
    id UUID PRIMARY KEY,
    producer_id TEXT NOT NULL,
    producer_event_id TEXT NOT NULL,
    owner_id UUID NOT NULL,
    name TEXT NOT NULL,
    data JSONB NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(producer_id, producer_event_id)
);
CREATE TABLE IF NOT EXISTS mcp_event_deliveries (
    subscription_id TEXT NOT NULL REFERENCES mcp_event_subscriptions(id),
    event_id UUID NOT NULL REFERENCES mcp_event_records(id),
    body BYTEA NOT NULL,
    state TEXT NOT NULL DEFAULT 'pending' CHECK (state IN ('pending','leased','delivered','dead','cancelled')),
    attempts INTEGER NOT NULL DEFAULT 0,
    next_attempt TIMESTAMPTZ NOT NULL DEFAULT now(),
    lease_id UUID,
    lease_until TIMESTAMPTZ,
    last_status INTEGER,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY(subscription_id,event_id)
);
CREATE INDEX IF NOT EXISTS mcp_event_deliveries_due ON mcp_event_deliveries(next_attempt) WHERE state IN ('pending','leased');
