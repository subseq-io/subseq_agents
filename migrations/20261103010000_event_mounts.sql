-- Existing router state and ciphertext identities remain valid after extraction.
ALTER TABLE mcp_event_subscriptions ADD COLUMN IF NOT EXISTS mount_name TEXT NOT NULL DEFAULT 'router';
ALTER TABLE mcp_event_records ADD COLUMN IF NOT EXISTS mount_name TEXT NOT NULL DEFAULT 'router';
ALTER TABLE mcp_event_subscriptions DROP CONSTRAINT IF EXISTS mcp_event_subscriptions_owner_id_name_arguments_callback_ur_key;
CREATE UNIQUE INDEX IF NOT EXISTS mcp_event_subscription_identity ON mcp_event_subscriptions(mount_name,owner_id,name,arguments,callback_url);
ALTER TABLE mcp_event_records DROP CONSTRAINT IF EXISTS mcp_event_records_producer_id_producer_event_id_key;
CREATE UNIQUE INDEX IF NOT EXISTS mcp_event_producer_identity ON mcp_event_records(mount_name,producer_id,producer_event_id);
CREATE INDEX IF NOT EXISTS mcp_event_subscriptions_mount ON mcp_event_subscriptions(mount_name);
