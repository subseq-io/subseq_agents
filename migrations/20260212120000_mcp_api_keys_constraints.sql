DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'mcp_api_keys_key_name_format_chk'
          AND connamespace = 'agent'::regnamespace
    ) THEN
        ALTER TABLE agent.mcp_api_keys
        ADD CONSTRAINT mcp_api_keys_key_name_format_chk
        CHECK (key_name ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$');
    END IF;
END $$;
