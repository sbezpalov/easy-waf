-- NULL means an administrator explicitly approved access until revocation.
-- Existing grants retain their original expiry.
ALTER TABLE mcp_oauth_grants
    ALTER COLUMN valid_until DROP NOT NULL,
    ADD COLUMN replay_revoked_at timestamptz;
