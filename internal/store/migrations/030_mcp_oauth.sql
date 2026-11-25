CREATE TABLE IF NOT EXISTS mcp_oauth_grants (
    id uuid PRIMARY KEY,
    issuer text NOT NULL,
    client_id text NOT NULL,
    name text NOT NULL,
    approved_by text NOT NULL,
    redirect_uri text NOT NULL,
    challenge text NOT NULL,
    code_hash text UNIQUE,
    code_until timestamptz NOT NULL DEFAULT now() + interval '3 minutes',
    access_hash text UNIQUE,
    access_until timestamptz,
    refresh_hash text UNIQUE,
    valid_until timestamptz NOT NULL DEFAULT now() + interval '30 days',
    last_used timestamptz
);

CREATE TABLE IF NOT EXISTS mcp_oauth_spent_refresh (
    token_hash text PRIMARY KEY,
    grant_id uuid NOT NULL REFERENCES mcp_oauth_grants(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS mcp_oauth_spent_grant ON mcp_oauth_spent_refresh(grant_id);
