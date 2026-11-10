-- Per-application path exposure: allowlist, required headers, timeouts, per-path rate limits.
-- Existing rows keep an empty object, which means "no extra path policy".
ALTER TABLE applications
	ADD COLUMN IF NOT EXISTS path_policy JSONB NOT NULL DEFAULT '{}'::jsonb;
