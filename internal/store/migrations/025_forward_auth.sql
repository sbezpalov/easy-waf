-- Per-application forward authentication (ADR 0005, fail closed).
ALTER TABLE applications ADD COLUMN IF NOT EXISTS forward_auth_url TEXT NOT NULL DEFAULT '';
ALTER TABLE applications ADD COLUMN IF NOT EXISTS forward_auth_bypass_cidrs JSONB NOT NULL DEFAULT '[]';
