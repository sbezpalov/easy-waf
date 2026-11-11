-- Per-application maintenance mode: a 503 page for everyone outside the
-- bypass list. Existing rows stay in service.
ALTER TABLE applications
	ADD COLUMN IF NOT EXISTS maintenance BOOLEAN NOT NULL DEFAULT false,
	ADD COLUMN IF NOT EXISTS maintenance_bypass_cidrs JSONB NOT NULL DEFAULT '[]'::jsonb;
