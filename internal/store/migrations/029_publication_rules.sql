ALTER TABLE applications ADD COLUMN IF NOT EXISTS policy_rules JSONB NOT NULL DEFAULT '[]'::jsonb;
