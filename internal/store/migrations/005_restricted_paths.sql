-- Per-app path prefixes allowed only from listed CIDRs (HAProxy fe_https ACLs)

ALTER TABLE applications
	ADD COLUMN IF NOT EXISTS restricted_paths JSONB NOT NULL DEFAULT '[]'::jsonb;
