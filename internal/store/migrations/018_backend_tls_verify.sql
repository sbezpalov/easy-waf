-- HTTPS backend TLS verification. New apps default to verify required.
-- Existing HTTPS backends keep verify none so upgrades do not outage; the insecure state is explicit.
--
-- OpenPostgres currently replays every migration. Keep the compatibility backfill repeat-safe:
-- only rows that predate this nullable column are legacy rows. Never rewrite an operator-selected
-- required value on a later store open.

ALTER TABLE applications
	ADD COLUMN IF NOT EXISTS backend_tls_verify VARCHAR(16),
	ADD COLUMN IF NOT EXISTS backend_tls_ca_file TEXT,
	ADD COLUMN IF NOT EXISTS backend_tls_server_name TEXT;

UPDATE applications
	SET backend_tls_verify = 'none'
	WHERE backend_https = TRUE
	  AND backend_tls_verify IS NULL;

UPDATE applications
	SET backend_tls_verify = 'required'
	WHERE backend_tls_verify IS NULL;

ALTER TABLE applications
	ALTER COLUMN backend_tls_verify SET DEFAULT 'required',
	ALTER COLUMN backend_tls_verify SET NOT NULL;
