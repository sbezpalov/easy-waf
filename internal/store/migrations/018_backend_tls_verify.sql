-- HTTPS backend TLS verification. New apps default to verify required.
-- Existing HTTPS backends keep verify none so upgrades do not outage; the insecure state is explicit.

ALTER TABLE applications
	ADD COLUMN IF NOT EXISTS backend_tls_verify VARCHAR(16) NOT NULL DEFAULT 'required',
	ADD COLUMN IF NOT EXISTS backend_tls_ca_file TEXT,
	ADD COLUMN IF NOT EXISTS backend_tls_server_name TEXT;

UPDATE applications
	SET backend_tls_verify = 'none'
	WHERE backend_https = TRUE
	  AND backend_tls_verify = 'required';
