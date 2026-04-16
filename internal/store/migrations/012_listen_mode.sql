-- Per-application HTTP/HTTPS publishing mode (fe_http vs fe_https).
ALTER TABLE applications
	ADD COLUMN IF NOT EXISTS listen_mode VARCHAR(32) NOT NULL DEFAULT 'https_only';
