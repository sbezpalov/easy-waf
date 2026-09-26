-- ACME retry state: a failed issuance or renewal is retried with exponential backoff
-- instead of staying 'failed' until an operator notices.
ALTER TABLE certificates
	ADD COLUMN IF NOT EXISTS acme_attempts INTEGER NOT NULL DEFAULT 0,
	ADD COLUMN IF NOT EXISTS acme_next_attempt_at TIMESTAMPTZ;
