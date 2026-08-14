-- One-time operator enrollment. Plaintext secret is never stored; only SHA-256 hex lives here.

CREATE TABLE IF NOT EXISTS operator_enrollment (
	id BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (id),
	secret_hash TEXT NOT NULL,
	created_at TIMESTAMPTZ NOT NULL,
	consumed_at TIMESTAMPTZ
);
