-- JWT session epoch: increment on password change so previously issued tokens fail closed.

ALTER TABLE users
	ADD COLUMN IF NOT EXISTS session_version INTEGER NOT NULL DEFAULT 1;
