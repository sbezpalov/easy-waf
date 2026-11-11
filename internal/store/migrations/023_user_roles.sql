-- Panel roles. Every existing operator stays an admin.
ALTER TABLE users
	ADD COLUMN IF NOT EXISTS role TEXT NOT NULL DEFAULT 'admin' CHECK (role IN ('admin', 'viewer'));
