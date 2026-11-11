-- Extra backend servers per application (failover / load balancing) and the
-- balance algorithm. Existing rows keep a single server and HAProxy's default.
ALTER TABLE applications
	ADD COLUMN IF NOT EXISTS backend_servers JSONB NOT NULL DEFAULT '[]'::jsonb,
	ADD COLUMN IF NOT EXISTS backend_balance TEXT NOT NULL DEFAULT '';
