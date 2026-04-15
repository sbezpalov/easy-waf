-- Extend audit_log for operator + client IP + query indexes (append-only table unchanged in spirit).

ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS user_name TEXT;
ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS source_ip VARCHAR(45);

CREATE INDEX IF NOT EXISTS idx_audit_log_at ON audit_log (at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_log_user_name ON audit_log (user_name);
CREATE INDEX IF NOT EXISTS idx_audit_log_action ON audit_log (action);
