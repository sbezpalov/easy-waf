-- Local IP allowlist (trusted CIDRs; HAProxy map, see docs/IPBL.md)

CREATE TABLE IF NOT EXISTS ipwl_local (
    id TEXT PRIMARY KEY,
    cidr TEXT NOT NULL,
    "comment" TEXT,
    created_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_ipwl_local_cidr ON ipwl_local (cidr);
