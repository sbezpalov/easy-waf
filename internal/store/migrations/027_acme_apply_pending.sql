-- Commit ACME ready metadata and edge-reconciliation intent together.
-- One generation per certificate bounds retained work; acknowledgement uses
-- both columns so a concurrent renewal cannot be cleared by an older apply.
CREATE TABLE IF NOT EXISTS acme_apply_pending (
    certificate_id TEXT PRIMARY KEY REFERENCES certificates(id) ON DELETE CASCADE,
    generation TEXT NOT NULL
);
