-- Substring patterns for User-Agent blocking (HAProxy fe_https, see docs)

CREATE TABLE IF NOT EXISTS blocked_user_agents (
    id TEXT PRIMARY KEY,
    pattern TEXT NOT NULL,
    "comment" TEXT,
    created_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_blocked_user_agents_pattern ON blocked_user_agents (pattern);

INSERT INTO blocked_user_agents (id, pattern, "comment", created_at) VALUES
    ('seed-nmap', 'Nmap', 'scanner', NOW()),
    ('seed-nikto', 'Nikto', 'scanner', NOW()),
    ('seed-sqlmap', 'sqlmap', 'scanner', NOW()),
    ('seed-dirbuster', 'dirbuster', 'scanner', NOW()),
    ('seed-gobuster', 'gobuster', 'scanner', NOW()),
    ('seed-masscan', 'masscan', 'scanner', NOW()),
    ('seed-zmeu', 'ZmEu', 'scanner', NOW()),
    ('seed-w3af', 'w3af', 'scanner', NOW())
ON CONFLICT (id) DO NOTHING;
