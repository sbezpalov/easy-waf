-- PostgreSQL schema for Easy Home WAF (SME-ready, cluster-friendly)

CREATE TABLE IF NOT EXISTS applications (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    public_host TEXT NOT NULL UNIQUE,
    backend_host TEXT NOT NULL,
    backend_port INTEGER NOT NULL,
    backend_https BOOLEAN NOT NULL DEFAULT FALSE,
    websocket BOOLEAN NOT NULL DEFAULT FALSE,
    health_path TEXT,
    path_prefix TEXT,
    profile TEXT NOT NULL,
    certificate_id TEXT,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS certificates (
    id TEXT PRIMARY KEY,
    primary_domain TEXT NOT NULL,
    san_json JSONB,
    mode TEXT NOT NULL,
    staging BOOLEAN NOT NULL DEFAULT TRUE,
    acme_status TEXT NOT NULL DEFAULT 'ready',
    pem_crt_path TEXT,
    pem_key_path TEXT,
    fullchain_path TEXT,
    not_before TIMESTAMPTZ,
    not_after TIMESTAMPTZ,
    last_error TEXT,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_certificates_acme_status ON certificates (acme_status);
CREATE INDEX IF NOT EXISTS idx_certificates_not_after ON certificates (not_after);

CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_log (
    id BIGSERIAL PRIMARY KEY,
    at TIMESTAMPTZ NOT NULL,
    action TEXT NOT NULL,
    detail_json JSONB
);

CREATE TABLE IF NOT EXISTS config_revisions (
    id BIGSERIAL PRIMARY KEY,
    at TIMESTAMPTZ NOT NULL,
    label TEXT,
    haproxy_sha256 TEXT NOT NULL,
    content_path TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ipbl_local (
    id TEXT PRIMARY KEY,
    cidr TEXT NOT NULL,
    note TEXT,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_ipbl_local_enabled ON ipbl_local (enabled);

CREATE TABLE IF NOT EXISTS ipbl_external_sources (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    url TEXT NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    refresh_seconds INTEGER NOT NULL DEFAULT 3600,
    last_fetch_at TIMESTAMPTZ,
    last_error TEXT,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);
