-- DNS-01: provider name + path to env file (KEY=value) for Lego provider credentials

ALTER TABLE certificates ADD COLUMN IF NOT EXISTS dns_provider TEXT;
ALTER TABLE certificates ADD COLUMN IF NOT EXISTS dns_credentials_env_file TEXT;

COMMENT ON COLUMN certificates.dns_provider IS 'cloudflare | cloudns | route53 | webhook (Lego httpreq)';
COMMENT ON COLUMN certificates.dns_credentials_env_file IS 'Linux path to root-only env file (e.g. /var/lib/easy-waf/secrets/dns/<id>.env)';
