-- Per-application security layers (JSONB) + mode index

ALTER TABLE applications
	ADD COLUMN IF NOT EXISTS security JSONB NOT NULL DEFAULT '{
		"mode": "balanced",
		"rate_limit_enabled": true,
		"path_acl_enabled": true,
		"method_filter_enabled": true,
		"basic_waf_enabled": true,
		"bot_protection_enabled": true,
		"ip_blacklist_enabled": true,
		"ip_allowlist_enabled": true,
		"geoip_enabled": false,
		"crowdsec_enabled": true,
		"geoip_policy": "allow",
		"geoip_country_list": []
	}'::jsonb;

CREATE INDEX IF NOT EXISTS idx_applications_security_mode ON applications ((security->>'mode'));
