-- Public DNS resolvers for ACME DNS-01 propagation checks (split-DNS); empty = system resolver.
UPDATE settings
SET value = (COALESCE(NULLIF(trim(value), ''), '{}')::jsonb || jsonb_build_object('acme_dns_resolvers', '[]'::jsonb))::text
WHERE key = 'global_settings_json'
  AND NOT (COALESCE(value::jsonb, '{}'::jsonb) ? 'acme_dns_resolvers');
