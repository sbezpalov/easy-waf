-- Trusted internal CIDRs for IPBL HTTP feed fetch (split-DNS); loopback/metadata always blocked in code.
UPDATE settings
SET value = (COALESCE(NULLIF(trim(value), ''), '{}')::jsonb || jsonb_build_object('ipbl_fetch_allowed_cidrs', '[]'::jsonb))::text
WHERE key = 'global_settings_json'
  AND NOT (COALESCE(value::jsonb, '{}'::jsonb) ? 'ipbl_fetch_allowed_cidrs');
