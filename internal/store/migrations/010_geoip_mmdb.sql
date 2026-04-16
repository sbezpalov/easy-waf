-- Add geoip_mmdb_path to persisted global settings JSON when missing.
UPDATE settings
SET value = (COALESCE(NULLIF(trim(value), ''), '{}')::jsonb || jsonb_build_object('geoip_mmdb_path', ''))::text
WHERE key = 'global_settings_json'
  AND NOT (COALESCE(value::jsonb, '{}'::jsonb) ? 'geoip_mmdb_path');
