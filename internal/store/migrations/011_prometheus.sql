-- Ensure prometheus_enabled exists in persisted global settings JSON (default off).
UPDATE settings
SET value = (COALESCE(NULLIF(trim(value), ''), '{}')::jsonb || jsonb_build_object('prometheus_enabled', false))::text
WHERE key = 'global_settings_json'
  AND NOT (COALESCE(value::jsonb, '{}'::jsonb) ? 'prometheus_enabled');
