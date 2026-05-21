-- Ensure ipbl_allow_private_fetch exists in persisted global settings JSON (default off).
UPDATE settings
SET value = (COALESCE(NULLIF(trim(value), ''), '{}')::jsonb || jsonb_build_object('ipbl_allow_private_fetch', false))::text
WHERE key = 'global_settings_json'
  AND NOT (COALESCE(value::jsonb, '{}'::jsonb) ? 'ipbl_allow_private_fetch');
