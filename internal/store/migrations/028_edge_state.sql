-- Persistent desired/applied edge generations. Existing appliances start in
-- unknown state until startup reconcile or an explicit Apply proves parity.
CREATE TABLE IF NOT EXISTS edge_state (
    singleton SMALLINT PRIMARY KEY DEFAULT 1 CHECK (singleton = 1),
    saved_generation BIGINT NOT NULL DEFAULT 1 CHECK (saved_generation >= 1),
    applied_generation BIGINT CHECK (applied_generation IS NULL OR applied_generation >= 1),
    last_apply_outcome TEXT CHECK (last_apply_outcome IS NULL OR last_apply_outcome IN ('success', 'failed', 'unknown', 'rollback')),
    last_apply_at TIMESTAMPTZ,
    last_apply_revision_sha TEXT,
    last_apply_error_code TEXT
);

INSERT INTO edge_state (singleton, saved_generation) VALUES (1, 1)
ON CONFLICT (singleton) DO NOTHING;

CREATE OR REPLACE FUNCTION easy_waf_bump_edge_generation()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    UPDATE edge_state SET saved_generation = saved_generation + 1 WHERE singleton = 1;
    RETURN NULL;
END;
$$;

DROP TRIGGER IF EXISTS applications_edge_generation ON applications;
CREATE TRIGGER applications_edge_generation
AFTER INSERT OR UPDATE OR DELETE ON applications
FOR EACH ROW EXECUTE FUNCTION easy_waf_bump_edge_generation();

DROP TRIGGER IF EXISTS certificates_edge_generation_insert_delete ON certificates;
CREATE TRIGGER certificates_edge_generation_insert_delete
AFTER INSERT OR DELETE ON certificates
FOR EACH ROW EXECUTE FUNCTION easy_waf_bump_edge_generation();

DROP TRIGGER IF EXISTS certificates_edge_generation_material ON certificates;
CREATE TRIGGER certificates_edge_generation_material
AFTER UPDATE OF pem_crt_path, pem_key_path, fullchain_path ON certificates
FOR EACH ROW EXECUTE FUNCTION easy_waf_bump_edge_generation();

DROP TRIGGER IF EXISTS settings_edge_generation ON settings;
CREATE TRIGGER settings_edge_generation
AFTER INSERT OR UPDATE OR DELETE ON settings
FOR EACH ROW EXECUTE FUNCTION easy_waf_bump_edge_generation();

DROP TRIGGER IF EXISTS ipbl_local_edge_generation_insert_delete ON ipbl_local;
CREATE TRIGGER ipbl_local_edge_generation_insert_delete
AFTER INSERT OR DELETE ON ipbl_local
FOR EACH ROW EXECUTE FUNCTION easy_waf_bump_edge_generation();

DROP TRIGGER IF EXISTS ipbl_local_edge_generation_values ON ipbl_local;
CREATE TRIGGER ipbl_local_edge_generation_values
AFTER UPDATE OF cidr, enabled ON ipbl_local
FOR EACH ROW EXECUTE FUNCTION easy_waf_bump_edge_generation();

DROP TRIGGER IF EXISTS ipbl_sources_edge_generation_insert_delete ON ipbl_external_sources;
CREATE TRIGGER ipbl_sources_edge_generation_insert_delete
AFTER INSERT OR DELETE ON ipbl_external_sources
FOR EACH ROW EXECUTE FUNCTION easy_waf_bump_edge_generation();

DROP TRIGGER IF EXISTS ipbl_sources_edge_generation_values ON ipbl_external_sources;
CREATE TRIGGER ipbl_sources_edge_generation_values
AFTER UPDATE OF name, url, enabled ON ipbl_external_sources
FOR EACH ROW EXECUTE FUNCTION easy_waf_bump_edge_generation();

DROP TRIGGER IF EXISTS ipwl_local_edge_generation_insert_delete ON ipwl_local;
CREATE TRIGGER ipwl_local_edge_generation_insert_delete
AFTER INSERT OR DELETE ON ipwl_local
FOR EACH ROW EXECUTE FUNCTION easy_waf_bump_edge_generation();

DROP TRIGGER IF EXISTS ipwl_local_edge_generation_values ON ipwl_local;
CREATE TRIGGER ipwl_local_edge_generation_values
AFTER UPDATE OF cidr ON ipwl_local
FOR EACH ROW EXECUTE FUNCTION easy_waf_bump_edge_generation();

DROP TRIGGER IF EXISTS blocked_ua_edge_generation_insert_delete ON blocked_user_agents;
CREATE TRIGGER blocked_ua_edge_generation_insert_delete
AFTER INSERT OR DELETE ON blocked_user_agents
FOR EACH ROW EXECUTE FUNCTION easy_waf_bump_edge_generation();

DROP TRIGGER IF EXISTS blocked_ua_edge_generation_values ON blocked_user_agents;
CREATE TRIGGER blocked_ua_edge_generation_values
AFTER UPDATE OF pattern ON blocked_user_agents
FOR EACH ROW EXECUTE FUNCTION easy_waf_bump_edge_generation();
