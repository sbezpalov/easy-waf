package store

import (
	"context"
	"database/sql"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/easy-waf/easy-waf/internal/config"
	"github.com/google/uuid"
	_ "github.com/jackc/pgx/v5/stdlib"
)

//go:embed migrations/001_initial.sql
var initialMigrationSQL string

//go:embed migrations/002_dns01.sql
var migration002SQL string

//go:embed migrations/003_users.sql
var migration003SQL string

//go:embed migrations/004_ipwl.sql
var migration004SQL string

//go:embed migrations/005_restricted_paths.sql
var migration005SQL string

//go:embed migrations/006_blocked_user_agents.sql
var migration006SQL string

//go:embed migrations/007_geoip_settings_note.sql
var migration007SQL string

// Store is the PostgreSQL-backed configuration store (SME / future HA).
type Store struct {
	db *sql.DB
}

// OpenPostgres connects using DATABASE_URL (postgres://user:pass@host:port/db?sslmode=disable).
func OpenPostgres(dsn string) (*Store, error) {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(30 * time.Minute)
	s := &Store{db: db}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if err := s.migrate(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) migrate(ctx context.Context) error {
	for _, raw := range []string{initialMigrationSQL, migration002SQL, migration003SQL, migration004SQL, migration005SQL, migration006SQL, migration007SQL} {
		sqlText := stripSQLComments(raw)
		parts := strings.Split(sqlText, ";")
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			if _, err := s.db.ExecContext(ctx, p); err != nil {
				return fmt.Errorf("migrate: %w", err)
			}
		}
	}
	return nil
}

func stripSQLComments(s string) string {
	lines := strings.Split(s, "\n")
	var b strings.Builder
	for _, line := range lines {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "--") {
			continue
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return b.String()
}

// Close releases the pool.
func (s *Store) Close() error { return s.db.Close() }

// ListApplications returns all apps.
func (s *Store) ListApplications(ctx context.Context) ([]config.Application, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, name, public_host, backend_host, backend_port, backend_https, websocket,
		       health_path, path_prefix, restricted_paths, profile, certificate_id, enabled, created_at, updated_at
		FROM applications ORDER BY public_host`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []config.Application
	for rows.Next() {
		var a config.Application
		var certID sql.NullString
		var hp, pp sql.NullString
		var rpJSON []byte
		if err := rows.Scan(&a.ID, &a.Name, &a.PublicHost, &a.BackendHost, &a.BackendPort,
			&a.BackendHTTPS, &a.WebSocket, &hp, &pp, &rpJSON, &a.Profile, &certID, &a.Enabled, &a.CreatedAt, &a.UpdatedAt); err != nil {
			return nil, err
		}
		if certID.Valid {
			a.CertificateID = certID.String
		}
		if hp.Valid {
			a.HealthPath = hp.String
		}
		if pp.Valid {
			a.PathPrefix = pp.String
		}
		if len(rpJSON) > 0 && string(rpJSON) != "null" {
			_ = json.Unmarshal(rpJSON, &a.RestrictedPaths)
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// UpsertApplication inserts or updates an application.
func (s *Store) UpsertApplication(ctx context.Context, a *config.Application) error {
	now := time.Now().UTC()
	if a.ID == "" {
		a.ID = uuid.NewString()
		a.CreatedAt = now
	}
	a.UpdatedAt = now
	if a.CreatedAt.IsZero() {
		a.CreatedAt = now
	}
	rp := a.RestrictedPaths
	if rp == nil {
		rp = []config.RestrictedPath{}
	}
	rpJSON, err := json.Marshal(rp)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO applications (
			id, name, public_host, backend_host, backend_port, backend_https, websocket,
			health_path, path_prefix, restricted_paths, profile, certificate_id, enabled, created_at, updated_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
		ON CONFLICT (id) DO UPDATE SET
			name = EXCLUDED.name,
			public_host = EXCLUDED.public_host,
			backend_host = EXCLUDED.backend_host,
			backend_port = EXCLUDED.backend_port,
			backend_https = EXCLUDED.backend_https,
			websocket = EXCLUDED.websocket,
			health_path = EXCLUDED.health_path,
			path_prefix = EXCLUDED.path_prefix,
			restricted_paths = EXCLUDED.restricted_paths,
			profile = EXCLUDED.profile,
			certificate_id = EXCLUDED.certificate_id,
			enabled = EXCLUDED.enabled,
			updated_at = EXCLUDED.updated_at
	`, a.ID, a.Name, a.PublicHost, a.BackendHost, a.BackendPort, a.BackendHTTPS, a.WebSocket,
		nullStrPtr(a.HealthPath), nullStrPtr(a.PathPrefix), rpJSON, a.Profile, nullStrPtr(a.CertificateID), a.Enabled, a.CreatedAt, a.UpdatedAt)
	return err
}

func nullStrPtr(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// DeleteApplication removes an application by id.
func (s *Store) DeleteApplication(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM applications WHERE id = $1`, id)
	return err
}

// GetSetting returns a string setting or empty if missing.
func (s *Store) GetSetting(ctx context.Context, key string) (string, error) {
	var v string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM settings WHERE key = $1`, key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return v, err
}

// SetSetting upserts a setting.
func (s *Store) SetSetting(ctx context.Context, key, value string) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO settings(key, value) VALUES($1,$2)
		ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value`, key, value)
	return err
}

// AppendAudit writes an audit record.
func (s *Store) AppendAudit(ctx context.Context, action string, detail any) error {
	var b []byte
	var err error
	if detail != nil {
		b, err = json.Marshal(detail)
		if err != nil {
			return err
		}
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO audit_log(at, action, detail_json) VALUES($1,$2,$3)`,
		time.Now().UTC(), action, b)
	return err
}

// AppendRevision records a successful HAProxy config revision.
func (s *Store) AppendRevision(ctx context.Context, label, sha256, path string) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO config_revisions(at, label, haproxy_sha256, content_path) VALUES($1,$2,$3,$4)`,
		time.Now().UTC(), label, sha256, path)
	return err
}

// ListCertificates returns all certificate rows.
func (s *Store) ListCertificates(ctx context.Context) ([]config.Certificate, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, primary_domain, san_json, mode, staging, acme_status, dns_provider, dns_credentials_env_file,
		       pem_crt_path, pem_key_path, fullchain_path, not_before, not_after, last_error, created_at, updated_at
		FROM certificates ORDER BY primary_domain`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanCertificates(rows)
}

func scanCertificates(rows *sql.Rows) ([]config.Certificate, error) {
	var out []config.Certificate
	for rows.Next() {
		var c config.Certificate
		var san []byte
		var pc, pk, fc, acmeSt, dnsP, dnsEnv, le sql.NullString
		var nb, na sql.NullTime
		if err := rows.Scan(&c.ID, &c.PrimaryDomain, &san, &c.Mode, &c.Staging, &acmeSt,
			&dnsP, &dnsEnv,
			&pc, &pk, &fc, &nb, &na, &le, &c.CreatedAt, &c.UpdatedAt); err != nil {
			return nil, err
		}
		if len(san) > 0 {
			_ = json.Unmarshal(san, &c.SAN)
		}
		if acmeSt.Valid {
			c.ACMEStatus = acmeSt.String
		}
		if dnsP.Valid {
			c.DNSProvider = dnsP.String
		}
		if dnsEnv.Valid {
			c.DNSCredentialsEnvFile = dnsEnv.String
		}
		if pc.Valid {
			c.PEMCrtPath = pc.String
		}
		if pk.Valid {
			c.PEMKeyPath = pk.String
		}
		if fc.Valid {
			c.FullchainPath = fc.String
		}
		if nb.Valid {
			t := nb.Time
			c.NotBefore = &t
		}
		if na.Valid {
			t := na.Time
			c.NotAfter = &t
		}
		if le.Valid {
			c.LastError = le.String
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// UpsertCertificate inserts or updates a certificate record.
func (s *Store) UpsertCertificate(ctx context.Context, c *config.Certificate) error {
	now := time.Now().UTC()
	if c.ID == "" {
		c.ID = uuid.NewString()
		c.CreatedAt = now
	}
	c.UpdatedAt = now
	if c.CreatedAt.IsZero() {
		c.CreatedAt = now
	}
	if c.ACMEStatus == "" {
		c.ACMEStatus = "ready"
	}
	var sanJSON any
	if len(c.SAN) > 0 {
		b, err := json.Marshal(c.SAN)
		if err != nil {
			return err
		}
		sanJSON = b
	}
	var nb, na any
	if c.NotBefore != nil {
		nb = *c.NotBefore
	}
	if c.NotAfter != nil {
		na = *c.NotAfter
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO certificates (
			id, primary_domain, san_json, mode, staging, acme_status, dns_provider, dns_credentials_env_file,
			pem_crt_path, pem_key_path, fullchain_path, not_before, not_after, last_error, created_at, updated_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)
		ON CONFLICT (id) DO UPDATE SET
			primary_domain = EXCLUDED.primary_domain,
			san_json = EXCLUDED.san_json,
			mode = EXCLUDED.mode,
			staging = EXCLUDED.staging,
			acme_status = EXCLUDED.acme_status,
			dns_provider = EXCLUDED.dns_provider,
			dns_credentials_env_file = EXCLUDED.dns_credentials_env_file,
			pem_crt_path = EXCLUDED.pem_crt_path,
			pem_key_path = EXCLUDED.pem_key_path,
			fullchain_path = EXCLUDED.fullchain_path,
			not_before = EXCLUDED.not_before,
			not_after = EXCLUDED.not_after,
			last_error = EXCLUDED.last_error,
			updated_at = EXCLUDED.updated_at
	`, c.ID, c.PrimaryDomain, sanJSON, c.Mode, c.Staging, c.ACMEStatus,
		nullStrPtr(c.DNSProvider), nullStrPtr(c.DNSCredentialsEnvFile),
		nullStrPtr(c.PEMCrtPath), nullStrPtr(c.PEMKeyPath), nullStrPtr(c.FullchainPath),
		nb, na, nullStrPtr(c.LastError), c.CreatedAt, c.UpdatedAt)
	return err
}

// ListCertificatesACMEPending returns rows awaiting issuance.
func (s *Store) ListCertificatesACMEPending(ctx context.Context, limit int) ([]config.Certificate, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, primary_domain, san_json, mode, staging, acme_status, dns_provider, dns_credentials_env_file,
		       pem_crt_path, pem_key_path, fullchain_path, not_before, not_after, last_error, created_at, updated_at
		FROM certificates WHERE acme_status = 'pending' ORDER BY updated_at ASC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanCertificates(rows)
}

// ListCertificatesACMERenew returns certs that should be renewed (not_after within window).
func (s *Store) ListCertificatesACMERenew(ctx context.Context, renewBefore time.Time, limit int) ([]config.Certificate, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, primary_domain, san_json, mode, staging, acme_status, dns_provider, dns_credentials_env_file,
		       pem_crt_path, pem_key_path, fullchain_path, not_before, not_after, last_error, created_at, updated_at
		FROM certificates
		WHERE acme_status = 'ready' AND mode IN ('http-01', 'dns-01') AND not_after IS NOT NULL AND not_after < $1
		ORDER BY not_after ASC LIMIT $2`, renewBefore, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanCertificates(rows)
}

// UpdateCertificateACMEState updates status and optional error after worker run.
func (s *Store) UpdateCertificateACMEState(ctx context.Context, id, status, lastErr string) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE certificates SET acme_status = $2, last_error = $3, updated_at = $4 WHERE id = $1`,
		id, status, nullStrPtr(lastErr), time.Now().UTC())
	return err
}

// --- IP allowlist (local) ---

// ListIPWLLocal returns all allowlist rows ordered by CIDR.
func (s *Store) ListIPWLLocal(ctx context.Context) ([]config.IPWLLocalEntry, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, cidr, "comment", created_at FROM ipwl_local ORDER BY cidr`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []config.IPWLLocalEntry
	for rows.Next() {
		var e config.IPWLLocalEntry
		var cm sql.NullString
		if err := rows.Scan(&e.ID, &e.CIDR, &cm, &e.CreatedAt); err != nil {
			return nil, err
		}
		if cm.Valid {
			e.Comment = cm.String
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// UpsertIPWLLocal inserts or updates a local allow entry.
func (s *Store) UpsertIPWLLocal(ctx context.Context, e *config.IPWLLocalEntry) error {
	now := time.Now().UTC()
	if e.ID == "" {
		e.ID = uuid.NewString()
	}
	if e.CreatedAt.IsZero() {
		e.CreatedAt = now
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO ipwl_local (id, cidr, "comment", created_at)
		VALUES ($1,$2,$3,$4)
		ON CONFLICT (id) DO UPDATE SET
			cidr = EXCLUDED.cidr,
			"comment" = EXCLUDED."comment"
	`, e.ID, e.CIDR, nullStrPtr(e.Comment), e.CreatedAt)
	return err
}

// DeleteIPWLLocal removes a row by id.
func (s *Store) DeleteIPWLLocal(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM ipwl_local WHERE id = $1`, id)
	return err
}

// --- IPBL ---

// ListIPBLLocal returns enabled and disabled entries.
func (s *Store) ListIPBLLocal(ctx context.Context) ([]config.IPBLLocalEntry, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, cidr, note, enabled, created_at, updated_at FROM ipbl_local ORDER BY cidr`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []config.IPBLLocalEntry
	for rows.Next() {
		var e config.IPBLLocalEntry
		if err := rows.Scan(&e.ID, &e.CIDR, &e.Note, &e.Enabled, &e.CreatedAt, &e.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// UpsertIPBLLocal inserts or updates a local deny entry.
func (s *Store) UpsertIPBLLocal(ctx context.Context, e *config.IPBLLocalEntry) error {
	now := time.Now().UTC()
	if e.ID == "" {
		e.ID = uuid.NewString()
		e.CreatedAt = now
	}
	e.UpdatedAt = now
	if e.CreatedAt.IsZero() {
		e.CreatedAt = now
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO ipbl_local (id, cidr, note, enabled, created_at, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6)
		ON CONFLICT (id) DO UPDATE SET
			cidr = EXCLUDED.cidr,
			note = EXCLUDED.note,
			enabled = EXCLUDED.enabled,
			updated_at = EXCLUDED.updated_at
	`, e.ID, e.CIDR, nullStrPtr(e.Note), e.Enabled, e.CreatedAt, e.UpdatedAt)
	return err
}

// DeleteIPBLLocal removes a local entry.
func (s *Store) DeleteIPBLLocal(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM ipbl_local WHERE id = $1`, id)
	return err
}

// ListIPBLExternalSources returns configured download sources.
func (s *Store) ListIPBLExternalSources(ctx context.Context) ([]config.IPBLExternalSource, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, name, url, enabled, refresh_seconds, last_fetch_at, last_error, created_at, updated_at
		FROM ipbl_external_sources ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []config.IPBLExternalSource
	for rows.Next() {
		var e config.IPBLExternalSource
		var lf sql.NullTime
		var le sql.NullString
		if err := rows.Scan(&e.ID, &e.Name, &e.URL, &e.Enabled, &e.RefreshSeconds, &lf, &le, &e.CreatedAt, &e.UpdatedAt); err != nil {
			return nil, err
		}
		if lf.Valid {
			t := lf.Time
			e.LastFetchAt = &t
		}
		if le.Valid {
			e.LastError = le.String
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// UpsertIPBLExternalSource inserts or updates an external list source.
func (s *Store) UpsertIPBLExternalSource(ctx context.Context, e *config.IPBLExternalSource) error {
	now := time.Now().UTC()
	if e.ID == "" {
		e.ID = uuid.NewString()
		e.CreatedAt = now
	}
	e.UpdatedAt = now
	if e.CreatedAt.IsZero() {
		e.CreatedAt = now
	}
	if e.RefreshSeconds <= 0 {
		e.RefreshSeconds = 3600
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO ipbl_external_sources (
			id, name, url, enabled, refresh_seconds, last_fetch_at, last_error, created_at, updated_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
		ON CONFLICT (id) DO UPDATE SET
			name = EXCLUDED.name,
			url = EXCLUDED.url,
			enabled = EXCLUDED.enabled,
			refresh_seconds = EXCLUDED.refresh_seconds,
			last_fetch_at = EXCLUDED.last_fetch_at,
			last_error = EXCLUDED.last_error,
			updated_at = EXCLUDED.updated_at
	`, e.ID, e.Name, e.URL, e.Enabled, e.RefreshSeconds, e.LastFetchAt, nullStrPtr(e.LastError), e.CreatedAt, e.UpdatedAt)
	return err
}

// TouchIPBLSourceFetch updates fetch metadata for a source.
func (s *Store) TouchIPBLSourceFetch(ctx context.Context, id string, fetchAt time.Time, fetchErr string) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE ipbl_external_sources SET last_fetch_at = $2, last_error = $3, updated_at = $4 WHERE id = $1`,
		id, fetchAt, nullStrPtr(fetchErr), time.Now().UTC())
	return err
}

// --- Blocked User-Agent patterns ---

// ListBlockedUserAgents returns all rows ordered by pattern.
func (s *Store) ListBlockedUserAgents(ctx context.Context) ([]config.BlockedUserAgent, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, pattern, "comment", created_at FROM blocked_user_agents ORDER BY pattern`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []config.BlockedUserAgent
	for rows.Next() {
		var e config.BlockedUserAgent
		var cm sql.NullString
		if err := rows.Scan(&e.ID, &e.Pattern, &cm, &e.CreatedAt); err != nil {
			return nil, err
		}
		if cm.Valid {
			e.Comment = cm.String
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// UpsertBlockedUserAgent inserts or updates a pattern row.
func (s *Store) UpsertBlockedUserAgent(ctx context.Context, e *config.BlockedUserAgent) error {
	now := time.Now().UTC()
	if e.ID == "" {
		e.ID = uuid.NewString()
	}
	if e.CreatedAt.IsZero() {
		e.CreatedAt = now
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO blocked_user_agents (id, pattern, "comment", created_at)
		VALUES ($1,$2,$3,$4)
		ON CONFLICT (id) DO UPDATE SET
			pattern = EXCLUDED.pattern,
			"comment" = EXCLUDED."comment"
	`, e.ID, strings.TrimSpace(e.Pattern), nullStrPtr(e.Comment), e.CreatedAt)
	return err
}

// DeleteBlockedUserAgent removes a row by id.
func (s *Store) DeleteBlockedUserAgent(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM blocked_user_agents WHERE id = $1`, id)
	return err
}

// FactoryReset removes all configuration rows (destructive). Schema is kept.
func (s *Store) FactoryReset(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `
		TRUNCATE applications, certificates, settings, audit_log, config_revisions, ipwl_local, ipbl_local, ipbl_external_sources, blocked_user_agents, users
		RESTART IDENTITY CASCADE`)
	return err
}
