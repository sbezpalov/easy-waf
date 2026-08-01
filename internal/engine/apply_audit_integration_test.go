package engine_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/easy-waf/easy-waf/internal/config"
	"github.com/easy-waf/easy-waf/internal/engine"
	"github.com/easy-waf/easy-waf/internal/store"
)

func writeTestBundlePEM(path string) error {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	tpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{Organization: []string{"easy-waf-apply-audit-test"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     []string{"audit-apply.local"},
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tpl, &tpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	var buf bytes.Buffer
	buf.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	buf.Write(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
	return os.WriteFile(path, buf.Bytes(), 0o600)
}

// TestApplyWritesAuditLogEntry checks that a successful Engine.Apply appends a row with action "apply".
// Requires PostgreSQL (DATABASE_URL). Skips when unset.
func TestApplyWritesAuditLogEntry(t *testing.T) {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL not set")
	}
	t.Setenv("EASY_WAF_SKIP_VALIDATE", "1")
	t.Setenv("EASY_WAF_SKIP_RELOAD", "1")

	ctx := context.Background()
	st, err := store.OpenPostgres(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	stateDir := t.TempDir()
	e := &engine.Engine{StateDir: stateDir, Store: st}
	if err := e.LoadSettings(ctx); err != nil {
		t.Fatal(err)
	}

	bundlePath := filepath.Join(stateDir, "bundle.pem")
	if err := writeTestBundlePEM(bundlePath); err != nil {
		t.Fatal(err)
	}

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	certID := "audit_apply_cert_" + suffix
	host := "audit-apply-" + suffix + ".example"
	appID := "audit_apply_app_" + suffix

	now := time.Now().UTC()
	cert := config.Certificate{
		ID:            certID,
		PrimaryDomain: host,
		Mode:          "self-signed",
		Staging:       true,
		ACMEStatus:    "ready",
		PEMCrtPath:    bundlePath,
		CreatedAt:     now,
		UpdatedAt:     now,
	}
	if err := st.UpsertCertificate(ctx, &cert); err != nil {
		t.Fatal(err)
	}
	app := config.Application{
		ID:            appID,
		Name:          "audit apply test",
		PublicHost:    host,
		BackendHost:   "127.0.0.1",
		BackendPort:   8080,
		Profile:       "balanced",
		CertificateID: certID,
		Enabled:       true,
		CreatedAt:     now,
		UpdatedAt:     now,
	}
	if err := st.UpsertApplication(ctx, &app); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx2, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_, _ = db.ExecContext(ctx2, `DELETE FROM applications WHERE id = $1`, appID)
		_, _ = db.ExecContext(ctx2, `DELETE FROM certificates WHERE id = $1`, certID)
	})

	var beforeMax int64
	if err := db.QueryRowContext(ctx, `SELECT COALESCE(MAX(id), 0) FROM audit_log`).Scan(&beforeMax); err != nil {
		t.Fatal(err)
	}

	if err := e.Apply(ctx, "integration-apply-audit"); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	var found bool
	err = db.QueryRowContext(ctx, `
		SELECT EXISTS(SELECT 1 FROM audit_log WHERE id > $1 AND action = 'apply')`, beforeMax).Scan(&found)
	if err != nil {
		t.Fatal(err)
	}
	if !found {
		t.Fatalf("expected new audit_log row with action 'apply' after Apply (audit ids after %d)", beforeMax)
	}

	revisions, err := st.ListConfigRevisions(ctx, 20)
	if err != nil {
		t.Fatal(err)
	}
	var applied *store.ConfigRevision
	for i := range revisions {
		if revisions[i].Label == "integration-apply-audit" {
			applied = &revisions[i]
			break
		}
	}
	if applied == nil {
		t.Fatal("expected config revision for integration apply")
	}
	if filepath.Base(applied.ContentPath) != "manifest.json" {
		t.Fatalf("revision content path = %q, want artifact manifest", applied.ContentPath)
	}
	if _, err := os.Stat(applied.ContentPath); err != nil {
		t.Fatalf("revision artifact manifest: %v", err)
	}
}
