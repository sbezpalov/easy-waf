// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package engine_test

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/easy-waf/easy-waf/internal/config"
	"github.com/easy-waf/easy-waf/internal/engine"
	"github.com/easy-waf/easy-waf/internal/haproxy"
	"github.com/easy-waf/easy-waf/internal/store"
)

// TestRollbackRestoresArtifactManifestSet verifies that a new-style revision
// restores generated maps and crt-list together with haproxy.cfg. It requires
// PostgreSQL and skips when DATABASE_URL is unset.
func TestRollbackRestoresArtifactManifestSet(t *testing.T) {
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
	cfg := config.DefaultSettings(stateDir)
	cfg.IPBLExternalEnabled = false
	e := engine.New(stateDir, st, cfg)
	// Apply renders from the stored settings, so store these for the test.
	useStoredSettingsForTest(t, st, e)

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	appID := "artifact_rollback_app_" + suffix
	ipblID := "artifact_rollback_ipbl_" + suffix
	labelV1 := "artifact-rollback-v1-" + suffix
	labelV2 := "artifact-rollback-v2-" + suffix
	started := time.Now().UTC()
	rollbackLabel := ""

	t.Cleanup(func() {
		ctx2, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_, _ = db.ExecContext(ctx2, `DELETE FROM applications WHERE id = $1`, appID)
		_, _ = db.ExecContext(ctx2, `DELETE FROM ipbl_local WHERE id = $1`, ipblID)
		_, _ = db.ExecContext(ctx2, `
			DELETE FROM config_revisions
			WHERE label = $1 OR label = $2 OR (label = $3 AND at >= $4)`,
			labelV1, labelV2, rollbackLabel, started)
		cfgPath := filepath.Join(stateDir, "haproxy", "haproxy.cfg")
		_, _ = db.ExecContext(ctx2, `
			DELETE FROM audit_log
			WHERE at >= $1 AND action IN ('apply', 'rollback')
			  AND detail_json->>'path' = $2`, started, cfgPath)
	})

	now := time.Now().UTC()
	app := config.Application{
		ID:          appID,
		Name:        "artifact rollback integration",
		PublicHost:  "artifact-rollback-" + suffix + ".example",
		BackendHost: "127.0.0.1",
		BackendPort: 8080,
		Profile:     "balanced",
		ListenMode:  "http_only",
		Enabled:     true,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if err := st.UpsertApplication(ctx, &app); err != nil {
		t.Fatal(err)
	}
	blocked := config.IPBLLocalEntry{
		ID:        ipblID,
		CIDR:      "192.0.2.10",
		Enabled:   true,
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := st.UpsertIPBLLocal(ctx, &blocked); err != nil {
		t.Fatal(err)
	}

	if err := e.Apply(ctx, labelV1); err != nil {
		t.Fatalf("Apply v1: %v", err)
	}
	revisions, err := st.ListConfigRevisions(ctx, 50)
	if err != nil {
		t.Fatal(err)
	}
	var revV1 store.ConfigRevision
	for _, rev := range revisions {
		if rev.Label == labelV1 {
			revV1 = rev
			break
		}
	}
	if revV1.ID == 0 {
		t.Fatal("v1 revision not found")
	}
	if filepath.Base(revV1.ContentPath) != "manifest.json" {
		t.Fatalf("v1 content path = %q, want manifest", revV1.ContentPath)
	}

	_, cfgPath, crtListPath := haproxy.Paths(stateDir)
	cfgV1, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	crtListV1, err := os.ReadFile(crtListPath)
	if err != nil {
		t.Fatal(err)
	}
	ipblV1, err := os.ReadFile(e.Settings().IPBlacklistMapPath)
	if err != nil {
		t.Fatal(err)
	}

	app.BackendPort = 9090
	if err := st.UpsertApplication(ctx, &app); err != nil {
		t.Fatal(err)
	}
	blocked.CIDR = "203.0.113.10"
	if err := st.UpsertIPBLLocal(ctx, &blocked); err != nil {
		t.Fatal(err)
	}
	if err := e.Apply(ctx, labelV2); err != nil {
		t.Fatalf("Apply v2: %v", err)
	}
	ipblV2, err := os.ReadFile(e.Settings().IPBlacklistMapPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(ipblV2) == string(ipblV1) {
		t.Fatal("test setup did not change the IPBL map")
	}

	if err := e.Rollback(ctx, revV1.ID); err != nil {
		t.Fatalf("Rollback v1: %v", err)
	}
	rollbackLabel = "rollback from " + revV1.HAProxySHA256[:12]

	cfgAfter, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(cfgAfter) != string(cfgV1) {
		t.Fatal("HAProxy config was not restored with artifact revision")
	}
	crtListAfter, err := os.ReadFile(crtListPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(crtListAfter) != string(crtListV1) {
		t.Fatal("crt-list was not restored with artifact revision")
	}
	ipblAfter, err := os.ReadFile(e.Settings().IPBlacklistMapPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(ipblAfter) != string(ipblV1) {
		t.Fatal("IPBL map was not restored with artifact revision")
	}

	latest, err := st.ListConfigRevisions(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(latest) != 1 || filepath.Base(latest[0].ContentPath) != "manifest.json" {
		t.Fatalf("rollback revision does not reference an artifact manifest: %+v", latest)
	}
}
