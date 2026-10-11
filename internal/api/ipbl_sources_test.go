// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/easy-waf/easy-waf/internal/config"
	"github.com/easy-waf/easy-waf/internal/engine"
	"github.com/easy-waf/easy-waf/internal/store"
)

// Saving a source as disabled deletes its last good copy at once, so it
// cannot come back through the fallback if it is re-enabled before a sync.
func TestUpsertIPBLSource_DisableForgetsSavedCopy(t *testing.T) {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL not set")
	}
	st, err := store.OpenPostgres(dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	state := t.TempDir()
	s := &Server{Eng: engine.New(state, st, config.DefaultSettings(state))}

	src := config.IPBLExternalSource{
		ID:      fmt.Sprintf("apitest-%d", time.Now().UnixNano()),
		Name:    "apitest feed",
		URL:     "https://203.0.113.10/list", // public literal: passes the SSRF pre-check without DNS
		Enabled: true,
	}
	if err := st.UpsertIPBLExternalSource(context.Background(), &src); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.DeleteIPBLExternalSource(context.Background(), src.ID) })
	copyPath := filepath.Join(state, "ipbl", "feeds", src.ID+".list")
	if err := os.MkdirAll(filepath.Dir(copyPath), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(copyPath, []byte("# saved\n192.0.2.1\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	src.Enabled = false
	body, _ := json.Marshal(src)
	rec := httptest.NewRecorder()
	s.upsertIPBLSource(rec, httptest.NewRequest(http.MethodPost, "/api/v1/ipbl/sources", bytes.NewReader(body)))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	if _, err := os.Stat(copyPath); !os.IsNotExist(err) {
		t.Fatalf("saved copy kept after disabling: %v", err)
	}
}
