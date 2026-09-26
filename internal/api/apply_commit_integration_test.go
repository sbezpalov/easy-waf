// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/easy-waf/easy-waf/internal/config"
	"github.com/easy-waf/easy-waf/internal/engine"
	"github.com/easy-waf/easy-waf/internal/store"
)

// applyFailingServer returns a server whose every apply fails validation
// (the configured haproxy binary is /bin/false) against a real database.
func applyFailingServer(t *testing.T) *Server {
	t.Helper()
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL not set")
	}
	st, err := store.OpenPostgres(dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	ctx := context.Background()
	const key = "global_settings_json"
	prev, err := st.GetSetting(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	stateDir := t.TempDir()
	cfg := config.DefaultSettings(stateDir)
	cfg.HAProxyBinary = "/bin/false"
	cfg.IPBLExternalEnabled = false
	eng := engine.New(stateDir, st, cfg)
	if err := eng.SaveSettings(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if prev == "" {
			_ = st.DeleteSetting(context.Background(), key)
		} else {
			_ = st.SetSetting(context.Background(), key, prev)
		}
	})
	t.Setenv("EASY_WAF_SKIP_RELOAD", "1")
	t.Setenv("EASY_WAF_NO_AUTO_APPLY", "")
	return &Server{Eng: eng}
}

func testApp(name string) config.Application {
	return config.Application{
		Name:        name,
		PublicHost:  name + ".example.com",
		BackendHost: "10.0.0.5",
		BackendPort: 8080,
		Profile:     "balanced",
		ListenMode:  "http_only",
		Enabled:     true,
	}
}

func putApp(t *testing.T, s *Server, a config.Application) *httptest.ResponseRecorder {
	t.Helper()
	b, _ := json.Marshal(a)
	rec := httptest.NewRecorder()
	s.upsertApp(rec, httptest.NewRequest(http.MethodPut, "/api/v1/applications", bytes.NewReader(b)))
	return rec
}

func TestFailedApplyDoesNotKeepNewApplication(t *testing.T) {
	s := applyFailingServer(t)
	name := fmt.Sprintf("rejectnew%d", time.Now().UnixNano())
	rec := putApp(t, s, testApp(name))
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	apps, err := s.Eng.Store.ListApplications(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range apps {
		if a.Name == name {
			_ = s.Eng.Store.DeleteApplication(context.Background(), a.ID)
			t.Fatal("application the edge rejected is still in the database")
		}
	}
}

func TestFailedApplyRestoresUpdatedApplication(t *testing.T) {
	s := applyFailingServer(t)
	ctx := context.Background()
	orig := testApp(fmt.Sprintf("rejectupd%d", time.Now().UnixNano()))
	if err := s.Eng.Store.UpsertApplication(ctx, &orig); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Eng.Store.DeleteApplication(context.Background(), orig.ID) })

	changed := orig
	changed.BackendPort = 9090
	if rec := putApp(t, s, changed); rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	got, err := s.Eng.Store.GetApplication(ctx, orig.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.BackendPort != 8080 {
		t.Fatalf("backend port %d after a rejected change, want the previous 8080", got.BackendPort)
	}

	// Deleting is undone the same way.
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", orig.ID)
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/applications/"+orig.ID, nil)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	rec := httptest.NewRecorder()
	s.deleteApp(rec, req)
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("delete status %d: %s", rec.Code, rec.Body.String())
	}
	if _, err := s.Eng.Store.GetApplication(ctx, orig.ID); errors.Is(err, sql.ErrNoRows) {
		t.Fatal("application deleted although the edge apply failed")
	}
}
