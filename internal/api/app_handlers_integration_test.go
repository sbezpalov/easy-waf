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
	"github.com/easy-waf/easy-waf/internal/config"
	"github.com/easy-waf/easy-waf/internal/haproxy"
	"github.com/easy-waf/easy-waf/internal/store"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
)

func withURLParam(r *http.Request, key, val string) *http.Request {
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add(key, val)
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
}

func TestRequestIssueReturnsStoredPendingStateWithoutReplacingPEMPaths(t *testing.T) {
	s := applyFailingServer(t)
	c := &config.Certificate{PrimaryDomain: "request-cas.example.test", Mode: "http-01", ACMEStatus: "failed", LastError: "previous failure", FullchainPath: "/fixture/fullchain.pem", PEMKeyPath: "/fixture/key.pem"}
	if err := s.Eng.Store.UpsertCertificate(t.Context(), c); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Eng.Store.DeleteCertificate(context.Background(), c.ID) })
	r := withURLParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`)), "id", c.ID)
	w := httptest.NewRecorder()
	s.requestCertIssue(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("request failed: %d", w.Code)
	}
	var got config.Certificate
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.ACMEStatus != "pending" || got.LastError != "" || got.FullchainPath != c.FullchainPath || got.PEMKeyPath != c.PEMKeyPath {
		t.Fatal("response does not describe the preserved stored certificate")
	}
}

func TestDeleteUnknownApplicationIs404WithoutApply(t *testing.T) {
	s := applyFailingServer(t) // any apply would fail, so a 404 proves none ran
	req := withURLParam(httptest.NewRequest(http.MethodDelete, "/api/v1/applications/x", nil), "id", "00000000-0000-0000-0000-000000000000")
	rec := httptest.NewRecorder()
	s.deleteApp(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
}

func TestDeleteApplicationRejectsInvalidRevision(t *testing.T) {
	s := &Server{} // validation must finish before touching the engine
	for _, query := range []string{
		"expected_updated_at=%ZZ",
		"expected_updated_at=",
		"expected_updated_at=not-a-timestamp",
		"expected_updated_at=0001-01-01T00%3A00%3A00Z",
		"expected_updated_at=2026-11-01T12%3A13%3A14Z&expected_updated_at=2026-11-01T12%3A13%3A15Z",
	} {
		req := httptest.NewRequest(http.MethodDelete, "/api/v1/applications/x", nil)
		req.URL.RawQuery = query
		rec := httptest.NewRecorder()
		s.deleteApp(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("query %q: %d %s", query, rec.Code, rec.Body)
		}
	}
}

func TestDeleteApplicationRequiresConfirmedRevisionWhenSupplied(t *testing.T) {
	s := applyFailingServer(t)
	t.Setenv("EASY_WAF_NO_AUTO_APPLY", "1")
	app := testApp(fmt.Sprintf("deleteconflict%d", time.Now().UnixNano()))
	save := func() config.Application {
		t.Helper()
		rec := putApp(t, s, app)
		if rec.Code != http.StatusOK {
			t.Fatalf("save publication: %d %s", rec.Code, rec.Body)
		}
		var saved config.Application
		if err := json.Unmarshal(rec.Body.Bytes(), &saved); err != nil {
			t.Fatal(err)
		}
		return saved
	}
	app = save()
	t.Cleanup(func() { _ = s.Eng.Store.DeleteApplication(context.Background(), app.ID) })
	confirmed := app.UpdatedAt
	app.Name = "Edited by another operator"
	app = save()

	remove := func(revision time.Time) *httptest.ResponseRecorder {
		t.Helper()
		path := "/api/v1/applications/x?expected_updated_at=" + url.QueryEscape(revision.Format(time.RFC3339Nano))
		req := withURLParam(httptest.NewRequest(http.MethodDelete, path, nil), "id", app.ID)
		rec := httptest.NewRecorder()
		s.deleteApp(rec, req)
		return rec
	}
	if rec := remove(confirmed); rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), `"code":"application_changed"`) {
		t.Fatalf("delete stale version: %d %s", rec.Code, rec.Body)
	}
	stored, err := s.Eng.Store.GetApplication(t.Context(), app.ID)
	if err != nil || stored.Name != app.Name || !stored.UpdatedAt.Equal(app.UpdatedAt) {
		t.Fatalf("conflict changed the stored publication: name=%q, updated_at=%s, error %v", stored.Name, stored.UpdatedAt, err)
	}
	if rec := remove(app.UpdatedAt); rec.Code != http.StatusNoContent {
		t.Fatalf("delete reviewed version: %d %s", rec.Code, rec.Body)
	}
	if _, err := s.Eng.Store.GetApplication(t.Context(), app.ID); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("confirmed publication was not deleted: %v", err)
	}
	if rec := remove(app.UpdatedAt); rec.Code != http.StatusConflict {
		t.Fatalf("delete already removed publication: %d %s", rec.Code, rec.Body)
	}
}

func TestGetUnknownApplicationIs404(t *testing.T) {
	s := applyFailingServer(t)
	req := withURLParam(httptest.NewRequest(http.MethodGet, "/api/v1/applications/x", nil), "id", "00000000-0000-0000-0000-000000000000")
	rec := httptest.NewRecorder()
	s.getApp(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
}

func TestUpsertResponseReportsStoredCreatedAt(t *testing.T) {
	s := applyFailingServer(t)
	t.Setenv("EASY_WAF_NO_AUTO_APPLY", "1")
	a := testApp(fmt.Sprintf("createdat%d", time.Now().UnixNano()))
	rec := putApp(t, s, a)
	if rec.Code != http.StatusOK {
		t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &a); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Eng.Store.DeleteApplication(context.Background(), a.ID) })
	stored, err := s.Eng.Store.GetApplication(context.Background(), a.ID)
	if err != nil {
		t.Fatal(err)
	}

	a.CreatedAt = time.Time{} // a client that omits created_at on update
	time.Sleep(10 * time.Millisecond)
	rec = putApp(t, s, a)
	if rec.Code != http.StatusOK {
		t.Fatalf("update: %d %s", rec.Code, rec.Body.String())
	}
	var got struct {
		CreatedAt time.Time `json:"created_at"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if !got.CreatedAt.Equal(stored.CreatedAt) {
		t.Fatalf("response created_at %v, stored %v", got.CreatedAt, stored.CreatedAt)
	}
}

func TestUpsertPreservesPublicationStateWhenOmitted(t *testing.T) {
	s := applyFailingServer(t)
	t.Setenv("EASY_WAF_NO_AUTO_APPLY", "1")
	a := testApp(fmt.Sprintf("enabled%d", time.Now().UnixNano()))
	rec := putApp(t, s, a)
	if rec.Code != http.StatusOK {
		t.Fatalf("create: %d %s", rec.Code, rec.Body)
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &a); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Eng.Store.DeleteApplication(context.Background(), a.ID) })
	var body map[string]json.RawMessage
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		field string
		want  bool
	}{
		{"", true},
		{"false", false},
		{"", false},
		{"null", false},
		{"true", true},
	} {
		delete(body, "enabled")
		if tc.field != "" {
			body["enabled"] = json.RawMessage(tc.field)
		}
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		rec = httptest.NewRecorder()
		s.upsertApp(rec, httptest.NewRequest(http.MethodPost, "/api/v1/applications", bytes.NewReader(raw)))
		if rec.Code != http.StatusOK {
			t.Fatalf("update with enabled %q: %d %s", tc.field, rec.Code, rec.Body)
		}
		stored, err := s.Eng.Store.GetApplication(t.Context(), a.ID)
		if err != nil || stored.Enabled != tc.want {
			t.Fatalf("enabled %q: stored %t, want %t, error %v", tc.field, stored.Enabled, tc.want, err)
		}
	}
}

func TestUpsertKeepsOmittedApplicationPaths(t *testing.T) {
	s := applyFailingServer(t)
	t.Setenv("EASY_WAF_NO_AUTO_APPLY", "1")
	a := testApp(fmt.Sprintf("paths%d", time.Now().UnixNano()))
	a.HealthPath, a.PathPrefix = "/ready", "/legacy"
	rec := putApp(t, s, a)
	if rec.Code != http.StatusOK {
		t.Fatalf("create: %d %s", rec.Code, rec.Body)
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &a); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Eng.Store.DeleteApplication(context.Background(), a.ID) })
	var body map[string]json.RawMessage
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		value          string
		health, prefix string
	}{
		{"", "/ready", "/legacy"},
		{"null", "/ready", "/legacy"},
		{`"/new-health"`, "/new-health", "/new-health"},
		{`""`, "", ""},
	} {
		for _, field := range []string{"health_path", "path_prefix"} {
			delete(body, field)
			if tc.value != "" {
				body[field] = json.RawMessage(tc.value)
			}
		}
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		rec = httptest.NewRecorder()
		s.upsertApp(rec, httptest.NewRequest(http.MethodPost, "/api/v1/applications", bytes.NewReader(raw)))
		if rec.Code != http.StatusOK {
			t.Fatalf("update with %q: %d %s", tc.value, rec.Code, rec.Body)
		}
		stored, err := s.Eng.Store.GetApplication(t.Context(), a.ID)
		if err != nil || stored.HealthPath != tc.health || stored.PathPrefix != tc.prefix {
			t.Fatalf("update with %q: health_path=%q, path_prefix=%q, error %v", tc.value, stored.HealthPath, stored.PathPrefix, err)
		}
		edge, err := haproxy.Render(haproxy.RenderInput{
			StateDir: s.Eng.StateDir, Settings: s.Eng.Settings(), Applications: []config.Application{stored},
		})
		if err != nil {
			t.Fatal(err)
		}
		httpCheck := "option httpchk GET "
		if tc.health != "" {
			httpCheck += tc.health
		}
		if strings.Contains(edge.HAProxyConfig, httpCheck) != (tc.health != "") {
			t.Fatalf("health_path %q did not reach the HAProxy configuration", tc.health)
		}
	}
}

func TestUpsertRejectsStalePublicationEdits(t *testing.T) {
	s := applyFailingServer(t)
	t.Setenv("EASY_WAF_NO_AUTO_APPLY", "1")
	a := testApp(fmt.Sprintf("editconflict%d", time.Now().UnixNano()))
	rec := putApp(t, s, a)
	if rec.Code != http.StatusOK {
		t.Fatalf("create: %d %s", rec.Code, rec.Body)
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &a); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Eng.Store.DeleteApplication(context.Background(), a.ID) })

	save := func(name string) *httptest.ResponseRecorder {
		t.Helper()
		draft := struct {
			config.Application
			ExpectedUpdatedAt time.Time `json:"expected_updated_at"`
		}{Application: a, ExpectedUpdatedAt: a.UpdatedAt}
		draft.Name = name
		raw, err := json.Marshal(draft)
		if err != nil {
			t.Fatal(err)
		}
		rec := httptest.NewRecorder()
		s.upsertApp(rec, httptest.NewRequest(http.MethodPost, "/api/v1/applications", bytes.NewReader(raw)))
		return rec
	}
	winner := save("First operator")
	if winner.Code != http.StatusOK {
		t.Fatalf("save current draft: %d %s", winner.Code, winner.Body)
	}
	var saved config.Application
	if err := json.Unmarshal(winner.Body.Bytes(), &saved); err != nil {
		t.Fatal(err)
	}
	if !saved.UpdatedAt.After(a.UpdatedAt) {
		t.Fatalf("revision did not advance: %s to %s", a.UpdatedAt, saved.UpdatedAt)
	}

	conflict := save("Second operator from old draft")
	if conflict.Code != http.StatusConflict || !strings.Contains(conflict.Body.String(), `"code":"application_changed"`) {
		t.Fatalf("save old draft: %d %s", conflict.Code, conflict.Body)
	}
	stored, err := s.Eng.Store.GetApplication(t.Context(), a.ID)
	if err != nil || stored.Name != saved.Name || !stored.UpdatedAt.Equal(saved.UpdatedAt) {
		t.Fatalf("conflict changed the stored publication: name=%q, updated_at=%s, error=%v", stored.Name, stored.UpdatedAt, err)
	}

	rec = httptest.NewRecorder()
	s.deleteApp(rec, withURLParam(httptest.NewRequest(http.MethodDelete, "/api/v1/applications/x", nil), "id", a.ID))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete: %d %s", rec.Code, rec.Body)
	}
	if rec := save("Deleted publication"); rec.Code != http.StatusConflict {
		t.Fatalf("save deleted draft: %d %s", rec.Code, rec.Body)
	}
	if _, err := s.Eng.Store.GetApplication(t.Context(), a.ID); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("deleted draft recreated the publication: %v", err)
	}
}

func TestUpsertKeepsSecurityTogglesSentWithoutMode(t *testing.T) {
	s := applyFailingServer(t)
	t.Setenv("EASY_WAF_NO_AUTO_APPLY", "1")
	a := testApp(fmt.Sprintf("secmode%d", time.Now().UnixNano()))
	a.Security.RateLimitEnabled = true // no mode, every other toggle off
	rec := putApp(t, s, a)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &a); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Eng.Store.DeleteApplication(context.Background(), a.ID) })
	stored, err := s.Eng.Store.GetApplication(context.Background(), a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !stored.Security.RateLimitEnabled || stored.Security.BasicWAFEnabled {
		t.Fatalf("stored security %+v", stored.Security)
	}
}

func TestUpsertCertificateIgnoresClientManagedFields(t *testing.T) {
	s := applyFailingServer(t)
	body := fmt.Sprintf(`{
		"primary_domain":"c%d.example.com",
		"mode":"http-01",
		"acme_status":"pending",
		"acme_attempts":7,
		"acme_next_attempt_at":"2030-01-01T00:00:00Z",
		"pem_crt_path":"/tmp/client.crt",
		"pem_key_path":"/tmp/client.key",
		"fullchain_path":"/tmp/client-fullchain.pem",
		"not_after":"2030-01-01T00:00:00Z",
		"last_error":"client-controlled"
	}`, time.Now().UnixNano())
	rec := httptest.NewRecorder()
	s.upsertCert(rec, httptest.NewRequest(http.MethodPost, "/api/v1/certificates", strings.NewReader(body)))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	var got config.Certificate
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Eng.Store.DeleteCertificate(context.Background(), got.ID) })
	if got.ACMEStatus != "ready" || got.ACMEAttempts != 0 || got.ACMENextAttemptAt != nil ||
		got.PEMCrtPath != "" || got.PEMKeyPath != "" || got.FullchainPath != "" ||
		got.NotAfter != nil || got.LastError != "" {
		t.Fatalf("client changed worker-managed fields: %+v", got)
	}
}

func TestUpsertCertificatePreservesStoredWorkerFields(t *testing.T) {
	s := applyFailingServer(t)
	notAfter := time.Now().UTC().Add(30 * 24 * time.Hour).Truncate(time.Second)
	original := config.Certificate{
		PrimaryDomain: "old.example.com",
		Mode:          "http-01",
		ACMEStatus:    "failed",
		PEMCrtPath:    "/var/lib/easy-waf/certs/original.crt",
		PEMKeyPath:    "/var/lib/easy-waf/certs/original.key",
		FullchainPath: "/var/lib/easy-waf/certs/original-fullchain.pem",
		NotAfter:      &notAfter,
		LastError:     "dns timeout",
	}
	if err := s.Eng.Store.UpsertCertificate(context.Background(), &original); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Eng.Store.DeleteCertificate(context.Background(), original.ID) })

	body := fmt.Sprintf(`{
		"id":%q,
		"primary_domain":"new.example.com",
		"mode":"dns-01",
		"acme_status":"pending",
		"pem_crt_path":"/tmp/client.crt",
		"pem_key_path":"/tmp/client.key",
		"fullchain_path":"/tmp/client-fullchain.pem",
		"not_after":"2040-01-01T00:00:00Z",
		"last_error":"replaced"
	}`, original.ID)
	rec := httptest.NewRecorder()
	s.upsertCert(rec, httptest.NewRequest(http.MethodPost, "/api/v1/certificates", strings.NewReader(body)))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	var got config.Certificate
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.PrimaryDomain != "new.example.com" || got.Mode != "dns-01" {
		t.Fatalf("operator fields were not updated: %+v", got)
	}
	if got.ACMEStatus != original.ACMEStatus || got.PEMCrtPath != original.PEMCrtPath ||
		got.PEMKeyPath != original.PEMKeyPath || got.FullchainPath != original.FullchainPath ||
		got.NotAfter == nil || !got.NotAfter.Equal(notAfter) || got.LastError != original.LastError {
		t.Fatalf("worker-managed fields were not preserved: %+v", got)
	}
}

func TestUpsertManualCertificateAcceptsOperatorPEMPaths(t *testing.T) {
	s := applyFailingServer(t)
	body := fmt.Sprintf(`{
		"primary_domain":"manual-%d.example.com",
		"mode":"manual",
		"pem_crt_path":"/var/lib/easy-waf/certs/manual.pem"
	}`, time.Now().UnixNano())
	rec := httptest.NewRecorder()
	s.upsertCert(rec, httptest.NewRequest(http.MethodPost, "/api/v1/certificates", strings.NewReader(body)))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	var got config.Certificate
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Eng.Store.DeleteCertificate(context.Background(), got.ID) })
	if got.PEMCrtPath != "/var/lib/easy-waf/certs/manual.pem" {
		t.Fatalf("manual PEM path = %q", got.PEMCrtPath)
	}
}

func TestUpsertBackendServersRoundTripAndKeep(t *testing.T) {
	s := applyFailingServer(t)
	t.Setenv("EASY_WAF_NO_AUTO_APPLY", "1")
	a := testApp(fmt.Sprintf("servers%d", time.Now().UnixNano()))
	a.BackendBalance = "leastconn"
	a.BackendServers = []config.BackendServer{{Host: "10.0.0.50", Port: 8080}, {Host: "standby.lan", Port: 8080, Backup: true}}
	rec := putApp(t, s, a)
	if rec.Code != http.StatusOK {
		t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &a); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Eng.Store.DeleteApplication(context.Background(), a.ID) })

	a.BackendServers = nil // a client that omits backend_servers keeps them
	a.BackendBalance = ""
	if rec := putApp(t, s, a); rec.Code != http.StatusOK {
		t.Fatalf("update: %d %s", rec.Code, rec.Body.String())
	}
	stored, err := s.Eng.Store.GetApplication(context.Background(), a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.BackendBalance != "leastconn" || len(stored.BackendServers) != 2 || !stored.BackendServers[1].Backup || stored.BackendServers[1].Host != "standby.lan" {
		t.Fatalf("stored %q %+v", stored.BackendBalance, stored.BackendServers)
	}

	// An explicit [] clears them (omitempty would drop an empty Go slice).
	var body map[string]any
	b, _ := json.Marshal(a)
	_ = json.Unmarshal(b, &body)
	body["backend_servers"] = []any{}
	b, _ = json.Marshal(body)
	rec = httptest.NewRecorder()
	s.upsertApp(rec, httptest.NewRequest(http.MethodPut, "/api/v1/applications", bytes.NewReader(b)))
	if rec.Code != http.StatusOK {
		t.Fatalf("clear: %d %s", rec.Code, rec.Body.String())
	}
	stored, err = s.Eng.Store.GetApplication(context.Background(), a.ID)
	if err != nil || len(stored.BackendServers) != 0 {
		t.Fatalf("cleared: %+v %v", stored.BackendServers, err)
	}

	a.BackendServers = []config.BackendServer{{Host: a.BackendHost, Port: a.BackendPort}}
	if rec := putApp(t, s, a); rec.Code != http.StatusBadRequest {
		t.Fatalf("duplicate of the primary server: %d", rec.Code)
	}
}

func TestUpsertPublicationRulesRoundTrip(t *testing.T) {
	s := applyFailingServer(t)
	t.Setenv("EASY_WAF_NO_AUTO_APPLY", "1")
	app := testApp(fmt.Sprintf("rules%d", time.Now().UnixNano()))
	app.PolicyRules = []config.PublicationRule{
		{ID: "watch", Action: config.RuleCount, Match: config.PublicationMatch{PathPrefix: "/api"}},
		{ID: "deny", Action: config.RuleBlock, Match: config.PublicationMatch{Methods: []string{"POST"}}},
	}
	rec := putApp(t, s, app)
	if rec.Code != http.StatusOK {
		t.Fatalf("create: %d %s", rec.Code, rec.Body)
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &app); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Eng.Store.DeleteApplication(context.Background(), app.ID) })

	app.PolicyRules = nil
	if rec := putApp(t, s, app); rec.Code != http.StatusOK {
		t.Fatalf("legacy update: %d %s", rec.Code, rec.Body)
	}
	stored, err := s.Eng.Store.GetApplication(t.Context(), app.ID)
	if err != nil || len(stored.PolicyRules) != 2 || stored.PolicyRules[0].ID != "watch" || stored.PolicyRules[1].ID != "deny" {
		t.Fatalf("legacy update lost policy order: %+v, %v", stored.PolicyRules, err)
	}
	raw, err := json.Marshal(app)
	if err != nil {
		t.Fatal(err)
	}
	raw = append(raw[:len(raw)-1], `,"policy_rules":[]}`...)
	rec = httptest.NewRecorder()
	s.upsertApp(rec, httptest.NewRequest(http.MethodPost, "/api/v1/applications", bytes.NewReader(raw)))
	if rec.Code != http.StatusOK {
		t.Fatalf("clear: %d %s", rec.Code, rec.Body)
	}
	stored, err = s.Eng.Store.GetApplication(t.Context(), app.ID)
	if err != nil || len(stored.PolicyRules) != 0 {
		t.Fatalf("rules were not cleared: %+v, %v", stored.PolicyRules, err)
	}
}

func TestAppMaintenanceToggle(t *testing.T) {
	s := applyFailingServer(t)
	t.Setenv("EASY_WAF_NO_AUTO_APPLY", "1")
	a := testApp(fmt.Sprintf("maint%d", time.Now().UnixNano()))
	rec := putApp(t, s, a)
	if rec.Code != http.StatusOK {
		t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &a); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Eng.Store.DeleteApplication(context.Background(), a.ID) })
	post := func(body string) int {
		rec := httptest.NewRecorder()
		req := withURLParam(httptest.NewRequest(http.MethodPost, "/api/v1/applications/x/maintenance", strings.NewReader(body)), "id", a.ID)
		s.postAppMaintenance(rec, req)
		return rec.Code
	}
	if code := post(`{"enabled":true,"bypass_cidrs":["192.168.1.0/24"]}`); code != http.StatusOK {
		t.Fatalf("enable: %d", code)
	}
	stored, err := s.Eng.Store.GetApplication(context.Background(), a.ID)
	if err != nil || !stored.Maintenance || len(stored.MaintenanceBypassCIDRs) != 1 {
		t.Fatalf("stored %+v %v", stored, err)
	}
	if code := post(`{"enabled":false}`); code != http.StatusOK {
		t.Fatalf("disable: %d", code)
	}
	stored, _ = s.Eng.Store.GetApplication(context.Background(), a.ID)
	if stored.Maintenance || len(stored.MaintenanceBypassCIDRs) != 1 {
		t.Fatalf("disable keeps the bypass list: %+v", stored)
	}
	if code := post(`{"enabled":true,"bypass_cidrs":["not-an-ip"]}`); code != http.StatusBadRequest {
		t.Fatalf("bad bypass: %d", code)
	}
}

func TestUpsertKeepsMaintenanceFromNewerMutation(t *testing.T) {
	s := applyFailingServer(t)
	t.Setenv("EASY_WAF_NO_AUTO_APPLY", "1")
	a := testApp(fmt.Sprintf("maintedit%d", time.Now().UnixNano()))
	rec := putApp(t, s, a)
	if rec.Code != http.StatusOK {
		t.Fatalf("create: %d %s", rec.Code, rec.Body)
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &a); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Eng.Store.DeleteApplication(context.Background(), a.ID) })
	var draft map[string]json.RawMessage
	if err := json.Unmarshal(rec.Body.Bytes(), &draft); err != nil {
		t.Fatal(err)
	}
	delete(draft, "maintenance")
	delete(draft, "maintenance_bypass_cidrs")
	draft["name"] = json.RawMessage(`"Updated publication"`)

	rec = httptest.NewRecorder()
	req := withURLParam(httptest.NewRequest(http.MethodPost, "/api/v1/applications/x/maintenance",
		strings.NewReader(`{"enabled":true,"bypass_cidrs":["192.0.2.0/24"]}`)), "id", a.ID)
	s.postAppMaintenance(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("enable maintenance: %d %s", rec.Code, rec.Body)
	}

	save := func(wantMode bool, wantBypass string) {
		t.Helper()
		raw, err := json.Marshal(draft)
		if err != nil {
			t.Fatal(err)
		}
		rec := httptest.NewRecorder()
		s.upsertApp(rec, httptest.NewRequest(http.MethodPost, "/api/v1/applications", bytes.NewReader(raw)))
		if rec.Code != http.StatusOK {
			t.Fatalf("update publication: %d %s", rec.Code, rec.Body)
		}
		stored, err := s.Eng.Store.GetApplication(t.Context(), a.ID)
		if err != nil || stored.Name != "Updated publication" || stored.Maintenance != wantMode ||
			strings.Join(stored.MaintenanceBypassCIDRs, ",") != wantBypass {
			t.Fatalf("stored name %q, maintenance %t, bypass %v: %v", stored.Name, stored.Maintenance, stored.MaintenanceBypassCIDRs, err)
		}
	}

	save(true, "192.0.2.0/24")
	draft["maintenance"] = json.RawMessage("null")
	draft["maintenance_bypass_cidrs"] = json.RawMessage("null")
	save(true, "192.0.2.0/24")
	draft["maintenance"] = json.RawMessage("false")
	save(false, "192.0.2.0/24")
	delete(draft, "maintenance")
	draft["maintenance_bypass_cidrs"] = json.RawMessage("[]")
	save(false, "")
}

func TestPanelUsersLifecycle(t *testing.T) {
	s := applyFailingServer(t)
	ctx := context.Background()
	admin := fmt.Sprintf("adm%d", time.Now().UnixNano())
	if err := s.Eng.Store.CreateUser(ctx, &config.AdminUser{Username: admin, PasswordHash: "x"}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Eng.Store.DeleteUserByUsername(ctx, admin) })
	do := func(method, path, user, body string, h http.HandlerFunc) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		if user != "" {
			req = withURLParam(req, "username", user)
		}
		rec := httptest.NewRecorder()
		h(rec, req)
		return rec
	}
	viewer := fmt.Sprintf("view%d", time.Now().UnixNano())
	rec := do(http.MethodPost, "/api/v1/panel-users", "", `{"username":"`+viewer+`","role":"viewer"}`, s.createPanelUser)
	if rec.Code != http.StatusCreated || !strings.Contains(rec.Body.String(), "temporary_password") {
		t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
	}
	t.Cleanup(func() { _ = s.Eng.Store.DeleteUserByUsername(ctx, viewer) })
	u, _ := s.Eng.Store.GetUserByUsername(ctx, viewer)
	if u == nil || u.Role != config.RoleViewer || !u.MustChangePassword {
		t.Fatalf("stored viewer %+v", u)
	}
	if rec := do(http.MethodPost, "/", "", `{"username":"`+viewer+`","role":"viewer"}`, s.createPanelUser); rec.Code != http.StatusConflict {
		t.Fatalf("duplicate: %d", rec.Code)
	}
	if rec := do(http.MethodPost, "/", "", `{"username":"x","role":"root"}`, s.createPanelUser); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad role: %d", rec.Code)
	}
	if rec := do(http.MethodPost, "/", viewer, ``, s.resetPanelUserPassword); rec.Code != http.StatusOK {
		t.Fatalf("reset: %d", rec.Code)
	}
	if rec := do(http.MethodPatch, "/", viewer, `{"role":"admin"}`, s.patchPanelUser); rec.Code != http.StatusOK {
		t.Fatalf("promote: %d", rec.Code)
	}
	if rec := do(http.MethodDelete, "/", viewer, ``, s.deletePanelUser); rec.Code != http.StatusNoContent {
		t.Fatalf("delete: %d", rec.Code)
	}
	if rec := do(http.MethodDelete, "/", viewer, ``, s.deletePanelUser); rec.Code != http.StatusNotFound {
		t.Fatalf("delete again: %d", rec.Code)
	}
}

func TestLastAdminIsProtected(t *testing.T) {
	s := applyFailingServer(t)
	ctx := context.Background()
	users, err := s.Eng.Store.ListUsers(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range users {
		if u.Role == config.RoleAdmin {
			t.Skip("database already has admins; the guard is covered when it has none")
		}
	}
	only := fmt.Sprintf("only%d", time.Now().UnixNano())
	if err := s.Eng.Store.CreateUser(ctx, &config.AdminUser{Username: only, PasswordHash: "x"}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Eng.Store.DeleteUserByUsername(ctx, only) })
	if err := s.Eng.Store.SetUserRole(ctx, only, config.RoleViewer); !errors.Is(err, store.ErrLastAdmin) {
		t.Fatalf("demote last admin: %v", err)
	}
	if err := s.Eng.Store.DeleteUser(ctx, only); !errors.Is(err, store.ErrLastAdmin) {
		t.Fatalf("delete last admin: %v", err)
	}
}
