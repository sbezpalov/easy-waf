// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/easy-waf/easy-waf/internal/config"
	"github.com/easy-waf/easy-waf/internal/store"
	"net/http"
	"net/http/httptest"
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

func TestDeleteUnknownApplicationIs404WithoutApply(t *testing.T) {
	s := applyFailingServer(t) // any apply would fail, so a 404 proves none ran
	req := withURLParam(httptest.NewRequest(http.MethodDelete, "/api/v1/applications/x", nil), "id", "00000000-0000-0000-0000-000000000000")
	rec := httptest.NewRecorder()
	s.deleteApp(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
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

func TestUpsertCertificateRespondsWithStoredRow(t *testing.T) {
	s := applyFailingServer(t)
	body := fmt.Sprintf(`{"primary_domain":"c%d.example.com","mode":"http-01","acme_attempts":7}`, time.Now().UnixNano())
	rec := httptest.NewRecorder()
	s.upsertCert(rec, httptest.NewRequest(http.MethodPost, "/api/v1/certificates", strings.NewReader(body)))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	var got struct {
		ID           string `json:"id"`
		ACMEAttempts int    `json:"acme_attempts"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Eng.Store.DeleteCertificate(context.Background(), got.ID) })
	if got.ACMEAttempts != 0 {
		t.Fatalf("response echoed client acme_attempts=%d; the store never writes it", got.ACMEAttempts)
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
