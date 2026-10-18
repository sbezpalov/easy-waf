// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
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
