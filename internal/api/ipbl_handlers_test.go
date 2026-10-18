// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/easy-waf/easy-waf/internal/config"
	"github.com/easy-waf/easy-waf/internal/ipbl"
)

func TestSyncResultJSONOmitsMergedList(t *testing.T) {
	b, err := json.Marshal(ipbl.SyncResult{LocalLines: 1, ExternalLines: 2, TotalLines: 3, MapPath: "/m", AllCIDRs: []string{"192.0.2.0/24"}})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(b), `{"local_lines":1,"external_lines":2,"total_lines":3,"map_path":"/m"}`; got != want {
		t.Fatalf("got %s, want %s", got, want)
	}
}

func TestBlockedUARejectsControlCharacters(t *testing.T) {
	s := &Server{}
	rec := httptest.NewRecorder()
	s.addBlockedUA(rec, httptest.NewRequest(http.MethodPost, "/api/v1/security/blocked-ua", strings.NewReader(`{"pattern":"curl\nwget"}`)))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
}

func TestIPBLLocalRejectsInvalidCIDR(t *testing.T) {
	s := &Server{}
	for _, body := range []string{`{"cidr":""}`, `{"cidr":"not-an-ip"}`, `{"cidr":"10.0.0.0/33"}`} {
		rec := httptest.NewRecorder()
		s.upsertIPBLLocal(rec, httptest.NewRequest(http.MethodPost, "/api/v1/ipbl/local", strings.NewReader(body)))
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status %d", body, rec.Code)
		}
	}
}

func TestIPBLLocalEnabledDefaultsOn(t *testing.T) {
	s := applyFailingServer(t)
	rec := httptest.NewRecorder()
	s.upsertIPBLLocal(rec, httptest.NewRequest(http.MethodPost, "/api/v1/ipbl/local", strings.NewReader(`{"cidr":"198.51.100.7"}`)))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	var e config.IPBLLocalEntry
	if err := json.Unmarshal(rec.Body.Bytes(), &e); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Eng.Store.DeleteIPBLLocal(context.Background(), e.ID) })
	if !e.Enabled {
		t.Fatal("an entry posted without \"enabled\" was stored disabled")
	}
}

func TestIPBLSourceFetchStatusIsServerOwned(t *testing.T) {
	s := applyFailingServer(t)
	ctx := context.Background()
	fetched := time.Now().UTC().Truncate(time.Second)
	src := config.IPBLExternalSource{Name: fmt.Sprintf("src%d", time.Now().UnixNano()), URL: "https://example.com/list.txt", Enabled: true}
	if err := s.Eng.Store.UpsertIPBLExternalSource(ctx, &src); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Eng.Store.DeleteIPBLExternalSource(context.Background(), src.ID) })
	if err := s.Eng.Store.TouchIPBLSourceFetch(ctx, src.ID, fetched, "HTTP 503"); err != nil {
		t.Fatal(err)
	}

	// An edit that omits the fetch status, or sends a forged one, keeps the stored status.
	for _, extra := range []string{``, `,"last_error":"","last_fetch_at":"2000-01-01T00:00:00Z"`} {
		body := fmt.Sprintf(`{"id":%q,"name":%q,"url":%q%s}`, src.ID, src.Name, src.URL, extra)
		if err := s.Eng.Store.UpsertIPBLExternalSource(ctx, mustSource(t, body)); err != nil {
			t.Fatal(err)
		}
		got := findSource(t, s, src.ID)
		if got.LastError != "HTTP 503" || got.LastFetchAt == nil || !got.LastFetchAt.Equal(fetched) {
			t.Fatalf("body %s: fetch status became %q %v", body, got.LastError, got.LastFetchAt)
		}
	}
}

func TestDeleteIPBLSource(t *testing.T) {
	s := applyFailingServer(t)
	src := config.IPBLExternalSource{Name: fmt.Sprintf("del%d", time.Now().UnixNano()), URL: "https://example.com/l.txt"}
	if err := s.Eng.Store.UpsertIPBLExternalSource(context.Background(), &src); err != nil {
		t.Fatal(err)
	}
	for _, want := range []int{http.StatusNoContent, http.StatusNotFound} {
		rec := httptest.NewRecorder()
		s.deleteIPBLSource(rec, withURLParam(httptest.NewRequest(http.MethodDelete, "/api/v1/ipbl/sources/x", nil), "id", src.ID))
		if rec.Code != want {
			t.Fatalf("status %d, want %d", rec.Code, want)
		}
	}
}

func mustSource(t *testing.T, body string) *config.IPBLExternalSource {
	t.Helper()
	var e config.IPBLExternalSource
	if err := json.Unmarshal([]byte(body), &e); err != nil {
		t.Fatal(err)
	}
	return &e
}

func findSource(t *testing.T, s *Server, id string) config.IPBLExternalSource {
	t.Helper()
	srcs, err := s.Eng.Store.ListIPBLExternalSources(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, src := range srcs {
		if src.ID == id {
			return src
		}
	}
	t.Fatalf("source %s not found", id)
	return config.IPBLExternalSource{}
}
