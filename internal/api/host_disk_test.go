// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/easy-waf/easy-waf/internal/config"
	"github.com/easy-waf/easy-waf/internal/engine"
	"github.com/easy-waf/easy-waf/internal/host/apt"
)

func TestHostAptClean_requiresXHR(t *testing.T) {
	eng := engine.New("", nil, config.GlobalSettings{ManagementAllowedCIDRs: []string{"127.0.0.0/8"}})
	s := &Server{Eng: eng, JWTSecret: []byte("test")}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/host/updates/clean", strings.NewReader("{}"))
	req.RemoteAddr = "127.0.0.1:12345"
	w := httptest.NewRecorder()
	RequireXHR(http.HandlerFunc(s.hostAptClean)).ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status %d", w.Code)
	}
}

func TestHostAptClean_freedBytes(t *testing.T) {
	var cacheCalls int
	restore := apt.SetPrivilegedFnForTest(func(_ context.Context, args ...string) ([]byte, error) {
		switch args[0] {
		case "apt-cache-size":
			cacheCalls++
			if cacheCalls == 1 {
				return []byte("5000\t/var/cache/apt/archives\n"), nil
			}
			return []byte("800\t/var/cache/apt/archives\n"), nil
		case "apt-clean":
			return nil, nil
		default:
			t.Fatalf("unexpected: %v", args)
			return nil, nil
		}
	})
	defer apt.SetPrivilegedFnForTest(restore)

	eng := engine.New("", nil, config.GlobalSettings{ManagementAllowedCIDRs: []string{"127.0.0.0/8"}})
	s := &Server{Eng: eng, JWTSecret: []byte("test")}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/host/updates/clean", strings.NewReader("{}"))
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	req.RemoteAddr = "127.0.0.1:12345"
	w := httptest.NewRecorder()
	s.hostAptClean(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d body %s", w.Code, w.Body.String())
	}
	var body map[string]int64
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["freed_bytes"] != 4200 {
		t.Fatalf("freed_bytes: %v", body)
	}
}

func TestHostDisk_jsonShape(t *testing.T) {
	restore := apt.SetPrivilegedFnForTest(func(_ context.Context, args ...string) ([]byte, error) {
		switch args[0] {
		case "apt-cache-size":
			return []byte("2048\t/var/cache/apt/archives\n"), nil
		case "apt-autoremove-simulate":
			return []byte("Remv pkg-a\nRemv pkg-b\n"), nil
		default:
			return nil, nil
		}
	})
	defer apt.SetPrivilegedFnForTest(restore)

	eng := engine.New("", nil, config.GlobalSettings{ManagementAllowedCIDRs: []string{"127.0.0.0/8"}})
	s := &Server{Eng: eng, JWTSecret: []byte("test")}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/host/disk", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	w := httptest.NewRecorder()
	s.hostDisk(w, req)
	if w.Code != http.StatusOK && w.Code != http.StatusInternalServerError {
		t.Fatalf("status %d", w.Code)
	}
	if w.Code == http.StatusInternalServerError {
		t.Skip("disk.Usage unavailable in this environment")
	}
	var body map[string]json.RawMessage
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if _, ok := body["mounts"]; !ok {
		t.Fatalf("missing mounts: %s", w.Body.String())
	}
	var cache int64
	if err := json.Unmarshal(body["cache_bytes"], &cache); err != nil || cache != 2048 {
		t.Fatalf("cache_bytes: %s", body["cache_bytes"])
	}
	var rem int
	if err := json.Unmarshal(body["removable_count"], &rem); err != nil || rem != 2 {
		t.Fatalf("removable_count: %s", body["removable_count"])
	}
}
