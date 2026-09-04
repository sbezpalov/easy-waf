// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The upload route must be exempt from the global 4 MiB cap, and nothing else
// may be: an exemption applied too broadly would uncap the whole API.
func TestLimitRequestBody_exemptsOnlyListedPaths(t *testing.T) {
	var got int64
	sink := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n, err := readAllCount(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusRequestEntityTooLarge)
			return
		}
		got = n
	})
	h := limitRequestBody(16, geoipDatabaseUploadPath)(sink)

	// A normal route is capped.
	req := httptest.NewRequest(http.MethodPost, "/api/v1/applications", strings.NewReader(strings.Repeat("x", 64)))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized body on a normal route: status %d", rec.Code)
	}

	// The upload route is not.
	got = 0
	req = httptest.NewRequest(http.MethodPost, geoipDatabaseUploadPath, strings.NewReader(strings.Repeat("x", 64)))
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || got != 64 {
		t.Fatalf("upload route was capped: status %d, read %d bytes", rec.Code, got)
	}

	// A path that merely starts with the exempt one must stay capped.
	req = httptest.NewRequest(http.MethodPost, geoipDatabaseUploadPath+"/../applications", strings.NewReader(strings.Repeat("x", 64)))
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("prefix of the exempt path was uncapped: status %d", rec.Code)
	}
}

func readAllCount(r *http.Request) (int64, error) {
	buf := make([]byte, 512)
	var total int64
	for {
		n, err := r.Body.Read(buf)
		total += int64(n)
		if err != nil {
			if err.Error() == "EOF" {
				return total, nil
			}
			return total, err
		}
	}
}
