// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"bytes"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5/middleware"
)

func TestManagementLogOmitsQueryAndPreservesHandlerRequest(t *testing.T) {
	var output bytes.Buffer
	format := &managementLogFormatter{middleware.DefaultLogFormatter{Logger: log.New(&output, "", 0), NoColor: true}}
	handler := middleware.RequestID(middleware.RequestLogger(format)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("state") != "fixture-state" || !strings.Contains(r.RequestURI, "fixture-state") {
			t.Error("handler lost the original OAuth request")
		}
		w.WriteHeader(http.StatusSeeOther)
	})))
	req := httptest.NewRequest(http.MethodGet, "https://waf.example/oauth/authorize?state=fixture-state&redirect_uri=https%3A%2F%2Fprivate.example", nil)
	req.Header.Set("X-Request-Id", "fixture-id")
	handler.ServeHTTP(httptest.NewRecorder(), req)
	entry := output.String()
	for _, expected := range []string{"fixture-id", "GET https://waf.example/oauth/authorize HTTP/", "303", req.RemoteAddr} {
		if !strings.Contains(entry, expected) {
			t.Fatalf("missing %q in %q", expected, entry)
		}
	}
	for _, excluded := range []string{"?", "fixture-state", "redirect_uri", "private.example"} {
		if strings.Contains(entry, excluded) {
			t.Fatalf("logged query data: %q", entry)
		}
	}
}
