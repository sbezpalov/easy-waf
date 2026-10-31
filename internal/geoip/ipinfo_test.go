// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package geoip

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestIPInfoProviderLookup(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/8.8.8.8/json" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"country": "US"})
	}))
	defer srv.Close()

	p := &IPInfoProvider{
		BaseURL:     srv.URL,
		HTTP:        srv.Client(),
		MinInterval: 0,
	}
	cc, err := p.Lookup(context.Background(), "8.8.8.8")
	if err != nil {
		t.Fatal(err)
	}
	if cc != "US" {
		t.Fatalf("country %q", cc)
	}
}

func TestIPInfoTokenNeverInURL(t *testing.T) {
	var gotAuth, gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth, gotQuery = r.Header.Get("Authorization"), r.URL.RawQuery
		_, _ = w.Write([]byte(`{"country":"DE"}`))
	}))
	defer srv.Close()
	p := NewIPInfoProvider("tok-secret")
	p.BaseURL = srv.URL
	p.MinInterval = 0
	if _, err := p.Lookup(context.Background(), "8.8.8.8"); err != nil {
		t.Fatal(err)
	}
	if gotAuth != "Bearer tok-secret" || strings.Contains(gotQuery, "tok-secret") {
		t.Fatalf("auth %q query %q", gotAuth, gotQuery)
	}
}
