package geoip

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
