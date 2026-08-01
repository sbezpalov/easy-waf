package geoip

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/easy-waf/easy-waf/internal/config"
)

type stubGeo map[string]string

func (m stubGeo) Lookup(_ context.Context, ip string) (string, error) {
	cc, ok := m[ip]
	if !ok {
		return "", fmt.Errorf("stub: unknown %s", ip)
	}
	return cc, nil
}

func TestWriteEnforceMapDenyList(t *testing.T) {
	td := t.TempDir()
	g := config.GlobalSettings{
		GeoIPDefaultPolicy:  "deny",
		GeoIPCountryList:    []string{"RU", "CN"},
		GeoIPEnforceMapPath: filepath.Join(td, "geoip_enforce.map"),
	}
	cache := NewMemoryCache(100, 0)
	prov := stubGeo{"1.1.1.1": "RU", "8.8.8.8": "US"}
	if err := WriteEnforceMap(context.Background(), prov, cache, g, td, []string{"1.1.1.1", "8.8.8.8"}); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(g.GeoIPEnforceMapPath)
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	if !strings.Contains(s, "1.1.1.1") {
		t.Fatalf("expected 1.1.1.1 in map:\n%s", s)
	}
	if strings.Contains(s, "8.8.8.8") {
		t.Fatalf("did not expect 8.8.8.8 in deny-list map:\n%s", s)
	}
}

func TestWriteEnforceMapAllowList(t *testing.T) {
	td := t.TempDir()
	g := config.GlobalSettings{
		GeoIPDefaultPolicy:  "allow",
		GeoIPCountryList:    []string{"US"},
		GeoIPEnforceMapPath: filepath.Join(td, "geoip_enforce.map"),
	}
	cache := NewMemoryCache(100, 0)
	prov := stubGeo{"1.1.1.1": "RU", "8.8.8.8": "US"}
	if err := WriteEnforceMap(context.Background(), prov, cache, g, td, []string{"1.1.1.1", "8.8.8.8"}); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(g.GeoIPEnforceMapPath)
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	if !strings.Contains(s, "1.1.1.1") {
		t.Fatalf("expected 1.1.1.1 (not allow-listed):\n%s", s)
	}
	if strings.Contains(s, "8.8.8.8") {
		t.Fatalf("did not expect 8.8.8.8 in allow-list enforce map:\n%s", s)
	}
}
