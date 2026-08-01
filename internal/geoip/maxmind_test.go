package geoip

import (
	"bytes"
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/easy-waf/easy-waf/internal/config"
	"github.com/maxmind/mmdbwriter"
	"github.com/maxmind/mmdbwriter/inserter"
	"github.com/maxmind/mmdbwriter/mmdbtype"
)

func writeTestCountryMMDB(t *testing.T, ip, iso string) string {
	t.Helper()
	tree, err := mmdbwriter.New(mmdbwriter.Options{
		DatabaseType: "GeoLite2-Country",
		IPVersion:    4,
		RecordSize:   24,
		Inserter:     inserter.ReplaceWith,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, n, err := net.ParseCIDR(ip + "/32")
	if err != nil {
		t.Fatal(err)
	}
	rec := mmdbtype.Map{
		"country": mmdbtype.Map{
			"iso_code": mmdbtype.String(iso),
		},
	}
	if err := tree.Insert(n, rec); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if _, err := tree.WriteTo(&buf); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	p := filepath.Join(dir, "test.mmdb")
	if err := os.WriteFile(p, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestNewMaxMindProvider_FileNotFound(t *testing.T) {
	_, err := NewMaxMindProvider("/nonexistent/no-such-file.mmdb")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestMaxMindProvider_Lookup(t *testing.T) {
	p := writeTestCountryMMDB(t, "8.8.8.8", "US")
	prov, err := NewMaxMindProvider(p)
	if err != nil {
		t.Fatal(err)
	}
	defer prov.Close()
	cc, err := prov.Lookup(context.Background(), "8.8.8.8")
	if err != nil {
		t.Fatal(err)
	}
	if cc != "US" {
		t.Fatalf("country: got %q want US", cc)
	}
}

func TestMaxMindProvider_Reload(t *testing.T) {
	dir := t.TempDir()
	p1 := filepath.Join(dir, "db.mmdb")
	p2 := filepath.Join(dir, "db2.mmdb")
	// First DB: US
	_ = os.WriteFile(p1, mustBuildMMDB(t, "8.8.8.8", "US"), 0o600)
	_ = os.WriteFile(p2, mustBuildMMDB(t, "8.8.8.8", "DE"), 0o600)

	prov, err := NewMaxMindProvider(p1)
	if err != nil {
		t.Fatal(err)
	}
	defer prov.Close()
	cc, err := prov.Lookup(context.Background(), "8.8.8.8")
	if err != nil || cc != "US" {
		t.Fatalf("lookup1: %v %q", err, cc)
	}
	if err := prov.Reload(p2); err != nil {
		t.Fatal(err)
	}
	cc, err = prov.Lookup(context.Background(), "8.8.8.8")
	if err != nil || cc != "DE" {
		t.Fatalf("lookup2: %v %q", err, cc)
	}
}

func mustBuildMMDB(t *testing.T, ip, iso string) []byte {
	t.Helper()
	tree, err := mmdbwriter.New(mmdbwriter.Options{
		DatabaseType: "GeoLite2-Country",
		IPVersion:    4,
		RecordSize:   24,
		Inserter:     inserter.ReplaceWith,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, n, err := net.ParseCIDR(ip + "/32")
	if err != nil {
		t.Fatal(err)
	}
	rec := mmdbtype.Map{
		"country": mmdbtype.Map{
			"iso_code": mmdbtype.String(iso),
		},
	}
	if err := tree.Insert(n, rec); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if _, err := tree.WriteTo(&buf); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestFactory_MaxMind_MissingPath(t *testing.T) {
	_, err := NewProviderForSettings(config.GlobalSettings{
		GeoIPProvider: "maxmind",
		GeoIPMMDBPath: "",
	})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestFactory_MaxMind_OK(t *testing.T) {
	p := writeTestCountryMMDB(t, "1.1.1.1", "AU")
	prov, err := NewProviderForSettings(config.GlobalSettings{
		GeoIPProvider: "maxmind",
		GeoIPMMDBPath: p,
	})
	if err != nil {
		t.Fatal(err)
	}
	mm, ok := prov.(*MaxMindProvider)
	if !ok || mm == nil {
		t.Fatalf("want *MaxMindProvider, got %T", prov)
	}
	defer mm.Close()
	cc, err := prov.Lookup(context.Background(), "1.1.1.1")
	if err != nil || cc != "AU" {
		t.Fatalf("lookup: %v %q", err, cc)
	}
}

func TestProviderForRuntime_ReusesMaxMind(t *testing.T) {
	p := writeTestCountryMMDB(t, "9.9.9.9", "FR")
	rt := NewRuntime(0)
	g := config.GlobalSettings{
		GeoIPProvider: "maxmind",
		GeoIPMMDBPath: p,
	}
	p1, err := ProviderForRuntime(rt, g)
	if err != nil {
		t.Fatal(err)
	}
	p2, err := ProviderForRuntime(rt, g)
	if err != nil {
		t.Fatal(err)
	}
	if p1 != p2 {
		t.Fatal("expected same cached MaxMind provider instance")
	}
	cc, err := p1.Lookup(context.Background(), "9.9.9.9")
	if err != nil || cc != "FR" {
		t.Fatalf("lookup: %v %q", err, cc)
	}
	rt.InvalidateGeoProvider()
}
