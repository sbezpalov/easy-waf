// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package geoip

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/easy-waf/easy-waf/internal/config"
	"github.com/maxmind/mmdbwriter"
	"github.com/maxmind/mmdbwriter/inserter"
	"github.com/maxmind/mmdbwriter/mmdbtype"
)

func TestCountryNetworksBuildsPositiveMembershipMaps(t *testing.T) {
	tree, err := mmdbwriter.New(mmdbwriter.Options{DatabaseType: "GeoLite2-Country", IPVersion: 6, RecordSize: 24})
	if err != nil {
		t.Fatal(err)
	}
	for cidr, country := range map[string]string{"80.57.0.0/16": "NL", "2a02:a000::/32": "NL", "81.48.0.0/16": "FR"} {
		_, ipnet, err := net.ParseCIDR(cidr)
		if err != nil {
			t.Fatal(err)
		}
		if err := tree.Insert(ipnet, mmdbtype.Map{"country": mmdbtype.Map{"iso_code": mmdbtype.String(country)}}); err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join(t.TempDir(), "test.mmdb")
	var db bytes.Buffer
	if _, err := tree.WriteTo(&db); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, db.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	provider, err := NewMaxMindProvider(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = provider.Close() })
	ctx := context.Background()
	networks, err := provider.CountryNetworks(ctx, []string{" nl ", "FR", "NL"})
	if err != nil {
		t.Fatal(err)
	}
	for country, body := range map[string]string{
		"NL": "2a02:a000::/32\n80.57.0.0/16\n",
		"FR": "81.48.0.0/16\n",
	} {
		out := filepath.Join(t.TempDir(), country+".map")
		if err := WriteAppEnforceMap(networks, []string{country, country}, out); err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile(out)
		if err != nil {
			t.Fatal(err)
		}
		_, ranges, _ := strings.Cut(string(got), "\n")
		if ranges != body {
			t.Errorf("%s ranges = %q, want %q", country, ranges, body)
		}
	}
	if _, err := provider.CountryNetworks(ctx, []string{"NL", "US"}); err == nil || !strings.Contains(err.Error(), "US") {
		t.Fatalf("missing selected country: %v", err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := provider.CountryNetworks(canceled, []string{"NL"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled traversal: %v", err)
	}
}

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

func TestRuntime_ReusesMaxMind(t *testing.T) {
	p := writeTestCountryMMDB(t, "9.9.9.9", "FR")
	rt := NewRuntime(0)
	g := config.GlobalSettings{
		GeoIPProvider: "maxmind",
		GeoIPMMDBPath: p,
	}
	rt.Configure(g)
	_, release, err := rt.Resolver(g)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	p1 := rt.prov
	cc, _, err := rt.Lookup(context.Background(), g, "9.9.9.9")
	if err != nil || cc != "FR" {
		t.Fatalf("lookup: %v %q", err, cc)
	}
	if rt.prov != p1 || p1 == nil {
		t.Fatal("expected same cached MaxMind provider instance")
	}
	rt.InvalidateGeoProvider()
}

// Lookups racing Reload and Close must never read an unmapped reader; run
// with -race. Before the fix this ended in "fatal error: fault".
func TestMaxMindProvider_ConcurrentLookupReloadClose(t *testing.T) {
	us := writeTestCountryMMDB(t, "8.8.8.8", "US")
	de := writeTestCountryMMDB(t, "8.8.8.8", "DE")
	prov, err := NewMaxMindProvider(us)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	stop := make(chan struct{})
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				cc, err := prov.Lookup(ctx, "8.8.8.8")
				if err != nil {
					if !strings.Contains(err.Error(), "reader closed") {
						errs <- err
						return
					}
					continue
				}
				if cc != "US" && cc != "DE" {
					errs <- fmt.Errorf("unexpected country %q", cc)
					return
				}
			}
		}()
	}
	for i := 0; i < 200; i++ {
		path := us
		if i%2 == 1 {
			path = de
		}
		if err := prov.Reload(path); err != nil {
			t.Fatal(err)
		}
	}
	_ = prov.Close()
	close(stop)
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("lookup: %v", err)
	}
}
