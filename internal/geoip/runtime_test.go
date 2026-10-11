// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package geoip

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/easy-waf/easy-waf/internal/config"
)

func maxmindSettings(path string) config.GlobalSettings {
	return config.GlobalSettings{GeoIPProvider: "maxmind", GeoIPMMDBPath: path}
}

// Lookups racing settings changes must never use a provider after it was
// closed, and every answer must come from the database of the settings the
// lookup was made with.
func TestRuntime_ConcurrentLookupConfigure(t *testing.T) {
	us := maxmindSettings(writeTestCountryMMDB(t, "8.8.8.8", "US"))
	de := maxmindSettings(writeTestCountryMMDB(t, "8.8.8.8", "DE"))
	rt := NewRuntime(time.Hour)
	rt.Configure(us)
	ctx := context.Background()
	stop := make(chan struct{})
	var wg sync.WaitGroup
	errs := make(chan string, 16)
	for i := 0; i < 8; i++ {
		g, want := us, "US"
		if i%2 == 1 {
			g, want = de, "DE"
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				cc, _, err := rt.Lookup(ctx, g, "8.8.8.8")
				if err != nil {
					errs <- err.Error()
					return
				}
				if cc != want {
					errs <- "got " + cc + " want " + want
					return
				}
			}
		}()
	}
	for i := 0; i < 200; i++ {
		if i%2 == 0 {
			rt.Configure(de)
		} else {
			rt.Configure(us)
		}
		if i%10 == 0 {
			rt.InvalidateGeoProvider()
		}
	}
	close(stop)
	wg.Wait()
	close(errs)
	for msg := range errs {
		t.Fatal(msg)
	}
	rt.InvalidateGeoProvider()
}

// R3: switching the database via settings must not keep serving countries
// cached from the old one.
func TestRuntime_ConfigureDropsCountriesFromOldDatabase(t *testing.T) {
	us := maxmindSettings(writeTestCountryMMDB(t, "8.8.8.8", "US"))
	de := maxmindSettings(writeTestCountryMMDB(t, "8.8.8.8", "DE"))
	rt := NewRuntime(time.Hour)
	rt.Configure(us)
	defer rt.InvalidateGeoProvider()
	ctx := context.Background()
	if cc, _, err := rt.Lookup(ctx, us, "8.8.8.8"); err != nil || cc != "US" {
		t.Fatalf("first lookup: %q %v", cc, err)
	}
	if _, cached, _ := rt.Lookup(ctx, us, "8.8.8.8"); !cached {
		t.Fatal("second lookup should hit the cache")
	}
	rt.Configure(de)
	cc, cached, err := rt.Lookup(ctx, de, "8.8.8.8")
	if err != nil || cc != "DE" || cached {
		t.Fatalf("after switch: %q cached=%v %v", cc, cached, err)
	}
}

// Saving settings unrelated to GeoIP resolution must keep the open reader and
// the cache; a TTL change applies to entries already cached.
func TestRuntime_ConfigureKeepsReaderForUnrelatedChanges(t *testing.T) {
	g := maxmindSettings(writeTestCountryMMDB(t, "8.8.8.8", "US"))
	g.GeoIPCacheTTL = config.Duration(time.Hour)
	rt := NewRuntime(time.Hour)
	rt.Configure(g)
	defer rt.InvalidateGeoProvider()
	ctx := context.Background()
	if _, _, err := rt.Lookup(ctx, g, "8.8.8.8"); err != nil {
		t.Fatal(err)
	}
	reader := rt.prov

	g2 := g
	g2.GeoIPCountryList = []string{"RU"}
	rt.Configure(g2)
	if rt.prov != reader {
		t.Fatal("unrelated settings change reopened the MMDB")
	}
	if _, cached, _ := rt.Lookup(ctx, g2, "8.8.8.8"); !cached {
		t.Fatal("unrelated settings change dropped the cache")
	}

	g3 := g2
	g3.GeoIPCacheTTL = config.Duration(time.Millisecond)
	rt.Configure(g3)
	if rt.Cache.TTL() != time.Millisecond {
		t.Fatalf("ttl not reconfigured: %v", rt.Cache.TTL())
	}
	time.Sleep(5 * time.Millisecond)
	if _, cached, _ := rt.Lookup(ctx, g3, "8.8.8.8"); cached {
		t.Fatal("entry outlived the new TTL")
	}
}

// A lookup made with settings other than the configured ones (an old render
// snapshot, a probe of another file) must not replace the shared reader or
// populate the shared cache.
func TestRuntime_ForeignSettingsDoNotTouchSharedState(t *testing.T) {
	us := maxmindSettings(writeTestCountryMMDB(t, "8.8.8.8", "US"))
	de := maxmindSettings(writeTestCountryMMDB(t, "8.8.8.8", "DE"))
	rt := NewRuntime(time.Hour)
	rt.Configure(us)
	defer rt.InvalidateGeoProvider()
	ctx := context.Background()
	_, release, err := rt.Resolver(us)
	if err != nil {
		t.Fatal(err)
	}
	release()
	reader := rt.prov
	cc, cached, err := rt.Lookup(ctx, de, "8.8.8.8")
	if err != nil || cc != "DE" || cached {
		t.Fatalf("probe: %q cached=%v %v", cc, cached, err)
	}
	if rt.prov != reader {
		t.Fatal("probe replaced the configured reader")
	}
	if cc, _, _ := rt.Lookup(ctx, us, "8.8.8.8"); cc != "US" {
		t.Fatalf("configured lookup after probe: %q", cc)
	}
}

// An answer from the retired database must not be cached after the switch.
func TestMemoryCache_SetIfGenerationRefusesStale(t *testing.T) {
	c := NewMemoryCache(time.Hour, 10)
	gen := c.Generation()
	c.Clear()
	if c.SetIfGeneration("8.8.8.8", "US", gen) {
		t.Fatal("stale result stored")
	}
	if _, ok := c.Get("8.8.8.8"); ok {
		t.Fatal("stale result visible")
	}
	if !c.SetIfGeneration("8.8.8.8", "DE", c.Generation()) {
		t.Fatal("current result refused")
	}
}

func TestResolver_MissingDatabaseFails(t *testing.T) {
	rt := NewRuntime(0)
	g := maxmindSettings("/nonexistent/db.mmdb")
	rt.Configure(g)
	if _, _, err := rt.Resolver(g); err == nil {
		t.Fatal("expected error for a missing MMDB")
	}
}

type countingProvider struct {
	mu    sync.Mutex
	calls map[string]int
}

func (p *countingProvider) Lookup(_ context.Context, ip string) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls[ip]++
	return "US", nil
}

func TestMemoProvider_ResolvesEachAddressOnce(t *testing.T) {
	inner := &countingProvider{calls: map[string]int{}}
	m := NewMemoProvider(inner)
	for i := 0; i < 3; i++ {
		if cc, err := m.Lookup(context.Background(), "1.1.1.1"); err != nil || cc != "US" {
			t.Fatalf("lookup: %q %v", cc, err)
		}
	}
	if inner.calls["1.1.1.1"] != 1 {
		t.Fatalf("calls: %d", inner.calls["1.1.1.1"])
	}
}

// Another process (easy-waf-acmed, or update-geoip-db.sh, which replaces the
// file and reloads only the API) may install a new database at the same path.
// The next settings refresh or render must pick it up, as reopening the file
// on every settings load used to.
func TestRuntime_PicksUpDatabaseReplacedOnDisk(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "GeoLite2-Country.mmdb")
	if err := os.WriteFile(path, mustBuildMMDB(t, "8.8.8.8", "US"), 0o600); err != nil {
		t.Fatal(err)
	}
	g := maxmindSettings(path)
	rt := NewRuntime(time.Hour)
	rt.Configure(g)
	defer rt.InvalidateGeoProvider()
	ctx := context.Background()
	if cc, _, err := rt.Lookup(ctx, g, "8.8.8.8"); err != nil || cc != "US" {
		t.Fatalf("before: %q %v", cc, err)
	}
	// Replace the file the way install(1) and rename-based installers do.
	tmp := path + ".new"
	if err := os.WriteFile(tmp, mustBuildMMDB(t, "8.8.8.8", "DE"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, path); err != nil {
		t.Fatal(err)
	}

	rt.Configure(g) // unchanged settings, as LoadSettings on every acmed tick
	if cc, cached, err := rt.Lookup(ctx, g, "8.8.8.8"); err != nil || cc != "DE" || cached {
		t.Fatalf("after Configure: %q cached=%v %v", cc, cached, err)
	}

	// And at the start of a render, without a settings refresh.
	if err := os.WriteFile(tmp, mustBuildMMDB(t, "8.8.8.8", "FR"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, path); err != nil {
		t.Fatal(err)
	}
	res, release, err := rt.Resolver(g)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if cc, err := res.Lookup(ctx, "8.8.8.8"); err != nil || cc != "FR" {
		t.Fatalf("after Resolver: %q %v", cc, err)
	}
}

// blockingProvider is a network-style provider (not closable) whose lookups
// wait until released, like ipinfo behind its rate limit or a slow HTTP call.
type blockingProvider struct {
	entered chan struct{}
	release chan struct{}
}

func (p *blockingProvider) Lookup(context.Context, string) (string, error) {
	p.entered <- struct{}{}
	<-p.release
	return "US", nil
}

// A slow network lookup must not hold the runtime lock: settings changes,
// the start of a render and cache hits go ahead meanwhile.
func TestRuntime_SlowNetworkLookupDoesNotBlock(t *testing.T) {
	g := config.GlobalSettings{GeoIPProvider: "ipinfo"}
	rt := NewRuntime(time.Hour)
	rt.Configure(g)
	bp := &blockingProvider{entered: make(chan struct{}, 1), release: make(chan struct{})}
	rt.mu.Lock()
	rt.prov, rt.provKey = bp, providerKey(g)
	rt.mu.Unlock()
	rt.Cache.Set("1.1.1.1", "AU")

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _, _ = rt.Lookup(context.Background(), g, "8.8.8.8")
	}()
	<-bp.entered

	finished := make(chan struct{})
	go func() {
		defer close(finished)
		g2 := g
		g2.GeoIPCacheTTL = config.Duration(2 * time.Hour)
		rt.Configure(g2)
		if _, release, err := rt.Resolver(g2); err == nil {
			release()
		}
		if cc, cached, _ := rt.Lookup(context.Background(), g2, "1.1.1.1"); cc != "AU" || !cached {
			t.Errorf("cache hit during slow lookup: %q cached=%v", cc, cached)
		}
	}()
	select {
	case <-finished:
	case <-time.After(2 * time.Second):
		t.Fatal("Configure/Resolver/cache hit blocked behind a slow network lookup")
	}
	close(bp.release)
	<-done
}

// Settings that stop matching the configured ones in the middle of a render
// get one provider for the rest of the render, not one per address, and it
// is closed by release.
func TestResolver_ForeignSettingsOpenOneProvider(t *testing.T) {
	us := maxmindSettings(writeTestCountryMMDB(t, "8.8.8.8", "US"))
	de := maxmindSettings(writeTestCountryMMDB(t, "8.8.8.8", "DE"))
	rt := NewRuntime(time.Hour)
	rt.Configure(us)
	defer rt.InvalidateGeoProvider()
	res, release, err := rt.Resolver(us)
	if err != nil {
		t.Fatal(err)
	}
	rt.Configure(de) // settings saved while the render runs
	rr := res.(*runtimeResolver)
	var first GeoProvider
	for i := 0; i < 5; i++ {
		cc, err := res.Lookup(context.Background(), "8.8.8.8")
		if err != nil || cc != "US" {
			t.Fatalf("lookup %d: %q %v", i, cc, err)
		}
		rr.mu.Lock()
		cur := rr.oneOff
		rr.mu.Unlock()
		if cur == nil || (first != nil && cur != first) {
			t.Fatalf("lookup %d: provider %p, first %p", i, cur, first)
		}
		first = cur
	}
	release()
	mm := first.(*MaxMindProvider)
	if _, err := mm.Lookup(context.Background(), "8.8.8.8"); err == nil {
		t.Fatal("release did not close the render's own provider")
	}
}
