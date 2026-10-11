// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package geoip

import (
	"context"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/easy-waf/easy-waf/internal/config"
)

// Runtime holds the shared in-memory cache and provider used by the API and
// the apply pipeline.
//
// Configure binds the runtime to the current settings. The shared provider and
// Cache only ever serve that configuration: a lookup made with other settings
// (an old render snapshot, a probe of another MMDB path) goes to a one-off
// provider and is not cached, so it can neither replace the configured reader
// nor leave answers from another database behind.
type Runtime struct {
	Cache *MemoryCache

	// mu guards the fields below. Provider lookups hold it for reading for
	// their whole duration; retiring a provider takes it exclusively, so no
	// caller ever uses a provider after it was closed.
	mu         sync.RWMutex
	prov       GeoProvider
	provKey    string // e.g. "maxmind:/path/to.mmdb"
	configured bool
	cfgKey     string
}

// NewRuntime builds a cache with TTL from settings and a bounded size.
func NewRuntime(ttl time.Duration) *Runtime {
	return &Runtime{Cache: NewMemoryCache(cacheTTL(ttl), 50000)}
}

func cacheTTL(ttl time.Duration) time.Duration {
	if ttl <= 0 {
		return 24 * time.Hour
	}
	return ttl
}

// providerKey identifies the database a configuration resolves against.
func providerKey(g config.GlobalSettings) string {
	switch name := strings.ToLower(strings.TrimSpace(g.GeoIPProvider)); name {
	case "maxmind":
		return "maxmind:" + strings.TrimSpace(g.GeoIPMMDBPath)
	case "ipinfo", "":
		return "ipinfo"
	default:
		return "unknown:" + name
	}
}

// Configure makes g the configuration the shared provider and cache serve. A
// change of provider or database path retires the old provider and drops every
// cached answer; a TTL change applies to existing entries too. Settings
// unrelated to GeoIP resolution change nothing, so they cost no MMDB reopen.
func (r *Runtime) Configure(g config.GlobalSettings) {
	if r == nil {
		return
	}
	r.Cache.SetTTL(cacheTTL(time.Duration(g.GeoIPCacheTTL)))
	key := providerKey(g)
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.configured && r.cfgKey == key {
		// Same settings, but the database file may have been replaced
		// underneath (another process installed an update).
		r.retireIfChangedLocked()
		return
	}
	r.configured, r.cfgKey = true, key
	if r.prov != nil && r.provKey != key {
		r.closeProviderLocked()
	}
	r.Cache.Clear()
}

// InvalidateGeoProvider closes any cached provider and drops cached answers;
// the next lookup reopens the database.
func (r *Runtime) InvalidateGeoProvider() {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closeProviderLocked()
	r.Cache.Clear()
}

// retireIfChangedLocked drops the shared MaxMind reader and the cached answers
// when its file changed on disk; the next lookup opens the new file. Caller
// holds r.mu exclusively.
func (r *Runtime) retireIfChangedLocked() {
	if mm, ok := r.prov.(*MaxMindProvider); ok && mm.ChangedOnDisk() {
		r.closeProviderLocked()
		r.Cache.Clear()
	}
}

func (r *Runtime) closeProviderLocked() {
	if c, ok := r.prov.(io.Closer); ok && c != nil {
		_ = c.Close()
	}
	r.prov = nil
	r.provKey = ""
}

// ReloadMaxMindDB reloads the MMDB from disk into the cached MaxMind provider,
// or opens one if missing, and drops answers cached from the previous file.
func (r *Runtime) ReloadMaxMindDB(dbPath string) error {
	if r == nil {
		return fmt.Errorf("geoip: runtime not initialized")
	}
	dbPath = strings.TrimSpace(dbPath)
	if dbPath == "" {
		return fmt.Errorf("geoip maxmind: empty path")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if mm, ok := r.prov.(*MaxMindProvider); ok && mm != nil {
		if err := mm.Reload(dbPath); err != nil {
			return err
		}
	} else {
		p, err := NewMaxMindProvider(dbPath)
		if err != nil {
			return err
		}
		r.closeProviderLocked()
		r.prov = p
	}
	r.provKey = "maxmind:" + dbPath
	r.Cache.Clear()
	return nil
}

// Lookup returns ISO country for ip, using cache then provider.
func (r *Runtime) Lookup(ctx context.Context, g config.GlobalSettings, ip string) (country string, cached bool, err error) {
	if r == nil || r.Cache == nil {
		return "", false, fmt.Errorf("geoip: runtime not initialized")
	}
	key := providerKey(g)
	// Reading the generation and the cache under the read lock pins both to
	// the configuration the runtime serves: Configure cannot switch databases
	// in between.
	r.mu.RLock()
	shared := !r.configured || r.cfgKey == key
	gen := r.Cache.Generation()
	if shared {
		if c, ok := r.Cache.Get(ip); ok {
			r.mu.RUnlock()
			return c, true, nil
		}
	}
	r.mu.RUnlock()
	cc, shared, err := r.lookupProvider(ctx, g, ip)
	if err != nil {
		return "", false, err
	}
	if shared {
		// Refused when the provider changed meanwhile: the answer came from
		// the database that was just retired.
		r.Cache.SetIfGeneration(ip, cc, gen)
	}
	return cc, false, nil
}

// lookupProvider resolves ip with the shared provider when g is the
// configuration the runtime serves, else with a one-off provider. shared
// reports which one answered.
func (r *Runtime) lookupProvider(ctx context.Context, g config.GlobalSettings, ip string) (cc string, shared bool, err error) {
	shared, err = r.withProvider(g, func(p GeoProvider) error {
		var lerr error
		cc, lerr = p.Lookup(ctx, ip)
		return lerr
	})
	return cc, shared, err
}

// withProvider runs fn with the provider for g: the shared one, held under
// the read lock so it cannot be closed meanwhile, or a one-off provider closed
// afterwards. Errors opening the provider are returned without calling fn.
func (r *Runtime) withProvider(g config.GlobalSettings, fn func(GeoProvider) error) (shared bool, err error) {
	key := providerKey(g)
	for {
		r.mu.RLock()
		if r.configured && r.cfgKey != key {
			r.mu.RUnlock()
			p, err := NewProviderForSettings(g)
			if err != nil {
				return false, err
			}
			if c, ok := p.(io.Closer); ok {
				defer c.Close()
			}
			return false, fn(p)
		}
		if r.prov != nil && r.provKey == key {
			err := fn(r.prov)
			r.mu.RUnlock()
			return true, err
		}
		r.mu.RUnlock()

		r.mu.Lock()
		if (!r.configured || r.cfgKey == key) && (r.prov == nil || r.provKey != key) {
			p, err := NewProviderForSettings(g)
			if err != nil {
				r.mu.Unlock()
				return false, err
			}
			if r.provKey != "" && r.provKey != key {
				// Answers cached so far came from another database. (An empty
				// key means the provider was retired, which already cleared.)
				r.Cache.Clear()
			}
			r.closeProviderLocked()
			r.prov, r.provKey = p, key
		}
		r.mu.Unlock()
		// Re-check under the read lock: Configure may have run in between.
	}
}

// Resolver returns a GeoProvider that resolves through the runtime (cache
// first) with settings g and stays valid across provider changes. It fails
// when the provider for g cannot be opened, e.g. a missing MMDB file. A
// shared reader whose file was replaced on disk is reopened first.
func (r *Runtime) Resolver(g config.GlobalSettings) (GeoProvider, error) {
	if r == nil || r.Cache == nil {
		return nil, fmt.Errorf("geoip: runtime not initialized")
	}
	// A render starts here: pick up a database replaced on disk since the
	// reader was opened, as every render did when it reopened the file.
	r.mu.Lock()
	if !r.configured || r.cfgKey == providerKey(g) {
		r.retireIfChangedLocked()
	}
	r.mu.Unlock()
	if _, err := r.withProvider(g, func(GeoProvider) error { return nil }); err != nil {
		return nil, err
	}
	return runtimeResolver{r: r, g: g}, nil
}

type runtimeResolver struct {
	r *Runtime
	g config.GlobalSettings
}

func (rr runtimeResolver) Lookup(ctx context.Context, ip string) (string, error) {
	cc, _, err := rr.r.Lookup(ctx, rr.g, ip)
	return cc, err
}

// MemoProvider remembers every answer, failures included, of the provider it
// wraps. It is meant for one batch such as a single render, where the same
// address is resolved for the global map and again for each application map.
type MemoProvider struct {
	prov GeoProvider
	mu   sync.Mutex
	memo map[string]memoResult
}

type memoResult struct {
	cc  string
	err error
}

// NewMemoProvider wraps prov.
func NewMemoProvider(prov GeoProvider) *MemoProvider {
	return &MemoProvider{prov: prov, memo: map[string]memoResult{}}
}

// Lookup implements GeoProvider.
func (m *MemoProvider) Lookup(ctx context.Context, ip string) (string, error) {
	m.mu.Lock()
	res, ok := m.memo[ip]
	m.mu.Unlock()
	if ok {
		return res.cc, res.err
	}
	cc, err := m.prov.Lookup(ctx, ip)
	if ctx.Err() != nil {
		// A canceled lookup says nothing about the address.
		return cc, err
	}
	m.mu.Lock()
	m.memo[ip] = memoResult{cc: cc, err: err}
	m.mu.Unlock()
	return cc, err
}
