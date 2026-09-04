// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package geoip

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/easy-waf/easy-waf/internal/config"
)

// Runtime holds the shared in-memory cache used by API and apply pipeline.
type Runtime struct {
	Cache   *MemoryCache
	mu      sync.Mutex
	prov    GeoProvider
	provKey string // e.g. "maxmind:/path/to.mmdb"
}

// NewRuntime builds a cache with TTL from settings and a bounded size.
func NewRuntime(ttl time.Duration) *Runtime {
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	return &Runtime{Cache: NewMemoryCache(ttl, 50000)}
}

// ProviderForRuntime returns a GeoProvider, reusing a cached MaxMind reader when possible.
func ProviderForRuntime(r *Runtime, g config.GlobalSettings) (GeoProvider, error) {
	if strings.ToLower(strings.TrimSpace(g.GeoIPProvider)) == "maxmind" {
		if r == nil {
			return NewProviderForSettings(g)
		}
		return r.maxMindProviderLocked(g)
	}
	return NewProviderForSettings(g)
}

func (r *Runtime) maxMindProviderLocked(g config.GlobalSettings) (GeoProvider, error) {
	path := strings.TrimSpace(g.GeoIPMMDBPath)
	key := "maxmind:" + path
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.prov != nil && r.provKey == key {
		return r.prov, nil
	}
	if r.prov != nil {
		if mm, ok := r.prov.(*MaxMindProvider); ok && mm != nil {
			_ = mm.Close()
		}
		r.prov = nil
		r.provKey = ""
	}
	p, err := NewMaxMindProvider(path)
	if err != nil {
		return nil, err
	}
	r.prov = p
	r.provKey = key
	return p, nil
}

// InvalidateGeoProvider closes any cached MaxMind reader (e.g. after provider/path change).
func (r *Runtime) InvalidateGeoProvider() {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if mm, ok := r.prov.(*MaxMindProvider); ok && mm != nil {
		_ = mm.Close()
	}
	r.prov = nil
	r.provKey = ""
}

// ReloadMaxMindDB reloads the MMDB from disk into the cached MaxMind provider, or opens one if missing.
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
		return mm.Reload(dbPath)
	}
	p, err := NewMaxMindProvider(dbPath)
	if err != nil {
		return err
	}
	r.prov = p
	r.provKey = "maxmind:" + dbPath
	return nil
}

// Lookup returns ISO country for ip, using cache then provider.
func (r *Runtime) Lookup(ctx context.Context, g config.GlobalSettings, ip string) (country string, cached bool, err error) {
	if r == nil || r.Cache == nil {
		return "", false, fmt.Errorf("geoip: runtime not initialized")
	}
	if c, ok := r.Cache.Get(ip); ok {
		return c, true, nil
	}
	prov, err := ProviderForRuntime(r, g)
	if err != nil {
		return "", false, err
	}
	cc, err := prov.Lookup(ctx, ip)
	if err != nil {
		return "", false, err
	}
	r.Cache.Set(ip, cc)
	return cc, false, nil
}
