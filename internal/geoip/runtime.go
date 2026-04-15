package geoip

import (
	"context"
	"fmt"
	"time"

	"github.com/easy-waf/easy-waf/internal/config"
)

// Runtime holds the shared in-memory cache used by API and apply pipeline.
type Runtime struct {
	Cache *MemoryCache
}

// NewRuntime builds a cache with TTL from settings and a bounded size.
func NewRuntime(ttl time.Duration) *Runtime {
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	return &Runtime{Cache: NewMemoryCache(ttl, 50000)}
}

// Lookup returns ISO country for ip, using cache then provider.
func (r *Runtime) Lookup(ctx context.Context, g config.GlobalSettings, ip string) (country string, cached bool, err error) {
	if r == nil || r.Cache == nil {
		return "", false, fmt.Errorf("geoip: runtime not initialized")
	}
	if c, ok := r.Cache.Get(ip); ok {
		return c, true, nil
	}
	prov, err := NewProviderForSettings(g)
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
