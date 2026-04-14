package geoip

import (
	"sync"
	"time"
)

// Entry is a cached country code result.
type Entry struct {
	Country string
	Expires time.Time
}

// MemoryCache is a simple TTL LRU-ish map for Geo lookups (replace backend with mmdb later).
type MemoryCache struct {
	mu    sync.RWMutex
	ttl   time.Duration
	items map[string]Entry
}

func NewMemoryCache(ttl time.Duration) *MemoryCache {
	return &MemoryCache{ttl: ttl, items: map[string]Entry{}}
}

func (m *MemoryCache) Get(ip string) (country string, ok bool) {
	m.mu.RLock()
	e, ok := m.items[ip]
	m.mu.RUnlock()
	if !ok || time.Now().After(e.Expires) {
		return "", false
	}
	return e.Country, true
}

func (m *MemoryCache) Set(ip, country string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.items[ip] = Entry{Country: country, Expires: time.Now().Add(m.ttl)}
}
