package geoip

import (
	"sync"
	"time"
)

// Entry is a cached country code result.
type Entry struct {
	Country string
	Expires time.Time
	// lastUsed supports naive LRU eviction when over capacity.
	lastUsed time.Time
}

// MemoryCache is a TTL map with optional max size and hit/miss statistics.
type MemoryCache struct {
	mu         sync.RWMutex
	ttl        time.Duration
	maxEntries int
	items      map[string]Entry
	hits       uint64
	misses     uint64
}

// NewMemoryCache returns a cache with TTL and optional LRU cap (0 = unlimited).
func NewMemoryCache(ttl time.Duration, maxEntries int) *MemoryCache {
	if maxEntries < 0 {
		maxEntries = 0
	}
	return &MemoryCache{ttl: ttl, maxEntries: maxEntries, items: map[string]Entry{}}
}

// Stats returns cache size and counters (O(n) for size if you need exact keys; here len(map)).
func (m *MemoryCache) Stats() Stats {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return Stats{
		Size:   len(m.items),
		Hits:   m.hits,
		Misses: m.misses,
	}
}

// Stats is returned by GET /api/v1/geoip/stats.
type Stats struct {
	Size   int    `json:"size"`
	Hits   uint64 `json:"hits"`
	Misses uint64 `json:"misses"`
}

func (m *MemoryCache) Get(ip string) (country string, ok bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.items[ip]
	if !ok || time.Now().After(e.Expires) {
		if ok {
			delete(m.items, ip)
		}
		m.misses++
		return "", false
	}
	m.hits++
	e.lastUsed = time.Now()
	m.items[ip] = e
	return e.Country, true
}

// Delete removes one IP from the cache (e.g. before a forced lookup).
func (m *MemoryCache) Delete(ip string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.items, ip)
}

// Clear drops all cached entries (e.g. after MMDB reload).
func (m *MemoryCache) Clear() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.items = map[string]Entry{}
}

func (m *MemoryCache) Set(ip, country string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	if m.maxEntries > 0 && len(m.items) >= m.maxEntries {
		if _, exists := m.items[ip]; !exists {
			m.evictOneLocked(now)
		}
	}
	m.items[ip] = Entry{Country: country, Expires: now.Add(m.ttl), lastUsed: now}
}

func (m *MemoryCache) evictOneLocked(now time.Time) {
	var victim string
	var oldest time.Time
	first := true
	for k, e := range m.items {
		if first || e.lastUsed.Before(oldest) {
			first = false
			oldest = e.lastUsed
			victim = k
		}
	}
	if victim != "" {
		delete(m.items, victim)
	}
}
