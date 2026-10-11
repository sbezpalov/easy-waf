// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package geoip

import (
	"container/list"
	"sync"
	"time"
)

// cacheItem is one cached country code result, kept in the LRU list.
type cacheItem struct {
	ip      string
	country string
	stored  time.Time
}

// MemoryCache is a bounded TTL+LRU map with hit/miss statistics.
//
// Expiry is computed from the time an entry was stored and the current TTL,
// so SetTTL takes effect for existing entries immediately. Every Clear starts
// a new generation: SetIfGeneration refuses results computed before it, which
// keeps a lookup still in flight against a retired database from writing its
// stale answer back after the cache was cleared.
type MemoryCache struct {
	mu         sync.Mutex
	ttl        time.Duration
	maxEntries int
	items      map[string]*list.Element // values are *cacheItem
	lru        *list.List               // front = most recently used
	gen        uint64
	hits       uint64
	misses     uint64
	now        func() time.Time
}

// NewMemoryCache returns a cache with TTL and optional LRU cap (0 = unlimited).
func NewMemoryCache(ttl time.Duration, maxEntries int) *MemoryCache {
	if maxEntries < 0 {
		maxEntries = 0
	}
	return &MemoryCache{
		ttl:        ttl,
		maxEntries: maxEntries,
		items:      map[string]*list.Element{},
		lru:        list.New(),
		now:        time.Now,
	}
}

// Stats returns cache size and counters.
func (m *MemoryCache) Stats() Stats {
	m.mu.Lock()
	defer m.mu.Unlock()
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
	el, ok := m.items[ip]
	if !ok {
		m.misses++
		return "", false
	}
	it := el.Value.(*cacheItem)
	if m.now().After(it.stored.Add(m.ttl)) {
		m.removeLocked(el)
		m.misses++
		return "", false
	}
	m.hits++
	m.lru.MoveToFront(el)
	return it.country, true
}

// Delete removes one IP from the cache (e.g. before a forced lookup).
func (m *MemoryCache) Delete(ip string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if el, ok := m.items[ip]; ok {
		m.removeLocked(el)
	}
}

// Clear drops all cached entries (e.g. after MMDB reload) and starts a new
// generation, so results computed before the call are not stored afterwards.
func (m *MemoryCache) Clear() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.items = map[string]*list.Element{}
	m.lru.Init()
	m.gen++
}

// Generation identifies the current cache contents; it changes on every Clear.
func (m *MemoryCache) Generation() uint64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.gen
}

// SetTTL changes the TTL for new and existing entries.
func (m *MemoryCache) SetTTL(ttl time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ttl = ttl
}

// TTL returns the current entry lifetime.
func (m *MemoryCache) TTL() time.Duration {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.ttl
}

// Set stores a result in the current generation.
func (m *MemoryCache) Set(ip, country string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.setLocked(ip, country)
}

// SetIfGeneration stores a result only if no Clear happened since gen was
// read with Generation. It reports whether the result was stored.
func (m *MemoryCache) SetIfGeneration(ip, country string, gen uint64) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.gen != gen {
		return false
	}
	m.setLocked(ip, country)
	return true
}

func (m *MemoryCache) setLocked(ip, country string) {
	now := m.now()
	if el, ok := m.items[ip]; ok {
		it := el.Value.(*cacheItem)
		it.country = country
		it.stored = now
		m.lru.MoveToFront(el)
		return
	}
	if m.maxEntries > 0 && len(m.items) >= m.maxEntries {
		if oldest := m.lru.Back(); oldest != nil {
			m.removeLocked(oldest)
		}
	}
	m.items[ip] = m.lru.PushFront(&cacheItem{ip: ip, country: country, stored: now})
}

func (m *MemoryCache) removeLocked(el *list.Element) {
	m.lru.Remove(el)
	delete(m.items, el.Value.(*cacheItem).ip)
}
