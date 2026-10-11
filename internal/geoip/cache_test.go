// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package geoip

import (
	"fmt"
	"testing"
	"time"
)

func TestMemoryCacheHitMiss(t *testing.T) {
	c := NewMemoryCache(time.Minute, 100)
	if _, ok := c.Get("1.1.1.1"); ok {
		t.Fatal("expected miss")
	}
	st := c.Stats()
	if st.Misses != 1 || st.Hits != 0 {
		t.Fatalf("stats after miss: %+v", st)
	}
	c.Set("1.1.1.1", "AU")
	if cc, ok := c.Get("1.1.1.1"); !ok || cc != "AU" {
		t.Fatalf("get: %q %v", cc, ok)
	}
	st = c.Stats()
	if st.Hits != 1 || st.Misses != 1 {
		t.Fatalf("stats after hit: %+v", st)
	}
	if st.Size != 1 {
		t.Fatalf("size: %d", st.Size)
	}
}

func TestMemoryCacheLRUEvict(t *testing.T) {
	c := NewMemoryCache(time.Hour, 2)
	c.Set("10.0.0.1", "US")
	time.Sleep(2 * time.Millisecond)
	c.Set("10.0.0.2", "DE")
	time.Sleep(2 * time.Millisecond)
	c.Set("10.0.0.3", "FR")
	if c.Stats().Size != 2 {
		t.Fatalf("expected cap 2, got %d", c.Stats().Size)
	}
}

// The least recently used entry is evicted, not merely the oldest insert.
func TestMemoryCacheEvictsLeastRecentlyUsed(t *testing.T) {
	c := NewMemoryCache(time.Hour, 2)
	c.Set("10.0.0.1", "US")
	c.Set("10.0.0.2", "DE")
	if _, ok := c.Get("10.0.0.1"); !ok {
		t.Fatal("expected hit")
	}
	c.Set("10.0.0.3", "FR")
	if _, ok := c.Get("10.0.0.2"); ok {
		t.Fatal("10.0.0.2 was least recently used and should be gone")
	}
	if _, ok := c.Get("10.0.0.1"); !ok {
		t.Fatal("10.0.0.1 was used recently and should stay")
	}
}

func TestMemoryCacheTTL(t *testing.T) {
	c := NewMemoryCache(time.Hour, 0)
	now := time.Unix(1000, 0)
	c.now = func() time.Time { return now }
	c.Set("1.1.1.1", "AU")
	now = now.Add(59 * time.Minute)
	if _, ok := c.Get("1.1.1.1"); !ok {
		t.Fatal("expired early")
	}
	c.SetTTL(30 * time.Minute)
	if _, ok := c.Get("1.1.1.1"); ok {
		t.Fatal("shorter TTL not applied to an existing entry")
	}
	if c.Stats().Size != 0 {
		t.Fatal("expired entry not removed")
	}
}

// Insertion into a full cache must not scale with its capacity.
func BenchmarkMemoryCacheSetFull(b *testing.B) {
	for _, capacity := range []int{1000, 50000} {
		b.Run(fmt.Sprint(capacity), func(b *testing.B) {
			c := NewMemoryCache(time.Hour, capacity)
			for i := 0; i < capacity; i++ {
				c.Set(fmt.Sprintf("seed-%d", i), "US")
			}
			keys := make([]string, b.N)
			for i := range keys {
				keys[i] = fmt.Sprintf("new-%d", i)
			}
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				c.Set(keys[i], "DE")
			}
		})
	}
}
