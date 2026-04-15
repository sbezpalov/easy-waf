package geoip

import (
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
