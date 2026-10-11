// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package metrics

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// R7: concurrent cache misses share one socket read.
func TestHAProxyCollector_CoalescesConcurrentMisses(t *testing.T) {
	release := make(chan struct{})
	var calls atomic.Int32
	c := &HAProxyCollector{fetch: func(string) (*HAProxyReport, error) {
		calls.Add(1)
		<-release
		return ParseShowStatCSV([]byte(sampleStatsCSV))
	}}
	const callers = 16
	var wg sync.WaitGroup
	errs := make(chan error, callers)
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rep, err := c.Fetch("/run/haproxy.sock")
			if err != nil || rep == nil || len(rep.Backends) != 2 {
				errs <- errors.New("bad result")
			}
		}()
	}
	// Let every caller reach the in-flight wait before the read completes.
	deadline := time.Now().Add(2 * time.Second)
	for calls.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	time.Sleep(20 * time.Millisecond)
	close(release)
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	if n := calls.Load(); n != 1 {
		t.Fatalf("socket reads = %d, want 1", n)
	}
	// Fresh now: served from cache without another read.
	if _, err := c.Fetch("/run/haproxy.sock"); err != nil {
		t.Fatal(err)
	}
	if n := calls.Load(); n != 1 {
		t.Fatalf("socket reads after cache hit = %d, want 1", n)
	}
}

// A caller that gives up returns at once; the shared read still completes
// and fills the cache for the next caller.
func TestHAProxyCollector_CallerCancellation(t *testing.T) {
	release := make(chan struct{})
	c := &HAProxyCollector{fetch: func(string) (*HAProxyReport, error) {
		<-release
		return ParseShowStatCSV([]byte(sampleStatsCSV))
	}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if rep, err := c.FetchContext(ctx, "/s"); rep != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled caller: rep=%v err=%v", rep, err)
	}
	close(release)
	rep, err := c.Fetch("/s")
	if err != nil || len(rep.Backends) != 2 {
		t.Fatalf("follow-up fetch: %v %+v", err, rep)
	}
}

// A panicking read must not crash the process or strand waiting callers.
func TestHAProxyCollector_FetchPanicBecomesError(t *testing.T) {
	c := &HAProxyCollector{fetch: func(string) (*HAProxyReport, error) { panic("boom") }}
	done := make(chan struct{})
	go func() {
		defer close(done)
		rep, err := c.Fetch("/s")
		if err == nil || rep == nil || rep.Error == "" {
			t.Errorf("want error report, got rep=%+v err=%v", rep, err)
		}
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("caller stranded after a panicking read")
	}
}
