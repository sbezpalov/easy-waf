// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"testing"
	"time"
)

func TestLoginRateLimiter_AllowsUnderLimit(t *testing.T) {
	rl := NewLoginRateLimiter(1*time.Minute, 3, 1*time.Minute)
	for i := 0; i < 3; i++ {
		ok, _ := rl.Allow("10.0.0.1")
		if !ok {
			t.Fatalf("attempt %d should be allowed", i+1)
		}
	}
}

func TestLoginRateLimiter_BlocksOverLimit(t *testing.T) {
	rl := NewLoginRateLimiter(1*time.Minute, 3, 1*time.Minute)
	for i := 0; i < 3; i++ {
		rl.Allow("10.0.0.1")
	}
	ok, retry := rl.Allow("10.0.0.1")
	if ok {
		t.Fatal("4th attempt should be blocked")
	}
	if retry <= 0 {
		t.Fatal("retry-after should be positive")
	}
}

func TestLoginRateLimiter_DifferentIPs(t *testing.T) {
	rl := NewLoginRateLimiter(1*time.Minute, 2, 1*time.Minute)
	rl.Allow("10.0.0.1")
	rl.Allow("10.0.0.1")
	ok, _ := rl.Allow("10.0.0.1")
	if ok {
		t.Fatal("IP 1 should be blocked")
	}
	ok2, _ := rl.Allow("10.0.0.2")
	if !ok2 {
		t.Fatal("IP 2 should still be allowed")
	}
}

func TestLoginRateLimiter_SuccessResets(t *testing.T) {
	rl := NewLoginRateLimiter(1*time.Minute, 3, 1*time.Minute)
	rl.Allow("10.0.0.1")
	rl.Allow("10.0.0.1")
	rl.RecordSuccess("10.0.0.1")
	for i := 0; i < 3; i++ {
		ok, _ := rl.Allow("10.0.0.1")
		if !ok {
			t.Fatalf("after reset, attempt %d should be allowed", i+1)
		}
	}
}

// fakeClock drives the limiter without sleeping.
type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time { return c.t }

func newTestLimiter(clk *fakeClock) *LoginRateLimiter {
	// Production values (bootstrap): 10 attempts per 5 minutes, 15-minute lockout.
	return &LoginRateLimiter{
		ips:      make(map[string]*loginAttempt),
		window:   5 * time.Minute,
		maxInWin: 10,
		lockout:  15 * time.Minute,
		now:      clk.now,
	}
}

// R2: the lockout must last its full 15 minutes even though the attempts that
// triggered it leave the 5-minute counting window after 5 minutes.
func TestLoginRateLimiter_LockoutOutlivesWindow(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_000_000, 0)}
	rl := newTestLimiter(clk)
	const ip = "203.0.113.9"
	for i := 0; i < 10; i++ {
		if ok, _ := rl.Allow(ip); !ok {
			t.Fatalf("attempt %d denied before the limit", i+1)
		}
	}
	start := clk.t
	for _, at := range []time.Duration{0, 6 * time.Minute, 14*time.Minute + 59*time.Second} {
		clk.t = start.Add(at)
		ok, retry := rl.Allow(ip)
		if ok {
			t.Fatalf("allowed at t=%v during the lockout", at)
		}
		if want := retryAfterSeconds(15*time.Minute - at); retry != want {
			t.Fatalf("t=%v: retry-after %d, want %d", at, retry, want)
		}
	}
	clk.t = start.Add(15 * time.Minute)
	if ok, retry := rl.Allow(ip); !ok || retry != 0 {
		t.Fatalf("still blocked when the lockout ended: retry=%d", retry)
	}
	// It starts over: the limit applies afresh.
	for i := 1; i < 10; i++ {
		if ok, _ := rl.Allow(ip); !ok {
			t.Fatalf("attempt %d after the lockout denied", i+1)
		}
	}
	if ok, _ := rl.Allow(ip); ok {
		t.Fatal("limit not re-applied after the lockout")
	}
}

// Old attempts outside the window do not count toward the limit.
func TestLoginRateLimiter_WindowSlides(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_000_000, 0)}
	rl := newTestLimiter(clk)
	const ip = "203.0.113.10"
	for i := 0; i < 9; i++ {
		rl.Allow(ip)
	}
	clk.t = clk.t.Add(5*time.Minute + time.Second)
	for i := 0; i < 9; i++ {
		if ok, _ := rl.Allow(ip); !ok {
			t.Fatalf("attempt %d in the new window denied", i+1)
		}
	}
}

// The periodic sweep must keep an IP that is still locked out, even with no
// attempt left inside the window.
func TestLoginRateLimiter_CleanupKeepsActiveLockout(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_000_000, 0)}
	rl := newTestLimiter(clk)
	const ip = "203.0.113.11"
	for i := 0; i < 10; i++ {
		rl.Allow(ip)
	}
	clk.t = clk.t.Add(10 * time.Minute)
	rl.cleanup()
	if ok, _ := rl.Allow(ip); ok {
		t.Fatal("cleanup lifted an active lockout")
	}
	clk.t = clk.t.Add(5 * time.Minute)
	rl.cleanup()
	if _, ok := rl.ips[ip]; ok {
		t.Fatal("expired lockout not swept")
	}
}

// Success clears the counter. A locked-out IP is refused before credentials
// are checked, so the only lockout a success can clear is the one its own
// (limit-reaching) attempt started.
func TestLoginRateLimiter_SuccessResetsCounterOnly(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_000_000, 0)}
	rl := newTestLimiter(clk)
	const ip = "203.0.113.12"
	for i := 0; i < 9; i++ {
		rl.Allow(ip)
	}
	rl.RecordSuccess(ip)
	for i := 0; i < 9; i++ {
		if ok, _ := rl.Allow(ip); !ok {
			t.Fatalf("attempt %d after success denied", i+1)
		}
	}
}
