// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"fmt"
	"testing"
	"time"
)

// A spray of distinct source IPs must not grow the table without bound between
// the one-minute cleanup sweeps.
func TestLoginRateLimiter_capsTrackedIPs(t *testing.T) {
	rl := &LoginRateLimiter{
		ips:      make(map[string]*loginAttempt),
		window:   5 * time.Minute,
		maxInWin: 10,
		lockout:  15 * time.Minute,
	}
	for i := 0; i < maxTrackedIPs+500; i++ {
		rl.Allow(fmt.Sprintf("10.%d.%d.%d", i>>16&0xff, i>>8&0xff, i&0xff))
	}
	if got := len(rl.ips); got > maxTrackedIPs {
		t.Fatalf("tracked IPs = %d, want <= %d", got, maxTrackedIPs)
	}
}

// Eviction must not silently disable limiting for the IP being evicted onto:
// the newest attempt still has to be recorded and still count.
func TestLoginRateLimiter_stillLimitsAfterEviction(t *testing.T) {
	rl := &LoginRateLimiter{
		ips:      make(map[string]*loginAttempt),
		window:   5 * time.Minute,
		maxInWin: 3,
		lockout:  15 * time.Minute,
	}
	for i := 0; i < maxTrackedIPs+10; i++ {
		rl.Allow(fmt.Sprintf("10.%d.%d.%d", i>>16&0xff, i>>8&0xff, i&0xff))
	}
	const victim = "192.0.2.7"
	for i := 0; i < 3; i++ {
		if allowed, _ := rl.Allow(victim); !allowed {
			t.Fatalf("attempt %d denied too early", i+1)
		}
	}
	if allowed, retryAfter := rl.Allow(victim); allowed || retryAfter <= 0 {
		t.Fatalf("limit not enforced after eviction pressure: allowed=%v retryAfter=%d", allowed, retryAfter)
	}
}

func TestLoginRateLimiter_evictsLeastRecentlySeen(t *testing.T) {
	rl := &LoginRateLimiter{
		ips:      make(map[string]*loginAttempt),
		window:   5 * time.Minute,
		maxInWin: 10,
		lockout:  15 * time.Minute,
	}
	now := time.Now()
	rl.ips["oldest"] = &loginAttempt{attempts: []time.Time{now.Add(-time.Minute)}}
	rl.ips["newer"] = &loginAttempt{attempts: []time.Time{now}}
	rl.evictOldestLocked()
	if _, ok := rl.ips["oldest"]; ok {
		t.Fatal("least recently seen entry survived eviction")
	}
	if _, ok := rl.ips["newer"]; !ok {
		t.Fatal("active entry was evicted instead")
	}
}
