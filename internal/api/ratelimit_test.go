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
