// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"sync"
	"time"
)

// loginAttempt tracks per-IP login attempt timestamps.
type loginAttempt struct {
	attempts []time.Time
}

// maxTrackedIPs caps the per-IP table. Without a cap, a spray from spoofed or
// distributed source addresses grows the map unboundedly between the one-minute
// sweeps, so the limiter meant to absorb abuse becomes the memory leak. On
// overflow the least recently seen entry is evicted: refusing new entries
// instead would let an attacker fill the table and switch rate limiting off for
// everyone else.
const maxTrackedIPs = 10000

// LoginRateLimiter implements a sliding-window per-IP rate limit for authentication endpoints.
type LoginRateLimiter struct {
	mu       sync.Mutex
	ips      map[string]*loginAttempt
	window   time.Duration // sliding window size
	maxInWin int           // max attempts within window
	lockout  time.Duration // lockout after exceeding limit
}

// NewLoginRateLimiter creates a limiter.
//   - window: time window for counting attempts (e.g. 5 minutes)
//   - maxAttempts: max failed/total attempts in window (e.g. 10)
//   - lockout: how long to block after exceeding (e.g. 15 minutes)
func NewLoginRateLimiter(window time.Duration, maxAttempts int, lockout time.Duration) *LoginRateLimiter {
	rl := &LoginRateLimiter{
		ips:      make(map[string]*loginAttempt),
		window:   window,
		maxInWin: maxAttempts,
		lockout:  lockout,
	}
	go func() {
		for {
			time.Sleep(1 * time.Minute)
			rl.cleanup()
		}
	}()
	return rl
}

// Allow checks if the IP is allowed to attempt login. Returns (allowed, retryAfterSeconds).
func (rl *LoginRateLimiter) Allow(ip string) (bool, int) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	entry, exists := rl.ips[ip]
	if !exists {
		if len(rl.ips) >= maxTrackedIPs {
			rl.pruneLocked(now)
		}
		if len(rl.ips) >= maxTrackedIPs {
			rl.evictOldestLocked()
		}
		entry = &loginAttempt{}
		rl.ips[ip] = entry
	}

	// Prune old attempts outside the window+lockout
	cutoff := now.Add(-(rl.window + rl.lockout))
	fresh := entry.attempts[:0]
	for _, t := range entry.attempts {
		if t.After(cutoff) {
			fresh = append(fresh, t)
		}
	}
	entry.attempts = fresh

	// Count attempts within the sliding window
	windowStart := now.Add(-rl.window)
	count := 0
	var lastAttempt time.Time
	for _, t := range entry.attempts {
		if t.After(windowStart) {
			count++
			if t.After(lastAttempt) {
				lastAttempt = t
			}
		}
	}

	if count >= rl.maxInWin {
		// Check if lockout has passed since the Nth attempt
		unlockAt := lastAttempt.Add(rl.lockout)
		if now.Before(unlockAt) {
			retryAfter := int(time.Until(unlockAt).Seconds()) + 1
			return false, retryAfter
		}
		// Lockout expired — allow and reset
		entry.attempts = nil
	}

	// Record this attempt
	entry.attempts = append(entry.attempts, now)
	return true, 0
}

// RecordSuccess removes all attempts for the IP (successful login resets counter).
func (rl *LoginRateLimiter) RecordSuccess(ip string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	delete(rl.ips, ip)
}

func (rl *LoginRateLimiter) cleanup() {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	rl.pruneLocked(time.Now())
}

// pruneLocked drops attempts older than window+lockout and any IP left empty.
// Caller holds rl.mu.
func (rl *LoginRateLimiter) pruneLocked(now time.Time) {
	cutoff := now.Add(-(rl.window + rl.lockout))
	for ip, entry := range rl.ips {
		fresh := entry.attempts[:0]
		for _, t := range entry.attempts {
			if t.After(cutoff) {
				fresh = append(fresh, t)
			}
		}
		if len(fresh) == 0 {
			delete(rl.ips, ip)
		} else {
			entry.attempts = fresh
		}
	}
}

// evictOldestLocked removes the entry whose most recent attempt is the oldest,
// so an active attacker's own entry is the last thing dropped. Caller holds rl.mu.
func (rl *LoginRateLimiter) evictOldestLocked() {
	var oldestIP string
	var oldest time.Time
	for ip, entry := range rl.ips {
		var last time.Time
		for _, t := range entry.attempts {
			if t.After(last) {
				last = t
			}
		}
		if oldestIP == "" || last.Before(oldest) {
			oldestIP, oldest = ip, last
		}
	}
	if oldestIP != "" {
		delete(rl.ips, oldestIP)
	}
}
