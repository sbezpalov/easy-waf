// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"sync"
	"time"
)

// loginAttempt tracks per-IP login attempt timestamps and an active lockout.
type loginAttempt struct {
	attempts []time.Time
	// blockedUntil is set when the attempts in one window reach the limit. It
	// is independent of the window: the lockout lasts its full duration even
	// after the attempts that caused it have aged out of the window.
	blockedUntil time.Time
}

// lastSeen returns the most recent attempt time.
func (e *loginAttempt) lastSeen() time.Time {
	var last time.Time
	for _, t := range e.attempts {
		if t.After(last) {
			last = t
		}
	}
	return last
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
	window   time.Duration    // sliding window size
	maxInWin int              // max attempts within window
	lockout  time.Duration    // lockout after exceeding limit
	now      func() time.Time // nil = time.Now; injectable for tests
}

func (rl *LoginRateLimiter) clock() time.Time {
	if rl.now != nil {
		return rl.now()
	}
	return time.Now()
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
//
// Every allowed call counts as an attempt. The attempt that brings the count
// within the window to the limit is still allowed but starts a lockout of
// rl.lockout; until it ends every call is refused (and not counted). When it
// ends the IP starts over with no attempts.
func (rl *LoginRateLimiter) Allow(ip string) (bool, int) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := rl.clock()
	entry, exists := rl.ips[ip]
	if !exists {
		if len(rl.ips) >= maxTrackedIPs {
			rl.pruneLocked(now)
		}
		if len(rl.ips) >= maxTrackedIPs {
			rl.evictOldestLocked(now)
		}
		entry = &loginAttempt{}
		rl.ips[ip] = entry
	}

	if !entry.blockedUntil.IsZero() {
		if now.Before(entry.blockedUntil) {
			return false, retryAfterSeconds(entry.blockedUntil.Sub(now))
		}
		// Lockout over — start from a clean slate.
		entry.blockedUntil = time.Time{}
		entry.attempts = nil
	}

	// Keep only attempts inside the sliding window.
	windowStart := now.Add(-rl.window)
	fresh := entry.attempts[:0]
	for _, t := range entry.attempts {
		if t.After(windowStart) {
			fresh = append(fresh, t)
		}
	}
	fresh = append(fresh, now)
	entry.attempts = fresh
	if len(entry.attempts) >= rl.maxInWin {
		entry.blockedUntil = now.Add(rl.lockout)
	}
	return true, 0
}

// retryAfterSeconds rounds a remaining lockout up to whole seconds.
func retryAfterSeconds(d time.Duration) int {
	secs := int(d / time.Second)
	if d%time.Second != 0 {
		secs++
	}
	if secs < 1 {
		secs = 1
	}
	return secs
}

// RecordSuccess forgets the IP: a successful login resets the counter. Allow
// refuses a locked-out IP before credentials are checked, so the only lockout
// this can clear is one started by the successful attempt itself.
func (rl *LoginRateLimiter) RecordSuccess(ip string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	delete(rl.ips, ip)
}

func (rl *LoginRateLimiter) cleanup() {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	rl.pruneLocked(rl.clock())
}

// pruneLocked drops attempts outside the window and any IP left with neither
// attempts nor an active lockout. Caller holds rl.mu.
func (rl *LoginRateLimiter) pruneLocked(now time.Time) {
	windowStart := now.Add(-rl.window)
	for ip, entry := range rl.ips {
		if !entry.blockedUntil.IsZero() {
			if now.Before(entry.blockedUntil) {
				continue
			}
			// Lockout over: Allow would start this IP from scratch anyway.
			delete(rl.ips, ip)
			continue
		}
		fresh := entry.attempts[:0]
		for _, t := range entry.attempts {
			if t.After(windowStart) {
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
// so an active attacker's own entry is the last thing dropped. Entries under an
// active lockout go only when nothing else is left, so a spray of fresh source
// addresses cannot lift a lockout by pushing it out. Caller holds rl.mu.
func (rl *LoginRateLimiter) evictOldestLocked(now time.Time) {
	var victim string
	var victimSeen time.Time
	victimBlocked := true
	for ip, entry := range rl.ips {
		blocked := now.Before(entry.blockedUntil)
		seen := entry.lastSeen()
		better := victim == "" ||
			(victimBlocked && !blocked) ||
			(victimBlocked == blocked && seen.Before(victimSeen))
		if better {
			victim, victimSeen, victimBlocked = ip, seen, blocked
		}
	}
	if victim != "" {
		delete(rl.ips, victim)
	}
}
