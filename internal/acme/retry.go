// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package acme

import "time"

const (
	retryBase = 10 * time.Minute
	retryMax  = 24 * time.Hour
)

// RetryBackoff is how long easy-waf-acmed waits before retrying a certificate
// that has now failed attempt times in a row (attempt >= 1): 10m, 20m, 40m, ...
// capped at 24h. That stays well inside Let's Encrypt's failed-validation limit
// while still recovering on its own from a transient DNS or HTTP-01 outage.
func RetryBackoff(attempt int) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	d := retryBase
	for i := 1; i < attempt; i++ {
		d *= 2
		if d >= retryMax {
			return retryMax
		}
	}
	return d
}
