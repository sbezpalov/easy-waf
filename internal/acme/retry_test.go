// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package acme

import (
	"testing"
	"time"
)

func TestRetryBackoff(t *testing.T) {
	cases := map[int]time.Duration{
		0:   10 * time.Minute,
		1:   10 * time.Minute,
		2:   20 * time.Minute,
		4:   80 * time.Minute,
		8:   1280 * time.Minute,
		9:   24 * time.Hour,
		100: 24 * time.Hour,
	}
	for attempt, want := range cases {
		if got := RetryBackoff(attempt); got != want {
			t.Errorf("RetryBackoff(%d) = %s, want %s", attempt, got, want)
		}
	}
}
