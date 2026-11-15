// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package acme

import (
	"context"
	"testing"
	"time"
)

func TestLegoCertificateTimeoutFloorDoesNotMoveTheChildDeadline(t *testing.T) {
	// A five-second context is too short for DNS-01 propagation, so Lego is
	// told to wait a minute. serveIssueChild still exits at the request
	// deadline (time.Until(deadline) -> os.Exit); this floor is not that timer.
	short, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if got := legoCertificateTimeout(short); got != time.Minute {
		t.Fatalf("short deadline: got %s, want 1m", got)
	}

	long, cancelLong := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancelLong()
	if got := legoCertificateTimeout(long); got < 90*time.Second || got > 2*time.Minute {
		t.Fatalf("long deadline: got %s", got)
	}
	if got := legoCertificateTimeout(context.Background()); got != 0 {
		t.Fatalf("no deadline: got %s, want 0", got)
	}
}
