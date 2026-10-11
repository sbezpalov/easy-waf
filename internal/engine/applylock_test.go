// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"context"
	"errors"
	"testing"
	"time"
)

// R8: waiting for the in-process apply lock honors the caller's deadline, so
// an apply started by a request cannot hang past its budget behind another
// apply.
func TestLockApply_WaitHonorsContext(t *testing.T) {
	e := &Engine{}
	e.applySemOnce.Do(func() { e.applySem = make(chan struct{}, 1) })
	e.applySem <- struct{}{} // another apply holds the lock

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	release, err := e.lockApply(ctx)
	if err == nil {
		_ = release()
		t.Fatal("acquired a lock that is held")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want deadline exceeded", err)
	}
	if waited := time.Since(start); waited > 2*time.Second {
		t.Fatalf("lock wait ignored the deadline: %v", waited)
	}
	if len(e.applySem) != 1 {
		t.Fatal("a failed wait must not take or release the slot")
	}
}
