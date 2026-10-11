// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/easy-waf/easy-waf/internal/config"
	"github.com/easy-waf/easy-waf/internal/engine"
)

func TestApplyPendingMark(t *testing.T) {
	state := t.TempDir()
	if applyPending(state) {
		t.Fatal("pending before anything was stored")
	}
	markApplyPending(state, "cert-1")
	if !applyPending(state) {
		t.Fatal("mark not visible")
	}
	b, err := os.ReadFile(applyPendingPath(state))
	if err != nil || len(b) == 0 {
		t.Fatalf("mark content: %q %v", b, err)
	}
	clearApplyPending(state)
	if applyPending(state) {
		t.Fatal("mark not cleared")
	}
	clearApplyPending(state) // clearing twice is fine
}

// reconcile must not apply when nothing is pending, while backing off, or
// with applies disabled. The engine has no store, so an Apply would panic.
func TestReconcileOnlyWhenPending(t *testing.T) {
	state := t.TempDir()
	w := &worker{eng: engine.New(state, nil, config.DefaultSettings(state))}
	ctx := context.Background()

	mustNotApply := func(name string) {
		t.Helper()
		defer func() {
			if p := recover(); p != nil {
				t.Fatalf("%s: reconcile tried to apply: %v", name, p)
			}
		}()
		w.reconcile(ctx)
	}

	mustNotApply("nothing pending")

	markApplyPending(state, "cert-1")
	w.lastTry = time.Now()
	mustNotApply("within the retry backoff")

	w.lastTry = time.Time{}
	t.Setenv("EASY_WAF_ACME_SKIP_APPLY", "1")
	mustNotApply("applies disabled")
	if !applyPending(state) {
		t.Fatal("mark dropped without a successful apply")
	}
}
