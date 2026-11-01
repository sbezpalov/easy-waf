// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"os"
	"strings"
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

func TestCertificateWarningsNameTheCertificateAndTheCause(t *testing.T) {
	now := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	soon, later := now.Add(10*24*time.Hour), now.Add(80*24*time.Hour)

	lines := certificateWarnings([]config.Certificate{
		{PrimaryDomain: "fine.example", ACMEStatus: "ready", NotAfter: &later},
		{PrimaryDomain: "soon.example", ACMEStatus: "ready", NotAfter: &soon},
		{PrimaryDomain: "failed.example", ACMEStatus: "failed", NotAfter: &later, LastError: "dns\ntimeout"},
	}, now)

	if len(lines) != 2 {
		t.Fatalf("lines %q", lines)
	}
	if !strings.Contains(lines[0], `"soon.example"`) || !strings.Contains(lines[0], "expires in 10 days") {
		t.Fatalf("line %q", lines[0])
	}
	if !strings.Contains(lines[1], "renewal failed") || !strings.Contains(lines[1], `dns\ntimeout`) {
		t.Fatalf("line %q", lines[1])
	}
	// A stored error must not be able to forge journal lines.
	if strings.Contains(lines[1], "\n") {
		t.Fatalf("raw newline in %q", lines[1])
	}
}

func TestCertificateWarningsQuietWhenAllIsWell(t *testing.T) {
	now := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	later := now.Add(80 * 24 * time.Hour)

	lines := certificateWarnings([]config.Certificate{{PrimaryDomain: "fine.example", ACMEStatus: "ready", NotAfter: &later}}, now)

	if len(lines) != 0 {
		t.Fatalf("lines %q", lines)
	}
}
