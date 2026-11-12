// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/easy-waf/easy-waf/internal/config"
	"github.com/easy-waf/easy-waf/internal/store"
)

func TestReloadPendingMarker(t *testing.T) {
	dir := t.TempDir()
	e := New(dir, &store.Store{}, config.DefaultSettings(dir))
	if e.hasReloadPending() {
		t.Fatal("expected no pending marker")
	}
	if err := e.markReloadPending(); err != nil {
		t.Fatal(err)
	}
	if !e.hasReloadPending() {
		t.Fatal("expected pending marker")
	}
	path := filepath.Join(dir, "haproxy", ".reload-pending")
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}
	e.clearReloadPending()
	if e.hasReloadPending() {
		t.Fatal("expected cleared marker")
	}
}
