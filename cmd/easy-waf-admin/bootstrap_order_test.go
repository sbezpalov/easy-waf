// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFinishBootstrapDoesNotWipeWhenReportCannotBeSaved(t *testing.T) {
	state := t.TempDir()
	reportIsADirectory := t.TempDir()
	err := finishBootstrap(context.Background(), nil, state, reportIsADirectory, "DATABASE_URL=secret\n")
	if err == nil || !strings.Contains(err.Error(), "write credentials report") {
		t.Fatalf("got %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(state, "haproxy")); statErr == nil {
		t.Fatal("state directory was wiped before the credentials report was saved")
	}
}
