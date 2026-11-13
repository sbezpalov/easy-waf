// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestApplyEdgeRejectsInvalidLabelBeforeOpeningState(t *testing.T) {
	previousArgs := os.Args
	t.Cleanup(func() { os.Args = previousArgs })
	for _, label := range []string{"invalid\x00label", "invalid\xfflabel"} {
		os.Args = []string{"easy-waf-admin", "apply-edge", "--env-file", filepath.Join(t.TempDir(), "missing.env"), "--database-url", "invalid-dsn", "--label", label}
		if err := runApplyEdge(); err == nil || !strings.HasPrefix(err.Error(), "label ") {
			t.Fatalf("invalid label reached environment/DB setup: %v", err)
		}
	}
}
