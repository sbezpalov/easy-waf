// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package geoip

import (
	"os"
	"testing"

	"github.com/easy-waf/easy-waf/internal/config"
)

// HAProxy runs as the haproxy user (group easy-waf) and must be able to read
// the maps easy-waf writes; 0600 would stop it starting.
func TestEnforceMapIsGroupReadable(t *testing.T) {
	dir := t.TempDir()
	g := config.DefaultSettings(dir)
	if err := WriteDisabledEnforceMap(g, dir); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(EnforceMapPath(g, dir))
	if err != nil {
		t.Fatal(err)
	}
	if got := st.Mode().Perm(); got != 0o640 {
		t.Fatalf("mode %o, want 640", got)
	}
}
