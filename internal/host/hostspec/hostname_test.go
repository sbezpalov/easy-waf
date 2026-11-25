// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package hostspec

import (
	"os"
	"path/filepath"
	"testing"
)

func TestStaticReportHostname(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hostname")
	if got := staticReportHostname(path); got != "" {
		t.Fatalf("missing static name: got %q", got)
	}
	for contents, want := range map[string]string{
		"waf\n":                           "waf",
		"LocalHost\n":                     "LocalHost",
		"# appliance\n\nedge.home.arpa\n": "edge.home.arpa",
		"":                                "",
		"edge-????\n":                     "",
		"unexpected value\n":              "",
	} {
		if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
		if got := staticReportHostname(path); got != want {
			t.Errorf("staticReportHostname(%q) = %q, want %q", contents, got, want)
		}
	}
}
