// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package haproxy

import (
	"strings"
	"testing"

	"github.com/easy-waf/easy-waf/internal/config"
)

// The stock haproxy.service starts HAProxy as root and relies on the config to
// drop privileges. Without these lines every worker, the process facing the
// internet, keeps root.
func TestRenderDropsRootInGlobal(t *testing.T) {
	r, err := Render(RenderInput{Settings: config.DefaultSettings("/tmp/state"), CRTListPath: "/tmp/state/haproxy/crt-list.txt"})
	if err != nil {
		t.Fatal(err)
	}
	global, _, _ := strings.Cut(r.HAProxyConfig, "\ndefaults")
	for _, want := range []string{"\n\tuser haproxy\n", "\n\tgroup haproxy\n"} {
		if !strings.Contains(global, want) {
			t.Fatalf("global section lacks %q:\n%s", strings.TrimSpace(want), global)
		}
	}
}
