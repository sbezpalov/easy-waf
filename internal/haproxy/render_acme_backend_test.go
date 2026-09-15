// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package haproxy

import (
	"strings"
	"testing"

	"github.com/easy-waf/easy-waf/internal/config"
)

// The bk_acme backend used to carry a hardcoded 127.0.0.1:8089 while the
// listener followed EASY_WAF_ACME_INTERNAL_HTTP. Moving the listener therefore
// pointed HAProxy at a closed port, and the only symptom was a failing health
// check on a backend nobody looks at until a certificate does not renew. The
// address now comes from settings, which is what both sides read.

func TestRenderACMEBackendDefaultsToLoopback8089(t *testing.T) {
	in := injectionInput()
	in.Settings.ACMEInternalHTTP = ""
	r, err := Render(in)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if !strings.Contains(r.HAProxyConfig, "server acme "+config.DefaultACMEInternalHTTP+" check") {
		t.Fatalf("unset acme_internal_http did not render the default address; got:\n%s", acmeBackendBlock(r.HAProxyConfig))
	}
}

func TestRenderACMEBackendFollowsSetting(t *testing.T) {
	in := injectionInput()
	in.Settings.ACMEInternalHTTP = "127.0.0.1:9090"
	r, err := Render(in)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if !strings.Contains(r.HAProxyConfig, "server acme 127.0.0.1:9090 check") {
		t.Fatalf("backend did not follow the setting; got:\n%s", acmeBackendBlock(r.HAProxyConfig))
	}
	if strings.Contains(r.HAProxyConfig, "server acme "+config.DefaultACMEInternalHTTP+" check") {
		t.Fatal("the old hardcoded address is still in the rendered config")
	}
}

func TestRenderRejectsUnsafeACMEInternalHTTP(t *testing.T) {
	// It lands on a `server` line, so the same rule as every other interpolated
	// value applies: refuse it here, not only where it was written.
	for _, bad := range []string{
		"127.0.0.1:8089\n    http-request allow",
		"acme.example.com:8089", // a name would need a resolvers section
		"127.0.0.1",             // no port
		"127.0.0.1:0",
		"127.0.0.1:70000",
		"127.0.0.1:http",
	} {
		in := injectionInput()
		in.Settings.ACMEInternalHTTP = bad
		r, err := Render(in)
		if err == nil {
			t.Errorf("render accepted acme_internal_http=%q; config contained:\n%s", bad, acmeBackendBlock(r.HAProxyConfig))
			continue
		}
		if !strings.Contains(err.Error(), "acme_internal_http") {
			t.Errorf("error for %q does not name the field: %v", bad, err)
		}
	}
}

func TestACMEInternalHTTPAcceptsRealisticValues(t *testing.T) {
	for _, good := range []string{
		"",
		"127.0.0.1:8089",
		"127.0.0.1:9090",
		"[::1]:8089",
		"0.0.0.0:8089",
	} {
		if err := config.ValidateListenAddr("acme_internal_http", good); err != nil {
			t.Errorf("rejected a legitimate address %q: %v", good, err)
		}
	}
}

func acmeBackendBlock(cfg string) string {
	i := strings.Index(cfg, "backend bk_acme")
	if i < 0 {
		return cfg
	}
	end := i + 200
	if end > len(cfg) {
		end = len(cfg)
	}
	return cfg[i:end]
}
