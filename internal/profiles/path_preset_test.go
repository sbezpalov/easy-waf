// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package profiles

import (
	"testing"

	"github.com/easy-waf/easy-waf/internal/config"
)

func TestHAMCPPresetIsValidAndStable(t *testing.T) {
	p := HAMCPPathPolicy()
	if err := config.ValidatePathPolicy(&p); err != nil {
		t.Fatal(err)
	}
	if p.Mode != config.PathModeAllowlist {
		t.Fatalf("mode %s", p.Mode)
	}
	for _, want := range []string{"/api/mcp", "/mcp_server/sse", "/auth", "/.well-known/oauth-authorization-server"} {
		found := false
		for _, got := range p.Allow {
			if got == want {
				found = true
			}
		}
		if !found {
			t.Errorf("missing allow %s in %#v", want, p.Allow)
		}
	}
	if _, err := Resolve("ha-mcp"); err != nil {
		t.Fatal(err)
	}
}

func TestResolvePathPolicy(t *testing.T) {
	preset := ResolvePathPolicy("ha-mcp", nil, nil)
	if preset == nil || preset.Mode != config.PathModeAllowlist {
		t.Fatalf("expected preset, got %#v", preset)
	}
	explicit := &config.PathPolicy{Mode: config.PathModeDefault}
	got := ResolvePathPolicy("ha-mcp", explicit, nil)
	if got.Mode != config.PathModeDefault {
		t.Fatalf("explicit default was replaced: %#v", got)
	}
	prev := &config.PathPolicy{Mode: config.PathModeAllowlist, Allow: []string{"/only"}}
	kept := ResolvePathPolicy("balanced", nil, prev)
	if kept == nil || len(kept.Allow) != 1 || kept.Allow[0] != "/only" {
		t.Fatalf("omitted policy was not kept: %#v", kept)
	}
	if prev.Allow[0] != "/only" {
		t.Fatal("previous policy was mutated")
	}
}
