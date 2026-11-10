// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestPathPolicyMarshalOmitsToken(t *testing.T) {
	p := PathPolicy{
		Mode:  PathModeAllowlist,
		Allow: []string{"/api/mcp"},
		Rules: []PathRule{{
			PathPrefix:      "/api/mcp",
			EdgeTokenHeader: "X-Edge-Token",
			EdgeToken:       "super-secret-token-value",
			ClearEdgeToken:  true,
		}},
	}
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "super-secret") || strings.Contains(string(raw), "clear_edge_token") {
		t.Fatalf("secret leaked into JSON: %s", raw)
	}
}

func TestValidatePathPolicyRejectsInjectionAndRange(t *testing.T) {
	cases := []PathPolicy{
		{Mode: "allowlist"},
		{Mode: "allowlist", Allow: []string{"/ok\nhttp-request allow"}},
		{Mode: "allowlist", Allow: []string{"/"}},
		{Mode: "weird"},
		{ClientTimeoutSec: 86401},
		{Rules: []PathRule{{PathPrefix: "/a", ClientTimeoutSec: 0, ServerTimeoutSec: -1}}},
		{Rules: []PathRule{{PathPrefix: "/a", RequireValuePrefix: "Bearer ", RatePer10s: 1}}},
		{Rules: []PathRule{{PathPrefix: "/a", EdgeTokenHeader: "X-Token", EdgeToken: "short"}}},
		{Rules: []PathRule{{PathPrefix: "/a", RequireHeader: "Bad Header"}}},
	}
	for i, p := range cases {
		if err := ValidatePathPolicy(&p); err == nil {
			t.Errorf("case %d: expected error for %+v", i, p)
		}
	}
	ok := PathPolicy{
		Mode:             PathModeAllowlist,
		Allow:            []string{"/api/mcp", "/api/mcp"},
		ClientTimeoutSec: 3600,
		Rules: []PathRule{{
			PathPrefix:         "/api/mcp",
			RequireHeader:      "Authorization",
			RequireValuePrefix: "Bearer ",
			RatePer10s:         20,
		}},
	}
	if err := ValidatePathPolicy(&ok); err != nil {
		t.Fatal(err)
	}
	if ok.Rules[0].RequireValuePrefix != "Bearer " {
		t.Fatalf("prefix trimmed: %q", ok.Rules[0].RequireValuePrefix)
	}
	if len(ok.Allow) != 1 {
		t.Fatalf("allow not deduped: %#v", ok.Allow)
	}
}

func TestSyncEdgeTokensRoundTripAndRedact(t *testing.T) {
	dir := t.TempDir()
	policy := &PathPolicy{Rules: []PathRule{{
		PathPrefix:      "/api/mcp",
		EdgeTokenHeader: "X-Edge-Token",
		EdgeToken:       "0123456789abcdef",
	}}}
	restore, err := SyncEdgeTokens(dir, "app1", policy, nil)
	if err != nil {
		t.Fatal(err)
	}
	if policy.Rules[0].EdgeToken != "" {
		t.Fatal("token stayed on the policy")
	}
	if !policy.Rules[0].EdgeTokenConfigured {
		t.Fatal("expected configured")
	}
	file, err := EdgeTokenFile(dir, "app1", "/api/mcp", "X-Edge-Token")
	if err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "0123456789abcdef\n" {
		t.Fatalf("file %q", body)
	}
	info, err := os.Stat(file)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o640 {
		t.Fatalf("mode %o", info.Mode().Perm())
	}

	kept := &PathPolicy{Rules: []PathRule{{
		PathPrefix:          "/api/mcp",
		EdgeTokenHeader:     "X-Edge-Token",
		EdgeTokenConfigured: true,
	}}}
	if _, err := SyncEdgeTokens(dir, "app1", kept, policy); err != nil {
		t.Fatal(err)
	}
	if !kept.Rules[0].EdgeTokenConfigured {
		t.Fatal("update without a new token dropped the stored one")
	}

	cleared := &PathPolicy{Rules: []PathRule{{
		PathPrefix:      "/api/mcp",
		EdgeTokenHeader: "X-Edge-Token",
		ClearEdgeToken:  true,
	}}}
	if _, err := SyncEdgeTokens(dir, "app1", cleared, kept); err != nil {
		t.Fatal(err)
	}
	if cleared.Rules[0].EdgeTokenConfigured || cleared.Rules[0].ClearEdgeToken {
		t.Fatal("clear left write-only state behind")
	}
	if _, err := os.Stat(file); !os.IsNotExist(err) {
		t.Fatalf("token file still present: %v", err)
	}
	if err := restore(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(file); !os.IsNotExist(err) {
		t.Fatalf("undo of the first write should remove the token, stat=%v", err)
	}
}
