// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package nft

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const sampleRuleset = `#!/usr/sbin/nft -f
# Managed by Easy Home WAF — prefer GUI/API; manual edits may be overwritten.

table inet easy_waf {
  chain input {
    type filter hook input priority filter; policy drop;
    ct state established,related accept
    iifname "lo" accept
    tcp dport 22 accept
    tcp dport { 80, 443 } accept
    udp dport 443 accept
    icmp type echo-request limit rate 5/second accept
  }
}
`

func TestStatusReportsZabbixRuleFromManagedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "easy-waf.nft")
	t.Setenv("EASY_WAF_HOSTD_SOCKET", filepath.Join(filepath.Dir(path), "absent.sock"))
	previous := RulesPath
	RulesPath = path
	t.Cleanup(func() { RulesPath = previous })

	readStatus := func() map[string]json.RawMessage {
		t.Helper()
		status, err := GetStatus(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		data, err := json.Marshal(status)
		if err != nil {
			t.Fatal(err)
		}
		var payload map[string]json.RawMessage
		if err := json.Unmarshal(data, &payload); err != nil {
			t.Fatal(err)
		}
		return payload
	}
	writeRules := func(rules string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(rules), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	if payload := readStatus(); payload["zabbix_agent_rule"] != nil || payload["managed_ruleset"] != nil {
		t.Fatalf("missing file reported managed state: %v", payload)
	}
	withRule, _ := EnsureZabbixAgentRule(sampleRuleset, true)
	writeRules(withRule)
	if got := string(readStatus()["zabbix_agent_rule"]); got != "true" {
		t.Fatalf("enabled rule reported state %q", got)
	}
	writeRules(sampleRuleset)
	payload := readStatus()
	if got := string(payload["zabbix_agent_rule"]); got != "false" {
		t.Fatalf("restored ruleset reported state %q", got)
	}
	var managed string
	if err := json.Unmarshal(payload["managed_ruleset"], &managed); err != nil || managed != sampleRuleset {
		t.Fatalf("expected the editable file verbatim: %q, %v", managed, err)
	}
}

func TestEnsureZabbixAgentRuleEnableDisable(t *testing.T) {
	t.Parallel()
	enabled, changed := EnsureZabbixAgentRule(sampleRuleset, true)
	if !changed {
		t.Fatal("expected change when enabling")
	}
	if !HasZabbixAgentRule(enabled) {
		t.Fatal("expected marked rule after enable")
	}
	if !strings.Contains(enabled, "tcp dport 10050 accept") {
		t.Fatal("missing tcp 10050 accept")
	}
	idxLo := strings.Index(enabled, `iifname "lo" accept`)
	idxZ := strings.Index(enabled, zabbixMarker)
	if idxLo < 0 || idxZ < idxLo {
		t.Fatal("zabbix block should follow loopback accept")
	}

	again, changed := EnsureZabbixAgentRule(enabled, true)
	if changed {
		t.Fatal("second enable should be idempotent")
	}
	if again != enabled {
		t.Fatal("idempotent enable changed text")
	}

	disabled, changed := EnsureZabbixAgentRule(enabled, false)
	if !changed {
		t.Fatal("expected change when disabling")
	}
	if HasZabbixAgentRule(disabled) {
		t.Fatal("marker should be removed")
	}
	if strings.Contains(disabled, "tcp dport 10050") {
		t.Fatal("port 10050 should be removed")
	}

	noop, changed := EnsureZabbixAgentRule(sampleRuleset, false)
	if changed {
		t.Fatal("disable on clean ruleset should not change")
	}
	if noop != sampleRuleset {
		t.Fatal("unexpected rewrite of clean ruleset")
	}
}

func TestEnsureZabbixAgentRuleCustomFileWithoutLo(t *testing.T) {
	t.Parallel()
	custom := "table inet easy_waf {\n  chain input {\n    tcp dport 22 accept\n  }\n}\n"
	out, changed := EnsureZabbixAgentRule(custom, true)
	if !changed || !HasZabbixAgentRule(out) {
		t.Fatalf("expected insert into custom chain, got changed=%v out=%q", changed, out)
	}
}

func TestEnsureZabbixAgentRuleMatchesLegacyMultilineSet(t *testing.T) {
	t.Parallel()
	legacy := "    " + zabbixMarker + "\n" +
		"    ip saddr { 127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16\n" +
		", 198.51.100.0/24 } tcp dport 10050 accept\n"
	base := strings.Replace(sampleRuleset, "    tcp dport 22 accept", "\n\n    tcp dport 22 accept", 1)
	withRule := strings.Replace(base, "    tcp dport 22 accept", legacy+"    tcp dport 22 accept", 1)
	if got, changed := EnsureZabbixAgentRule(withRule, true); changed || got != withRule {
		t.Fatal("enabling an existing legacy rule should leave it in place")
	}
	if got, changed := EnsureZabbixAgentRule(withRule, false); !changed || got != base {
		t.Fatalf("disabling should remove only the marked multiline rule, got %q", got)
	}
	if got, changed := EnsureZabbixAgentRule(base, false); changed || got != base {
		t.Fatal("disabling an absent rule should preserve unrelated whitespace")
	}
}
