// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package nft

import (
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
