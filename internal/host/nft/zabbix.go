// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package nft

import (
	"os"
	"regexp"
	"strings"
)

// ZabbixAgentPort is the default Zabbix agent passive-check port.
const ZabbixAgentPort = 10050

const (
	zabbixMarker = "# easy-waf:zabbix-agent"
	zabbixRule   = "ip saddr { 127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 } tcp dport 10050 accept"
)

// Managed rulesets may carry a prior Zabbix block. The accept line may include
// EASY_WAF_EXTRA_LAN_CIDR from the installer, so match by marker + port only.
var zabbixBlockRE = regexp.MustCompile(`(?m)^[ \t]*` + regexp.QuoteMeta(zabbixMarker) + `\r?\n` +
	`[ \t]*ip saddr \{[^}\n]+\} tcp dport 10050 accept\r?\n?`)

// ReadManagedRuleset returns the on-disk managed nftables file contents.
// Live `nft list ruleset` output is not used: it includes the guard table and
// is not a safe round-trip target for apply-rollback.
func ReadManagedRuleset() (string, error) {
	b, err := os.ReadFile(RulesPath)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// HasZabbixAgentRule reports whether the managed ruleset already carries the
// marked LAN-only accept for TCP 10050.
func HasZabbixAgentRule(ruleset string) bool {
	return zabbixBlockRE.MatchString(ruleset)
}

// EnsureZabbixAgentRule adds or removes the marked TCP 10050 LAN accept block.
// Returns the updated ruleset and whether the text changed.
func EnsureZabbixAgentRule(ruleset string, enabled bool) (string, bool) {
	trimmed := strings.TrimRight(ruleset, "\n") + "\n"
	without := zabbixBlockRE.ReplaceAllString(trimmed, "")
	without = collapseExtraBlankLines(without)

	if !enabled {
		if without == trimmed {
			return ruleset, false
		}
		return without, true
	}
	if HasZabbixAgentRule(without) {
		return without, without != trimmed
	}

	block := "    " + zabbixMarker + "\n    " + zabbixRule + "\n"
	updated := insertZabbixBlock(without, block)
	if updated == trimmed {
		return ruleset, false
	}
	return updated, true
}

func insertZabbixBlock(ruleset, block string) string {
	// Prefer placing the optional agent rule after the loopback accept, which
	// every installer-managed ruleset has. Fall back to the start of the input
	// chain so a customized but still valid file still receives the block.
	lo := regexp.MustCompile(`(?m)^([ \t]*iifname "lo" accept\r?\n)`)
	if loc := lo.FindStringIndex(ruleset); loc != nil {
		return ruleset[:loc[1]] + block + ruleset[loc[1]:]
	}
	chain := regexp.MustCompile(`(?m)^(  chain input \{\r?\n)`)
	if loc := chain.FindStringIndex(ruleset); loc != nil {
		return ruleset[:loc[1]] + block + ruleset[loc[1]:]
	}
	return strings.TrimRight(ruleset, "\n") + "\n" + block
}

func collapseExtraBlankLines(s string) string {
	re := regexp.MustCompile(`\n{3,}`)
	return re.ReplaceAllString(s, "\n\n")
}
