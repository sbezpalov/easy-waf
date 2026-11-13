// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

//go:build linux && integration

package hostd

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// Run only in a disposable network namespace: this test changes real nftables.
func TestNftRollbackReplacesManagedTables(t *testing.T) {
	if os.Getenv("RUN_NFT_ROLLBACK_INTEGRATION") != "1" {
		t.Skip("requires an explicitly enabled disposable network namespace")
	}
	rollbackTestEnv(t)
	DefaultRunner = osRunner{}
	nft := func(args ...string) string {
		t.Helper()
		out, err := exec.Command(binNft, args...).CombinedOutput()
		if err != nil {
			t.Fatalf("nft %v: %v\n%s", args, err, out)
		}
		return string(out)
	}
	const baseline = "table inet easy_waf_test {\n chain input {\n tcp dport 80 accept\n }\n}\n"
	const changed = "table inet easy_waf_test {\n chain input {\n tcp dport 443 drop\n }\n}\ntable ip easy_waf_test_added {\n chain extra {\n counter\n }\n}\n"
	// No base-chain hooks: fixtures cannot affect the container's traffic.
	if err := os.WriteFile(nftRulesPath, []byte(baseline+"table inet easy_waf_test_foreign {\n}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	nft("-f", nftRulesPath)
	for _, table := range []struct{ family, name string }{
		{"inet", "easy_waf_test"}, {"ip", "easy_waf_test_added"}, {"inet", "easy_waf_test_foreign"},
	} {
		t.Cleanup(func() { _ = exec.Command(binNft, "delete", "table", table.family, table.name).Run() })
	}
	if err := stateWriteFile(rollbackBackupPath("nft", testToken), []byte(baseline), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(nftRulesPath, []byte(changed), 0o600); err != nil {
		t.Fatal(err)
	}
	nft("-f", nftRulesPath)
	if err := RunRevert("nft", testToken); err != nil {
		t.Fatal(err)
	}
	got := nft("list", "table", "inet", "easy_waf_test")
	if strings.Count(got, "tcp dport 80 accept") != 1 || strings.Contains(got, "443") {
		t.Fatalf("rollback merged or duplicated rules:\n%s", got)
	}
	if out, err := exec.Command(binNft, "list", "table", "ip", "easy_waf_test_added").CombinedOutput(); err == nil {
		t.Fatalf("new managed table survived rollback: %s", out)
	}
	nft("list", "table", "inet", "easy_waf_test_foreign")
	if got, err := os.ReadFile(nftRulesPath); err != nil || string(got) != baseline {
		t.Fatalf("on-disk baseline not restored: %q, %v", got, err)
	}
	// A transaction that cannot restore its backup must not delete live tables
	// or rewrite the file first, leaving the firewall half-restored.
	if err := os.WriteFile(nftRulesPath, []byte(changed), 0o600); err != nil {
		t.Fatal(err)
	}
	nft("-f", nftRulesPath)
	before := nft("list", "ruleset")
	if err := stateWriteFile(rollbackBackupPath("nft", testToken), []byte("table inet easy_waf_test { broken syntax }\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := RunRevert("nft", testToken); err == nil {
		t.Fatal("invalid backup unexpectedly restored")
	}
	if after := nft("list", "ruleset"); after != before {
		t.Fatalf("failed rollback modified live tables:\nbefore: %s\nafter: %s", before, after)
	}
	if got, err := os.ReadFile(nftRulesPath); err != nil || string(got) != changed {
		t.Fatalf("failed rollback changed the live file: %q, %v", got, err)
	}
	for cycle := 0; cycle < 2; cycle++ {
		var emptyBaseline []byte
		if cycle > 0 {
			emptyBaseline = []byte(nftEmptyRuleset)
		}
		if err := stateWriteFile(rollbackBackupPath("nft", testToken), emptyBaseline, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(nftRulesPath, []byte(changed), 0o600); err != nil {
			t.Fatal(err)
		}
		nft("-f", nftRulesPath)
		if err := RunRevert("nft", testToken); err != nil {
			t.Fatalf("empty-baseline cycle %d: %v", cycle, err)
		}
		for _, table := range []struct{ family, name string }{{"inet", "easy_waf_test"}, {"ip", "easy_waf_test_added"}} {
			if out, err := exec.Command(binNft, "list", "table", table.family, table.name).CombinedOutput(); err == nil {
				t.Fatalf("empty-baseline cycle %d left table: %s", cycle, out)
			}
		}
		nft("list", "table", "inet", "easy_waf_test_foreign")
	}
}
