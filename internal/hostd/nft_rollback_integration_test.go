// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

//go:build linux && integration

package hostd

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"

	firewall "github.com/easy-waf/easy-waf/internal/host/nft"
	"github.com/easy-waf/easy-waf/internal/host/staging"
)

type nftKernelRunner struct{ recordingRunner }

func (r *nftKernelRunner) Run(ctx context.Context, name string, args ...string) ([]byte, []byte, int, error) {
	if name == binNft {
		return (osRunner{}).Run(ctx, name, args...)
	}
	return r.recordingRunner.Run(ctx, name, args...)
}

// Run in an isolated network namespace. Only timer management is simulated.
func TestNftApplyConfirmDisablesZabbixInKernel(t *testing.T) {
	if os.Getenv("RUN_NFT_ROLLBACK_INTEGRATION") != "1" {
		t.Skip("requires an explicitly enabled disposable network namespace")
	}
	rollbackTestEnv(t)
	DefaultRunner = osRunner{}
	const table = "easy_waf_zabbix_test"
	const foreignTable = "easy_waf_zabbix_foreign_test"
	const base = "table inet " + table + " {\n  chain input {\n    tcp dport 22 accept\n  }\n}\n"
	baseline, _ := firewall.EnsureZabbixAgentRule(base, true)
	if err := os.WriteFile(nftRulesPath, []byte(baseline), 0o600); err != nil {
		t.Fatal(err)
	}
	nft := func(args ...string) string {
		t.Helper()
		out, err := exec.Command(binNft, args...).CombinedOutput()
		if err != nil {
			t.Fatalf("nft %v: %v\n%s", args, err, out)
		}
		return string(out)
	}
	nft("-f", nftRulesPath)
	nft("add", "table", "inet", foreignTable)
	t.Cleanup(func() {
		nft("delete", "table", "inet", table)
		nft("delete", "table", "inet", foreignTable)
	})
	disabled, _ := firewall.EnsureZabbixAgentRule(baseline, false)
	runner := &nftKernelRunner{}
	applyDisabled := func(t *testing.T) {
		t.Helper()
		if err := staging.WithFile("zabbix-test-*.nft", []byte(disabled), func(path string) error {
			if resp := nftApplyConfirm(t.Context(), runner, path, "90", testToken); !resp.OK {
				t.Fatalf("apply failed: %+v", resp)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if got := nft("list", "table", "inet", table); strings.Contains(got, "tcp dport 10050") || strings.Count(got, "tcp dport 22 accept") != 1 {
			t.Fatalf("apply retained old or duplicate rules:\n%s", got)
		}
		nft("list", "table", "inet", foreignTable)
	}
	applyDisabled(t)
	if got, err := os.ReadFile(nftRulesPath); err != nil || string(got) != disabled {
		t.Fatalf("apply did not save the submitted source: %q, %v", got, err)
	}
	if err := RunRevert("nft", testToken); err != nil {
		t.Fatal(err)
	}
	if got := nft("list", "table", "inet", table); strings.Count(got, "tcp dport 10050 accept") != 1 {
		t.Fatalf("rollback did not restore the Zabbix rule:\n%s", got)
	}
	if got, err := os.ReadFile(nftRulesPath); err != nil || string(got) != baseline {
		t.Fatalf("rollback did not restore the original source: %q, %v", got, err)
	}

	// Older brokers saved the edited file without removing the old kernel
	// rule. Applying the same file again must reconcile that existing drift.
	if err := os.WriteFile(nftRulesPath, []byte(disabled), 0o600); err != nil {
		t.Fatal(err)
	}
	applyDisabled(t)
	if resp := nftCommit(t.Context(), runner, testToken); !resp.OK {
		t.Fatalf("confirming the reapplied rules failed: %+v", resp)
	}
	if got := nft("list", "table", "inet", table); strings.Contains(got, "tcp dport 10050") {
		t.Fatalf("confirming the reapplied rules restored the stale rule:\n%s", got)
	}
}

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
	const changedBase = "table inet easy_waf_test {\n  chain input {\n    tcp dport 443 drop\n  }\n}\ntable ip easy_waf_test_added {\n chain extra {\n counter\n }\n}\n"
	changed, _ := firewall.EnsureZabbixAgentRule(changedBase, true)
	const zabbixAccept = "tcp dport 10050 accept"
	// No base-chain hooks: fixtures cannot affect the container's traffic.
	if err := os.WriteFile(nftRulesPath, []byte(baseline+"table inet easy_waf_test_foreign {\n}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	nft("-f", nftRulesPath)
	t.Cleanup(func() {
		_ = exec.Command(binNft, "delete", "table", "inet", "easy_waf_test").Run()
		_ = exec.Command(binNft, "delete", "table", "ip", "easy_waf_test_added").Run()
		_ = exec.Command(binNft, "delete", "table", "inet", "easy_waf_test_foreign").Run()
	})
	if err := stateWriteFile(rollbackBackupPath("nft", testToken), []byte(baseline), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(nftRulesPath, []byte(changed), 0o600); err != nil {
		t.Fatal(err)
	}
	nft("-f", nftRulesPath)
	if live := nft("list", "table", "inet", "easy_waf_test"); strings.Count(live, zabbixAccept) != 1 {
		t.Fatalf("staged Zabbix rule was not loaded exactly once:\n%s", live)
	}
	if err := RunRevert("nft", testToken); err != nil {
		t.Fatal(err)
	}
	got := nft("list", "table", "inet", "easy_waf_test")
	if strings.Count(got, "tcp dport 80 accept") != 1 || strings.Contains(got, "443") {
		t.Fatalf("rollback merged or duplicated rules:\n%s", got)
	}
	if strings.Contains(got, zabbixAccept) {
		t.Fatalf("rollback retained the staged Zabbix rule:\n%s", got)
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
	// Repair the claimed backup and finish recovery before a new lifecycle.
	if err := stateWriteFile(rollbackRevertingPath("nft", testToken), []byte(baseline), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := RunRevert("nft", testToken); err != nil {
		t.Fatalf("recovery after backup repair: %v", err)
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
		if out, err := exec.Command(binNft, "list", "table", "inet", "easy_waf_test").CombinedOutput(); err == nil {
			t.Fatalf("empty-baseline cycle %d left the managed table: %s", cycle, out)
		}
		if out, err := exec.Command(binNft, "list", "table", "ip", "easy_waf_test_added").CombinedOutput(); err == nil {
			t.Fatalf("empty-baseline cycle %d left the added table: %s", cycle, out)
		}
		nft("list", "table", "inet", "easy_waf_test_foreign")
	}
	// A failed confirmation must undo real kernel rules even when systemd
	// cancellation cannot be trusted. Only that stop command is mocked.
	if err := stateWriteFile(rollbackBackupPath("nft", testToken), []byte(baseline), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(nftRulesPath, []byte(changed), 0o600); err != nil {
		t.Fatal(err)
	}
	nft("-f", nftRulesPath)
	stopFailure := &recordingRunner{failOn: map[string]bool{binSystemctl + " stop": true}}
	resp := nftCommit(context.Background(), stopFailure, testToken)
	if resp.OK || !strings.Contains(resp.Error, "stop rollback units") {
		t.Fatalf("confirmation failure hidden: %+v", resp)
	}
	restored := nft("list", "table", "inet", "easy_waf_test")
	if strings.Count(restored, "tcp dport 80 accept") != 1 || strings.Contains(restored, "443") {
		t.Fatalf("failed confirmation did not restore kernel rules:\n%s", restored)
	}
	if strings.Contains(restored, zabbixAccept) {
		t.Fatalf("failed confirmation retained the staged Zabbix rule:\n%s", restored)
	}
	if _, err := exec.Command(binNft, "list", "table", "ip", "easy_waf_test_added").CombinedOutput(); err == nil {
		t.Fatal("failed confirmation retained the added table")
	}
	nft("list", "table", "inet", "easy_waf_test_foreign")
	for _, path := range []string{rollbackBackupPath("nft", testToken), rollbackRevertingPath("nft", testToken)} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("completed confirmation recovery left state: %v", err)
		}
	}
}
