// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package hostd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// recordingRunner logs every command, remembers the content of files passed
// to `nft -f`, and fails the commands listed in failOn.
type recordingRunner struct {
	calls   []string
	nftSeen []string
	failOn  map[string]bool
	onStop  func()
	onRun   func(string, []string)
}

func (m *recordingRunner) Run(_ context.Context, name string, args ...string) ([]byte, []byte, int, error) {
	call := strings.TrimSpace(name + " " + strings.Join(args, " "))
	m.calls = append(m.calls, call)
	if m.onRun != nil {
		m.onRun(name, args)
	}
	if name == binNft && len(args) == 2 && args[0] == "-f" {
		b, _ := os.ReadFile(args[1])
		m.nftSeen = append(m.nftSeen, string(b))
	}
	for prefix := range m.failOn {
		if strings.HasPrefix(call, prefix) {
			return nil, []byte("boom"), 1, nil
		}
	}
	if name == binSystemctl && len(args) > 0 && args[0] == "stop" && m.onStop != nil {
		m.onStop()
	}
	return nil, nil, 0, nil
}

// rollbackTestEnv points the broker's live files, state dir and runner at a
// temporary tree.
func rollbackTestEnv(t *testing.T) (*recordingRunner, string) {
	t.Helper()
	root := t.TempDir()
	state := filepath.Join(root, "state")
	if err := os.MkdirAll(filepath.Join(state, "rollback"), 0o750); err != nil {
		t.Fatal(err)
	}
	restore := SetStateDirForTest(state)
	oldNft, oldNetplan, oldRun, oldRunner := nftRulesPath, netplanPath, runtimeDir, DefaultRunner
	nftRulesPath = filepath.Join(root, "easy-waf.nft")
	oldGuard := nftGuardPath
	nftGuardPath = filepath.Join(root, "easy-waf-guard.nft")
	t.Cleanup(func() { nftGuardPath = oldGuard })
	netplanPath = filepath.Join(root, "99-easy-waf.yaml")
	runtimeDir = filepath.Join(root, "run")
	m := &recordingRunner{failOn: map[string]bool{}}
	DefaultRunner = m
	t.Cleanup(func() {
		restore()
		nftRulesPath, netplanPath, runtimeDir, DefaultRunner = oldNft, oldNetplan, oldRun, oldRunner
	})
	return m, root
}

const testToken = "abcdef0123456789abcdef0123456789"

func replaceBackupWithNonemptyDirectory(t *testing.T, backup string) {
	t.Helper()
	if err := os.Remove(backup); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(backup, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(backup, "keep"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestRevertReportsCleanupFailureAndCanRetry(t *testing.T) {
	for _, scenario := range []string{"nft", "nft-empty", "netplan"} {
		t.Run(scenario, func(t *testing.T) {
			m, _ := rollbackTestEnv(t)
			kind, data := "nft", []byte("table inet easy_waf { }\n")
			switch scenario {
			case "nft-empty":
				data = nil
				writeRules(t)
			case "netplan":
				kind = "netplan"
				data = []byte("network: {version: 2, ethernets: {}}\n")
			}
			backup := rollbackBackupPath(kind, testToken)
			if err := stateWriteFile(backup, data, 0o600); err != nil {
				t.Fatal(err)
			}
			m.onRun = func(string, []string) {
				m.onRun = nil
				replaceBackupWithNonemptyDirectory(t, backup)
			}
			if err := RunRevert(kind, testToken); err == nil || !strings.Contains(err.Error(), "remove pending rollback") {
				t.Fatalf("rollback cleanup failure hidden: %v", err)
			}
			if err := os.Remove(filepath.Join(backup, "keep")); err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(backup); err != nil {
				t.Fatal(err)
			}
			if err := stateWriteFile(backup, data, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := RunRevert(kind, testToken); err != nil {
				t.Fatalf("retry after repair failed: %v", err)
			}
			if _, err := os.Stat(backup); !os.IsNotExist(err) {
				t.Fatalf("retry left pending backup: %v", err)
			}
		})
	}
}

func TestNetplanRevertReportsLiveFileRemovalFailure(t *testing.T) {
	m, _ := rollbackTestEnv(t)
	backup := rollbackBackupPath("netplan", testToken)
	if err := stateWriteFile(backup, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(netplanPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(netplanPath, "keep"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := RunRevert("netplan", testToken); err == nil || !strings.Contains(err.Error(), "remove netplan") {
		t.Fatalf("failed live-file removal hidden: %v", err)
	}
	if len(m.calls) != 0 {
		t.Fatalf("netplan applied despite failed removal: %v", m.calls)
	}
	if _, err := os.Stat(backup); err != nil {
		t.Fatalf("pending recovery backup lost: %v", err)
	}
}

func TestTimerFailureReportsBackupCleanupFailure(t *testing.T) {
	m, _ := rollbackTestEnv(t)
	m.failOn["systemd-run"] = true
	m.onRun = func(name string, _ []string) {
		if name == "systemd-run" {
			replaceBackupWithNonemptyDirectory(t, rollbackBackupPath("netplan", testToken))
		}
	}
	_, err := beginConfirmedChange(context.Background(), m, "netplan", testToken, netplanPath, netplanMode, 90)
	if err == nil || !strings.Contains(err.Error(), "systemd-run") || !strings.Contains(err.Error(), "remove pending rollback") {
		t.Fatalf("timer/cleanup failure not preserved: %v", err)
	}
}

func TestCommitCancelsRollbackAndReportsFailures(t *testing.T) {
	for _, kind := range []string{"nft", "netplan"} {
		for _, scenario := range []string{"success", "stop failure", "backup removal failure"} {
			t.Run(kind+"/"+scenario, func(t *testing.T) {
				m, _ := rollbackTestEnv(t)
				backup := rollbackBackupPath(kind, testToken)
				if err := stateWriteFile(backup, []byte("previous configuration"), 0o600); err != nil {
					t.Fatal(err)
				}
				if scenario == "backup removal failure" {
					m.onStop = func() {
						// Simulate a filesystem failure after pending-state inspection.
						if err := os.Remove(backup); err != nil {
							t.Fatal(err)
						}
						if err := os.Mkdir(backup, 0o700); err != nil {
							t.Fatal(err)
						}
						if err := os.WriteFile(filepath.Join(backup, "keep"), nil, 0o600); err != nil {
							t.Fatal(err)
						}
					}
				}
				if scenario == "stop failure" {
					m.failOn[binSystemctl+" stop"] = true
				}
				commit := nftCommit
				if kind == "netplan" {
					commit = netplanCommit
				}
				resp := commit(context.Background(), m, testToken)
				if scenario != "success" {
					if resp.OK || resp.Code == 0 || resp.Error == "" {
						t.Fatalf("commit hid %s: %+v", scenario, resp)
					}
					if _, err := os.Stat(backup); err != nil {
						t.Fatalf("pending backup lost on failure: %v", err)
					}
					if scenario == "backup removal failure" && !strings.Contains(resp.Error, "remove pending rollback") {
						t.Fatalf("did not exercise backup removal: %+v", resp)
					}
					return
				}
				if !resp.OK {
					t.Fatalf("commit: %+v", resp)
				}
				unit := "easy-waf-rb-" + kind + "-" + testToken
				stop := binSystemctl + " stop " + unit + ".timer " + unit + ".service"
				if indexOf(m.calls, stop) < 0 {
					t.Fatalf("timer and service not both stopped: %v", m.calls)
				}
				if _, err := os.Stat(backup); !os.IsNotExist(err) {
					t.Fatalf("backup remains after commit: %v", err)
				}
				// A collected transient unit is absent on a retry. No systemd
				// operation is needed once pending state has been removed.
				m.failOn[binSystemctl+" stop"] = true
				if resp := commit(context.Background(), m, testToken); !resp.OK {
					t.Fatalf("repeat commit: %+v", resp)
				}
			})
		}
	}
}

func TestAbortRestoresEvenWhenTimerStopFails(t *testing.T) {
	m, _ := rollbackTestEnv(t)
	previous := []byte("network:\n  version: 2\n  ethernets: {}\n")
	if err := stateWriteFile(rollbackBackupPath("netplan", testToken), previous, 0o600); err != nil {
		t.Fatal(err)
	}
	m.failOn[binSystemctl+" stop"] = true
	if err := abortConfirmedChange(context.Background(), m, "netplan", testToken); err == nil {
		t.Fatal("timer cancellation failure hidden")
	}
	if got, err := os.ReadFile(netplanPath); err != nil || string(got) != string(previous) {
		t.Fatalf("previous configuration not restored: %q, %v", got, err)
	}
}

func indexOf(calls []string, prefix string) int {
	for i, c := range calls {
		if strings.HasPrefix(c, prefix) {
			return i
		}
	}
	return -1
}

func TestBeginConfirmedChangeArmsTimerAndRefusesReusedToken(t *testing.T) {
	m, _ := rollbackTestEnv(t)
	if err := os.WriteFile(nftRulesPath, []byte("table inet easy_waf {\n}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := beginConfirmedChange(ctx, m, "nft", testToken, nftRulesPath, nftRulesMode, 90); err != nil {
		t.Fatal(err)
	}
	if indexOf(m.calls, "systemd-run") < 0 {
		t.Fatalf("revert timer not armed: %v", m.calls)
	}
	if _, err := beginConfirmedChange(ctx, m, "nft", testToken, nftRulesPath, nftRulesMode, 90); err == nil {
		t.Fatal("reused token accepted; it would overwrite the pending backup")
	}
}

func TestPendingChangeRejectsOtherTokensAndLegacyWrites(t *testing.T) {
	for _, kind := range []string{"nft", "netplan"} {
		t.Run(kind, func(t *testing.T) {
			m, _ := rollbackTestEnv(t)
			path, mode := nftRulesPath, nftRulesMode
			if kind == "netplan" {
				path, mode = netplanPath, netplanMode
			}
			ctx := context.Background()
			if _, err := beginConfirmedChange(ctx, m, kind, testToken, path, mode, 90); err != nil {
				t.Fatal(err)
			}
			const nextToken = "1234567890abcdef"
			before := len(m.calls)
			if _, err := beginConfirmedChange(ctx, m, kind, nextToken, path, mode, 90); err == nil {
				t.Fatal("second unconfirmed change accepted with a different token")
			}
			if len(m.calls) != before {
				t.Fatalf("second timer armed: %v", m.calls[before:])
			}
			d := Dispatcher{Runner: m}
			for _, op := range []string{kind + "-apply", kind + "-install"} {
				resp := d.Dispatch(ctx, []string{op, "/unused/staged"})
				if resp.OK || !strings.Contains(resp.Error, "pending change") {
					t.Fatalf("legacy mutation bypassed pending state: %+v", resp)
				}
			}
			commit := nftCommit
			if kind == "netplan" {
				commit = netplanCommit
			}
			if resp := commit(ctx, m, testToken); !resp.OK {
				t.Fatal(resp.Error)
			}
			if _, err := beginConfirmedChange(ctx, m, kind, nextToken, path, mode, 90); err != nil {
				t.Fatalf("new change rejected after commit: %v", err)
			}
		})
	}
}

func TestRollbackOperationsRejectConcurrentMutation(t *testing.T) {
	m, _ := rollbackTestEnv(t)
	unlock, err := lockRollback(false)
	if err != nil {
		t.Fatal(err)
	}
	// Release exactly once, including when an assertion fails.
	t.Cleanup(unlock)
	d := Dispatcher{Runner: m}
	for _, argv := range [][]string{
		{"nft-apply-confirm", "/unused", "90", testToken},
		{"netplan-apply-confirm", "/unused", "90", testToken},
		{"nft-commit", testToken}, {"netplan-commit", testToken},
		{"nft-apply"}, {"nft-install", "/unused"},
		{"netplan-apply"}, {"netplan-install", "/unused"},
	} {
		resp := d.Dispatch(context.Background(), argv)
		if resp.OK || !strings.Contains(resp.Error, "busy") {
			t.Fatalf("concurrent mutation accepted for %v: %+v", argv, resp)
		}
	}
	if len(m.calls) != 0 {
		t.Fatalf("busy operations ran commands: %v", m.calls)
	}
}

func TestPendingChangesAreIndependentBySubsystem(t *testing.T) {
	m, _ := rollbackTestEnv(t)
	ctx := context.Background()
	if _, err := beginConfirmedChange(ctx, m, "nft", testToken, nftRulesPath, nftRulesMode, 90); err != nil {
		t.Fatal(err)
	}
	if _, err := beginConfirmedChange(ctx, m, "netplan", testToken, netplanPath, netplanMode, 90); err != nil {
		t.Fatalf("unrelated subsystem blocked: %v", err)
	}
}

func TestBeginConfirmedChangeTimerFailureLeavesNothingPending(t *testing.T) {
	m, _ := rollbackTestEnv(t)
	m.failOn["systemd-run"] = true
	if _, err := beginConfirmedChange(context.Background(), m, "netplan", testToken, netplanPath, netplanMode, 90); err == nil {
		t.Fatal("expected systemd-run failure")
	}
	if _, exists, _ := stateFileSize(rollbackBackupPath("netplan", testToken)); exists {
		t.Fatal("backup left behind for a change that was never made")
	}
}

// A netplan file that `netplan generate` rejects used to stay in /etc/netplan
// and take effect at the next boot.
func TestAbortConfirmedChangeRestoresNetplan(t *testing.T) {
	m, _ := rollbackTestEnv(t)
	prev := []byte("network:\n  version: 2\n  ethernets: {}\n")
	if err := os.WriteFile(netplanPath, prev, 0o600); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := beginConfirmedChange(ctx, m, "netplan", testToken, netplanPath, netplanMode, 90); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(netplanPath, []byte("broken: ["), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := abortConfirmedChange(ctx, m, "netplan", testToken); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(netplanPath)
	if string(got) != string(prev) {
		t.Fatalf("netplan after abort = %q", got)
	}
	if indexOf(m.calls, binSystemctl+" stop easy-waf-rb-netplan-"+testToken) < 0 {
		t.Fatalf("revert timer not cancelled: %v", m.calls)
	}
	if _, exists, _ := stateFileSize(rollbackBackupPath("netplan", testToken)); exists {
		t.Fatal("backup kept after abort")
	}
}

// With no managed ruleset before the change, the revert used to run
// `flush ruleset`, wiping fail2ban's, CrowdSec's and Docker's tables too.
func TestRevertNftEmptyBackupDestroysOnlyManagedTables(t *testing.T) {
	m, _ := rollbackTestEnv(t)
	if _, err := beginConfirmedChange(context.Background(), m, "nft", testToken, nftRulesPath, nftRulesMode, 90); err != nil {
		t.Fatal(err)
	}
	applied := "table inet easy_waf {\n  chain input {\n  }\n}\ntable ip easy_waf_nat {\n}\n"
	if err := os.WriteFile(nftRulesPath, []byte(applied), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := RunRevert("nft", testToken); err != nil {
		t.Fatal(err)
	}
	if len(m.nftSeen) != 1 {
		t.Fatalf("nft -f runs: %v", m.calls)
	}
	script := m.nftSeen[0]
	if strings.Contains(script, "flush ruleset") ||
		!strings.Contains(script, "table inet easy_waf\ndelete table inet easy_waf\n") ||
		!strings.Contains(script, "table ip easy_waf_nat\ndelete table ip easy_waf_nat\n") {
		t.Fatalf("revert script:\n%s", script)
	}
	if got, _ := os.ReadFile(nftRulesPath); string(got) != nftEmptyRuleset {
		t.Fatalf("managed file after revert: %q", got)
	}
}

func TestRevertNftNoRulesetSurvivesRepeatedApplyCycles(t *testing.T) {
	m, _ := rollbackTestEnv(t)
	for cycle := 0; cycle < 2; cycle++ {
		if _, err := beginConfirmedChange(context.Background(), m, "nft", testToken, nftRulesPath, nftRulesMode, 90); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(nftRulesPath, []byte("table inet easy_waf { }\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := RunRevert("nft", testToken); err != nil {
			t.Fatal(err)
		}
		if len(m.nftSeen) != cycle+1 || !strings.Contains(m.nftSeen[cycle], "delete table inet easy_waf\n") {
			t.Fatalf("cycle %d did not remove the newly applied rules: %v", cycle, m.nftSeen)
		}
		if got, err := os.ReadFile(nftRulesPath); err != nil || string(got) != nftEmptyRuleset {
			t.Fatalf("cycle %d did not preserve no-ruleset baseline: %q, %v", cycle, got, err)
		}
	}
}

func TestBeginConfirmedChangeRejectsUnrestorableBaseline(t *testing.T) {
	for _, kind := range []string{"nft", "netplan"} {
		t.Run(kind, func(t *testing.T) {
			m, _ := rollbackTestEnv(t)
			path, mode := nftRulesPath, nftRulesMode
			data := []byte("include \"/etc/other.nft\"\n")
			if kind == "netplan" {
				path, mode = netplanPath, netplanMode
				data = []byte("network: {version: 2, tunnels: {}}\n")
			}
			if err := os.WriteFile(path, data, mode); err != nil {
				t.Fatal(err)
			}
			_, err := beginConfirmedChange(context.Background(), m, kind, testToken, path, mode, 90)
			if err == nil || !strings.Contains(err.Error(), "rollback baseline rejected") {
				t.Fatalf("unrestorable baseline accepted: %v", err)
			}
			if len(m.calls) != 0 {
				t.Fatalf("timer/commands ran before rejecting baseline: %v", m.calls)
			}
			if _, err := os.Stat(rollbackBackupPath(kind, testToken)); !os.IsNotExist(err) {
				t.Fatalf("invalid pending state was created: %v", err)
			}
			if got, err := os.ReadFile(path); err != nil || string(got) != string(data) {
				t.Fatalf("live configuration changed: %q, %v", got, err)
			}
		})
	}
}

func TestRollbackBackupSizeLimit(t *testing.T) {
	for _, size := range []int64{maxRollbackBackupBytes, maxRollbackBackupBytes + 1} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			m, _ := rollbackTestEnv(t)
			backup := rollbackBackupPath("nft", testToken)
			f, err := os.Create(backup)
			if err != nil {
				t.Fatal(err)
			}
			if err := f.Truncate(size); err != nil {
				_ = f.Close()
				t.Fatal(err)
			}
			if err := f.Close(); err != nil {
				t.Fatal(err)
			}
			data, ok, err := readRollbackBackup(backup)
			if size == maxRollbackBackupBytes {
				if err != nil || !ok || int64(len(data)) != size {
					t.Fatalf("boundary backup rejected: len=%d ok=%v err=%v", len(data), ok, err)
				}
				return
			}
			if err == nil || data != nil || ok {
				t.Fatalf("oversized backup was truncated/accepted: len=%d ok=%v err=%v", len(data), ok, err)
			}
			if err := os.Rename(backup, nftRulesPath); err != nil {
				t.Fatal(err)
			}
			if _, err := beginConfirmedChange(context.Background(), m, "nft", testToken, nftRulesPath, nftRulesMode, 90); err == nil {
				t.Fatal("oversized baseline accepted")
			}
			if len(m.calls) != 0 {
				t.Fatalf("timer armed with oversized baseline: %v", m.calls)
			}
			if _, err := os.Stat(backup); !os.IsNotExist(err) {
				t.Fatalf("oversized pending state created: %v", err)
			}
		})
	}
}

func TestNftDestroyScriptRefusesFlushFallback(t *testing.T) {
	if got := nftDestroyScript([]byte("add rule ip filter input drop\n")); got != "" {
		t.Fatalf("expected empty (hard fail), got %q", got)
	}
	if got := nftDestroyScript([]byte("table filter {\n}\n")); got != "table ip filter\ndelete table ip filter\n" {
		t.Fatalf("family defaults to ip: %q", got)
	}
}

// The backup directory belongs to the easy-waf account; a ruleset planted
// there must pass the same check as one sent to nft-install.
func TestRevertNftRejectsTamperedBackup(t *testing.T) {
	m, _ := rollbackTestEnv(t)
	if err := stateWriteFile(rollbackBackupPath("nft", testToken), []byte("include \"/etc/shadow\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := RunRevert("nft", testToken); err == nil {
		t.Fatal("tampered backup accepted")
	}
	if len(m.nftSeen) != 0 {
		t.Fatalf("nft ran on a rejected backup: %v", m.calls)
	}
}

func TestRevertNetplanRejectsTamperedBackup(t *testing.T) {
	m, _ := rollbackTestEnv(t)
	bad := []byte("network:\n  version: 2\n  tunnels:\n    tun0:\n      mode: gre\n")
	if err := stateWriteFile(rollbackBackupPath("netplan", testToken), bad, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := RunRevert("netplan", testToken); err == nil {
		t.Fatal("tampered netplan backup accepted")
	}
	if indexOf(m.calls, binNetplan+" apply") >= 0 {
		t.Fatalf("netplan ran on a rejected backup: %v", m.calls)
	}
}

// A reboot inside the window cancels the transient revert timer; the broker
// reverts whatever is still uncommitted when it starts.
func TestRevertPendingChangesAtStartup(t *testing.T) {
	m, _ := rollbackTestEnv(t)
	prev := []byte("network:\n  version: 2\n  ethernets: {}\n")
	if err := os.WriteFile(netplanPath, prev, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := beginConfirmedChange(context.Background(), m, "netplan", testToken, netplanPath, netplanMode, 90); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(netplanPath, []byte("network: {version: 2, ethernets: {}}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Junk in the directory is ignored.
	_ = stateWriteFile(filepath.Join(stateDir, "rollback", "not-a-backup.txt"), []byte("x"), 0o600)

	RevertPendingChanges()

	if got, _ := os.ReadFile(netplanPath); string(got) != string(prev) {
		t.Fatalf("netplan after startup revert = %q", got)
	}
	if indexOf(m.calls, binNetplan+" apply") < 0 {
		t.Fatalf("netplan not re-applied: %v", m.calls)
	}
}
