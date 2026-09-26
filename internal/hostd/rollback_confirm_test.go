// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package hostd

import (
	"context"
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
}

func (m *recordingRunner) Run(_ context.Context, name string, args ...string) ([]byte, []byte, int, error) {
	call := strings.TrimSpace(name + " " + strings.Join(args, " "))
	m.calls = append(m.calls, call)
	if name == "/usr/sbin/nft" && len(args) == 2 && args[0] == "-f" {
		b, _ := os.ReadFile(args[1])
		m.nftSeen = append(m.nftSeen, string(b))
	}
	for prefix := range m.failOn {
		if strings.HasPrefix(call, prefix) {
			return nil, []byte("boom"), 1, nil
		}
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
	if err := beginConfirmedChange(ctx, m, "nft", testToken, nftRulesPath, nftRulesMode, 90); err != nil {
		t.Fatal(err)
	}
	if indexOf(m.calls, "systemd-run") < 0 {
		t.Fatalf("revert timer not armed: %v", m.calls)
	}
	if err := beginConfirmedChange(ctx, m, "nft", testToken, nftRulesPath, nftRulesMode, 90); err == nil {
		t.Fatal("reused token accepted; it would overwrite the pending backup")
	}
}

func TestBeginConfirmedChangeTimerFailureLeavesNothingPending(t *testing.T) {
	m, _ := rollbackTestEnv(t)
	m.failOn["systemd-run"] = true
	if err := beginConfirmedChange(context.Background(), m, "netplan", testToken, netplanPath, netplanMode, 90); err == nil {
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
	prev := []byte("network: {version: 2}\n")
	if err := os.WriteFile(netplanPath, prev, 0o600); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := beginConfirmedChange(ctx, m, "netplan", testToken, netplanPath, netplanMode, 90); err != nil {
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
	if indexOf(m.calls, "systemctl stop easy-waf-rb-netplan-"+testToken) < 0 {
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
	if err := beginConfirmedChange(context.Background(), m, "nft", testToken, nftRulesPath, nftRulesMode, 90); err != nil {
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
		!strings.Contains(script, "destroy table inet easy_waf\n") ||
		!strings.Contains(script, "destroy table ip easy_waf_nat\n") {
		t.Fatalf("revert script:\n%s", script)
	}
	if got, _ := os.ReadFile(nftRulesPath); string(got) != nftEmptyRuleset {
		t.Fatalf("managed file after revert: %q", got)
	}
}

func TestNftDestroyScriptFallsBackToFlush(t *testing.T) {
	if got := nftDestroyScript([]byte("add rule ip filter input drop\n")); got != "flush ruleset\n" {
		t.Fatalf("got %q", got)
	}
	if got := nftDestroyScript([]byte("table filter {\n}\n")); got != "destroy table ip filter\n" {
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

// A reboot inside the window cancels the transient revert timer; the broker
// reverts whatever is still uncommitted when it starts.
func TestRevertPendingChangesAtStartup(t *testing.T) {
	m, _ := rollbackTestEnv(t)
	prev := []byte("network: {version: 2}\n")
	if err := os.WriteFile(netplanPath, prev, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := beginConfirmedChange(context.Background(), m, "netplan", testToken, netplanPath, netplanMode, 90); err != nil {
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
	if indexOf(m.calls, "netplan apply") < 0 {
		t.Fatalf("netplan not re-applied: %v", m.calls)
	}
}
