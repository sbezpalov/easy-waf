// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package hostd

import (
	"os"
	"strings"
	"testing"
)

func TestFailedRevertCannotBeCommittedAndResumesAtStartup(t *testing.T) {
	for _, kind := range []string{"nft", "netplan"} {
		t.Run(kind, func(t *testing.T) {
			m, live := seedReceiptChange(t, kind)
			baseline, err := os.ReadFile(live)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(live, append(append([]byte(nil), baseline...), []byte("# pending change\n")...), 0o600); err != nil {
				t.Fatal(err)
			}
			failure := binNetplan + " apply"
			if kind == "nft" {
				writeGuard(t)
				failure = binNft + " -f " + nftGuardPath
			}
			m.failOn[failure] = true
			if err := RunRevert(kind, testToken); err == nil {
				t.Fatal("expected a late recovery command failure")
			}
			if data, err := os.ReadFile(live); err != nil || string(data) != string(baseline) {
				t.Fatalf("did not exercise a failure after restoring the live file: %q, %v", data, err)
			}
			if data, err := os.ReadFile(rollbackRevertingPath(kind, testToken)); err != nil || string(data) != string(baseline) {
				t.Fatalf("recovery phase lost the original backup: %q, %v", data, err)
			}
			if _, err := os.Stat(rollbackBackupPath(kind, testToken)); !os.IsNotExist(err) {
				t.Fatalf("recovery still has a confirmable backup: %v", err)
			}
			delete(m.failOn, failure)
			d := Dispatcher{Runner: m}
			before := len(m.calls)
			resp := d.Dispatch(t.Context(), []string{kind + "-commit", testToken})
			if resp.OK || !strings.Contains(resp.Error, "rollback") {
				t.Fatalf("failed revert falsely confirmed: %+v", resp)
			}
			if len(m.calls) != before {
				t.Fatal("commit touched systemd after rollback started")
			}
			for _, op := range []string{kind + "-apply", kind + "-install"} {
				if resp := d.Dispatch(t.Context(), []string{op, "/unused/staged"}); resp.OK {
					t.Fatal("legacy mutation bypassed incomplete rollback")
				}
			}
			mode := nftRulesMode
			if kind == "netplan" {
				mode = netplanMode
			}
			if _, err := beginConfirmedChange(t.Context(), m, kind, "1234567890abcdef", live, mode, 90); err == nil {
				t.Fatal("new apply overwrote incomplete recovery")
			}
			RevertPendingChanges()
			if _, err := os.Stat(rollbackRevertingPath(kind, testToken)); !os.IsNotExist(err) {
				t.Fatalf("startup did not finish the claimed recovery: %v", err)
			}
			if after, err := os.ReadFile(live); err != nil || string(after) != string(baseline) {
				t.Fatalf("startup did not finish recovery: %q, %v", after, err)
			}
			if resp := d.Dispatch(t.Context(), []string{kind + "-commit", testToken}); resp.OK {
				t.Fatal("completed recovery was reported as a committed apply")
			}
		})
	}
}

func TestConflictingRollbackPhasesPreserveBothBackups(t *testing.T) {
	for _, kind := range []string{"nft", "netplan"} {
		t.Run(kind, func(t *testing.T) {
			m, _ := seedReceiptChange(t, kind)
			pending, reverting := rollbackBackupPath(kind, testToken), rollbackRevertingPath(kind, testToken)
			original, err := os.ReadFile(pending)
			if err != nil {
				t.Fatal(err)
			}
			if err := stateWriteFile(reverting, []byte("another recovery backup"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := stateWriteFile(rollbackReceiptPath(kind), []byte(testToken), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := RunRevert(kind, testToken); err == nil || !strings.Contains(err.Error(), "conflicting") {
				t.Fatalf("conflicting recovery state accepted: %v", err)
			}
			d := Dispatcher{Runner: m}
			if resp := d.Dispatch(t.Context(), []string{kind + "-commit", testToken}); resp.OK {
				t.Fatal("receipt bypassed conflicting recovery state")
			}
			for path, want := range map[string]string{pending: string(original), reverting: "another recovery backup"} {
				if data, err := os.ReadFile(path); err != nil || string(data) != want {
					t.Fatalf("conflict overwrote recovery data: %q, %v", data, err)
				}
			}
			if len(m.calls) != 0 {
				t.Fatal("conflicting state touched live services")
			}
		})
	}
}
