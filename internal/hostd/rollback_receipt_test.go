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

func TestCommitRejectsUnknownAndRevertedChanges(t *testing.T) {
	for _, kind := range []string{"nft", "netplan"} {
		for _, reverted := range []bool{false, true} {
			name := kind + "/unknown"
			if reverted {
				name = kind + "/reverted"
			}
			t.Run(name, func(t *testing.T) {
				m, _ := rollbackTestEnv(t)
				if reverted {
					data := []byte("network: {version: 2, ethernets: {}}\n")
					if kind == "nft" {
						data = []byte("table inet easy_waf { }\n")
						if err := os.WriteFile(nftRulesPath, data, 0o600); err != nil {
							t.Fatal(err)
						}
					}
					if err := stateWriteFile(rollbackBackupPath(kind, testToken), data, 0o600); err != nil {
						t.Fatal(err)
					}
					if err := RunRevert(kind, testToken); err != nil {
						t.Fatal(err)
					}
				}
				before := len(m.calls)
				commit := nftCommit
				if kind == "netplan" {
					commit = netplanCommit
				}
				resp := commit(context.Background(), m, testToken)
				if resp.OK || resp.Code == 0 || resp.Error == "" {
					t.Fatalf("absent backup falsely confirmed as kept: %+v", resp)
				}
				if len(m.calls) != before {
					t.Fatalf("unknown/reverted token touched systemd: %v", m.calls[before:])
				}
			})
		}
	}
}

func seedReceiptChange(t *testing.T, kind string) (*recordingRunner, string) {
	t.Helper()
	m, _ := rollbackTestEnv(t)
	live := netplanPath
	data := []byte("network: {version: 2, ethernets: {}}\n")
	if kind == "nft" {
		live = nftRulesPath
		data = []byte("table inet easy_waf { }\n")
	}
	if err := os.WriteFile(live, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := stateWriteFile(rollbackBackupPath(kind, testToken), data, 0o600); err != nil {
		t.Fatal(err)
	}
	return m, live
}

func TestCommitReceiptSurvivesStartupAndNewApplyInvalidatesIt(t *testing.T) {
	for _, kind := range []string{"nft", "netplan"} {
		t.Run(kind, func(t *testing.T) {
			m, live := seedReceiptChange(t, kind)
			d := Dispatcher{Runner: m}
			ctx := t.Context()
			if resp := d.Dispatch(ctx, []string{kind + "-commit", testToken}); !resp.OK {
				t.Fatal(resp.Error)
			}
			if data, err := os.ReadFile(rollbackReceiptPath(kind)); err != nil || string(data) != testToken {
				t.Fatalf("receipt must contain only the confirmed token: %q, %v", data, err)
			}
			before := len(m.calls)
			RevertPendingChanges()
			// A fresh dispatcher and startup recovery use persisted state; no
			// in-memory flag or surviving systemd unit is evidence of a commit.
			fresh := &recordingRunner{failOn: map[string]bool{binSystemctl + " stop": true}}
			restarted := Dispatcher{Runner: fresh}
			if resp := restarted.Dispatch(ctx, []string{kind + "-commit", testToken}); !resp.OK {
				t.Fatalf("confirmed retry after startup failed: %s", resp.Error)
			}
			if len(m.calls) != before || len(fresh.calls) != 0 {
				t.Fatal("confirmed retry or startup changed the live configuration")
			}
			mode := nftRulesMode
			if kind == "netplan" {
				mode = netplanMode
			}
			if _, err := beginConfirmedChange(ctx, m, kind, testToken, live, mode, 90); err == nil {
				t.Fatal("already confirmed token reused for a new change")
			}
			const nextToken = "1234567890abcdef"
			if _, err := beginConfirmedChange(ctx, m, kind, nextToken, live, mode, 90); err != nil {
				t.Fatal(err)
			}
			before = len(m.calls)
			if resp := d.Dispatch(ctx, []string{kind + "-commit", testToken}); resp.OK {
				t.Fatal("stale receipt confirmed while another change was pending")
			}
			if len(m.calls) != before {
				t.Fatal("stale token interfered with the new timer")
			}
			if err := RunRevert(kind, nextToken); err != nil {
				t.Fatal(err)
			}
			for _, token := range []string{testToken, nextToken} {
				if resp := d.Dispatch(ctx, []string{kind + "-commit", token}); resp.OK {
					t.Fatal("stale or reverted token accepted after the new change reverted")
				}
			}
		})
	}
}

func TestCommitReceiptDoesNotCrossSubsystems(t *testing.T) {
	m, _ := seedReceiptChange(t, "nft")
	ctx := t.Context()
	if resp := nftCommit(ctx, m, testToken); !resp.OK {
		t.Fatal(resp.Error)
	}
	if resp := netplanCommit(ctx, m, testToken); resp.OK {
		t.Fatal("firewall receipt was accepted as a network confirmation")
	}
	if _, err := beginConfirmedChange(ctx, m, "netplan", testToken, netplanPath, netplanMode, 90); err != nil {
		t.Fatal(err)
	}
	if resp := nftCommit(ctx, m, testToken); !resp.OK {
		t.Fatal("starting network apply invalidated the firewall receipt")
	}
	if resp := netplanCommit(ctx, m, testToken); !resp.OK {
		t.Fatal(resp.Error)
	}
	entries, err := os.ReadDir(filepath.Join(stateDir, "rollback"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("receipt storage must be bounded to one file per subsystem: %v", entries)
	}
}

func TestMalformedOrForeignReceiptCannotConfirm(t *testing.T) {
	for _, scenario := range []string{"empty", "too large", "invalid token", "foreign token", "directory"} {
		t.Run(scenario, func(t *testing.T) {
			m, _ := rollbackTestEnv(t)
			data := []byte("")
			switch scenario {
			case "too large":
				data = []byte(strings.Repeat("a", 65))
			case "invalid token":
				data = []byte("not-a-token")
			case "foreign token":
				data = []byte("1234567890abcdef")
			}
			if scenario == "directory" {
				if err := os.Mkdir(rollbackReceiptPath("nft"), 0o700); err != nil {
					t.Fatal(err)
				}
			} else if err := stateWriteFile(rollbackReceiptPath("nft"), data, 0o600); err != nil {
				t.Fatal(err)
			}
			if resp := nftCommit(t.Context(), m, testToken); resp.OK || resp.Error == "" {
				t.Fatalf("unusable receipt accepted: %+v", resp)
			}
			if len(m.calls) != 0 {
				t.Fatal("unusable receipt touched systemd")
			}
		})
	}
}

func TestCommitReceiptWriteFailureReportsKeptConfiguration(t *testing.T) {
	for _, kind := range []string{"nft", "netplan"} {
		t.Run(kind, func(t *testing.T) {
			m, live := seedReceiptChange(t, kind)
			before, err := os.ReadFile(live)
			if err != nil {
				t.Fatal(err)
			}
			// Both OS implementations must fail to replace a nonempty directory.
			receipt := rollbackReceiptPath(kind)
			if err := os.Mkdir(receipt, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(receipt, "keep"), nil, 0o600); err != nil {
				t.Fatal(err)
			}
			d := Dispatcher{Runner: m}
			resp := d.Dispatch(t.Context(), []string{kind + "-commit", testToken})
			if resp.OK || !strings.Contains(resp.Error, "change kept but recording confirmation failed") {
				t.Fatalf("late receipt failure misreported: %+v", resp)
			}
			if _, err := os.Stat(rollbackBackupPath(kind, testToken)); !os.IsNotExist(err) {
				t.Fatalf("did not reach the post-removal failure: %v", err)
			}
			RevertPendingChanges()
			if after, err := os.ReadFile(live); err != nil || string(after) != string(before) {
				t.Fatalf("kept configuration was changed: %q, %v", after, err)
			}
			if err := os.Remove(filepath.Join(receipt, "keep")); err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(receipt); err != nil {
				t.Fatal(err)
			}
			if retry := d.Dispatch(t.Context(), []string{kind + "-commit", testToken}); retry.OK {
				t.Fatal("retry invented confirmation after a failed receipt write")
			}
		})
	}
}

func TestPendingRecoveryInvalidatesStaleConfirmation(t *testing.T) {
	for _, kind := range []string{"nft", "netplan"} {
		t.Run(kind, func(t *testing.T) {
			m, _ := seedReceiptChange(t, kind)
			// A recovered/inconsistent state tree may contain both files. The
			// pending backup must win, and its revert must invalidate the receipt.
			if err := stateWriteFile(rollbackReceiptPath(kind), []byte(testToken), 0o600); err != nil {
				t.Fatal(err)
			}
			RevertPendingChanges()
			if _, err := os.Stat(rollbackBackupPath(kind, testToken)); !os.IsNotExist(err) {
				t.Fatalf("pending recovery did not finish: %v", err)
			}
			d := Dispatcher{Runner: m}
			if resp := d.Dispatch(t.Context(), []string{kind + "-commit", testToken}); resp.OK {
				t.Fatal("stale receipt survived recovery and confirmed a reverted change")
			}
		})
	}
}

func TestRecoveryReceiptInvalidationFailurePreservesPendingState(t *testing.T) {
	for _, kind := range []string{"nft", "netplan"} {
		t.Run(kind, func(t *testing.T) {
			m, _ := seedReceiptChange(t, kind)
			receipt := rollbackReceiptPath(kind)
			if err := os.Mkdir(receipt, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(receipt, "keep"), nil, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := RunRevert(kind, testToken); err == nil || !strings.Contains(err.Error(), "invalidate rollback confirmation") {
				t.Fatalf("receipt invalidation failure hidden: %v", err)
			}
			if len(m.calls) != 0 {
				t.Fatal("live state changed before invalidating stale confirmation")
			}
			if _, err := os.Stat(rollbackBackupPath(kind, testToken)); err != nil {
				t.Fatal("recovery failure lost the pending backup")
			}
			if err := os.Remove(filepath.Join(receipt, "keep")); err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(receipt); err != nil {
				t.Fatal(err)
			}
			if err := RunRevert(kind, testToken); err != nil {
				t.Fatalf("recovery could not resume after repair: %v", err)
			}
		})
	}
}
