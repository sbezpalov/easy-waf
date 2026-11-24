// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package hostd

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
)

type collectedRollbackServiceRunner struct {
	*recordingRunner
	state     string
	stateCode int
}

func (r collectedRollbackServiceRunner) Run(ctx context.Context, name string, args ...string) ([]byte, []byte, int, error) {
	out, stderr, code, err := r.recordingRunner.Run(ctx, name, args...)
	if name == binSystemctl && len(args) > 1 && strings.HasSuffix(args[len(args)-1], ".service") {
		switch args[0] {
		case "stop":
			return nil, []byte("Unit not loaded."), 5, nil
		case "show":
			return []byte(r.state), nil, r.stateCode, nil
		}
	}
	return out, stderr, code, err
}

func TestConfirmationVerifiesCollectedRollbackService(t *testing.T) {
	const collected = "LoadState=not-found\nActiveState=inactive\nJob=\n"
	for _, test := range []struct {
		name      string
		state     string
		stateCode int
		keep      bool
	}{
		{name: "collected", state: collected, keep: true},
		{name: "active", state: "LoadState=not-found\nActiveState=active\nJob=\n"},
		{name: "queued", state: "LoadState=not-found\nActiveState=inactive\nJob=123\n"},
		{name: "loaded", state: "LoadState=loaded\nActiveState=inactive\nJob=\n"},
		{name: "unknown job state", state: "LoadState=not-found\nActiveState=inactive\n"},
		{name: "status failed", state: collected, stateCode: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			m, live := seedReceiptChange(t, "nft")
			before, err := os.ReadFile(live)
			if err != nil {
				t.Fatal(err)
			}
			pending := string(before) + "# pending change\n"
			if err := os.WriteFile(live, []byte(pending), nftRulesMode); err != nil {
				t.Fatal(err)
			}
			r := collectedRollbackServiceRunner{recordingRunner: m, state: test.state, stateCode: test.stateCode}
			resp := nftCommit(t.Context(), r, testToken)
			if resp.OK != test.keep {
				t.Fatalf("confirmation result: %+v, keep=%v", resp, test.keep)
			}
			want, receipt := string(before), ""
			if test.keep {
				want, receipt = pending, testToken
			}
			if data, err := os.ReadFile(live); err != nil || string(data) != want {
				t.Fatalf("unexpected live ruleset: %q, %v", data, err)
			}
			if got, err := readRollbackReceipt("nft"); err != nil || got != receipt {
				t.Fatalf("unexpected confirmation receipt: %q, %v", got, err)
			}
		})
	}
}

func TestFailedConfirmationAttemptsSafetyRecovery(t *testing.T) {
	for _, kind := range []string{"nft", "netplan"} {
		for _, recoveryFails := range []bool{false, true} {
			name := kind + "/recovered"
			if recoveryFails {
				name = kind + "/recovery-failed"
			}
			t.Run(name, func(t *testing.T) {
				m, live := seedReceiptChange(t, kind)
				baseline, err := os.ReadFile(live)
				if err != nil {
					t.Fatal(err)
				}
				pending := string(baseline) + "# pending change\n"
				if err := os.WriteFile(live, []byte(pending), 0o600); err != nil {
					t.Fatal(err)
				}
				m.failOn[binSystemctl+" stop"] = true
				if recoveryFails {
					if kind == "nft" {
						writeGuard(t)
						m.failOn[binNft+" -f "+nftGuardPath] = true
					} else {
						m.failOn[binNetplan+" apply"] = true
					}
				}
				d := Dispatcher{Runner: m}
				resp := d.Dispatch(t.Context(), []string{kind + "-commit", testToken})
				if resp.OK || !strings.Contains(resp.Error, "stop rollback units") {
					t.Fatalf("confirmation failure hidden: %+v", resp)
				}
				if data, err := os.ReadFile(live); err != nil || string(data) != string(baseline) {
					t.Fatalf("no immediate recovery after failed confirmation: %q, %v", data, err)
				}
				if confirmed, err := readRollbackReceipt(kind); err != nil || confirmed != "" {
					t.Fatalf("failed confirmation left a receipt: %q, %v", confirmed, err)
				}
				if recoveryFails {
					if !strings.Contains(resp.Error, "immediate rollback also failed") {
						t.Fatalf("recovery failure lost: %+v", resp)
					}
					if data, err := os.ReadFile(rollbackRevertingPath(kind, testToken)); err != nil || string(data) != string(baseline) {
						t.Fatalf("failed recovery lost its backup: %q, %v", data, err)
					}
					m.failOn = map[string]bool{}
					RevertPendingChanges()
				}
				for _, path := range []string{rollbackBackupPath(kind, testToken), rollbackRevertingPath(kind, testToken)} {
					if _, err := os.Stat(path); !os.IsNotExist(err) {
						t.Fatalf("completed recovery still pending: %v", err)
					}
				}
				if retry := d.Dispatch(t.Context(), []string{kind + "-commit", testToken}); retry.OK {
					t.Fatal("failed/reverted confirmation accepted on retry")
				}
			})
		}
	}
}

type confirmationContextRunner struct{ delegate *recordingRunner }

func (r confirmationContextRunner) Run(ctx context.Context, name string, args ...string) ([]byte, []byte, int, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, 1, err
	}
	return r.delegate.Run(ctx, name, args...)
}

func TestCanceledConfirmationStillRecovers(t *testing.T) {
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
			runner := confirmationContextRunner{delegate: m}
			DefaultRunner = runner
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			err = commitConfirmedChange(ctx, runner, kind, testToken)
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("cancellation reason lost: %v", err)
			}
			if data, err := os.ReadFile(live); err != nil || string(data) != string(baseline) {
				t.Fatalf("canceled confirmation suppressed safety recovery: %q, %v", data, err)
			}
			if len(m.calls) == 0 {
				t.Fatal("recovery command never received a usable context")
			}
			if confirmed, err := readRollbackReceipt(kind); err != nil || confirmed != "" {
				t.Fatalf("canceled confirmation left a receipt: %q, %v", confirmed, err)
			}
			for _, path := range []string{rollbackBackupPath(kind, testToken), rollbackRevertingPath(kind, testToken)} {
				if _, err := os.Stat(path); !os.IsNotExist(err) {
					t.Fatalf("canceled confirmation left completed recovery pending: %v", err)
				}
			}
		})
	}
}
