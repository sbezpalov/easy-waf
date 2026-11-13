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
