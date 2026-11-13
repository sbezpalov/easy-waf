// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package hostd

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

type commandDeadlineProbe struct {
	deadline time.Time
	bounded  bool
}

type commandContextFailure struct{ cause error }

func (f commandContextFailure) Run(context.Context, string, ...string) ([]byte, []byte, int, error) {
	return nil, []byte("tool warning"), -1, f.cause
}

func TestRollbackCommandWrappersKeepContextFailure(t *testing.T) {
	for _, cause := range []error{context.Canceled, context.DeadlineExceeded} {
		for _, operation := range []string{"schedule", "nft", "netplan", "response"} {
			t.Run(operation+"/"+cause.Error(), func(t *testing.T) {
				_, _ = seedReceiptChange(t, "netplan")
				runner := commandContextFailure{cause: cause}
				DefaultRunner = runner
				var err error
				switch operation {
				case "schedule":
					_, err = scheduleRevert(t.Context(), runner, "netplan", testToken, 90)
				case "nft":
					err = runNftScript(t.Context(), "table inet easy_waf { }\n")
				case "netplan":
					err = RunRevert("netplan", testToken)
				case "response":
					resp := failExec(nil, []byte("tool warning"), -1, cause)
					if !strings.Contains(resp.Error, cause.Error()) || !strings.Contains(resp.Error, "tool warning") {
						t.Fatalf("response dropped failure or stderr: %+v", resp)
					}
					return
				}
				if !errors.Is(err, cause) || !strings.Contains(err.Error(), "tool warning") {
					t.Fatalf("wrapper dropped failure or stderr: %v", err)
				}
			})
		}
	}
}

func (p *commandDeadlineProbe) Run(ctx context.Context, _ string, _ ...string) ([]byte, []byte, int, error) {
	p.deadline, p.bounded = ctx.Deadline()
	return nil, nil, 0, nil
}

func (p *commandDeadlineProbe) RunApt(ctx context.Context, name string, args []string, _ func(string) error) (int, error) {
	_, _, code, err := p.Run(ctx, name, args...)
	return code, err
}

func TestDispatchBoundsCommandsAndPreservesEarlierDeadline(t *testing.T) {
	overrideAptActionLogForTest(t)
	resetAptUpgradeState()
	t.Cleanup(resetAptUpgradeState)
	for _, tc := range []struct {
		name   string
		argv   []string
		budget time.Duration
	}{
		{"ordinary", []string{"nft-list"}, 2 * time.Minute},
		{"apt", []string{"apt-upgrade"}, 30 * time.Minute},
	} {
		t.Run(tc.name, func(t *testing.T) {
			probe := &commandDeadlineProbe{}
			d := Dispatcher{Runner: probe}
			started := time.Now()
			if resp := d.Dispatch(context.Background(), tc.argv); !resp.OK {
				t.Fatal(resp.Error)
			}
			if !probe.bounded || probe.deadline.Before(started.Add(tc.budget-time.Second)) || probe.deadline.After(time.Now().Add(tc.budget)) {
				t.Fatalf("command budget not enforced: bounded=%v deadline=%v", probe.bounded, probe.deadline)
			}
			earlier := time.Now().Add(5 * time.Second)
			ctx, cancel := context.WithDeadline(context.Background(), earlier)
			defer cancel()
			if resp := d.Dispatch(ctx, tc.argv); !resp.OK {
				t.Fatal(resp.Error)
			}
			if !probe.bounded || !probe.deadline.Equal(earlier) {
				t.Fatal("command extended the caller's earlier deadline")
			}
		})
	}
}
