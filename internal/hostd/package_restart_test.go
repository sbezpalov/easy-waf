// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package hostd

import (
	"context"
	"errors"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"
)

type packageRestartRunner func(context.Context, string, ...string) ([]byte, []byte, int, error)

func (f packageRestartRunner) Run(ctx context.Context, name string, args ...string) ([]byte, []byte, int, error) {
	return f(ctx, name, args...)
}

func TestPackageRestartRequiresLocksAndHoldsThemAcrossTheJob(t *testing.T) {
	for _, outcome := range []string{"success", "acquire", "command", "exit", "release", "canceled", "cancel_during_job"} {
		t.Run(outcome, func(t *testing.T) {
			failure := errors.New("fixture " + outcome)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			held, calls, releases := false, 0, 0
			acquire := func(context.Context) (func() error, error) {
				if outcome == "acquire" {
					return nil, failure
				}
				held = true
				if outcome == "canceled" {
					cancel()
				}
				return func() error {
					held = false
					releases++
					if outcome == "release" {
						return failure
					}
					return nil
				}, nil
			}
			runner := packageRestartRunner(func(ctx context.Context, name string, args ...string) ([]byte, []byte, int, error) {
				calls++
				if !held || name != binSystemctl || !slices.Equal(args, []string{"try-restart", "easy-waf-apt.service", "easy-waf-hostd.service"}) {
					t.Errorf("unsafe restart boundary: held=%v command=%s %v", held, name, args)
				}
				deadline, ok := ctx.Deadline()
				if !ok || time.Until(deadline) > hostCommandTimeout {
					t.Error("restart command lost its execution budget")
				}
				if outcome == "cancel_during_job" {
					cancel()
					if ctx.Err() != nil {
						t.Error("acquisition cancellation interrupted the manager job wait")
					}
				}
				if outcome == "command" {
					return nil, nil, 1, failure
				}
				if outcome == "exit" {
					return nil, []byte("unit failed"), 7, nil
				}
				return nil, nil, 0, nil
			})
			err := restartBrokerAfterPackages(ctx, runner, acquire)
			wantError := outcome != "success" && outcome != "cancel_during_job"
			if held || (wantError && err == nil) || (!wantError && err != nil) {
				t.Fatalf("lost failure/lease: held=%v err=%v", held, err)
			}
			wantCalls, wantReleases := 1, 1
			if outcome == "acquire" {
				wantCalls, wantReleases = 0, 0
			}
			if outcome == "canceled" {
				wantCalls = 0
			}
			if calls != wantCalls || releases != wantReleases {
				t.Fatalf("wrong restart/cleanup: calls=%d releases=%d err=%v", calls, releases, err)
			}
			switch outcome {
			case "acquire", "command", "release":
				if !errors.Is(err, failure) {
					t.Fatalf("lost cause: %v", err)
				}
			case "canceled":
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("lost cancellation: %v", err)
				}
			case "exit":
				if !strings.Contains(err.Error(), "unit failed") {
					t.Fatalf("lost restart diagnostic: %v", err)
				}
			}
		})
	}
}

func TestPackageRestartIsNotABrokerOpcode(t *testing.T) {
	runner := &mockRunner{}
	d := Dispatcher{Runner: runner}
	if resp := d.Dispatch(t.Context(), []string{"restart-after-packages"}); resp.OK || runner.lastName != "" {
		t.Fatalf("root maintenance CLI became remotely callable: %+v command=%s", resp, runner.lastName)
	}
	if runtime.GOOS != "linux" {
		if _, err := acquireDpkgLocks(t.Context()); err == nil || !strings.Contains(err.Error(), "only on Linux") {
			t.Fatalf("non-Linux build emulated package locks: %v", err)
		}
	}
}
