// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package hostd

import (
	"os"
	"testing"
)

func TestRecoveredAptProcessDoesNotOwnLocalReservation(t *testing.T) {
	for _, disappeared := range []bool{false, true} {
		name := "dead PID"
		if disappeared {
			name = "missing PID"
		}
		t.Run(name, func(t *testing.T) {
			overrideAptActionLogForTest(t)
			resetAptUpgradeState()
			defer resetAptUpgradeState()
			// Signal 0 observes this test process without sending it a signal.
			if err := writeAptActionPID(os.Getpid()); err != nil {
				t.Fatal(err)
			}
			if started, err := aptActionTryStart(); err != nil || started {
				t.Fatalf("surviving process did not block a new primary: %v, %v", started, err)
			}
			if active, _, _ := aptActionSnapshot(); !active {
				t.Fatal("recovered running process reported inactive")
			}
			if disappeared {
				if err := clearAptActionPID(); err != nil {
					t.Fatal(err)
				}
			} else if err := writeAptActionPID(0); err != nil {
				t.Fatal(err)
			}
			if active, code, message := aptActionSnapshot(); active || code != -1 || message == "" {
				t.Fatalf("recovered completion fabricated a result: active=%v code=%d error=%q", active, code, message)
			}
			if started, err := aptActionTryStart(); err != nil || !started {
				t.Fatalf("recovered process left a local reservation: %v, %v", started, err)
			}
			aptActionFinish(3, "known result")
			if active, code, _ := aptActionSnapshot(); active || code != 3 {
				t.Fatalf("new local result lost: active=%v code=%d", active, code)
			}
		})
	}
}
