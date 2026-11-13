// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package hostd

import (
	"context"
	"testing"
	"time"
)

func TestConfirmedChangePreservesTimerDeadline(t *testing.T) {
	for _, kind := range []string{"nft", "netplan"} {
		t.Run(kind, func(t *testing.T) {
			m, _ := rollbackTestEnv(t)
			var armed, finished time.Time
			m.onRun = func(name string, _ []string) {
				if name == "systemd-run" {
					armed = time.Now()
					time.Sleep(30 * time.Millisecond)
					finished = time.Now()
				}
			}
			started := time.Now()
			path, mode := nftRulesPath, nftRulesMode
			if kind == "netplan" {
				path, mode = netplanPath, netplanMode
			}
			deadline, err := beginConfirmedChange(context.Background(), m, kind, testToken, path, mode, 90)
			if err != nil {
				t.Fatal(err)
			}
			if armed.IsZero() || finished.Before(armed) || deadline.Before(started.Add(90*time.Second)) || deadline.After(armed.Add(90*time.Second)) {
				t.Fatalf("deadline must be based on arming, not completion: started=%v armed=%v finished=%v expires=%v", started, armed, finished, deadline)
			}
		})
	}
}
