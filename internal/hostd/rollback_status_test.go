// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package hostd

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

func TestPendingRollbackStatusUsesPersistedDeadlineWithoutToken(t *testing.T) {
	_, _ = rollbackTestEnv(t)
	now := time.Now().UTC().Truncate(time.Second)
	cases := []struct {
		kind, token, suffix, phase string
		expires                    time.Time
		confirmable                bool
	}{
		{"netplan", testToken, ".bak", "pending", now.Add(time.Minute), true},
		{"nft", "0123456789abcdef0123456789abcdef", ".bak", "expired", now.Add(-time.Second), false},
	}
	for _, tc := range cases {
		path := rollbackBackupPath(tc.kind, tc.token)
		if tc.suffix == ".reverting" {
			path = rollbackRevertingPath(tc.kind, tc.token)
		}
		if err := stateWriteFile(path, []byte("baseline"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := writeRollbackDeadline(tc.kind, tc.token, tc.expires); err != nil {
			t.Fatal(err)
		}
	}

	status, err := pendingRollbackStatus(now)
	if err != nil {
		t.Fatal(err)
	}
	if len(status.Changes) != 2 {
		t.Fatalf("changes %+v", status.Changes)
	}
	for _, got := range status.Changes {
		var want *struct {
			kind, token, suffix, phase string
			expires                    time.Time
			confirmable                bool
		}
		for i := range cases {
			if cases[i].kind == got.Kind {
				want = &cases[i]
				break
			}
		}
		if want == nil || got.OperationID != rollbackOperationID(want.token) || got.OperationID == want.token ||
			got.Phase != want.phase || got.Confirmable != want.confirmable || got.ExpiresAt == nil || !got.ExpiresAt.Equal(want.expires) {
			t.Fatalf("change %+v, want %+v", got, want)
		}
	}
	resp := rollbackStatus()
	if !resp.OK || strings.Contains(resp.Stdout, testToken) || !strings.Contains(resp.Stdout, rollbackOperationID(testToken)) {
		t.Fatalf("status leaked token or lost operation id: %+v", resp)
	}
}

func TestExpiredCommitRevertsInsteadOfExtendingSafetyWindow(t *testing.T) {
	m, _ := rollbackTestEnv(t)
	baseline := []byte("network: {version: 2, ethernets: {}}\n")
	changed := []byte("network: {version: 2, ethernets: {eth0: {dhcp4: true}}}\n")
	if err := os.WriteFile(netplanPath, baseline, netplanMode); err != nil {
		t.Fatal(err)
	}
	if _, err := beginConfirmedChange(context.Background(), m, "netplan", testToken, netplanPath, netplanMode, 30); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(netplanPath, changed, netplanMode); err != nil {
		t.Fatal(err)
	}
	if err := writeRollbackDeadline("netplan", testToken, time.Now().UTC().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}

	err := commitConfirmedChange(context.Background(), m, "netplan", testToken)
	if err == nil || !strings.Contains(err.Error(), "safety window expired; change reverted") {
		t.Fatalf("expired commit: %v", err)
	}
	got, err := os.ReadFile(netplanPath)
	if err != nil || string(got) != string(baseline) {
		t.Fatalf("live netplan was not restored: %q %v", got, err)
	}
	if _, exists, err := stateFileSize(rollbackBackupPath("netplan", testToken)); err != nil || exists {
		t.Fatalf("pending backup remains: exists=%v err=%v", exists, err)
	}
	if receipt, err := readRollbackReceipt("netplan"); err != nil || receipt != "" {
		t.Fatalf("expired change was recorded as committed: %q %v", receipt, err)
	}
}

func TestLegacyPendingRollbackStatusKeepsUnknownDeadline(t *testing.T) {
	_, _ = rollbackTestEnv(t)
	if err := stateWriteFile(rollbackBackupPath("nft", testToken), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	status, err := pendingRollbackStatus(time.Now().UTC())
	if err != nil || len(status.Changes) != 1 {
		t.Fatalf("status %+v: %v", status, err)
	}
	if status.Changes[0].ExpiresAt != nil || !status.Changes[0].Confirmable || status.Changes[0].Phase != "pending" {
		t.Fatalf("legacy status %+v", status.Changes[0])
	}
}
