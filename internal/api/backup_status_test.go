// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package api

import "testing"

func TestBackupServiceStatus(t *testing.T) {
	const finished = "ExecMainExitTimestamp=Wed 2026-11-25 12:34:56 UTC\n"
	for _, tc := range []struct {
		properties, state string
		timestamp         bool
	}{
		{"LoadState=not-found\nActiveState=inactive\nResult=success", "unavailable", false},
		{"LoadState=loaded\nActiveState=inactive\nResult=success", "unavailable", false},
		{"LoadState=loaded\nActiveState=activating\n" + finished, "running", false},
		{"LoadState=loaded\nActiveState=inactive\nResult=success\n" + finished, "succeeded", true},
		{"LoadState=loaded\nActiveState=failed\nResult=exit-code\n" + finished, "failed", true},
		{"LoadState=loaded\nActiveState=failed\nResult=resources", "failed", false},
	} {
		got := parseBackupServiceStatus(tc.properties)
		if got.State != tc.state || (got.FinishedAt != nil) != tc.timestamp {
			t.Errorf("properties %q: got %+v", tc.properties, got)
		}
		if got.FinishedAt != nil && got.FinishedAt.UTC().Format("2006-01-02T15:04:05Z") != "2026-11-25T12:34:56Z" {
			t.Errorf("unexpected completion time %s", got.FinishedAt)
		}
	}
}
