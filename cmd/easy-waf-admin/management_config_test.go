// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestManagementConfigRejectsConflictingFlagsBeforeOpeningTheDatabase(t *testing.T) {
	previous := os.Args
	t.Cleanup(func() { os.Args = previous })
	missing := filepath.Join(t.TempDir(), "missing.env")
	cases := []struct {
		args []string
		want string
	}{
		{[]string{"-listen-loopback", "-listen-lan"}, "listen-loopback"},
		{[]string{"-listen-loopback", "-listen-http", "127.0.0.1:8000"}, "listen-http"},
		{[]string{"-listen-lan", "-listen-https", "0.0.0.0:8443"}, "listen-https"},
		{[]string{"-default-management-cidrs", "-management-cidrs", "10.0.0.0/8"}, "management-cidrs"},
	}
	for _, tc := range cases {
		os.Args = append([]string{"easy-waf-admin", "management-config", "-env-file", missing}, tc.args...)
		err := runManagementConfig()
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("args %v: got %v", tc.args, err)
		}
		if strings.Contains(err.Error(), "DATABASE_URL") {
			t.Fatalf("args %v reached the database: %v", tc.args, err)
		}
	}
}
