// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package hostd

import "testing"

func TestFail2banClientArgs_allowed(t *testing.T) {
	cases := [][]string{
		{"ping"},
		{"status"},
		{"status", "sshd"},
		{"set", "sshd", "unbanip", "203.0.113.1"},
	}
	for _, args := range cases {
		got, ok := fail2banClientArgs(args)
		if !ok {
			t.Fatalf("expected allowed: %v", args)
		}
		if len(got) != len(args) {
			t.Fatalf("args: %v", got)
		}
	}
}

func TestFail2banClientArgs_reject(t *testing.T) {
	cases := [][]string{
		{"reload"},
		{"set", "sshd", "banip", "1.2.3.4"},
		{"status", "../evil"},
		{"set", "sshd", "unbanip", "not-ip"},
		{"ping", "extra"},
		{"status", "sshd", "more"},
	}
	for _, args := range cases {
		if _, ok := fail2banClientArgs(args); ok {
			t.Fatalf("expected reject: %v", args)
		}
	}
}
