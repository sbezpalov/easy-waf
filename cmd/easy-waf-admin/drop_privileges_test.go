// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestStateOwnerUIDReadsDirectoryOwner(t *testing.T) {
	dir := t.TempDir()

	uid, gid, err := stateOwner(dir)

	if err != nil {
		t.Fatal(err)
	}
	if uid != os.Getuid() || gid != os.Getgid() {
		t.Fatalf("owner %d:%d, want %d:%d", uid, gid, os.Getuid(), os.Getgid())
	}
}

func TestStateOwnerFailsOnMissingDirectory(t *testing.T) {
	if _, _, err := stateOwner(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("want an error: continuing as root would leave root-owned files")
	}
}

func TestNeedsDrop(t *testing.T) {
	for name, tc := range map[string]struct {
		euid, owner int
		want        bool
	}{
		"root with service-owned state": {euid: 0, owner: 103, want: true},
		"root with root-owned state":    {euid: 0, owner: 0, want: false},
		"already the service account":   {euid: 103, owner: 103, want: false},
	} {
		t.Run(name, func(t *testing.T) {
			if got := needsDrop(tc.euid, tc.owner); got != tc.want {
				t.Fatalf("needsDrop(%d, %d) = %v", tc.euid, tc.owner, got)
			}
		})
	}
}

func TestSwitchIdentityStopsAtFirstFailure(t *testing.T) {
	failure := errors.New("refused")
	var calls []string
	ids := identitySwitch{
		setgroups: func([]int) error { calls = append(calls, "setgroups"); return nil },
		setgid:    func(int) error { calls = append(calls, "setgid"); return failure },
		setuid:    func(int) error { calls = append(calls, "setuid"); return nil },
	}

	err := ids.apply(103, 105, []int{105, 102})

	if !errors.Is(err, failure) {
		t.Fatalf("err = %v", err)
	}
	if len(calls) != 2 {
		t.Fatalf("calls = %v: setuid must not run after a failed setgid", calls)
	}
}
