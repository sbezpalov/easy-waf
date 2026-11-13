// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package hostd

import (
	"os"
	"path/filepath"
	"testing"
)

func TestStateRenamePreservesContentsAndRefusesOverwrite(t *testing.T) {
	state := newTestStateDir(t)
	src, dst := filepath.Join(state, "rollback", "pending.bak"), filepath.Join(state, "rollback", "pending.reverting")
	if err := stateWriteFile(src, []byte("original backup"), 0o600); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(src)
	if err != nil {
		t.Fatal(err)
	}
	if err := stateRenameFile(src, dst); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(dst); err != nil || string(data) != "original backup" {
		t.Fatalf("backup changed during claim: %q, %v", data, err)
	}
	after, err := os.Stat(dst)
	if err != nil || before.Mode().Perm() != after.Mode().Perm() {
		t.Fatalf("backup permissions changed: %v", err)
	}
	if _, err := os.Stat(src); !os.IsNotExist(err) {
		t.Fatalf("source remains after claim: %v", err)
	}
	if err := stateWriteFile(src, []byte("other pending backup"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := stateRenameFile(src, dst); err == nil {
		t.Fatal("existing recovery backup overwritten")
	}
	for path, want := range map[string]string{src: "other pending backup", dst: "original backup"} {
		if data, err := os.ReadFile(path); err != nil || string(data) != want {
			t.Fatalf("failed claim changed %s: %q, %v", filepath.Base(path), data, err)
		}
	}
}

func TestStateRenameRejectsOutsideAndDifferentDirectories(t *testing.T) {
	state := newTestStateDir(t)
	_, outside := secretOutside(t)
	src, dst := filepath.Join(state, "rollback", "pending.bak"), filepath.Join(state, "rollback", "pending.reverting")
	if err := stateWriteFile(src, []byte("original backup"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, paths := range [][2]string{{outside, dst}, {src, outside}, {src, filepath.Join(state, "other", "reverting")}} {
		if err := stateRenameFile(paths[0], paths[1]); err == nil {
			t.Fatalf("unsafe rename accepted: %v", paths)
		}
	}
	if data, err := os.ReadFile(src); err != nil || string(data) != "original backup" {
		t.Fatalf("unsafe claim lost source: %q, %v", data, err)
	}
	if data, err := os.ReadFile(outside); err != nil || string(data) != "root:$6$hash\n" {
		t.Fatalf("unsafe claim touched outside file: %q, %v", data, err)
	}
}

func TestStateRenameRefusesSymlinks(t *testing.T) {
	for _, scenario := range []string{"source", "target", "parent"} {
		t.Run(scenario, func(t *testing.T) {
			state := newTestStateDir(t)
			outside, secret := secretOutside(t)
			src, dst := filepath.Join(state, "pending.bak"), filepath.Join(state, "pending.reverting")
			link, target := src, secret
			if scenario != "source" {
				if err := stateWriteFile(src, []byte("original backup"), 0o600); err != nil {
					t.Fatal(err)
				}
				link = dst
			}
			if scenario == "parent" {
				link, target = filepath.Join(state, "linked"), outside
				src, dst = filepath.Join(link, "shadow"), filepath.Join(link, "moved")
			}
			if err := os.Symlink(target, link); err != nil {
				t.Skipf("symlinks unavailable: %v", err)
			}
			if err := stateRenameFile(src, dst); err == nil {
				t.Fatal("symlinked state rename accepted")
			}
			if data, err := os.ReadFile(secret); err != nil || string(data) != "root:$6$hash\n" {
				t.Fatalf("outside file moved or modified: %q, %v", data, err)
			}
		})
	}
}
