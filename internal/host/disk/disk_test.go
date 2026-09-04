// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package disk

import (
	"runtime"
	"testing"
)

func TestUsage_root(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("statfs not used on windows")
	}
	mounts, err := Usage("/")
	if err != nil {
		t.Fatal(err)
	}
	if len(mounts) != 1 {
		t.Fatalf("mounts: %+v", mounts)
	}
	m := mounts[0]
	if m.TotalBytes == 0 {
		t.Fatal("expected non-zero total")
	}
	if m.UsedPercent < 0 || m.UsedPercent > 100 {
		t.Fatalf("used_percent: %d", m.UsedPercent)
	}
	if m.FreeBytes+m.UsedBytes > m.TotalBytes+1024 {
		t.Fatalf("inconsistent bytes: total=%d used=%d free=%d", m.TotalBytes, m.UsedBytes, m.FreeBytes)
	}
}

func TestUsage_skipsMissingPath(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("statfs not used on windows")
	}
	mounts, err := Usage("/", "/nonexistent-path-ewaf-disk-test")
	if err != nil {
		t.Fatal(err)
	}
	if len(mounts) < 1 {
		t.Fatalf("expected at least /: %+v", mounts)
	}
}

func TestUsage_dedupesSameFilesystem(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("statfs not used on windows")
	}
	mounts, err := Usage("/", "/")
	if err != nil {
		t.Fatal(err)
	}
	if len(mounts) != 1 {
		t.Fatalf("expected dedup: %+v", mounts)
	}
}
