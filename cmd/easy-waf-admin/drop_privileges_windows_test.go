// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package main

import (
	"strings"
	"testing"
)

func TestDropToStateOwnerFailsClosedOnWindows(t *testing.T) {
	err := dropToStateOwner(t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "unsupported on Windows") {
		t.Fatalf("dropToStateOwner() error = %v, want unsupported-platform error", err)
	}
}
