// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package hostd

import (
	"os"
	"path/filepath"
	"testing"
)

var testAptLogDir string

// TestMain enables unix-socket tests when `go test` runs as a user other than easy-waf.
func TestMain(m *testing.M) {
	SetBypassPeerCheckForTest(true)
	if dir, err := os.MkdirTemp("", "easy-waf-hostd-apt-*"); err == nil {
		testAptLogDir = dir
		SetAptActionLogPathOverrideForTest(filepath.Join(dir, "apt-action.log"))
	}
	code := m.Run()
	if testAptLogDir != "" {
		_ = os.RemoveAll(testAptLogDir)
		aptActionLogPathOverride = ""
	}
	os.Exit(code)
}

// SetStateDirForTest points the state-directory helpers at a temporary tree and
// returns a function that restores the real path.
func SetStateDirForTest(dir string) func() {
	prev := stateDir
	stateDir = dir
	return func() { stateDir = prev }
}
