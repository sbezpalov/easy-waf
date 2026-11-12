// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package hostd

import (
	"os"
	"runtime"
	"testing"
)

func assertFileMode(t *testing.T, info os.FileInfo, want os.FileMode) {
	t.Helper()
	if runtime.GOOS == "windows" {
		// Windows exposes only a read-only attribute through os.FileMode, not
		// Unix owner/group/other permission bits.
		return
	}
	if got := info.Mode().Perm(); got != want {
		t.Fatalf("%s mode = %o, want %04o", info.Name(), got, want)
	}
}
