// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package hostd

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestOpenStagedFileRejectsFIFO(t *testing.T) {
	root := t.TempDir()
	restore := SetStateDirForTest(root)
	t.Cleanup(restore)
	staging := filepath.Join(root, "staging")
	if err := os.MkdirAll(staging, 0o750); err != nil {
		t.Fatal(err)
	}
	fifo := filepath.Join(staging, "hang.fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := openStagedFile(fifo)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected FIFO rejected")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("openStagedFile hung on FIFO")
	}
}
