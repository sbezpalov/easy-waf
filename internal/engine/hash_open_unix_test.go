// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package engine

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestHashArtifactRejectsFIFOWithoutWaiting(t *testing.T) {
	path := filepath.Join(t.TempDir(), "artifact")
	if err := unix.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	finished := make(chan error, 1)
	go func() {
		_, err := sha256HexFile(path)
		finished <- err
	}()
	select {
	case err := <-finished:
		if err == nil || !strings.Contains(err.Error(), "expected a regular file") {
			t.Fatalf("unexpected hash error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("hash waited for a FIFO writer")
	}
	go func() {
		dst := filepath.Join(filepath.Dir(path), "live.cfg")
		finished <- copyFileAtomic(path, dst, 0o640, sha256HexBytes(nil))
	}()
	select {
	case err := <-finished:
		if err == nil || !strings.Contains(err.Error(), "expected a regular file") {
			t.Fatalf("unexpected copy error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("artifact copy waited for a FIFO writer")
	}

	// Simulate replacement between path inspection and Open by passing the
	// FIFO directly to the opener. File type is checked again on the handle.
	go func() {
		f, err := openArtifactForHash(path)
		if err == nil {
			info, statErr := f.Stat()
			_ = f.Close()
			err = statErr
			if statErr == nil && info.Mode()&os.ModeNamedPipe == 0 {
				err = errors.New("opened file was not a FIFO")
			}
		}
		finished <- err
	}()
	select {
	case err := <-finished:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("open waited for a FIFO writer after the path changed")
	}
}
