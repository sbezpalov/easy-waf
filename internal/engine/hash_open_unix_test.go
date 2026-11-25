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

	"github.com/easy-waf/easy-waf/internal/config"
	"golang.org/x/sys/unix"
)

func TestHashArtifactRejectsFIFOWithoutWaiting(t *testing.T) {
	state := t.TempDir()
	revisions := filepath.Join(state, "revisions")
	if err := os.Mkdir(revisions, 0o750); err != nil {
		t.Fatal(err)
	}
	sha := strings.Repeat("a", 64)
	path := filepath.Join(revisions, "haproxy-"+sha[:12]+".cfg")
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
	go func() {
		e := New(state, nil, config.GlobalSettings{})
		data, truncated := e.RevisionPreview(sha)
		if data != nil || truncated {
			finished <- errors.New("revision preview accepted a FIFO")
			return
		}
		finished <- nil
	}()
	select {
	case err := <-finished:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("revision preview waited for a FIFO writer")
	}

	// Simulate replacement between path inspection and Open by passing the
	// FIFO directly to the opener. File type is checked again on the handle.
	go func() {
		f, err := os.OpenFile(path, os.O_RDONLY|artifactReadFlags, 0)
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
