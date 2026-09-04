// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package metrics

import (
	"io"
	"net"
	"path/filepath"
	"sync"
	"testing"
)

func TestHAProxyCollectorUnixMock(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "stats.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 64)
		_, _ = c.Read(buf)
		_, _ = io.WriteString(c, sampleStatsCSV)
	}()

	coll := NewHAProxyCollector()
	rep, err := coll.Fetch(sock)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Frontends) < 1 {
		t.Fatalf("expected frontends from socket, got %+v", rep)
	}
	_ = ln.Close()
	wg.Wait()

	rep2, err := coll.Fetch(sock)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep2.Frontends) != len(rep.Frontends) {
		t.Fatal("cache mismatch")
	}
}
