// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package metrics

import (
	"bufio"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func listenHAProxyStatsSocket(t *testing.T) (string, net.Listener) {
	t.Helper()
	// The Unix socket address must fit even when TMPDIR or the subtest name is long.
	dir, err := os.MkdirTemp("/tmp", "easy-waf-stats-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	sock := filepath.Join(dir, "stats.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	return sock, ln
}

func TestHAProxyCollectorUnixMock(t *testing.T) {
	sock, ln := listenHAProxyStatsSocket(t)

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

func TestHAProxyCollectorRejectsOversizedStats(t *testing.T) {
	// A complete CSV followed by whitespace is parseable at any truncation
	// point here. The socket reader must detect the overflow itself.
	payload := sampleStatsCSV + strings.Repeat(" ", maxHAProxyStatsBytes-len(sampleStatsCSV)+1)
	for _, tc := range []struct {
		name string
		size int
	}{
		{"at limit", maxHAProxyStatsBytes},
		{"over limit", maxHAProxyStatsBytes + 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sock, ln := listenHAProxyStatsSocket(t)
			finished := make(chan error, 1)
			go func() {
				c, err := ln.Accept()
				if err != nil {
					finished <- err
					return
				}
				defer c.Close()
				if _, err = bufio.NewReader(c).ReadString('\n'); err == nil {
					_, err = io.WriteString(c, payload[:tc.size])
				}
				finished <- err
			}()
			coll := NewHAProxyCollector()
			rep, err := coll.Fetch(sock)
			if writeErr := <-finished; writeErr != nil {
				t.Fatalf("writing stats fixture: %v", writeErr)
			}
			if tc.size == maxHAProxyStatsBytes {
				if err != nil || rep == nil || len(rep.Backends) != 2 || rep.Error != "" {
					t.Fatalf("expected a complete report at the limit, got %+v, %v", rep, err)
				}
				return
			}
			if err == nil || rep == nil || !strings.Contains(rep.Error, "exceeds") ||
				len(rep.Backends) != 0 || len(rep.Frontends) != 0 || BuildSummary(rep).Error != rep.Error {
				t.Fatalf("expected an error instead of a partial report, got %+v, %v", rep, err)
			}
		})
	}
}
