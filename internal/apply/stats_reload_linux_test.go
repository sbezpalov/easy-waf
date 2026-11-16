// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package apply

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestRealHAProxyReloadKeepsStatsSocket(t *testing.T) {
	binary, err := exec.LookPath("haproxy")
	if err != nil {
		t.Skip("HAProxy not installed")
	}
	reference, err := os.ReadFile(filepath.Join("..", "..", "packaging", "systemd", "haproxy-easy-waf-dropin.conf"))
	if err != nil {
		t.Fatal(err)
	}
	// Keep Unix socket names below Linux's sockaddr_un path limit, including
	// when the test runner has a long TMPDIR or package/test name.
	dir, err := os.MkdirTemp("/tmp", "ewf-stats-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	stats := filepath.Join(dir, "stats.sock")
	config := filepath.Join(dir, "fixture.cfg")
	body := fmt.Sprintf("global\n  nbthread 1\n  stats socket %s mode 600\ndefaults\n  mode http\n  timeout connect 1s\n  timeout client 2s\n  timeout server 2s\nfrontend fixture\n  bind %s\n  http-request deny deny_status 503\n", stats, filepath.Join(dir, "http.sock"))
	if err := os.WriteFile(config, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	log, err := os.Create(filepath.Join(dir, "haproxy.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	cmd := exec.Command(binary, "-W", "-db", "-f", config)
	cmd.Dir = "/"
	cmd.Stdout, cmd.Stderr = log, log
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
		done := make(chan struct{})
		go func() { _ = cmd.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			<-done
		}
	})
	worker := waitForStatsWorker(t, stats, 0)
	for i := 0; i < 2; i++ {
		// Execute the relevant production reload steps against private fixture
		// paths. Unlinking before SIGUSR2 breaks HAProxy's listener-FD reuse.
		if strings.Contains(string(reference), "ExecReload=+/bin/rm -f /run/haproxy/easy-waf-admin.sock") {
			if err := os.Remove(stats); err != nil {
				t.Fatal(err)
			}
		}
		ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
		err := Validate(ctx, binary, config)
		cancel()
		if err != nil {
			t.Fatal(err)
		}
		if err := cmd.Process.Signal(syscall.SIGUSR2); err != nil {
			t.Fatal(err)
		}
		worker = waitForStatsWorker(t, stats, worker)
	}
}

func waitForStatsWorker(t *testing.T, path string, previous int) int {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		pid, err := statsWorker(path)
		if err == nil && pid > 0 && pid != previous {
			return pid
		}
		lastErr = err
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("stats socket did not expose a new worker after reload (previous %d): %v", previous, lastErr)
	return 0
}

func statsWorker(path string) (int, error) {
	conn, err := net.DialTimeout("unix", path, 200*time.Millisecond)
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(200 * time.Millisecond)); err != nil {
		return 0, err
	}
	if _, err := io.WriteString(conn, "show info\n"); err != nil {
		return 0, err
	}
	data, err := io.ReadAll(conn)
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		if value, ok := strings.CutPrefix(line, "Pid:"); ok {
			return strconv.Atoi(strings.TrimSpace(value))
		}
	}
	return 0, fmt.Errorf("no worker PID in stats response")
}
