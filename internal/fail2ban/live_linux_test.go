// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

//go:build linux && integration

package fail2ban

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

// Start a private daemon with no firewall actions or access to system jails.
func TestLiveFail2banOverviewAndUnban(t *testing.T) {
	bin, err := exec.LookPath("fail2ban-client")
	if err != nil {
		t.Fatal("integration test requires fail2ban-client")
	}
	dir := t.TempDir()
	write := func(name, contents string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write("fail2ban.conf", "[Definition]\nlogtarget = "+filepath.Join(dir, "daemon.log")+"\ndbfile = None\n")
	write("events.log", "")
	write("jail.conf", fmt.Sprintf("[fixture]\nenabled = true\nbackend = polling\nlogpath = %s\nfailregex = ^fixture <HOST>$\naction =\nbantime = 600\n", filepath.Join(dir, "events.log")))
	c := &Client{Bin: bin, Run: func(ctx context.Context, bin string, args ...string) ([]byte, error) {
		options := []string{"-c", dir, "-s", filepath.Join(dir, "socket"), "-p", filepath.Join(dir, "pid")}
		return exec.CommandContext(ctx, bin, append(options, args...)...).CombinedOutput()
	}}
	if out, err := c.run(t.Context(), "start"); err != nil {
		t.Fatalf("start: %v: %s", err, out)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if out, err := c.run(ctx, "stop"); err != nil {
			t.Errorf("stop: %v: %s", err, out)
		}
	})
	check := func(want ...string) {
		t.Helper()
		ov, err := c.Overview(t.Context())
		if err != nil || !ov.Status.Running || len(ov.Jails) != 1 || ov.Jails[0].Name != "fixture" ||
			ov.Jails[0].Unavailable || !slices.Equal(ov.Jails[0].BannedIPs, want) {
			t.Fatalf("overview = %+v, err = %v, want bans %v", ov, err, want)
		}
	}
	check()
	const ip = "192.0.2.1"
	if out, err := c.run(t.Context(), "set", "fixture", "banip", ip); err != nil {
		t.Fatalf("seed ban: %v: %s", err, out)
	}
	check(ip)
	if err := c.UnbanIP(t.Context(), "fixture", ip); err != nil {
		t.Fatal(err)
	}
	check()
}
