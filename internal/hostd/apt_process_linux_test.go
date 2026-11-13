// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package hostd

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestParseLinuxAptStatHandlesCommAndRejectsBadFields(t *testing.T) {
	fields := strings.Fields("R 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 42")
	for _, comm := range []string{"apt-get", "odd ) ( name\n"} {
		data := []byte("123 (" + comm + ") " + strings.Join(fields, " "))
		state, ticks, err := parseLinuxAptStat(data, 123)
		if err != nil || state != 'R' || ticks != 42 {
			t.Fatalf("comm/stat parsing changed: state=%c ticks=%d err=%v", state, ticks, err)
		}
	}
	for _, input := range []string{"123 no-comm", "124 (apt-get) " + strings.Join(fields, " "), "123 (apt-get) R 0", "123 (apt-get) RR " + strings.Join(fields[1:], " "), "123 (apt-get) " + strings.Join(fields[:19], " ") + " -1"} {
		if _, _, err := parseLinuxAptStat([]byte(input), 123); err == nil {
			t.Fatalf("malformed proc stat accepted: %q", input)
		}
	}
}

func TestLegacyAptRecoveryPinsOnlyRecognizedExecutable(t *testing.T) {
	const bootID = "12345678-1234-1234-1234-123456789abc"
	procRoot := t.TempDir()
	bootDir := filepath.Join(procRoot, "sys", "kernel", "random")
	pidDir := filepath.Join(procRoot, "123")
	for _, path := range []string{bootDir, pidDir} {
		if err := os.MkdirAll(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(bootDir, "boot_id"), []byte(bootID), 0o600); err != nil {
		t.Fatal(err)
	}
	stat := "123 (apt-get) S 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 42\n"
	if err := os.WriteFile(filepath.Join(pidDir, "stat"), []byte(stat), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, executable := range []string{binAptGet, binAptGet + " (deleted)", "/usr/bin/unrelated"} {
		t.Run(filepath.Base(executable), func(t *testing.T) {
			exePath := filepath.Join(pidDir, "exe")
			if err := os.Symlink(executable, exePath); err != nil {
				t.Fatal(err)
			}
			defer func() { _ = os.Remove(exePath) }()
			identity, err := resolveLinuxAptProcess(procRoot, aptProcessIdentity{pid: 123})
			wantLive := strings.HasPrefix(executable, binAptGet)
			if err != nil || (identity != nil) != wantLive {
				t.Fatalf("legacy executable validation failed: identity=%+v err=%v", identity, err)
			}
			if identity != nil && (identity.bootID != bootID || identity.startTicks != 42) {
				t.Fatalf("legacy process epoch not pinned: %+v", identity)
			}
		})
	}
	if err := os.Remove(filepath.Join(bootDir, "boot_id")); err != nil {
		t.Fatal(err)
	}
	if _, err := resolveLinuxAptProcess(procRoot, aptProcessIdentity{pid: 123, bootID: bootID, startTicks: 42}); !os.IsNotExist(err) || errors.Is(err, errNoSavedAptProcess) {
		t.Fatalf("missing boot_id was confused with absent bookkeeping: %v", err)
	}
	for _, state := range []string{"Z", "X", "x"} {
		if err := os.WriteFile(filepath.Join(pidDir, "stat"), []byte(strings.Replace(stat, ") S ", ") "+state+" ", 1)), 0o600); err != nil {
			t.Fatal(err)
		}
		if identity, err := resolveLinuxAptProcess(procRoot, aptProcessIdentity{pid: 123}); err != nil || identity != nil {
			t.Fatalf("dead state %s accepted: identity=%+v err=%v", state, identity, err)
		}
	}
	// A read error is uncertainty, not proof that the process exited.
	if err := os.Remove(filepath.Join(pidDir, "stat")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(pidDir, "stat"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := resolveLinuxAptProcess(procRoot, aptProcessIdentity{pid: 123}); err == nil {
		t.Fatal("unreadable stat treated as exited")
	}
}

func testAptProcFields(t *testing.T, pid int) []string {
	t.Helper()
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		t.Fatal(err)
	}
	end := strings.LastIndexByte(string(data), ')')
	if end < 0 {
		t.Fatal("invalid fixture proc stat")
	}
	return strings.Fields(string(data[end+1:]))
}

func TestAptRecoveryRejectsDifferentProcessEpoch(t *testing.T) {
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		t.Fatal(err)
	}
	start, err := strconv.ParseUint(testAptProcFields(t, os.Getpid())[19], 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	for _, changedBoot := range []bool{false, true} {
		name := "reused_pid"
		if changedBoot {
			name = "different_boot"
		}
		t.Run(name, func(t *testing.T) {
			overrideAptActionLogForTest(t)
			resetAptUpgradeState()
			defer resetAptUpgradeState()
			bootID, ticks := strings.TrimSpace(string(boot)), start+1
			if changedBoot {
				bootID, ticks = "00000000-0000-0000-0000-000000000000", start
			}
			data := fmt.Sprintf("%d\nv1 %s %d\n", os.Getpid(), bootID, ticks)
			if err := os.WriteFile(aptActionPIDPath(), []byte(data), 0o600); err != nil {
				t.Fatal(err)
			}
			if active, code, message := aptActionSnapshot(); active || code != -1 || message == "" {
				t.Fatalf("different process recovered as live APT: active=%v code=%d error=%q", active, code, message)
			}
			if started, err := aptActionTryStart(); err != nil || !started {
				t.Fatalf("stale identity blocked the next run: started=%v err=%v", started, err)
			}
		})
	}
}

func TestAptRecoveryRejectsUnrelatedLegacyPID(t *testing.T) {
	overrideAptActionLogForTest(t)
	resetAptUpgradeState()
	defer resetAptUpgradeState()
	if err := os.WriteFile(aptActionPIDPath(), []byte(strconv.Itoa(os.Getpid())+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if active, code, message := aptActionSnapshot(); active || code != -1 || message == "" {
		t.Fatalf("non-APT legacy PID accepted: active=%v code=%d error=%q", active, code, message)
	}
}

func TestAptRecoveryPinsLiveIdentityAndExcludesZombie(t *testing.T) {
	for _, replacePID := range []bool{false, true} {
		name := "pid_file_removed"
		if replacePID {
			name = "pid_file_replaced"
		}
		t.Run(name, func(t *testing.T) {
			overrideAptActionLogForTest(t)
			resetAptUpgradeState()
			defer resetAptUpgradeState()
			executable, dir := commandProcessFixture(t, "wait")
			cmd := exec.Command(executable, "-test.run=^TestHostdCommandProcessHelper$")
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			// Only this owned child is killed. Wait stays in cleanup so the
			// exited child remains a real zombie during the recovery assertion.
			t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
			waitCommandFixture(t, filepath.Join(dir, "ready"))
			if err := writeAptActionPID(cmd.Process.Pid); err != nil {
				t.Fatal(err)
			}
			if active, _, _ := aptActionSnapshot(); !active {
				t.Fatal("live recorded child not recovered")
			}
			if replacePID {
				if err := writeAptActionPID(os.Getpid()); err != nil {
					t.Fatal(err)
				}
			} else if err := clearAptActionPID(); err != nil {
				t.Fatal(err)
			}
			if active, _, _ := aptActionSnapshot(); !active {
				t.Fatal("removing bookkeeping released a known live process")
			}
			if err := cmd.Process.Kill(); err != nil {
				t.Fatal(err)
			}
			limit := time.Now().Add(3 * time.Second)
			for testAptProcFields(t, cmd.Process.Pid)[0] != "Z" {
				if time.Now().After(limit) {
					t.Fatal("owned child did not become a zombie")
				}
				time.Sleep(time.Millisecond)
			}
			if active, code, message := aptActionSnapshot(); active || code != -1 || message == "" {
				t.Fatalf("zombie/replacement kept APT active: active=%v code=%d error=%q", active, code, message)
			}
		})
	}
}
