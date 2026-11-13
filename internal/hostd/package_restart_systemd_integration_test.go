// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

//go:build linux && integration

package hostd

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/easy-waf/easy-waf/internal/host/runner"
)

const packageSystemdRoot = "/opt/easy-waf-package-fixture"

// This entrypoint is used only by the fixture API/ACME services. The broker and
// maintenance service run the normal production executable and packaged units.
func TestPackageSystemdServiceHelper(t *testing.T) {
	service := os.Getenv("EASY_WAF_PACKAGE_FIXTURE_SERVICE")
	if service == "" {
		return
	}
	if service != "api" && service != "acmed" {
		t.Fatal("invalid fixture service")
	}
	requirePackageSystemdFixture(t)
	ctx, stop := signal.NotifyContext(t.Context(), syscall.SIGTERM)
	defer stop()
	packageSystemdWrite(t, service+".started", "started\n", 0o644)
	<-ctx.Done()
	if service == "acmed" {
		packageSystemdWrite(t, "acmed.draining", "draining\n", 0o644)
		packageSystemdWait(t, "ACME release", func() bool {
			_, err := os.Stat(filepath.Join(packageSystemdRoot, "release-acmed"))
			return err == nil
		})
	}
}

// A read-only client used as the real easy-waf UID/executable in the private
// fixture. It performs no filesystem mutation or package operation itself.
func TestAPTWorkerPeerProbe(t *testing.T) {
	target := os.Getenv("EASY_WAF_APT_PEER_PROBE")
	if target == "" {
		return
	}
	socket := DefaultAPTWorkerSocket
	if target == "broker" {
		socket = DefaultSocket
	} else if target != "worker" {
		t.Fatal("unknown peer probe target")
	}
	conn, err := net.DialTimeout("unix", socket, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := json.NewEncoder(conn).Encode(Request{Argv: []string{"apt-action-status"}}); err != nil {
		t.Fatal(err)
	}
	var response Response
	if err := json.NewDecoder(conn).Decode(&response); err != nil {
		t.Fatal(err)
	}
	if target == "broker" && !response.OK {
		t.Fatalf("genuine API peer could not use the broker: %+v", response)
	}
	if target == "worker" && (response.OK || response.Error != "peer not allowed") {
		t.Fatalf("unprivileged API peer reached the root-only worker: %+v", response)
	}
}

func requirePackageSystemdFixture(t *testing.T) {
	t.Helper()
	marker, err := os.ReadFile(filepath.Join(packageSystemdRoot, "container-marker"))
	if err != nil || string(marker) != "easy-waf-package-fixture-v1\n" {
		t.Fatal("refusing package operations outside the disposable fixture")
	}
	if _, err := os.Stat("/.dockerenv"); err != nil || os.Geteuid() != 0 {
		t.Fatal("requires the fixture's Docker root, never a live appliance")
	}
	osRelease, err := os.ReadFile("/etc/os-release")
	if err != nil || !strings.Contains(string(osRelease), "ID=ubuntu\n") || !strings.Contains(string(osRelease), "VERSION_ID=\"24.04\"") {
		t.Fatal("requires the supported Ubuntu 24.04 fixture OS")
	}
	init, err := os.ReadFile("/proc/1/comm")
	if err != nil || strings.TrimSpace(string(init)) != "systemd" {
		t.Fatal("requires a real systemd PID 1")
	}
}

func TestPackageRestartSystemdLifecycle(t *testing.T) {
	if os.Getenv("RUN_PACKAGE_RESTART_INTEGRATION") != "1" {
		t.Skip("requires scripts/test-package-restart-e2e.sh disposable systemd fixture")
	}
	requirePackageSystemdFixture(t)
	if _, err := exec.CommandContext(t.Context(), "dpkg-query", "-W", "easy-waf").CombinedOutput(); err == nil {
		t.Fatal("fixture already has easy-waf installed")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 150*time.Second)
	defer cancel()
	f := &packageSystemdFixture{t: t, ctx: ctx}
	f.prepare()
	t.Cleanup(func() {
		for _, name := range []string{"hostd", "hostd-restart", "api", "acmed"} {
			data, _ := os.ReadFile(filepath.Join(packageSystemdRoot, name+".log"))
			if len(data) > 8192 {
				data = data[len(data)-8192:]
			}
			t.Logf("%s log:\n%s", name, data)
		}
	})

	t.Run("synchronous_owner_restart_kills_its_transaction", func(t *testing.T) {
		f.t = t
		f.reset(true)
		f.startServices()
		before := f.property("easy-waf-apt.service", "MainPID")
		done, closeClient := f.startAPT()
		defer closeClient()
		packageSystemdWait(t, "negative-control owner restart", func() bool {
			pid := f.property("easy-waf-apt.service", "MainPID")
			return pid != "0" && pid != before
		})
		select {
		case err := <-done:
			t.Logf("old broker APT stream closed: %v", err)
		case <-time.After(5 * time.Second):
			t.Fatal("negative control did not interrupt its APT stream")
		}
		if _, err := os.Stat(filepath.Join(packageSystemdRoot, "postinst-done")); err == nil {
			t.Fatal("negative control completed postinst despite self-kill")
		}
		if f.packageStatus() == "install ok installed" {
			t.Fatal("negative control did not detect the broken package transaction")
		}
		t.Log("confirmed: synchronous control-group restart kills its owned dpkg")
	})
	if t.Failed() {
		return
	}
	t.Run("upgrade_waits_for_dpkg_and_apt_without_waiting_for_acme", func(t *testing.T) {
		f.t = t
		f.reset(false)
		f.startServices()
		before := f.property("easy-waf-hostd.service", "MainPID")
		apiBefore := f.property("easy-waf-api.service", "MainPID")
		acmeBefore := f.property("easy-waf-acmed.service", "MainPID")
		done, closeClient := f.startAPT()
		defer closeClient()
		packageSystemdWait(t, "postinst checkpoint", func() bool { return f.exists("postinst-done") })
		packageSystemdWait(t, "slow ACME drain", func() bool { return f.exists("acmed.draining") })
		f.assertPackageLock("lock-frontend", true)
		f.assertPackageLock("lock", true)
		f.assertBrokerHeld(before)
		if f.property("easy-waf-hostd-restart.service", "ActiveState") != "activating" {
			t.Fatal("the actual maintenance unit was not queued")
		}
		brokerGroup := f.property("easy-waf-hostd.service", "ControlGroup")
		helperGroup := f.property("easy-waf-hostd-restart.service", "ControlGroup")
		if brokerGroup == "" || helperGroup == "" || helperGroup == brokerGroup || strings.HasPrefix(helperGroup, brokerGroup+"/") {
			t.Fatalf("helper is not outside the broker kill domain: %q / %q", brokerGroup, helperGroup)
		}
		packageSystemdWrite(t, "release-dpkg", "release\n", 0o644)
		packageSystemdWait(t, "APT frontend-only checkpoint", func() bool { return f.exists("apt-frontend-held") })
		if f.packageStatus() != "install ok installed" {
			t.Fatal("dpkg did not finish while ACME was draining")
		}
		f.assertPackageLock("lock-frontend", true)
		f.assertPackageLock("lock", false)
		f.assertBrokerHeld(before)
		packageSystemdWrite(t, "release-apt", "release\n", 0o644)
		packageSystemdWait(t, "post-transaction broker restart", func() bool {
			pid := f.property("easy-waf-hostd.service", "MainPID")
			return pid != "0" && pid != before
		})
		packageSystemdWait(t, "maintenance completion", func() bool {
			return f.property("easy-waf-hostd-restart.service", "ActiveState") == "inactive"
		})
		if result := f.property("easy-waf-hostd-restart.service", "Result"); result != "success" {
			t.Fatalf("maintenance unit failed: %s", result)
		}
		f.assertPackageLock("lock-frontend", false)
		f.assertPackageLock("lock", false)
		if state := f.property("easy-waf-acmed.service", "SubState"); state != "stop-sigterm" {
			t.Fatalf("APT/broker restart waited for ACME drain: %s", state)
		}
		packageSystemdWrite(t, "release-acmed", "release\n", 0o644)
		packageSystemdWait(t, "new ACME process", func() bool {
			pid := f.property("easy-waf-acmed.service", "MainPID")
			return pid != "0" && pid != acmeBefore && f.property("easy-waf-acmed.service", "ActiveState") == "active"
		})
		if pid := f.property("easy-waf-api.service", "MainPID"); pid == "0" || pid == apiBefore {
			t.Fatalf("API did not restart: %s", pid)
		}
		select {
		case err := <-done: // A terminal result or a closed old-broker socket is legitimate.
			t.Logf("old broker APT stream closed: %v", err)
		case <-time.After(5 * time.Second):
			t.Fatal("old broker connection stayed open after its process restart")
		}
		if audit := f.run("dpkg", "--audit"); strings.TrimSpace(audit) != "" {
			t.Fatalf("incomplete package transaction: %s", audit)
		}
	})
	if t.Failed() {
		return
	}
	t.Run("worker_rejects_the_public_api_identity", func(t *testing.T) {
		f.t = t
		f.reset(false)
		f.startServices()
		data, err := os.ReadFile("/inputs/hostd.test")
		if err != nil {
			t.Fatal(err)
		}
		// #nosec G306 -- Executable fixture at the real trusted API path, root-owned.
		if err := os.WriteFile("/usr/sbin/easy-waf-api", data, 0o755); err != nil {
			t.Fatal(err)
		}
		identityDir := filepath.Join(packageSystemdRoot, "api-identity")
		f.run("install", "-d", "-m", "0700", "-o", "easy-waf", "-g", "easy-waf", identityDir)
		var identity unix.Stat_t
		if err := unix.Stat(identityDir, &identity); err != nil {
			t.Fatal(err)
		}
		// Remove the filesystem barrier only in this fixture: the worker must
		// still reject an API peer that the public broker verifiably accepts.
		if err := os.Chmod(filepath.Dir(DefaultAPTWorkerSocket), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(DefaultAPTWorkerSocket, 0o666); err != nil {
			t.Fatal(err)
		}
		defer func() {
			_ = os.Chmod(DefaultAPTWorkerSocket, 0o600)
			_ = os.Chmod(filepath.Dir(DefaultAPTWorkerSocket), 0o700)
		}()
		for _, target := range []string{"broker", "worker"} {
			cmd := exec.CommandContext(f.ctx, "/usr/sbin/easy-waf-api", "-test.run=^TestAPTWorkerPeerProbe$", "-test.v")
			cmd.Env = append(os.Environ(), "EASY_WAF_APT_PEER_PROBE="+target)
			cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: identity.Uid, Gid: identity.Gid}}
			if data, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("real API identity at %s boundary: %v\n%s", target, err, data)
			}
		}
	})
	if t.Failed() {
		return
	}
	t.Run("broker_restart_does_not_interrupt_apt", func(t *testing.T) {
		f.t = t
		f.reset(false)
		// Generic package checkpoint, without self-upgrade scheduling: operation
		// and result must survive both normal broker stop and SIGKILL.
		packageSystemdWrite(t, "actual-postinst", "#!/bin/sh\nexit 0\n", 0o755)
		f.startServices()
		workerPID := f.property("easy-waf-apt.service", "MainPID")
		done, closeClient := f.startAPT()
		defer closeClient()
		packageSystemdWait(t, "dpkg checkpoint before broker stop", func() bool { return f.exists("postinst-done") })
		before := f.status()
		if !before.Active || before.RunID == "" {
			t.Fatalf("missing active operation: %+v", before)
		}
		f.run("systemctl", "stop", "easy-waf-hostd.service")
		f.assertPackageLock("lock-frontend", true)
		f.assertPackageLock("lock", true)
		if workerPID == "0" || f.property("easy-waf-apt.service", "MainPID") != workerPID {
			t.Fatal("APT owner did not survive stopping the broker")
		}
		f.run("systemctl", "start", "easy-waf-hostd.service")
		f.waitBrokerSocket()
		after := f.status()
		if !after.Active || after.RunID != before.RunID {
			t.Fatalf("broker restart lost the selected operation: before=%+v after=%+v", before, after)
		}
		brokerPID := f.property("easy-waf-hostd.service", "MainPID")
		f.run("systemctl", "kill", "--kill-whom=main", "--signal=KILL", "easy-waf-hostd.service")
		packageSystemdWait(t, "broker recovery after SIGKILL", func() bool {
			pid := f.property("easy-waf-hostd.service", "MainPID")
			return pid != "0" && pid != brokerPID
		})
		f.waitBrokerSocket()
		f.assertPackageLock("lock-frontend", true)
		after = f.status()
		if !after.Active || after.RunID != before.RunID || f.property("easy-waf-apt.service", "MainPID") != workerPID {
			t.Fatalf("broker SIGKILL lost or replaced active APT: %+v", after)
		}
		observer, err := net.DialTimeout("unix", DefaultSocket, 3*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer observer.Close()
		if err := observer.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
			t.Fatal(err)
		}
		if err := json.NewEncoder(observer).Encode(Request{Argv: []string{"apt-action-attach-stream", before.RunID}}); err != nil {
			t.Fatal(err)
		}
		decoder := json.NewDecoder(observer)
		var event struct {
			Type  string `json:"type"`
			Data  string `json:"data"`
			Code  *int   `json:"code"`
			Error string `json:"error"`
		}
		if err := decoder.Decode(&event); err != nil || event.Type != "line" {
			t.Fatalf("could not reattach to the still-active operation: %+v %v", event, err)
		}
		packageSystemdWrite(t, "release-dpkg", "release\n", 0o644)
		packageSystemdWait(t, "frontend checkpoint after broker recovery", func() bool { return f.exists("apt-frontend-held") })
		packageSystemdWrite(t, "release-apt", "release\n", 0o644)
		packageSystemdWait(t, "real APT result after reconnect", func() bool { after = f.status(); return !after.Active })
		if after.ExitCode != 0 || after.RunID != before.RunID {
			t.Fatalf("completed operation result was lost: %+v", after)
		}
		var replay strings.Builder
		for {
			if err := decoder.Decode(&event); err != nil {
				t.Fatalf("reattached stream ended without its original result: %v", err)
			}
			if event.Type == "exit" {
				if event.Code == nil || *event.Code != 0 || event.Error != "" {
					t.Fatalf("reattached operation lost its actual exit: %+v", event)
				}
				break
			}
			replay.WriteString(event.Data)
		}
		if !strings.Contains(replay.String(), "Setting up easy-waf") {
			t.Fatalf("reattached stream lost saved package output: %s", replay.String())
		}
		t.Setenv("EASY_WAF_HOSTD_SOCKET", DefaultSocket)
		var saved strings.Builder
		if err := runner.DownloadAPTLog(t.Context(), &saved); err != nil || !strings.Contains(saved.String(), "Setting up easy-waf") {
			t.Fatalf("saved-log download through real broker/worker failed: bytes=%d err=%v", saved.Len(), err)
		}
		if audit := f.run("dpkg", "--audit"); strings.TrimSpace(audit) != "" {
			t.Fatalf("broker interruption damaged package state: %s", audit)
		}
		select {
		case err := <-done:
			t.Logf("closed original broker stream: %v", err)
		case <-time.After(3 * time.Second):
			t.Fatal("stopped broker retained its client connection")
		}
	})
	if t.Failed() {
		return
	}
	t.Run("active_worker_refreshes_without_starting_stopped_broker", func(t *testing.T) {
		f.t = t
		f.reset(false)
		f.startServices()
		packageSystemdWrite(t, "release-acmed", "release\n", 0o644)
		f.run("systemctl", "stop", "easy-waf-hostd.service", "easy-waf-api.service", "easy-waf-acmed.service")
		before := f.property("easy-waf-apt.service", "MainPID")
		packageSystemdWrite(t, "release-dpkg", "release\n", 0o644)
		packageSystemdWrite(t, "release-apt", "release\n", 0o644)
		f.run("apt-get", "-y", "upgrade")
		packageSystemdWait(t, "active APT owner refreshed without its broker", func() bool {
			pid := f.property("easy-waf-apt.service", "MainPID")
			return pid != "0" && pid != before
		})
		for _, name := range []string{"hostd", "api", "acmed"} {
			if state := f.property("easy-waf-"+name+".service", "ActiveState"); state != "inactive" {
				t.Fatalf("stopped %s was started while refreshing its worker: %s", name, state)
			}
		}
	})
	if t.Failed() {
		return
	}
	t.Run("stopped_services_remain_stopped", func(t *testing.T) {
		f.t = t
		f.reset(false)
		packageSystemdWrite(t, "release-dpkg", "release\n", 0o644)
		packageSystemdWrite(t, "release-apt", "release\n", 0o644)
		before := f.property("easy-waf-hostd-restart.service", "ExecMainStartTimestampMonotonic")
		f.run("apt-get", "-y", "upgrade")
		for _, name := range []string{"hostd", "api", "acmed"} {
			if state := f.property("easy-waf-"+name+".service", "ActiveState"); state != "inactive" {
				t.Fatalf("stopped %s was started: %s", name, state)
			}
		}
		if after := f.property("easy-waf-hostd-restart.service", "ExecMainStartTimestampMonotonic"); after != before {
			t.Fatal("a maintenance job was started for an inactive broker")
		}
		if f.packageStatus() != "install ok installed" {
			t.Fatal("stopped-service upgrade did not finish")
		}
		if version := strings.TrimSpace(f.run("dpkg-query", "-W", "-f=${Version}", "easy-waf")); version != "1.6.1" {
			t.Fatalf("new package version was not installed: %s", version)
		}
	})
	if t.Failed() {
		return
	}
	t.Run("removing_own_worker_does_not_deadlock_dpkg", func(t *testing.T) {
		f.t = t
		f.reset(false)
		f.startServices()
		workerPID, err := strconv.Atoi(f.property("easy-waf-apt.service", "MainPID"))
		if err != nil || workerPID <= 0 {
			t.Fatalf("missing APT owner: %d %v", workerPID, err)
		}
		identity, err := captureAptProcessIdentity(workerPID)
		if err != nil {
			t.Fatal(err)
		}
		f.run("apt-mark", "auto", "easy-waf")
		done, closeClient := f.startAPTAction("apt-autoremove-stream")
		defer closeClient()
		packageSystemdWait(t, "prerm after asynchronous owner stop", func() bool { return f.exists("prerm-done") })
		f.assertPackageLock("lock-frontend", true)
		f.assertPackageLock("lock", true)
		if state := f.property("easy-waf-apt.service", "SubState"); state != "stop-sigterm" {
			t.Fatalf("APT owner was killed or did not drain: %s", state)
		}
		packageSystemdWrite(t, "release-prerm", "release\n", 0o644)
		packageSystemdWait(t, "worker exit after its own package removal", func() bool {
			process, err := resolveAptProcess(identity)
			if err != nil {
				t.Fatal(err)
			}
			return process == nil
		})
		packageSystemdWrite(t, "release-acmed", "release\n", 0o644)
		if audit := f.run("dpkg", "--audit"); strings.TrimSpace(audit) != "" {
			t.Fatalf("own-package removal left incomplete dpkg state: %s", audit)
		}
		if data, err := exec.CommandContext(f.ctx, "dpkg-query", "-W", "easy-waf").CombinedOutput(); err == nil {
			t.Fatalf("worker package was not removed: %s", data)
		}
		select {
		case err := <-done:
			t.Logf("closed removal observation: %v", err)
		case <-time.After(3 * time.Second):
			t.Fatal("removed broker kept its client connection")
		}
	})
}

type packageSystemdFixture struct {
	t   *testing.T
	ctx context.Context
}

type packageSystemdStatus struct {
	Active   bool   `json:"active"`
	RunID    string `json:"run_id"`
	ExitCode int    `json:"exit_code"`
}

func (f *packageSystemdFixture) waitBrokerSocket() {
	packageSystemdWait(f.t, "broker socket ready", func() bool {
		conn, err := net.DialTimeout("unix", DefaultSocket, 100*time.Millisecond)
		if err != nil {
			return false
		}
		_ = conn.Close()
		return true
	})
}

func (f *packageSystemdFixture) status() packageSystemdStatus {
	f.t.Helper()
	conn, err := net.DialTimeout("unix", DefaultSocket, 3*time.Second)
	if err != nil {
		f.t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		f.t.Fatal(err)
	}
	if err := json.NewEncoder(conn).Encode(Request{Argv: []string{"apt-action-status"}}); err != nil {
		f.t.Fatal(err)
	}
	var response Response
	if err := json.NewDecoder(conn).Decode(&response); err != nil || !response.OK {
		f.t.Fatalf("APT status: %+v error=%v", response, err)
	}
	var status packageSystemdStatus
	if err := json.Unmarshal([]byte(response.Stdout), &status); err != nil {
		f.t.Fatal(err)
	}
	return status
}

func packageSystemdWrite(t *testing.T, name, data string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(packageSystemdRoot, name), []byte(data), mode); err != nil {
		t.Fatal(err)
	}
}

func packageSystemdWait(t *testing.T, what string, ready func() bool) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if ready() {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func (f *packageSystemdFixture) run(name string, args ...string) string {
	f.t.Helper()
	data, err := exec.CommandContext(f.ctx, name, args...).CombinedOutput()
	if err != nil {
		f.t.Fatalf("%s %v: %v\n%s", name, args, err, data)
	}
	return string(data)
}

func (f *packageSystemdFixture) property(unit, property string) string {
	return strings.TrimSpace(f.run("systemctl", "show", unit, "--property="+property, "--value"))
}

func (f *packageSystemdFixture) packageStatus() string {
	return strings.TrimSpace(f.run("dpkg-query", "-W", "-f=${Status}", "easy-waf"))
}

func (f *packageSystemdFixture) exists(name string) bool {
	_, err := os.Stat(filepath.Join(packageSystemdRoot, name))
	return err == nil
}

func (f *packageSystemdFixture) assertBrokerHeld(before string) {
	f.t.Helper()
	// The helper has had multiple lock-poll intervals to run; observing one PID
	// before its goroutine was scheduled would not prove exclusion.
	time.Sleep(550 * time.Millisecond)
	if after := f.property("easy-waf-hostd.service", "MainPID"); after != before {
		f.t.Fatalf("broker restarted inside the package transaction: %s -> %s", before, after)
	}
}

func (f *packageSystemdFixture) assertPackageLock(name string, busy bool) {
	f.t.Helper()
	// These are the disposable container's real package locks. Probe from this
	// process, separate from both APT/dpkg and the maintenance service.
	file, err := os.OpenFile(filepath.Join("/var/lib/dpkg", name), os.O_RDWR, 0)
	if err != nil {
		f.t.Fatal(err)
	}
	defer file.Close()
	lock := unix.Flock_t{Type: unix.F_WRLCK, Whence: int16(unix.SEEK_SET)}
	err = unix.FcntlFlock(file.Fd(), unix.F_SETLK, &lock)
	if busy && (err == unix.EAGAIN || err == unix.EACCES) {
		return
	}
	if !busy && err == nil {
		return // Closing the descriptor releases this probe's lock.
	}
	f.t.Fatalf("package lock %s: busy=%v error=%v", name, busy, err)
}

func (f *packageSystemdFixture) prepare() {
	for _, dir := range []string{"repository", "lists/partial", "old", "new"} {
		if err := os.MkdirAll(filepath.Join(packageSystemdRoot, dir), 0o755); err != nil {
			f.t.Fatal(err)
		}
	}
	f.run("groupadd", "--system", "easy-waf")
	f.run("useradd", "--system", "--gid", "easy-waf", "--home-dir", "/var/lib/easy-waf", "--shell", "/usr/sbin/nologin", "easy-waf")
	packageSystemdWrite(f.t, "apt.conf", `Dir::Etc::parts "-";
Dir::Etc::main "-";
Dir::Etc::sourcelist "/opt/easy-waf-package-fixture/sources.list";
Dir::Etc::sourceparts "-";
Dir::State::lists "/opt/easy-waf-package-fixture/lists";
Dir::State::extended_states "/opt/easy-waf-package-fixture/extended_states";
DPkg::Post-Invoke {"/opt/easy-waf-package-fixture/after-dpkg";};
`, 0o644)
	f.t.Setenv("APT_CONFIG", filepath.Join(packageSystemdRoot, "apt.conf"))
	packageSystemdWrite(f.t, "sources.list", "deb [trusted=yes] file:"+packageSystemdRoot+"/repository ./\n", 0o644)
	packageSystemdWrite(f.t, "after-dpkg", `#!/bin/sh
set -eu
cd /opt/easy-waf-package-fixture
if [ -e postinst-returning ]; then
  : >apt-frontend-held
  while [ ! -e release-apt ]; do sleep 0.05; done
fi
`, 0o755)
	for _, service := range []string{"api", "acmed"} {
		unit := fmt.Sprintf(`[Unit]
Description=Fixture %s worker (no database or ACME network)
DefaultDependencies=no
[Service]
Type=simple
ExecStart=/inputs/hostd.test -test.run=^TestPackageSystemdServiceHelper$
Environment=EASY_WAF_PACKAGE_FIXTURE_SERVICE=%s
TimeoutStopSec=50min
StandardOutput=append:%s/%s.log
StandardError=inherit
`, service, service, packageSystemdRoot, service)
		// #nosec G306 -- Public fixture unit; use the normal systemd unit mode.
		if err := os.WriteFile("/run/systemd/system/easy-waf-"+service+".service", []byte(unit), 0o644); err != nil {
			f.t.Fatal(err)
		}
	}
	if err := os.MkdirAll("/run/systemd/system/easy-waf-hostd.service.d", 0o755); err != nil {
		f.t.Fatal(err)
	}
	dropin := "[Unit]\nDefaultDependencies=no\n[Service]\nEnvironment=APT_CONFIG=" + packageSystemdRoot + "/apt.conf\nStandardOutput=append:" + packageSystemdRoot + "/hostd.log\nStandardError=inherit\n"
	// #nosec G306 -- Public fixture drop-in contains paths, no credentials.
	if err := os.WriteFile("/run/systemd/system/easy-waf-hostd.service.d/fixture.conf", []byte(dropin), 0o644); err != nil {
		f.t.Fatal(err)
	}
	if err := os.MkdirAll("/run/systemd/system/easy-waf-apt.service.d", 0o755); err != nil {
		f.t.Fatal(err)
	}
	if err := os.WriteFile("/run/systemd/system/easy-waf-apt.service.d/fixture.conf", []byte(dropin), 0o600); err != nil {
		f.t.Fatal(err)
	}
	f.buildPackage("old", "1.6.0", "#!/bin/sh\nexit 0\n")
	f.run("dpkg", "--install", filepath.Join(packageSystemdRoot, "old.deb"))
	f.run("systemctl", "daemon-reload")
}

func (f *packageSystemdFixture) buildPackage(stage, version, postinst string) string {
	root := filepath.Join(packageSystemdRoot, stage)
	for _, dir := range []string{"DEBIAN", "usr/sbin", "lib/systemd/system", "usr/share/easy-waf-fixture"} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0o755); err != nil {
			f.t.Fatal(err)
		}
	}
	files := map[string]string{
		"/repo/packaging/systemd/easy-waf-apt.service":           "/lib/systemd/system/easy-waf-apt.service",
		"/inputs/easy-waf-hostd":                                 "/usr/sbin/easy-waf-hostd",
		"/repo/packaging/systemd/easy-waf-hostd.service":         "/lib/systemd/system/easy-waf-hostd.service",
		"/repo/packaging/systemd/easy-waf-hostd-restart.service": "/lib/systemd/system/easy-waf-hostd-restart.service",
	}
	for src, dst := range files {
		data, err := os.ReadFile(src)
		if err != nil {
			f.t.Fatal(err)
		}
		mode := os.FileMode(0o644)
		if strings.HasSuffix(src, "/easy-waf-hostd") {
			mode = 0o755
		}
		if err := os.WriteFile(filepath.Join(root, dst), data, mode); err != nil {
			f.t.Fatal(err)
		}
	}
	control := fmt.Sprintf("Package: easy-waf\nVersion: %s\nArchitecture: %s\nMaintainer: Easy WAF tests\nDescription: Disposable package lifecycle fixture\n", version, runtime.GOARCH)
	// #nosec G306 -- Public Debian package metadata has the conventional mode.
	if err := os.WriteFile(filepath.Join(root, "DEBIAN/control"), []byte(control), 0o644); err != nil {
		f.t.Fatal(err)
	}
	// #nosec G306 -- dpkg requires an executable maintainer script.
	if err := os.WriteFile(filepath.Join(root, "DEBIAN/postinst"), []byte(postinst), 0o755); err != nil {
		f.t.Fatal(err)
	}
	actualPrerm, err := os.ReadFile("/repo/packaging/deb/prerm")
	if err != nil {
		f.t.Fatal(err)
	}
	packageSystemdWrite(f.t, "actual-prerm", string(actualPrerm), 0o600)
	prerm := `#!/bin/sh
set -eu
/bin/sh /opt/easy-waf-package-fixture/actual-prerm "$@"
if [ "$1" = remove ]; then
  cd /opt/easy-waf-package-fixture
  : >prerm-done
  while [ ! -e release-prerm ]; do sleep 0.05; done
fi
`
	// #nosec G306 -- dpkg must execute this fixture maintainer script.
	if err := os.WriteFile(filepath.Join(root, "DEBIAN/prerm"), []byte(prerm), 0o755); err != nil {
		f.t.Fatal(err)
	}
	path := filepath.Join(packageSystemdRoot, stage+".deb")
	f.run("dpkg-deb", "--build", "--root-owner-group", root, path)
	return path
}

func (f *packageSystemdFixture) reset(negative bool) {
	packageSystemdWrite(f.t, "release-acmed", "release\n", 0o644)
	f.run("systemctl", "stop", "easy-waf-hostd-restart.service", "easy-waf-hostd.service", "easy-waf-apt.service", "easy-waf-api.service", "easy-waf-acmed.service")
	negativeDropin := "/run/systemd/system/easy-waf-apt.service.d/negative.conf"
	if negative {
		if err := os.WriteFile(negativeDropin, []byte("[Service]\nKillMode=control-group\n"), 0o600); err != nil {
			f.t.Fatal(err)
		}
	} else if err := os.Remove(negativeDropin); err != nil && !os.IsNotExist(err) {
		f.t.Fatal(err)
	}
	for _, name := range []string{"postinst-done", "postinst-returning", "apt-frontend-held", "release-dpkg", "release-apt", "release-acmed", "api.started", "acmed.started", "acmed.draining", "prerm-done", "release-prerm"} {
		if err := os.Remove(filepath.Join(packageSystemdRoot, name)); err != nil && !os.IsNotExist(err) {
			f.t.Fatal(err)
		}
	}
	f.run("dpkg", "--install", filepath.Join(packageSystemdRoot, "old.deb"))
	actual, err := os.ReadFile("/repo/packaging/deb/postinst")
	if err != nil {
		f.t.Fatal(err)
	}
	if negative {
		before := "systemctl restart --no-block easy-waf-hostd-restart.service"
		if strings.Count(string(actual), before) != 1 {
			f.t.Fatal("negative control no longer matches the actual scheduler")
		}
		actual = []byte(strings.Replace(string(actual), before, "systemctl restart easy-waf-apt.service", 1))
	}
	// The wrapper adds an observable backend-lock checkpoint after executing the
	// complete production postinst. No command or lock in that postinst is mocked.
	packageSystemdWrite(f.t, "actual-postinst", string(actual), 0o755)
	wrapper := `#!/bin/sh
set -eu
/opt/easy-waf-package-fixture/actual-postinst "$@"
cd /opt/easy-waf-package-fixture
: >postinst-done
while [ ! -e release-dpkg ]; do sleep 0.05; done
: >postinst-returning
`
	path := f.buildPackage("new", "1.6.1", wrapper)
	data, err := os.ReadFile(path)
	if err != nil {
		f.t.Fatal(err)
	}
	packageSystemdWrite(f.t, "repository/easy-waf.deb", string(data), 0o644)
	index := fmt.Sprintf("Package: easy-waf\nVersion: 1.6.1\nArchitecture: %s\nMaintainer: Easy WAF tests\nDescription: Disposable package lifecycle fixture\nFilename: ./easy-waf.deb\nSize: %d\nSHA256: %x\n\n", runtime.GOARCH, len(data), sha256.Sum256(data))
	packageSystemdWrite(f.t, "repository/Packages", index, 0o644)
	f.run("apt-get", "update")
	f.run("systemctl", "daemon-reload")
}

func (f *packageSystemdFixture) startServices() {
	f.run("systemctl", "start", "easy-waf-hostd.service", "easy-waf-api.service", "easy-waf-acmed.service")
	packageSystemdWait(f.t, "broker socket and fixture workers", func() bool {
		st, err := os.Stat(DefaultSocket)
		return f.exists("api.started") && f.exists("acmed.started") && err == nil && st.Mode()&os.ModeSocket != 0
	})
}

func (f *packageSystemdFixture) startAPT() (<-chan error, func()) {
	return f.startAPTAction("apt-upgrade-stream")
}

func (f *packageSystemdFixture) startAPTAction(opcode string) (<-chan error, func()) {
	f.t.Helper()
	conn, err := net.DialTimeout("unix", DefaultSocket, 3*time.Second)
	if err != nil {
		f.t.Fatal(err)
	}
	if err := conn.SetDeadline(time.Now().Add(90 * time.Second)); err != nil {
		f.t.Fatal(err)
	}
	if err := json.NewEncoder(conn).Encode(Request{Argv: []string{opcode}}); err != nil {
		f.t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := io.Copy(io.Discard, conn)
		done <- err
	}()
	return done, func() { _ = conn.Close() }
}
