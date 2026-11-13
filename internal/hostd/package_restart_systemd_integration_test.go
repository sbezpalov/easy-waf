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
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
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

	t.Run("old_synchronous_restart_kills_its_transaction", func(t *testing.T) {
		f.t = t
		f.reset(true)
		f.startServices()
		before := f.property("easy-waf-hostd.service", "MainPID")
		done, closeClient := f.startAPT()
		defer closeClient()
		packageSystemdWait(t, "negative-control broker restart", func() bool {
			pid := f.property("easy-waf-hostd.service", "MainPID")
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
		t.Log("confirmed: synchronous broker restart kills dpkg in the broker cgroup")
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
}

type packageSystemdFixture struct {
	t   *testing.T
	ctx context.Context
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
	path := filepath.Join(packageSystemdRoot, stage+".deb")
	f.run("dpkg-deb", "--build", "--root-owner-group", root, path)
	return path
}

func (f *packageSystemdFixture) reset(negative bool) {
	packageSystemdWrite(f.t, "release-acmed", "release\n", 0o644)
	f.run("systemctl", "stop", "easy-waf-hostd-restart.service", "easy-waf-hostd.service", "easy-waf-api.service", "easy-waf-acmed.service")
	for _, name := range []string{"postinst-done", "postinst-returning", "apt-frontend-held", "release-dpkg", "release-apt", "release-acmed", "api.started", "acmed.started", "acmed.draining"} {
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
		actual = []byte(strings.Replace(string(actual), before, "systemctl restart easy-waf-hostd.service", 1))
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
	f.t.Helper()
	conn, err := net.DialTimeout("unix", DefaultSocket, 3*time.Second)
	if err != nil {
		f.t.Fatal(err)
	}
	if err := conn.SetDeadline(time.Now().Add(90 * time.Second)); err != nil {
		f.t.Fatal(err)
	}
	if err := json.NewEncoder(conn).Encode(Request{Argv: []string{"apt-upgrade-stream"}}); err != nil {
		f.t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := io.Copy(io.Discard, conn)
		done <- err
	}()
	return done, func() { _ = conn.Close() }
}
