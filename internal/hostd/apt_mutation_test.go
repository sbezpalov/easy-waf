// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package hostd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type aptMutationRunner struct {
	calls atomic.Int32
	run   func(context.Context, string, []string, func(string) error) (int, error)
}

func (r *aptMutationRunner) execute(ctx context.Context, name string, args []string, emit func(string) error) (int, error) {
	r.calls.Add(1)
	if r.run != nil {
		return r.run(ctx, name, args, emit)
	}
	_ = emit("fixture output")
	return 0, nil
}

func (r *aptMutationRunner) Run(ctx context.Context, name string, args ...string) ([]byte, []byte, int, error) {
	var output bytes.Buffer
	code, err := r.execute(ctx, name, args, func(line string) error { _, _ = output.WriteString(line + "\n"); return nil })
	return output.Bytes(), nil, code, err
}

// Explicit tracked-runner contract; this fake has no OS process to publish.
func (r *aptMutationRunner) RunApt(ctx context.Context, name string, args []string, emit func(string) error) (int, error) {
	return r.execute(ctx, name, args, emit)
}

func TestSynchronousAptMutationsCannotBypassStreamReservation(t *testing.T) {
	overrideAptActionLogForTest(t)
	resetAptUpgradeState()
	started, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	SetAptUpgradeStreamHookForTest(func(ctx context.Context, _ func(string) error) (int, error) {
		close(started)
		select {
		case <-release:
		case <-ctx.Done():
			return 1, ctx.Err()
		}
		return 0, nil
	})
	go func() { defer close(done); dispatchAptStream(&bytes.Buffer{}, "upgrade") }()
	t.Cleanup(func() {
		close(release)
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("stream fixture did not finish")
		}
		resetAptUpgradeState()
	})
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("stream fixture did not start")
	}
	for _, op := range []string{"apt-update", "apt-upgrade", "apt-clean"} {
		runner := &aptMutationRunner{}
		d := Dispatcher{Runner: runner}
		resp := d.Dispatch(t.Context(), []string{op})
		if resp.OK || !strings.Contains(resp.Error, "in progress") || runner.calls.Load() != 0 {
			t.Errorf("%s bypassed live stream: response=%+v calls=%d", op, resp, runner.calls.Load())
		}
	}
	if active, _, _ := aptActionSnapshot(); !active {
		t.Fatal("rejected synchronous mutation released the stream")
	}
}

func TestSynchronousAptMutationsReserveAgainstOtherMutations(t *testing.T) {
	for _, leader := range []string{"apt-update", "apt-upgrade", "apt-clean"} {
		t.Run(leader, func(t *testing.T) {
			overrideAptActionLogForTest(t)
			resetAptUpgradeState()
			entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
			runner := &aptMutationRunner{run: func(ctx context.Context, _ string, _ []string, emit func(string) error) (int, error) {
				_ = emit("original operation")
				close(entered)
				select {
				case <-release:
				case <-ctx.Done():
					return 1, ctx.Err()
				}
				return 7, nil
			}}
			var result Response
			go func() {
				defer close(done)
				d := Dispatcher{Runner: runner}
				result = d.Dispatch(t.Context(), []string{leader})
			}()
			t.Cleanup(func() {
				select {
				case <-release:
				default:
					close(release)
				}
				select {
				case <-done:
				case <-time.After(3 * time.Second):
					t.Error("synchronous fixture did not finish")
				}
				resetAptUpgradeState()
			})
			select {
			case <-entered:
			case <-time.After(3 * time.Second):
				t.Fatal("synchronous fixture did not start")
			}
			if active, _, _ := aptActionSnapshot(); !active {
				t.Error("synchronous mutation did not reserve ownership")
			}
			var status struct {
				Active bool   `json:"active"`
				Action string `json:"action"`
				Stream *bool  `json:"stream"`
			}
			if err := json.Unmarshal([]byte(dispatchAptActionStatus().Stdout), &status); err != nil || !status.Active || status.Action != strings.TrimPrefix(leader, "apt-") || status.Stream == nil || *status.Stream {
				t.Fatalf("synchronous status identity missing: %+v %v", status, err)
			}
			for _, op := range []string{"apt-update", "apt-upgrade", "apt-clean"} {
				other := &aptMutationRunner{}
				d := Dispatcher{Runner: other}
				if resp := d.Dispatch(t.Context(), []string{op}); resp.OK || other.calls.Load() != 0 {
					t.Errorf("%s allowed concurrent %s: response=%+v calls=%d", leader, op, resp, other.calls.Load())
				}
			}
			var hookCalls atomic.Int32
			SetAptUpgradeStreamHookForTest(func(context.Context, func(string) error) (int, error) { hookCalls.Add(1); return 0, nil })
			for _, action := range []string{"upgrade", "autoremove"} {
				var output bytes.Buffer
				dispatchAptStream(&output, action)
				events := readStreamEvents(t, &output)
				last := events[len(events)-1]
				if last.Code == 0 || !strings.Contains(last.Error, "in progress") || hookCalls.Load() != 0 {
					t.Errorf("stream %s started/claimed completion during %s: %+v calls=%d", action, leader, last, hookCalls.Load())
				}
			}
			close(release)
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				t.Fatal("synchronous fixture did not stop")
			}
			if result.Code != 7 || result.OK || !strings.Contains(result.Stdout, "original operation") {
				t.Fatalf("original synchronous result lost: %+v", result)
			}
			if active, code, _ := aptActionSnapshot(); active || code != 7 {
				t.Fatalf("result not retained: active=%v code=%d", active, code)
			}
		})
	}
}

func TestAptReadOnlyCommandsRemainAvailableDuringMutation(t *testing.T) {
	overrideAptActionLogForTest(t)
	resetAptUpgradeState()
	defer resetAptUpgradeState()
	if started, err := aptActionTryStart(); err != nil || !started {
		t.Fatalf("reserve: %v %v", started, err)
	}
	for _, op := range []string{"apt-simulate", "apt-autoremove-simulate", "apt-cache-size"} {
		runner := &aptMutationRunner{}
		d := Dispatcher{Runner: runner}
		if resp := d.Dispatch(t.Context(), []string{op}); !resp.OK || runner.calls.Load() != 1 {
			t.Fatalf("read-only %s blocked: %+v calls=%d", op, resp, runner.calls.Load())
		}
	}
	if active, _, _ := aptActionSnapshot(); !active {
		t.Fatal("read-only query released a mutation reservation")
	}
}

func TestAptMutationsRequireTrackedRunnerAndFixedArguments(t *testing.T) {
	overrideAptActionLogForTest(t)
	resetAptUpgradeState()
	defer resetAptUpgradeState()
	plain := &mockRunner{}
	d := Dispatcher{Runner: plain}
	if resp := d.Dispatch(t.Context(), []string{"apt-upgrade"}); resp.OK || !strings.Contains(resp.Error, "tracked") || plain.lastName != "" {
		t.Fatalf("untracked process fallback accepted: %+v executor=%q", resp, plain.lastName)
	}
	for _, action := range []string{"update", "upgrade", "autoremove", "clean"} {
		want := []string{"-o", "Dpkg::Use-Pty=0", "-o", "DPkg::Lock::Timeout=120", action}
		if action == "upgrade" || action == "autoremove" {
			want = append([]string{"-y"}, want...)
		}
		runner := &aptMutationRunner{run: func(_ context.Context, name string, args []string, _ func(string) error) (int, error) {
			if name != binAptGet || !slices.Equal(args, want) {
				t.Errorf("unexpected executable/arguments: %s %v", name, args)
			}
			return 0, nil
		}}
		if code, err := runAptMutation(t.Context(), runner, action, func(string) error { return nil }); err != nil || code != 0 || runner.calls.Load() != 1 {
			t.Fatalf("fixed mutation %s failed: code=%d err=%v", action, code, err)
		}
	}
	runner := &aptMutationRunner{}
	for _, action := range []string{"install", "upgrade --allow-unauthenticated", "upgrade; touch x"} {
		if _, err := runAptMutation(t.Context(), runner, action, func(string) error { return nil }); err == nil || runner.calls.Load() != 0 {
			t.Fatalf("unknown action accepted: %q", action)
		}
	}
}

func TestSynchronousAptCancellationReleasesReservation(t *testing.T) {
	overrideAptActionLogForTest(t)
	resetAptUpgradeState()
	t.Cleanup(resetAptUpgradeState)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	entered := make(chan struct{})
	runner := &aptMutationRunner{run: func(ctx context.Context, _ string, _ []string, emit func(string) error) (int, error) {
		_ = emit("before cancel")
		close(entered)
		<-ctx.Done()
		return 1, ctx.Err()
	}}
	done := make(chan Response, 1)
	finished := false
	t.Cleanup(func() {
		cancel()
		if !finished {
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				t.Error("canceled fixture did not finish during cleanup")
			}
		}
	})
	go func() { d := Dispatcher{Runner: runner}; done <- d.Dispatch(ctx, []string{"apt-upgrade"}) }()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("mutation did not enter executor")
	}
	cancel()
	select {
	case resp := <-done:
		finished = true
		if resp.OK || !strings.Contains(resp.Error, "context canceled") || !strings.Contains(resp.Error, "before cancel") {
			t.Fatalf("cancellation/diagnostic cause lost: %+v", resp)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("canceled mutation did not finish")
	}
	d := Dispatcher{Runner: &aptMutationRunner{}}
	if resp := d.Dispatch(t.Context(), []string{"apt-clean"}); !resp.OK {
		t.Fatalf("canceled action retained reservation: %+v", resp)
	}
}

func TestSynchronousAptResponseIsBoundedWhileSavedLogContinues(t *testing.T) {
	overrideAptActionLogForTest(t)
	resetAptUpgradeState()
	defer resetAptUpgradeState()
	line := strings.Repeat("x", 64<<10)
	runner := &aptMutationRunner{run: func(_ context.Context, _ string, _ []string, emit func(string) error) (int, error) {
		for range 32 {
			_ = emit(line)
		}
		_ = emit("final diagnostic")
		return 7, nil
	}}
	d := Dispatcher{Runner: runner}
	resp := d.Dispatch(t.Context(), []string{"apt-upgrade"})
	if resp.OK || resp.Code != 7 || len(resp.Stdout) > synchronousAptOutputLimit || !strings.HasSuffix(resp.Stdout, aptExcerptNotice) || !strings.Contains(resp.Error, "final diagnostic") {
		t.Fatalf("response cap/result/diagnostic lost: code=%d bytes=%d error=%q", resp.Code, len(resp.Stdout), resp.Error)
	}
	data, err := readAptActionLog(aptActionLogPath())
	if err != nil || bytes.Count(data, []byte(line)) != 32 || !bytes.Contains(data, []byte("final diagnostic")) {
		t.Fatalf("response cap truncated saved output: log bytes=%d err=%v", len(data), err)
	}
}

func TestProductionAptRunnerPublishesOwnedProcessIdentity(t *testing.T) {
	overrideAptActionLogForTest(t)
	executable, dir := commandProcessFixture(t, "wait")
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	type result struct {
		code int
		err  error
	}
	done := make(chan result, 1)
	finished := false
	t.Cleanup(func() {
		cancel()
		if !finished {
			select {
			case <-done:
			case <-time.After(6 * time.Second):
				t.Error("tracked child did not stop during cleanup")
			}
		}
		_ = clearAptActionPID()
	})
	go func() {
		code, err := (osRunner{}).RunApt(ctx, executable, []string{"-test.run=^TestHostdCommandProcessHelper$"}, func(string) error { return nil })
		done <- result{code, err}
	}()
	waitCommandFixture(t, filepath.Join(dir, "ready"))
	data := waitCommandFixture(t, aptActionPIDPath())
	identity, err := parseAptActionPID(data)
	if err != nil || identity.pid <= 0 || identity.pid == os.Getpid() {
		t.Errorf("tracked runner did not publish its child: %+v %v", identity, err)
	}
	cancel()
	select {
	case got := <-done:
		finished = true
		if got.code == 0 || !errors.Is(got.err, context.Canceled) {
			t.Fatalf("tracked child cancellation cause lost: code=%d err=%v", got.code, got.err)
		}
	case <-time.After(6 * time.Second):
		t.Fatal("tracked child did not stop")
	}
}

func TestSynchronousAptLogFailureCannotClaimSuccess(t *testing.T) {
	overrideAptActionLogForTest(t)
	resetAptUpgradeState()
	defer resetAptUpgradeState()
	logPath := filepath.Join(t.TempDir(), "log-is-a-directory")
	if err := os.Mkdir(logPath, 0o700); err != nil {
		t.Fatal(err)
	}
	SetAptActionLogPathOverrideForTest(logPath)
	runner := &aptMutationRunner{}
	d := Dispatcher{Runner: runner}
	resp := d.Dispatch(t.Context(), []string{"apt-clean"})
	if resp.OK || resp.Code == 0 || !strings.Contains(resp.Error, "apt action log incomplete (command exit code 0)") || runner.calls.Load() != 1 {
		t.Fatalf("log failure canceled execution or claimed success: response=%+v calls=%d", resp, runner.calls.Load())
	}
	if active, code, message := aptActionSnapshot(); active || code != resp.Code || message != resp.Error {
		t.Fatalf("capture failure missing from final status: active=%v code=%d error=%q", active, code, message)
	}
}

func TestSynchronousAptMutationsRespectUnverifiableRecovery(t *testing.T) {
	overrideAptActionLogForTest(t)
	resetAptUpgradeState()
	defer resetAptUpgradeState()
	if err := os.Mkdir(aptActionPIDPath(), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, op := range []string{"apt-update", "apt-upgrade", "apt-clean"} {
		runner := &aptMutationRunner{}
		d := Dispatcher{Runner: runner}
		if resp := d.Dispatch(t.Context(), []string{op}); resp.OK || !strings.Contains(resp.Error, "cannot verify") || runner.calls.Load() != 0 {
			t.Errorf("%s bypassed uncertain recovery: response=%+v calls=%d", op, resp, runner.calls.Load())
		}
	}
}
