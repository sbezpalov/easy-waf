// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package hostd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type aptReplayGate struct {
	bytes.Buffer
	entered chan struct{}
	release chan struct{}
}

func (w *aptReplayGate) Write(p []byte) (int, error) {
	var event streamEvent
	if json.Unmarshal(bytes.TrimSpace(p), &event) == nil && event.Data == "first-line" {
		close(w.entered)
		<-w.release
	}
	return w.Buffer.Write(p)
}

func TestAptFollowerKeepsFinalOutputAndOriginalResult(t *testing.T) {
	for _, fixture := range []struct{ nextAction, anchored, observer, synchronous bool }{
		{}, {nextAction: true}, {anchored: true}, {nextAction: true, anchored: true},
		{observer: true}, {nextAction: true, observer: true}, {anchored: true, observer: true},
		{nextAction: true, anchored: true, observer: true},
		{nextAction: true, anchored: true, observer: true, synchronous: true},
	} {
		nextAction := fixture.nextAction
		name := "final_drain"
		if nextAction {
			name = "next_action"
		}
		if fixture.anchored {
			name += "_state"
		}
		if fixture.observer {
			name += "_observer"
		}
		if fixture.synchronous {
			name += "_synchronous"
		}
		t.Run(name, func(t *testing.T) {
			if fixture.anchored {
				newTestStateDir(t)
				previous := aptActionLogPathOverride
				aptActionLogPathOverride = ""
				t.Cleanup(func() { aptActionLogPathOverride = previous })
			} else {
				overrideAptActionLogForTest(t)
			}
			resetAptUpgradeState()
			started := make(chan struct{})
			finishPrimary := make(chan struct{})
			primaryDone := make(chan struct{})
			gate := &aptReplayGate{entered: make(chan struct{}), release: make(chan struct{})}
			followerDone := make(chan struct{})
			execute := func(ctx context.Context, emit func(string) error) (int, error) {
				_ = emit("first-line")
				close(started)
				select {
				case <-finishPrimary:
				case <-ctx.Done():
					return 1, ctx.Err()
				}
				_ = emit("last-line")
				return 7, nil
			}
			SetAptUpgradeStreamHookForTest(execute)
			t.Cleanup(func() {
				for _, ch := range []chan struct{}{finishPrimary, gate.release} {
					select {
					case <-ch:
					default:
						close(ch)
					}
				}
				for _, ch := range []chan struct{}{primaryDone, followerDone} {
					select {
					case <-ch:
					case <-time.After(3 * time.Second):
						t.Error("APT replay fixture did not stop")
					}
				}
				resetAptUpgradeState()
			})
			go func() {
				defer close(primaryDone)
				if fixture.synchronous {
					d := Dispatcher{Runner: &aptMutationRunner{run: func(ctx context.Context, _ string, _ []string, emit func(string) error) (int, error) {
						return execute(ctx, emit)
					}}}
					_ = d.Dispatch(context.Background(), []string{"apt-clean"})
				} else {
					dispatchAptStream(io.Discard, "upgrade")
				}
			}()
			select {
			case <-started:
			case <-time.After(3 * time.Second):
				t.Fatal("primary did not start")
			}
			id := aptStatusRunID(t)
			go func() {
				defer close(followerDone)
				if fixture.observer {
					dispatchAptObserveStream(gate, id)
				} else {
					dispatchAptStream(gate, "autoremove")
				}
			}()
			select {
			case <-gate.entered:
			case <-time.After(3 * time.Second):
				t.Fatal("follower did not read first line")
			}
			aptActionMu.Lock()
			originalLog := aptActionCurrent.log
			aptActionMu.Unlock()
			close(finishPrimary)
			select {
			case <-primaryDone:
			case <-time.After(3 * time.Second):
				t.Fatal("primary did not finish")
			}
			if nextAction {
				SetAptUpgradeStreamHookForTest(func(context.Context, func(string) error) (int, error) { return 0, nil })
				dispatchAptStream(io.Discard, "autoremove")
				if _, err := originalLog.Stat(); err != nil {
					t.Fatalf("next action closed a live follower's log: %v", err)
				}
			}
			close(gate.release)
			select {
			case <-followerDone:
			case <-time.After(3 * time.Second):
				t.Fatal("follower did not finish")
			}
			events := readStreamEvents(t, &gate.Buffer)
			var lines []string
			for _, event := range events {
				if event.Type == "line" {
					lines = append(lines, event.Data)
				}
			}
			last := events[len(events)-1]
			if last.Type != "exit" || last.Code != 7 || !strings.Contains(strings.Join(lines, "\n"), "last-line") {
				t.Fatalf("follower lost its final output/result: lines=%v exit=%+v", lines, last)
			}
			if nextAction {
				if _, err := originalLog.ReadAt(make([]byte, 1), 0); !errors.Is(err, os.ErrClosed) {
					t.Fatalf("old log descriptor leaked after last follower: %v", err)
				}
				if active, code, _ := aptActionSnapshot(); active || code != 0 {
					t.Fatalf("old follower changed latest status: active=%v code=%d", active, code)
				}
			}
		})
	}
}

type aptLogFaultFile struct {
	bytes.Buffer
	writeErr error
	short    bool
	syncErr  error
	closeErr error
	syncs    int
}

func (f *aptLogFaultFile) Write(p []byte) (int, error) {
	if f.writeErr != nil {
		return 0, f.writeErr
	}
	if f.short {
		return f.Buffer.Write(p[:len(p)-1])
	}
	return f.Buffer.Write(p)
}

func (f *aptLogFaultFile) Sync() error  { f.syncs++; return f.syncErr }
func (f *aptLogFaultFile) Close() error { return f.closeErr }

func TestAptLogSinkReportsPersistenceFailureAndBoundsSize(t *testing.T) {
	fault := errors.New("fixture disk failure")
	for _, stage := range []string{"write", "short", "sync", "close", "limit"} {
		t.Run(stage, func(t *testing.T) {
			file := &aptLogFaultFile{}
			sink := aptLogSink{file: file}
			switch stage {
			case "write":
				file.writeErr = fault
			case "short":
				file.short = true
			case "sync":
				file.syncErr = fault
			case "close":
				file.closeErr = fault
			case "limit":
				sink.size = maxAptActionLogBytes - int64(len("line\n"))
			}
			sink.line("line")
			if stage != "close" {
				sink.line("second line")
			}
			err := sink.close()
			switch stage {
			case "limit":
				if err == nil || !strings.Contains(err.Error(), "64 MiB") || file.String() != "line\n" {
					t.Fatalf("log limit not enforced at a complete-line boundary: output=%q err=%v", file.String(), err)
				}
			case "short":
				if !errors.Is(err, io.ErrShortWrite) {
					t.Fatalf("short write hidden: %v", err)
				}
			default:
				if !errors.Is(err, fault) {
					t.Fatalf("%s cause lost: %v", stage, err)
				}
			}
			if stage == "write" && file.syncs != 0 {
				t.Fatal("continued syncing after write failed")
			}
			if stage == "sync" && (file.syncs != 1 || file.String() != "line\n") {
				t.Fatal("continued writing after persistence failed")
			}
		})
	}
}

func TestAptReplayRejectsCorruptLog(t *testing.T) {
	overrideAptActionLogForTest(t)
	path := aptActionLogPath()
	if err := os.WriteFile(path, []byte("ok\n"+strings.Repeat("x", 3*maxAptOutputLineBytes)), 0o600); err != nil {
		t.Fatal(err)
	}
	lines, offset, err := readAptActionLogFrom(0)
	if err == nil || len(lines) != 1 || lines[0] != "ok" || offset != 3 {
		t.Fatalf("oversized line not rejected after complete output: lines=%v offset=%d err=%v", lines, offset, err)
	}
	if err := os.Truncate(path, 0); err != nil {
		t.Fatal(err)
	}
	for _, invalidOffset := range []int64{-1, offset} {
		if _, _, err := readAptActionLogFrom(invalidOffset); err == nil {
			t.Fatalf("invalid/truncated offset %d accepted", invalidOffset)
		}
	}
}

func TestAptFollowerReportsIncompleteFinalLine(t *testing.T) {
	overrideAptActionLogForTest(t)
	resetAptUpgradeState()
	defer resetAptUpgradeState()
	record, started, err := acquireAptAction("upgrade", aptStreaming)
	if err != nil || !started {
		t.Fatalf("reserve: %v %v", started, err)
	}
	defer releaseAptAction(record)
	f, err := createAptActionLog(aptActionLogPath())
	if err != nil {
		t.Fatal(err)
	}
	publishAptActionLog(record, nil)
	_, writeErr := f.WriteString("complete\nincomplete")
	closeErr := f.Close()
	if err := errors.Join(writeErr, closeErr); err != nil {
		t.Fatal(err)
	}
	finishAptAction(record, 0, "")
	var output bytes.Buffer
	dispatchAptActionAttach(newAptStreamConn(&output), record)
	events := readStreamEvents(t, &output)
	last := events[len(events)-1]
	if last.Type != "exit" || last.Code == 0 || !strings.Contains(last.Error, "incomplete final") {
		t.Fatalf("incomplete final log reported success: %+v", last)
	}
	if len(events) != 3 || events[1].Data != "complete" {
		t.Fatalf("complete/partial line delivery changed: %+v", events)
	}
}

func TestAptReplayUsesBoundedBatches(t *testing.T) {
	overrideAptActionLogForTest(t)
	line := strings.Repeat("x", 64<<10) + "\n"
	if err := os.WriteFile(aptActionLogPath(), []byte(strings.Repeat(line, 48)), 0o600); err != nil {
		t.Fatal(err)
	}
	var offset int64
	var count int
	var batches int
	for {
		lines, next, err := readAptActionLogFrom(offset)
		if err != nil {
			t.Fatal(err)
		}
		if len(lines) == 0 {
			break
		}
		batches++
		if next <= offset || next-offset > maxAptReplayBatchBytes+int64(len(line)) {
			t.Fatalf("unbounded/invalid batch: %d -> %d", offset, next)
		}
		for _, got := range lines {
			if got+"\n" != line {
				t.Fatal("batch split a complete log line")
			}
		}
		count += len(lines)
		offset = next
	}
	if batches < 2 || count != 48 || offset != 48*int64(len(line)) {
		t.Fatalf("replay lost/duplicated output: batches=%d lines=%d offset=%d", batches, count, offset)
	}
}

func TestAptReplayBoundsEmptyLineCount(t *testing.T) {
	overrideAptActionLogForTest(t)
	if err := os.WriteFile(aptActionLogPath(), []byte(strings.Repeat("\n", 3*maxAptReplayBatchLines)), 0o600); err != nil {
		t.Fatal(err)
	}
	lines, offset, err := readAptActionLogFrom(0)
	if err != nil || len(lines) != maxAptReplayBatchLines || offset != maxAptReplayBatchLines {
		t.Fatalf("unbounded empty-line batch: lines=%d offset=%d err=%v", len(lines), offset, err)
	}
}

func TestAptReplayRetainsPartialLineUntilAppend(t *testing.T) {
	overrideAptActionLogForTest(t)
	if err := os.WriteFile(aptActionLogPath(), []byte("complete\npar"), 0o600); err != nil {
		t.Fatal(err)
	}
	lines, offset, err := readAptActionLogFrom(0)
	if err != nil || len(lines) != 1 || lines[0] != "complete" || offset != 9 {
		t.Fatalf("partial line consumed: lines=%v offset=%d err=%v", lines, offset, err)
	}
	f, err := os.OpenFile(aptActionLogPath(), os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.WriteString("tial\r\n")
	_ = f.Close()
	if err != nil {
		t.Fatal(err)
	}
	lines, offset, err = readAptActionLogFrom(offset)
	if err != nil || len(lines) != 1 || lines[0] != "partial" || offset != 18 {
		t.Fatalf("append lost/duplicated: lines=%v offset=%d err=%v", lines, offset, err)
	}
}

func TestAptLogCreationFailureCannotReportSuccess(t *testing.T) {
	overrideAptActionLogForTest(t)
	resetAptUpgradeState()
	defer resetAptUpgradeState()
	blocker := filepath.Join(t.TempDir(), "log-is-a-directory")
	if err := os.Mkdir(blocker, 0o700); err != nil {
		t.Fatal(err)
	}
	// The .pid sibling remains valid on every OS: fail log creation itself,
	// not the earlier PID cleanup (ENOTDIR classification differs by platform).
	SetAptActionLogPathOverrideForTest(blocker)
	called := false
	SetAptUpgradeStreamHookForTest(func(_ context.Context, emit func(string) error) (int, error) {
		called = true
		_ = emit("output survives log creation failure")
		return 0, nil
	})
	var output bytes.Buffer
	dispatchAptStream(&output, "upgrade")
	if !called {
		t.Fatal("fixture did not reach the command after log creation failed")
	}
	events := readStreamEvents(t, &output)
	last := events[len(events)-1]
	liveOutput := false
	for _, event := range events {
		if event.Data == "output survives log creation failure" {
			liveOutput = true
		}
	}
	if !liveOutput {
		t.Fatal("saved-log failure prevented healthy live delivery")
	}
	if last.Code == 0 || !strings.Contains(last.Error, "apt action log") {
		t.Fatalf("unavailable log reported as success: %+v", last)
	}
	if active, code, message := aptActionSnapshot(); active || code != last.Code || message != last.Error {
		t.Fatalf("log failure missing from status: active=%v code=%d error=%q", active, code, message)
	}
}
