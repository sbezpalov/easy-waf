// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package hostd

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

// aptActionLogPathOverride is set in tests to use a temp directory.
var aptActionLogPathOverride string

const maxAptOutputLineBytes = 1 << 20

func aptActionLogPath() string {
	if aptActionLogPathOverride != "" {
		return aptActionLogPathOverride
	}
	return filepath.Join(stateDir, "apt-action.log")
}

// aptActionHeartbeatIntervalNanos is the heartbeat period, overridable in tests.
//
// Stored atomically so test configuration can be read by an active worker.
var aptActionHeartbeatIntervalNanos atomic.Int64

func init() { aptActionHeartbeatIntervalNanos.Store(int64(15 * time.Second)) }

func aptActionHeartbeatInterval() time.Duration {
	return time.Duration(aptActionHeartbeatIntervalNanos.Load())
}

// setAptActionHeartbeatIntervalForTest overrides the heartbeat period.
func setAptActionHeartbeatIntervalForTest(d time.Duration) {
	aptActionHeartbeatIntervalNanos.Store(int64(d))
}

// streamEvent is one NDJSON line on the broker socket for streaming ops.
type streamEvent struct {
	Type  string `json:"type"`
	Data  string `json:"data,omitempty"`
	Code  int    `json:"code"`
	Error string `json:"error,omitempty"`
}

type aptActionPhase uint8

const (
	aptLocal     aptActionPhase = iota // owned by this broker, including the gap before PID publication
	aptRecovered                       // observed a surviving child whose result this broker cannot collect
	aptFinished                        // this broker collected the exit result
)

var (
	aptActionMu         sync.Mutex
	aptActionCurrent    *aptActionRecord
	aptActionStreamHook func(ctx context.Context, action string, emit func(string) error) (code int, err error)
)

func validAptStreamAction(action string) bool {
	return action == "upgrade" || action == "autoremove"
}

func aptActionPIDPath() string {
	if aptActionLogPathOverride != "" {
		return aptActionLogPathOverride + ".pid"
	}
	return filepath.Join(stateDir, "apt-action.pid")
}

func clearAptActionPID() error {
	path := aptActionPIDPath()
	if underStateDir(path) {
		return stateRemoveFile(path)
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// ResetAptUpgradeStateForTest clears single-flight state (tests only).
func ResetAptUpgradeStateForTest() {
	ResetAptActionStateForTest()
}

// ResetAptActionStateForTest clears single-flight state (tests only).
func ResetAptActionStateForTest() {
	aptActionMu.Lock()
	releaseAptActionLocked(aptActionCurrent)
	aptActionCurrent = nil
	aptActionMu.Unlock()
	aptActionStreamHook = nil
	_ = clearAptActionPID()
}

// SetAptUpgradeStreamHookForTest overrides apt execution for upgrade (tests only).
func SetAptUpgradeStreamHookForTest(hook func(ctx context.Context, emit func(string) error) (int, error)) {
	SetAptActionStreamHookForTest(func(ctx context.Context, action string, emit func(string) error) (int, error) {
		_ = action
		return hook(ctx, emit)
	})
}

// SetAptActionStreamHookForTest overrides apt execution (tests only).
func SetAptActionStreamHookForTest(hook func(ctx context.Context, action string, emit func(string) error) (int, error)) {
	aptActionStreamHook = hook
}

// SetAptActionLogPathOverrideForTest redirects the apt action log file (tests only).
func SetAptActionLogPathOverrideForTest(path string) {
	aptActionLogPathOverride = path
}

// aptStreamConn serializes NDJSON writes (heartbeat and apt output share one bufio.Writer).
type aptStreamConn struct {
	bw      *bufio.Writer
	writer  io.Writer
	expires time.Time
	mu      sync.Mutex
}

const (
	aptStreamWriteTimeout = 5 * time.Second
	aptStreamLifetime     = 35 * time.Minute
)

func newAptStreamConn(conn io.Writer) *aptStreamConn {
	return &aptStreamConn{bw: bufio.NewWriter(conn), writer: conn, expires: time.Now().Add(aptStreamLifetime)}
}

func (s *aptStreamConn) close() {
	if closer, ok := s.writer.(io.Closer); ok {
		_ = closer.Close()
	}
}

func (s *aptStreamConn) writeEvent(ev streamEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if time.Now().After(s.expires) {
		return os.ErrDeadlineExceeded
	}
	if socket, ok := s.writer.(interface{ SetWriteDeadline(time.Time) error }); ok {
		deadline := time.Now().Add(aptStreamWriteTimeout)
		if deadline.After(s.expires) {
			deadline = s.expires
		}
		if err := socket.SetWriteDeadline(deadline); err != nil {
			return err
		}
	}
	b, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	if _, err := s.bw.Write(append(b, '\n')); err != nil {
		return err
	}
	return s.bw.Flush()
}

// dispatchAptUpgradeStream runs apt-get upgrade (wrapper).
func dispatchAptUpgradeStream(conn io.Writer) {
	dispatchAptStream(conn, "upgrade")
}

// dispatchAptStream runs apt-get upgrade or autoremove, or attaches to in-flight action.
func dispatchAptStream(conn io.Writer, action string) {
	sc := newAptStreamConn(conn)
	emitExit := func(code int, errMsg string) {
		_ = sc.writeEvent(streamEvent{Type: "exit", Code: code, Error: errMsg})
	}

	if !validAptStreamAction(action) {
		emitExit(-1, "unknown apt action: "+action)
		return
	}
	record, started, err := acquireAptAction(action, aptStreaming)
	if err != nil {
		emitExit(1, err.Error())
		return
	}
	defer releaseAptAction(record)
	if !started {
		if record.mode == aptSynchronous {
			emitExit(1, aptBusyMessage(record))
			return
		}
		dispatchAptActionAttach(sc, record)
		return
	}
	dispatchAptActionPrimary(sc, action, record)
}

func dispatchAptActionPrimary(sc *aptStreamConn, action string, record *aptActionRecord) {
	delivery := newAptLiveDelivery(sc)
	code, runErr := runAptPrimary(context.Background(), record, action, func(ctx context.Context, emit func(string) error) (int, error) {
		return runAptActionStream(ctx, action, emit)
	}, delivery.line)
	errMsg := ""
	if runErr != nil {
		errMsg = runErr.Error()
	}
	delivery.finish(code, errMsg)
}

func dispatchAptActionAttach(sc *aptStreamConn, record *aptActionRecord) {
	followAptRecord(sc, record, "==> attaching to apt action already in progress ...")
}

// Unlike mutation streams, this opcode only reads the selected record, even
// when it completed after the client's status request. It never starts APT.
func dispatchAptObserveStream(conn io.Writer, id string) {
	sc := newAptStreamConn(conn)
	record, err := acquireObservedAptAction(id)
	if err != nil {
		_ = sc.writeEvent(streamEvent{Type: "exit", Code: -1, Error: err.Error()})
		return
	}
	defer releaseAptAction(record)
	followAptRecord(sc, record, "==> following saved apt action output ...")
}

func followAptRecord(sc *aptStreamConn, record *aptActionRecord, banner string) {
	emitExit := func(code int, errMsg string) {
		_ = sc.writeEvent(streamEvent{Type: "exit", Code: code, Error: errMsg})
	}

	emitLine := func(line string) error {
		return sc.writeEvent(streamEvent{Type: "line", Data: line})
	}

	if err := emitLine(banner); err != nil {
		return
	}
	readyTimeout := time.NewTimer(time.Until(sc.expires))
	defer readyTimeout.Stop()
	select {
	case <-record.ready:
	case <-readyTimeout.C:
		return
	}
	if active, code, message := aptRecordSnapshot(record); active && message != "" {
		emitExit(code, message)
		return
	}
	if record.logErr != nil {
		emitExit(-1, "cannot read apt action log: "+record.logErr.Error())
		return
	}

	var offset int64
	lastDelivery := time.Now()
	for {
		// Observe completion before reading: a completed run can no longer
		// append, so the final drain cannot miss a line written before Finish.
		active, code, errMsg := aptRecordSnapshot(record)
		if active && errMsg != "" {
			emitExit(code, errMsg)
			return
		}
		lines, newOff, err := readAptActionLogFileFrom(record.log, offset)
		offset = newOff
		for _, line := range lines {
			if err := emitLine(line); err != nil {
				return
			}
			lastDelivery = time.Now()
		}
		if err != nil {
			emitExit(-1, "cannot read apt action log: "+err.Error())
			return
		}

		if len(lines) > 0 {
			continue // catch up/drain bounded batches without a polling delay
		}
		if !active {
			st, statErr := record.log.Stat()
			if statErr != nil {
				emitExit(-1, "cannot read apt action log: "+statErr.Error())
				return
			}
			if offset < st.Size() {
				emitExit(-1, "incomplete final apt action log line")
				return
			}
			emitExit(code, errMsg)
			return
		}
		if time.Since(lastDelivery) >= aptActionHeartbeatInterval() {
			if err := emitLine("==> waiting for apt action output ..."); err != nil {
				return
			}
			lastDelivery = time.Now()
		}
		time.Sleep(250 * time.Millisecond)
	}
}

func readAptActionLogFrom(offset int64) (lines []string, newOffset int64, err error) {
	f, err := openAptActionLog(aptActionLogPath())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, 0, nil
		}
		return nil, offset, err
	}
	defer f.Close()
	return readAptActionLogFileFrom(f, offset)
}

// dispatchAptActionStatus returns whether an apt action is in progress (JSON in stdout).
func dispatchAptActionStatus() Response {
	aptActionMu.Lock()
	active, code, errMsg := aptActionSnapshotLocked()
	status := map[string]any{
		"active":    active,
		"exit_code": code,
		"error":     errMsg,
	}
	if aptActionCurrent != nil {
		status["run_id"] = aptActionCurrent.id
	}
	if aptActionCurrent != nil && aptActionCurrent.action != "" {
		status["action"] = aptActionCurrent.action
		status["stream"] = aptActionCurrent.mode == aptStreaming
	}
	aptActionMu.Unlock()
	payload, err := json.Marshal(status)
	if err != nil {
		return failResp(err.Error(), 1)
	}
	return okResp(payload, nil, 0)
}

// dispatchAptUpgradeStatus is a legacy alias.
func dispatchAptUpgradeStatus() Response {
	return dispatchAptActionStatus()
}

// dispatchAptActionLog returns the current apt action log (read-only).
func dispatchAptActionLog() Response {
	b, err := readAptActionLog(aptActionLogPath())
	if err != nil {
		if os.IsNotExist(err) {
			return okResp(nil, nil, 0)
		}
		return failResp(err.Error(), 1)
	}
	return okResp(b, nil, 0)
}

// dispatchAptUpgradeLog is a legacy alias.
func dispatchAptUpgradeLog() Response {
	return dispatchAptActionLog()
}

func runAptActionStream(ctx context.Context, action string, emit func(string) error) (int, error) {
	return runAptOutput(ctx, func(ctx context.Context, emit func(string) error) (int, error) {
		if aptActionStreamHook != nil {
			return aptActionStreamHook(ctx, action, emit)
		}
		return execAptStream(ctx, action, emit)
	}, emit)
}

func runAptOutput(ctx context.Context, execute aptExecution, emit func(string) error) (int, error) {
	done := make(chan struct{})
	heartbeatDone := make(chan struct{})
	var emitMu sync.Mutex
	lastLineAt := time.Now()
	started := time.Now()
	go func() {
		defer close(heartbeatDone)
		aptActionHeartbeat(ctx, done, started, &emitMu, &lastLineAt, emit)
	}()
	defer func() {
		close(done)
		// The caller may now emit the final exit and close its log/socket.
		// No callback can remain in flight once we return.
		<-heartbeatDone
	}()

	wrapEmit := func(line string) error {
		emitMu.Lock()
		defer func() {
			lastLineAt = time.Now()
			emitMu.Unlock()
		}()
		return emit(line)
	}

	return execute(ctx, wrapEmit)
}

func execAptStream(ctx context.Context, action string, emit func(string) error) (int, error) {
	return runAptMutation(ctx, DefaultRunner, action, emit)
}

func (osRunner) RunApt(ctx context.Context, name string, args []string, emit func(string) error) (int, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")
	return execAptCommand(ctx, cmd, emit)
}

func execAptCommand(ctx context.Context, cmd *exec.Cmd, emit func(string) error) (int, error) {
	if cmd.Stdout != nil || cmd.Stderr != nil {
		return 1, errors.New("apt output already configured")
	}
	// Own these descriptors: StdoutPipe/StderrPipe would let concurrent Wait
	// close the readers before all buffered output has been consumed.
	stdout, stdoutWriter, err := os.Pipe()
	if err != nil {
		return 1, err
	}
	defer stdout.Close()
	defer stdoutWriter.Close()
	stderr, stderrWriter, err := os.Pipe()
	if err != nil {
		return 1, err
	}
	defer stderr.Close()
	defer stderrWriter.Close()
	cmd.Stdout, cmd.Stderr = stdoutWriter, stderrWriter
	cmd.WaitDelay = commandWaitDelay
	prepareCommandProcess(cmd)
	if err := cmd.Start(); err != nil {
		return 1, err
	}
	// Only the child owns write ends now, so EOF reflects child/descendant exit.
	_ = stdoutWriter.Close()
	_ = stderrWriter.Close()
	if cmd.Process != nil {
		if err := writeAptActionPID(cmd.Process.Pid); err != nil {
			cleanupErr := finishCommandProcess(cmd, true)
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			return 1, errors.Join(fmt.Errorf("write apt action pid: %w", err), cleanupErr)
		}
	}

	lineCh := make(chan string, 64)
	captureErrors := make(chan error, 2)
	var wg sync.WaitGroup
	pipeLines := func(r io.Reader, stream string) {
		defer wg.Done()
		sc := bufio.NewScanner(r)
		sc.Buffer(make([]byte, 64<<10), maxAptOutputLineBytes)
		for sc.Scan() {
			lineCh <- sc.Text()
		}
		if scanErr := sc.Err(); scanErr != nil {
			// In particular, ErrTooLong leaves the child able to fill this pipe
			// and block forever. Keep consuming with bounded memory so apt can
			// finish; report incomplete capture rather than pretending success.
			_, drainErr := io.Copy(io.Discard, r)
			captureErrors <- fmt.Errorf("apt output (%s): %w", stream, errors.Join(scanErr, drainErr))
		}
	}
	wg.Add(2)
	go pipeLines(stdout, "stdout")
	go pipeLines(stderr, "stderr")
	readersDone := make(chan struct{})
	go func() {
		wg.Wait()
		close(lineCh)
		close(captureErrors)
		close(readersDone)
	}()
	waitResult := make(chan error, 1)
	go func() {
		// Reap the parent even when a service/helper inherited an output pipe.
		// Give normal buffered output time to drain; an open inherited pipe
		// cannot keep single-flight ownership forever after the parent exits.
		runErr := cmd.Wait()
		timer := time.NewTimer(commandWaitDelay)
		defer timer.Stop()
		select {
		case <-readersDone:
		case <-timer.C:
			_ = stdout.Close()
			_ = stderr.Close()
			runErr = errors.Join(runErr, exec.ErrWaitDelay)
		}
		waitResult <- runErr
	}()

	for line := range lineCh {
		_ = emit(line)
	}

	var captureErr error
	for err := range captureErrors {
		captureErr = errors.Join(captureErr, err)
	}
	runErr := <-waitResult
	if ctxErr := ctx.Err(); runErr != nil && ctxErr != nil && !errors.Is(runErr, ctxErr) {
		runErr = errors.Join(runErr, ctxErr)
	}
	// A successful package script may intentionally start a service. Failed
	// commands/capture must not leave their process group holding dpkg resources.
	cleanupErr := finishCommandProcess(cmd, runErr != nil || captureErr != nil)
	resultErr := errors.Join(runErr, captureErr, cleanupErr)
	code := cmd.ProcessState.ExitCode()
	if code == 0 && resultErr != nil {
		code = 1
	}
	return code, resultErr
}

func aptActionHeartbeat(ctx context.Context, done <-chan struct{}, started time.Time, emitMu *sync.Mutex, lastLineAt *time.Time, emit func(string) error) {
	ticker := time.NewTicker(aptActionHeartbeatInterval())
	defer ticker.Stop()
	emitHeartbeat := func() {
		emitMu.Lock()
		defer emitMu.Unlock()
		// Output may have held the mutex while the command finished or was
		// canceled. Do not emit a queued heartbeat after shutdown began.
		select {
		case <-ctx.Done():
			return
		case <-done:
			return
		default:
		}
		if time.Since(*lastLineAt) < aptActionHeartbeatInterval() {
			return
		}
		elapsed := time.Since(started).Round(time.Second)
		_ = emit(fmt.Sprintf("... still working (elapsed %s) ...", elapsed))
		*lastLineAt = time.Now()
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-done:
			return
		case <-ticker.C:
			emitHeartbeat()
		}
	}
}
