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
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
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
	aptIdle      aptActionPhase = iota
	aptLocal                    // owned by this broker, including the gap before PID publication
	aptRecovered                // observed a surviving child whose result this broker cannot collect
	aptFinished                 // this broker collected the exit result
)

var (
	aptActionMu         sync.Mutex
	aptActionState      aptActionPhase
	aptActionLastCode   int
	aptActionLastErr    string
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

func aptActionPIDAlive() bool {
	b, err := readAptActionPID()
	if err != nil {
		return false
	}
	var pid int
	if _, err := fmt.Sscanf(strings.TrimSpace(string(b)), "%d", &pid); err != nil || pid <= 0 {
		return false
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	// Signal 0: existence check on Unix.
	return proc.Signal(syscall.Signal(0)) == nil
}

func readAptActionPID() ([]byte, error) {
	path := aptActionPIDPath()
	if underStateDir(path) {
		f, err := stateOpenFile(path)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		return io.ReadAll(io.LimitReader(f, 128))
	}
	return os.ReadFile(path)
}

func writeAptActionPID(pid int) error {
	path := aptActionPIDPath()
	data := []byte(fmt.Sprintf("%d\n", pid))
	if underStateDir(path) {
		return stateWriteFile(path, data, 0o600)
	}
	return os.WriteFile(path, data, 0o600)
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

func aptActionTryStart() (bool, error) {
	aptActionMu.Lock()
	defer aptActionMu.Unlock()
	if aptActionState == aptLocal {
		return false, nil
	}
	// Persist across hostd restarts: an apt-get left running still owns the
	// dpkg lock; treat it as in-flight so callers attach instead of starting a second.
	if aptActionState != aptFinished && aptActionPIDAlive() {
		aptActionState = aptRecovered
		return false, nil
	}
	if err := clearAptActionPID(); err != nil {
		return false, fmt.Errorf("clear apt action pid: %w", err)
	}
	aptActionState = aptLocal
	aptActionLastCode = 0
	aptActionLastErr = ""
	return true, nil
}

func aptActionFinish(code int, errMsg string) {
	aptActionMu.Lock()
	defer aptActionMu.Unlock()
	// Clear the old PID before releasing single-flight ownership. Otherwise a
	// new primary could publish its PID and have this completion remove it.
	if err := clearAptActionPID(); err != nil {
		logOp("clear apt action pid: %v", err)
	}
	aptActionState = aptFinished
	aptActionLastCode = code
	aptActionLastErr = errMsg
}

func aptActionSnapshot() (active bool, code int, errMsg string) {
	aptActionMu.Lock()
	defer aptActionMu.Unlock()
	if aptActionState == aptLocal {
		// PID liveness cannot release a local reservation: the child may not
		// have started yet, or may have exited before its owner calls Finish.
		return true, aptActionLastCode, aptActionLastErr
	}
	if aptActionState == aptFinished {
		return false, aptActionLastCode, aptActionLastErr
	}
	if aptActionPIDAlive() {
		aptActionState = aptRecovered
		return true, 0, ""
	}
	_, pidErr := readAptActionPID()
	if aptActionState == aptRecovered || !os.IsNotExist(pidErr) {
		return false, -1, "apt action exit status unavailable after broker restart; inspect the apt action log"
	}
	return false, aptActionLastCode, aptActionLastErr
}

// ResetAptUpgradeStateForTest clears single-flight state (tests only).
func ResetAptUpgradeStateForTest() {
	ResetAptActionStateForTest()
}

// ResetAptActionStateForTest clears single-flight state (tests only).
func ResetAptActionStateForTest() {
	aptActionMu.Lock()
	aptActionState = aptIdle
	aptActionLastCode = 0
	aptActionLastErr = ""
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
	bw *bufio.Writer
	mu sync.Mutex
}

func newAptStreamConn(conn io.Writer) *aptStreamConn {
	return &aptStreamConn{bw: bufio.NewWriter(conn)}
}

func (s *aptStreamConn) writeEvent(ev streamEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
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
	started, err := aptActionTryStart()
	if err != nil {
		emitExit(1, err.Error())
		return
	}
	if !started {
		dispatchAptActionAttach(sc)
		return
	}
	dispatchAptActionPrimary(sc, action)
}

func dispatchAptActionPrimary(sc *aptStreamConn, action string) {
	emitExit := func(code int, errMsg string) {
		_ = sc.writeEvent(streamEvent{Type: "exit", Code: code, Error: errMsg})
	}

	logPath := aptActionLogPath()
	logFile, err := createAptActionLog(logPath)
	if err != nil {
		logOp("apt-stream %s: log file: %v", action, err)
	}
	if logFile != nil {
		defer logFile.Close()
	}

	aptCtx, cancel := context.WithTimeout(context.Background(), aptCommandTimeout)
	defer cancel()

	clientDown := false
	emitLine := func(line string) error {
		if logFile != nil {
			_, _ = fmt.Fprintln(logFile, line)
			_ = logFile.Sync()
		}
		if clientDown {
			return nil
		}
		if err := sc.writeEvent(streamEvent{Type: "line", Data: line}); err != nil {
			clientDown = true
			return nil
		}
		return nil
	}

	_ = emitLine(fmt.Sprintf("==> starting apt-get %s ...", action))
	emitDpkgLockHint(emitLine)

	code, runErr := runAptActionStream(aptCtx, action, emitLine)
	errMsg := ""
	if runErr != nil {
		errMsg = runErr.Error()
		if code == 0 {
			code = 1
		}
	}
	aptActionFinish(code, errMsg)
	emitExit(code, errMsg)
}

func dispatchAptActionAttach(sc *aptStreamConn) {
	emitExit := func(code int, errMsg string) {
		_ = sc.writeEvent(streamEvent{Type: "exit", Code: code, Error: errMsg})
	}

	clientDown := false
	emitLine := func(line string) error {
		if clientDown {
			return nil
		}
		if err := sc.writeEvent(streamEvent{Type: "line", Data: line}); err != nil {
			clientDown = true
			return nil
		}
		return nil
	}

	_ = emitLine("==> attaching to apt action already in progress ...")

	var offset int64
	for {
		lines, newOff, err := readAptActionLogFrom(offset)
		if err != nil {
			emitExit(-1, "cannot read apt action log: "+err.Error())
			return
		}
		offset = newOff
		for _, line := range lines {
			_ = emitLine(line)
		}

		active, code, errMsg := aptActionSnapshot()
		if !active {
			emitExit(code, errMsg)
			return
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
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return nil, offset, err
	}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), maxAptOutputLineBytes)
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	if err := sc.Err(); err != nil {
		return lines, offset, err
	}
	newOffset, err = f.Seek(0, io.SeekCurrent)
	return lines, newOffset, err
}

// dispatchAptActionStatus returns whether an apt action is in progress (JSON in stdout).
func dispatchAptActionStatus() Response {
	active, code, errMsg := aptActionSnapshot()
	payload, err := json.Marshal(map[string]any{
		"active":    active,
		"exit_code": code,
		"error":     errMsg,
	})
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

	if aptActionStreamHook != nil {
		return aptActionStreamHook(ctx, action, wrapEmit)
	}
	return execAptStream(ctx, action, wrapEmit)
}

func execAptStream(ctx context.Context, action string, emit func(string) error) (int, error) {
	args := []string{
		"-y",
		"-o", "Dpkg::Use-Pty=0",
		"-o", "DPkg::Lock::Timeout=120",
		action,
	}
	cmd := exec.CommandContext(ctx, binAptGet, args...)
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
