package hostd

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
	"sync/atomic"
	"time"
)

const (
	defaultAptActionLogPath  = "/var/lib/easy-waf/apt-action.log"
	defaultAptUpgradeLogPath = "/var/lib/easy-waf/apt-upgrade.log" // legacy path (read fallback)
)

// aptActionLogPathOverride is set in tests to use a temp directory.
var aptActionLogPathOverride string

func aptActionLogPath() string {
	if aptActionLogPathOverride != "" {
		return aptActionLogPathOverride
	}
	return defaultAptActionLogPath
}

// aptActionHeartbeatIntervalNanos is the heartbeat period, overridable in tests.
//
// Stored atomically: the heartbeat goroutine outlives the request that started
// it by a moment, so a test restoring the default while that goroutine still
// reads the value is a genuine data race (caught by `go test -race`).
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
	Code  int    `json:"code,omitempty"`
	Error string `json:"error,omitempty"`
}

var (
	aptActionMu         sync.Mutex
	aptActionActive     bool
	aptActionLastCode   int
	aptActionLastErr    string
	aptActionStreamHook func(ctx context.Context, action string, emit func(string) error) (code int, err error)
)

func validAptStreamAction(action string) bool {
	return action == "upgrade" || action == "autoremove"
}

func aptActionTryStart() bool {
	aptActionMu.Lock()
	defer aptActionMu.Unlock()
	if aptActionActive {
		return false
	}
	aptActionActive = true
	aptActionLastCode = 0
	aptActionLastErr = ""
	return true
}

func aptActionFinish(code int, errMsg string) {
	aptActionMu.Lock()
	aptActionActive = false
	aptActionLastCode = code
	aptActionLastErr = errMsg
	aptActionMu.Unlock()
}

func aptActionSnapshot() (active bool, code int, errMsg string) {
	aptActionMu.Lock()
	defer aptActionMu.Unlock()
	return aptActionActive, aptActionLastCode, aptActionLastErr
}

// ResetAptUpgradeStateForTest clears single-flight state (tests only).
func ResetAptUpgradeStateForTest() {
	ResetAptActionStateForTest()
}

// ResetAptActionStateForTest clears single-flight state (tests only).
func ResetAptActionStateForTest() {
	aptActionMu.Lock()
	aptActionActive = false
	aptActionLastCode = 0
	aptActionLastErr = ""
	aptActionMu.Unlock()
	aptActionStreamHook = nil
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
	if !aptActionTryStart() {
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

	aptCtx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
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
	if err != nil && os.IsNotExist(err) {
		b, err = readAptActionLog(defaultAptUpgradeLogPath)
	}
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
	defer close(done)
	var lastLineMu sync.Mutex
	lastLineAt := time.Now()
	started := time.Now()
	go aptActionHeartbeat(ctx, done, started, &lastLineMu, &lastLineAt, emit)

	wrapEmit := func(line string) error {
		lastLineMu.Lock()
		lastLineAt = time.Now()
		lastLineMu.Unlock()
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
	cmd := exec.CommandContext(ctx, "apt-get", args...)
	cmd.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return 1, err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return 1, err
	}
	if err := cmd.Start(); err != nil {
		return 1, err
	}

	lineCh := make(chan string, 64)
	var wg sync.WaitGroup
	pipeLines := func(r io.Reader) {
		defer wg.Done()
		sc := bufio.NewScanner(r)
		sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		for sc.Scan() {
			lineCh <- sc.Text()
		}
	}
	wg.Add(2)
	go pipeLines(stdout)
	go pipeLines(stderr)
	go func() {
		wg.Wait()
		close(lineCh)
	}()

	for line := range lineCh {
		_ = emit(line)
	}

	if err := cmd.Wait(); err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return ee.ExitCode(), err
		}
		return 1, err
	}
	return 0, nil
}

func aptActionHeartbeat(ctx context.Context, done <-chan struct{}, started time.Time, lastLineMu *sync.Mutex, lastLineAt *time.Time, emit func(string) error) {
	ticker := time.NewTicker(aptActionHeartbeatInterval())
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-done:
			return
		case <-ticker.C:
			lastLineMu.Lock()
			silent := time.Since(*lastLineAt)
			lastLineMu.Unlock()
			if silent < aptActionHeartbeatInterval() {
				continue
			}
			elapsed := time.Since(started).Round(time.Second)
			_ = emit(fmt.Sprintf("... still working (elapsed %s) ...", elapsed))
			lastLineMu.Lock()
			*lastLineAt = time.Now()
			lastLineMu.Unlock()
		}
	}
}
