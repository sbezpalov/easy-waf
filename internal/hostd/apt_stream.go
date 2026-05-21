package hostd

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"
)

const defaultAptUpgradeLogPath = "/var/lib/easy-waf/apt-upgrade.log"

// aptUpgradeLogPathOverride is set in tests to use a temp directory.
var aptUpgradeLogPathOverride string

func aptUpgradeLogPath() string {
	if aptUpgradeLogPathOverride != "" {
		return aptUpgradeLogPathOverride
	}
	return defaultAptUpgradeLogPath
}

// aptUpgradeHeartbeatInterval is overridable in tests.
var aptUpgradeHeartbeatInterval = 15 * time.Second

// streamEvent is one NDJSON line on the broker socket for streaming ops.
type streamEvent struct {
	Type  string `json:"type"`
	Data  string `json:"data,omitempty"`
	Code  int    `json:"code,omitempty"`
	Error string `json:"error,omitempty"`
}

var (
	aptUpgradeMu         sync.Mutex
	aptUpgradeActive     bool
	aptUpgradeLastCode   int
	aptUpgradeLastErr    string
	aptUpgradeStreamHook func(ctx context.Context, emit func(string) error) (code int, err error)
)

func aptUpgradeTryStart() bool {
	aptUpgradeMu.Lock()
	defer aptUpgradeMu.Unlock()
	if aptUpgradeActive {
		return false
	}
	aptUpgradeActive = true
	aptUpgradeLastCode = 0
	aptUpgradeLastErr = ""
	return true
}

func aptUpgradeFinish(code int, errMsg string) {
	aptUpgradeMu.Lock()
	aptUpgradeActive = false
	aptUpgradeLastCode = code
	aptUpgradeLastErr = errMsg
	aptUpgradeMu.Unlock()
}

func aptUpgradeIsActive() bool {
	aptUpgradeMu.Lock()
	defer aptUpgradeMu.Unlock()
	return aptUpgradeActive
}

func aptUpgradeSnapshot() (active bool, code int, errMsg string) {
	aptUpgradeMu.Lock()
	defer aptUpgradeMu.Unlock()
	return aptUpgradeActive, aptUpgradeLastCode, aptUpgradeLastErr
}

// ResetAptUpgradeStateForTest clears single-flight state (tests only).
func ResetAptUpgradeStateForTest() {
	aptUpgradeMu.Lock()
	aptUpgradeActive = false
	aptUpgradeLastCode = 0
	aptUpgradeLastErr = ""
	aptUpgradeMu.Unlock()
	aptUpgradeStreamHook = nil
}

// SetAptUpgradeStreamHookForTest overrides apt execution (tests only).
func SetAptUpgradeStreamHookForTest(hook func(ctx context.Context, emit func(string) error) (int, error)) {
	aptUpgradeStreamHook = hook
}

func writeStreamEvent(w *bufio.Writer, ev streamEvent) error {
	b, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	if _, err := w.Write(append(b, '\n')); err != nil {
		return err
	}
	return w.Flush()
}

// dispatchAptUpgradeStream runs apt-get upgrade or attaches to an in-flight upgrade.
func dispatchAptUpgradeStream(conn io.Writer) {
	if !aptUpgradeTryStart() {
		dispatchAptUpgradeAttach(conn)
		return
	}
	dispatchAptUpgradePrimary(conn)
}

func dispatchAptUpgradePrimary(conn io.Writer) {
	bw := bufio.NewWriter(conn)
	emitExit := func(code int, errMsg string) {
		_ = writeStreamEvent(bw, streamEvent{Type: "exit", Code: code, Error: errMsg})
	}

	logPath := aptUpgradeLogPath()
	_ = os.MkdirAll(filepath.Dir(logPath), 0o750)
	logFile, err := os.Create(logPath)
	if err != nil {
		logOp("apt-upgrade-stream: log file: %v", err)
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
		if err := writeStreamEvent(bw, streamEvent{Type: "line", Data: line}); err != nil {
			clientDown = true
			return nil
		}
		return nil
	}

	_ = emitLine("==> starting apt-get upgrade ...")
	emitDpkgLockHint(emitLine)

	code, runErr := runAptUpgradeStream(aptCtx, emitLine)
	errMsg := ""
	if runErr != nil {
		errMsg = runErr.Error()
	}
	aptUpgradeFinish(code, errMsg)
	emitExit(code, errMsg)
}

func dispatchAptUpgradeAttach(conn io.Writer) {
	bw := bufio.NewWriter(conn)
	emitExit := func(code int, errMsg string) {
		_ = writeStreamEvent(bw, streamEvent{Type: "exit", Code: code, Error: errMsg})
	}

	clientDown := false
	emitLine := func(line string) error {
		if clientDown {
			return nil
		}
		if err := writeStreamEvent(bw, streamEvent{Type: "line", Data: line}); err != nil {
			clientDown = true
			return nil
		}
		return nil
	}

	_ = emitLine("==> attaching to upgrade already in progress ...")

	var offset int64
	for {
		lines, newOff, err := readAptUpgradeLogFrom(offset)
		if err != nil {
			emitExit(-1, "cannot read upgrade log: "+err.Error())
			return
		}
		offset = newOff
		for _, line := range lines {
			_ = emitLine(line)
		}

		active, code, errMsg := aptUpgradeSnapshot()
		if !active {
			emitExit(code, errMsg)
			return
		}
		time.Sleep(250 * time.Millisecond)
	}
}

func readAptUpgradeLogFrom(offset int64) (lines []string, newOffset int64, err error) {
	f, err := os.Open(aptUpgradeLogPath())
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

// dispatchAptUpgradeStatus returns whether an upgrade is in progress (JSON in stdout).
func dispatchAptUpgradeStatus() Response {
	active, code, errMsg := aptUpgradeSnapshot()
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

// dispatchAptUpgradeLog returns the current upgrade log file (read-only).
func dispatchAptUpgradeLog() Response {
	b, err := os.ReadFile(aptUpgradeLogPath())
	if err != nil {
		if os.IsNotExist(err) {
			return okResp(nil, nil, 0)
		}
		return failResp(err.Error(), 1)
	}
	return okResp(b, nil, 0)
}

func runAptUpgradeStream(ctx context.Context, emit func(string) error) (int, error) {
	done := make(chan struct{})
	defer close(done)
	var lastLineMu sync.Mutex
	lastLineAt := time.Now()
	started := time.Now()
	go aptUpgradeHeartbeat(ctx, done, started, &lastLineMu, &lastLineAt, emit)

	wrapEmit := func(line string) error {
		lastLineMu.Lock()
		lastLineAt = time.Now()
		lastLineMu.Unlock()
		return emit(line)
	}

	if aptUpgradeStreamHook != nil {
		return aptUpgradeStreamHook(ctx, wrapEmit)
	}
	return execAptUpgradeStream(ctx, wrapEmit)
}

func execAptUpgradeStream(ctx context.Context, emit func(string) error) (int, error) {
	cmd := exec.CommandContext(ctx, "apt-get",
		"-y",
		"-o", "Dpkg::Use-Pty=0",
		"-o", "DPkg::Lock::Timeout=120",
		"upgrade",
	)
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

func aptUpgradeHeartbeat(ctx context.Context, done <-chan struct{}, started time.Time, lastLineMu *sync.Mutex, lastLineAt *time.Time, emit func(string) error) {
	ticker := time.NewTicker(aptUpgradeHeartbeatInterval)
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
			if silent < aptUpgradeHeartbeatInterval {
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
