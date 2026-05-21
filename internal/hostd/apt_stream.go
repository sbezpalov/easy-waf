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

const aptUpgradeLogPath = "/var/lib/easy-waf/apt-upgrade.log"

// streamEvent is one NDJSON line on the broker socket for streaming ops.
type streamEvent struct {
	Type  string `json:"type"`
	Data  string `json:"data,omitempty"`
	Code  int    `json:"code,omitempty"`
	Error string `json:"error,omitempty"`
}

var (
	aptUpgradeMu      sync.Mutex
	aptUpgradeActive  bool
	aptUpgradeStreamHook func(ctx context.Context, emit func(string) error) (code int, err error)
)

func aptUpgradeTryStart() bool {
	aptUpgradeMu.Lock()
	defer aptUpgradeMu.Unlock()
	if aptUpgradeActive {
		return false
	}
	aptUpgradeActive = true
	return true
}

func aptUpgradeEnd() {
	aptUpgradeMu.Lock()
	aptUpgradeActive = false
	aptUpgradeMu.Unlock()
}

// ResetAptUpgradeStateForTest clears single-flight state (tests only).
func ResetAptUpgradeStateForTest() {
	aptUpgradeMu.Lock()
	aptUpgradeActive = false
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

// dispatchAptUpgradeStream runs apt-get upgrade and streams NDJSON events on conn.
// Client disconnect does not cancel apt; context is independent of the connection.
func dispatchAptUpgradeStream(conn io.Writer) {
	bw := bufio.NewWriter(conn)
	emitExit := func(code int, errMsg string) {
		_ = writeStreamEvent(bw, streamEvent{Type: "exit", Code: code, Error: errMsg})
	}

	if !aptUpgradeTryStart() {
		emitExit(-1, "upgrade already in progress")
		return
	}
	defer aptUpgradeEnd()

	_ = os.MkdirAll(filepath.Dir(aptUpgradeLogPath), 0o750)
	logFile, err := os.Create(aptUpgradeLogPath)
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

	code, runErr := runAptUpgradeStream(aptCtx, emitLine)
	errMsg := ""
	if runErr != nil {
		errMsg = runErr.Error()
	}
	emitExit(code, errMsg)
}

func runAptUpgradeStream(ctx context.Context, emit func(string) error) (int, error) {
	if aptUpgradeStreamHook != nil {
		return aptUpgradeStreamHook(ctx, emit)
	}
	return execAptUpgradeStream(ctx, emit)
}

func execAptUpgradeStream(ctx context.Context, emit func(string) error) (int, error) {
	cmd := exec.CommandContext(ctx, "apt-get", "-y", "-o", "Dpkg::Use-Pty=0", "upgrade")
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
