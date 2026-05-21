package hostd

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
)

// CommandRunner runs subprocesses without a shell.
type CommandRunner interface {
	Run(ctx context.Context, name string, args ...string) (stdout, stderr []byte, code int, err error)
}

type osRunner struct{}

func (osRunner) Run(ctx context.Context, name string, args ...string) ([]byte, []byte, int, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	runErr := cmd.Run()
	code := 0
	if runErr != nil {
		if ee, ok := runErr.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else {
			return out.Bytes(), errb.Bytes(), 1, runErr
		}
	}
	return out.Bytes(), errb.Bytes(), code, nil
}

// DefaultRunner is the production command executor.
var DefaultRunner CommandRunner = osRunner{}

func runCmd(ctx context.Context, r CommandRunner, name string, args ...string) (stdout, stderr []byte, code int, err error) {
	if r == nil {
		r = DefaultRunner
	}
	return r.Run(ctx, name, args...)
}

func okResp(stdout, stderr []byte, code int) Response {
	return Response{OK: code == 0, Stdout: string(stdout), Stderr: string(stderr), Code: code}
}

func failResp(msg string, code int) Response {
	if code == 0 {
		code = 1
	}
	return Response{OK: false, Code: code, Error: msg}
}

func failExec(stdout, stderr []byte, code int, err error) Response {
	msg := string(stderr)
	if msg == "" && err != nil {
		msg = err.Error()
	}
	return Response{OK: false, Stdout: string(stdout), Stderr: string(stderr), Code: code, Error: msg}
}

func copyFile(src, dst string, mode os.FileMode) error {
	b, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	if err := os.WriteFile(dst, b, mode); err != nil {
		return err
	}
	return nil
}

func touchEmpty(path string) error {
	return os.WriteFile(path, nil, 0o600)
}

func fileSize(path string) (int64, error) {
	st, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	return st.Size(), nil
}

func ensureDir(path string) error {
	return os.MkdirAll(path, 0o750)
}

func logOp(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "[easy-waf-hostd] "+format+"\n", args...)
}
