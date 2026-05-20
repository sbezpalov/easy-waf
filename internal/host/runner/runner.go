package runner

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

const privilegedHelper = "/usr/lib/easy-waf/host-privileged.sh"

// Privileged runs a validated subcommand via sudo -n (install.sh installs sudoers).
func Privileged(ctx context.Context, args ...string) ([]byte, error) {
	if len(args) == 0 {
		return nil, fmt.Errorf("privileged: empty args")
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	full := append([]string{"-n", privilegedHelper}, args...)
	cmd := exec.CommandContext(ctx, "/usr/bin/sudo", full...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return stdout.Bytes(), fmt.Errorf("%w: %s", err, msg)
	}
	return stdout.Bytes(), nil
}

// Run executes a command directly (no elevation).
func Run(ctx context.Context, timeout time.Duration, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return stdout.Bytes(), fmt.Errorf("%w: %s", err, msg)
	}
	return stdout.Bytes(), nil
}

// HelperInstalled reports whether the privileged helper is on disk.
func HelperInstalled() bool {
	_, err := os.Stat(privilegedHelper)
	return err == nil
}
