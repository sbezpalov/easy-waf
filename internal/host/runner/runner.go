// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package runner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"time"

	"github.com/easy-waf/easy-waf/internal/commandoutput"
)

// Privileged sends a validated subcommand to easy-waf-hostd over the unix socket.
func Privileged(ctx context.Context, args ...string) ([]byte, error) {
	resp, err := privileged(ctx, args...)
	return []byte(resp.Stdout), err
}

// PrivilegedWithRollback returns the timer deadline supplied by hostd. During
// a rolling upgrade an older broker may omit it; start that fallback before
// the RPC so waiting for apply never grants a fictitious extra safety window.
func PrivilegedWithRollback(ctx context.Context, window time.Duration, args ...string) (time.Time, error) {
	fallback := time.Now().UTC().Add(window)
	resp, err := privileged(ctx, args...)
	if err != nil {
		return time.Time{}, err
	}
	if resp.RollbackExpiresAt != nil && !resp.RollbackExpiresAt.IsZero() {
		return *resp.RollbackExpiresAt, nil
	}
	return fallback, nil
}

func privileged(ctx context.Context, args ...string) (brokerResponse, error) {
	if len(args) == 0 {
		return brokerResponse{}, fmt.Errorf("privileged: empty args")
	}
	if !BrokerAvailable() {
		return brokerResponse{}, fmt.Errorf("privileged: host broker unavailable at %s (is easy-waf-hostd running?)", BrokerSocket())
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(ctx, "unix", BrokerSocket())
	if err != nil {
		return brokerResponse{}, fmt.Errorf("privileged: dial broker: %w", err)
	}
	defer conn.Close()
	stop := closeOnCancel(ctx, conn)
	defer stop()
	req := brokerRequest{Argv: args}
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return brokerResponse{}, brokerIOError(ctx, err)
	}
	var resp brokerResponse
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return brokerResponse{}, fmt.Errorf("privileged: decode response: %w", brokerIOError(ctx, err))
	}
	if !resp.OK || resp.Code != 0 {
		msg := strings.TrimSpace(resp.Error)
		if msg == "" {
			msg = strings.TrimSpace(resp.Stderr)
		}
		if msg == "" {
			msg = fmt.Sprintf("exit code %d", resp.Code)
		}
		return resp, fmt.Errorf("%s", msg)
	}
	return resp, nil
}

// Run executes a command directly (no elevation).
func Run(ctx context.Context, timeout time.Duration, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	var capture commandoutput.Capture
	cmd.Stdout = capture.Stdout()
	cmd.Stderr = capture.Stderr()
	runErr := cmd.Run()
	stdout, stderr, captureErr := capture.Result()
	err := errors.Join(runErr, captureErr)
	if err != nil {
		msg := strings.TrimSpace(string(stderr))
		if msg == "" {
			msg = err.Error()
		}
		return stdout, fmt.Errorf("%w: %s", err, msg)
	}
	return stdout, nil
}
