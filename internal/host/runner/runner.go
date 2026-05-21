package runner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"time"
)

// Privileged sends a validated subcommand to easy-waf-hostd over the unix socket.
func Privileged(ctx context.Context, args ...string) ([]byte, error) {
	if len(args) == 0 {
		return nil, fmt.Errorf("privileged: empty args")
	}
	if !BrokerAvailable() {
		return nil, fmt.Errorf("privileged: host broker unavailable at %s (is easy-waf-hostd running?)", BrokerSocket())
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(ctx, "unix", BrokerSocket())
	if err != nil {
		return nil, fmt.Errorf("privileged: dial broker: %w", err)
	}
	defer conn.Close()
	req := brokerRequest{Argv: args}
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return nil, err
	}
	var resp brokerResponse
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return nil, fmt.Errorf("privileged: decode response: %w", err)
	}
	out := []byte(resp.Stdout)
	if !resp.OK || resp.Code != 0 {
		msg := strings.TrimSpace(resp.Error)
		if msg == "" {
			msg = strings.TrimSpace(resp.Stderr)
		}
		if msg == "" {
			msg = fmt.Sprintf("exit code %d", resp.Code)
		}
		return out, fmt.Errorf("%s", msg)
	}
	return out, nil
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
