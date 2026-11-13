// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package hostd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"
)

const DefaultAPTWorkerSocket = "/run/easy-waf-apt/worker.sock"

func isAPTWorkerOpcode(op string) bool {
	switch op {
	case "apt-update", "apt-upgrade", "apt-simulate", "apt-autoremove-simulate", "apt-cache-size", "apt-clean",
		"apt-upgrade-stream", "apt-autoremove-stream", "apt-action-attach-stream",
		"apt-upgrade-status", "apt-action-status", "apt-upgrade-log", "apt-action-log":
		return true
	}
	return false
}

func isAPTMutationOpcode(op string) bool {
	switch op {
	case "apt-update", "apt-upgrade", "apt-clean", "apt-upgrade-stream", "apt-autoremove-stream":
		return true
	}
	return false
}

func isAPTStreamOpcode(op string) bool {
	return op == "apt-upgrade-stream" || op == "apt-autoremove-stream" || op == "apt-action-attach-stream"
}

// RunAPTWorker owns package processes and their observation state independently
// of the management broker's cgroup. This root CLI has no public broker opcode.
func RunAPTWorker() error {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		return errors.New("APT worker requires root on Linux")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	DefaultRunner = aptWorkerRunner{}
	return serveSocket(ctx, DefaultAPTWorkerSocket, aptWorkerSocket)
}

type aptWorkerRunner struct{ osRunner }

func notifyAPTReady() error {
	socket := os.Getenv("NOTIFY_SOCKET")
	if socket == "" {
		return nil
	}
	// #nosec G704 -- Root systemd supplies NOTIFY_SOCKET; transport is AF_UNIX,
	// not an API-controlled network destination.
	conn, err := net.DialTimeout("unixgram", socket, time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := conn.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
		return err
	}
	_, err = conn.Write([]byte("READY=1"))
	return err
}

func (aptWorkerRunner) RunApt(ctx context.Context, name string, args []string, emit func(string) error) (code int, err error) {
	release, err := acquireAPTExecutionLease(ctx, false)
	if err != nil {
		return 1, fmt.Errorf("APT execution reserved for maintenance: %w", err)
	}
	defer func() { err = errors.Join(err, release()) }()
	return (osRunner{}).RunApt(ctx, name, args, emit)
}

func proxyAPTRequest(ctx context.Context, client net.Conn, req Request, socket string) {
	ctx, cancel := context.WithTimeout(ctx, aptStreamLifetime)
	defer cancel()
	_ = client.SetDeadline(time.Now().Add(aptStreamLifetime))
	fail := func(err error) {
		message := "APT execution service unavailable: " + err.Error()
		if isAPTStreamOpcode(req.Argv[0]) {
			_ = newAptStreamConn(client).writeEvent(streamEvent{Type: "exit", Code: -1, Error: message})
		} else {
			_ = writeResponse(client, failResp(message, 1))
		}
	}
	dialCtx, cancelDial := context.WithTimeout(ctx, 15*time.Second)
	defer cancelDial()
	conn, err := (&net.Dialer{}).DialContext(dialCtx, "unix", socket)
	if err != nil {
		fail(err)
		return
	}
	defer conn.Close()
	stopClose := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stopClose()
	if err := allowRootPeer(conn.(*net.UnixConn)); err != nil {
		fail(err)
		return
	}
	deadline, _ := ctx.Deadline()
	if err := conn.SetDeadline(deadline); err != nil {
		fail(err)
		return
	}
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		fail(err)
		return
	}
	// Bounded copying preserves JSON/NDJSON. Worker owns APT and its log when
	// this broker process or client connection disappears.
	_, _ = io.Copy(aptProxyWriter{conn: client, expires: deadline}, conn)
}

type aptProxyWriter struct {
	conn    net.Conn
	expires time.Time
}

func (w aptProxyWriter) Write(p []byte) (int, error) {
	deadline := time.Now().Add(aptStreamWriteTimeout)
	if w.expires.Before(deadline) {
		deadline = w.expires
	}
	if err := w.conn.SetWriteDeadline(deadline); err != nil {
		return 0, err
	}
	return w.conn.Write(p)
}
