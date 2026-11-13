// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package hostd

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// DefaultSocket is the unix socket path (root:easy-waf 0660).
const DefaultSocket = "/run/easy-waf/hostd.sock"

type socketRole uint8

const (
	localSocket socketRole = iota
	brokerSocket
	aptWorkerSocket
)

// Serve listens on sockPath until ctx is cancelled.
func Serve(ctx context.Context, sockPath string) error {
	return serveSocket(ctx, sockPath, brokerSocket)
}

func serveSocket(ctx context.Context, sockPath string, role socketRole) error {
	if sockPath == "" {
		sockPath = DefaultSocket
	}
	dirMode := os.FileMode(0o750)
	if role == aptWorkerSocket {
		dirMode = 0o700
	}
	if err := os.MkdirAll(filepath.Dir(sockPath), dirMode); err != nil {
		return err
	}
	if role == aptWorkerSocket {
		if err := validateAPTWorkerDirectory(filepath.Dir(sockPath)); err != nil {
			return err
		}
	}
	_ = os.Remove(sockPath)
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		return err
	}
	defer ln.Close()
	if err := setSocketPermissions(sockPath); err != nil {
		return err
	}
	if role == aptWorkerSocket {
		if err := os.Chmod(sockPath, 0o600); err != nil {
			return err
		}
	}
	logOp("listening on %s", sockPath)
	if role == aptWorkerSocket {
		if err := notifyAPTReady(); err != nil {
			return err
		}
	}
	var handlers sync.WaitGroup
	var connectionsMu sync.Mutex
	connections := make(map[net.Conn]struct{})

	go func() {
		<-ctx.Done()
		_ = ln.Close()
		if role == aptWorkerSocket {
			connectionsMu.Lock()
			for c := range connections {
				_ = c.Close()
			}
			connectionsMu.Unlock()
		}
	}()

	d := &Dispatcher{Runner: DefaultRunner}
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				if role == aptWorkerSocket {
					handlers.Wait()
				}
				return nil
			default:
				return err
			}
		}
		connectionsMu.Lock()
		connections[conn] = struct{}{}
		connectionsMu.Unlock()
		if ctx.Err() != nil {
			_ = conn.Close()
		}
		handlers.Add(1)
		go func() {
			defer handlers.Done()
			defer func() {
				connectionsMu.Lock()
				delete(connections, conn)
				connectionsMu.Unlock()
			}()
			handleConnRole(ctx, conn, d, role)
		}()
	}
}

func handleConn(ctx context.Context, c net.Conn, d *Dispatcher) {
	handleConnRole(ctx, c, d, localSocket)
}

func handleConnRole(ctx context.Context, c net.Conn, d *Dispatcher, role socketRole) {
	defer c.Close()
	// Fail closed: anything that is not a verifiable unix peer is rejected.
	uc, ok := c.(*net.UnixConn)
	if !ok {
		logOp("reject peer: not a unix connection")
		_ = writeResponse(c, failResp("peer not allowed", 1))
		return
	}
	checkPeer := allowPeer
	if role == aptWorkerSocket {
		checkPeer = allowRootPeer
	}
	if err := checkPeer(uc); err != nil {
		logOp("reject peer: %v", err)
		_ = writeResponse(c, failResp("peer not allowed", 1))
		return
	}
	_ = c.SetDeadline(time.Now().Add(2 * time.Minute))
	var req Request
	dec := json.NewDecoder(c)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		_ = writeResponse(c, failResp("invalid request: "+err.Error(), 1))
		return
	}
	if len(req.Argv) == 0 {
		_ = writeResponse(c, failResp("empty argv", 1))
		return
	}
	if role == aptWorkerSocket && !isAPTWorkerOpcode(req.Argv[0]) {
		_ = writeResponse(c, failResp("APT worker opcode not allowed", 1))
		return
	}
	if role == brokerSocket && isAPTWorkerOpcode(req.Argv[0]) {
		proxyAPTRequest(ctx, c, req, DefaultAPTWorkerSocket)
		return
	}
	if role == aptWorkerSocket && isAPTMutationOpcode(req.Argv[0]) {
		ctx = context.WithoutCancel(ctx)
	}
	switch req.Argv[0] {
	case "apt-action-attach-stream":
		_ = c.SetDeadline(time.Now().Add(35 * time.Minute))
		if len(req.Argv) != 2 {
			_ = newAptStreamConn(c).writeEvent(streamEvent{Type: "exit", Code: -1, Error: "APT observation requires one run ID"})
			return
		}
		dispatchAptObserveStream(c, req.Argv[1])
		return
	case "apt-upgrade-stream":
		_ = c.SetDeadline(time.Now().Add(35 * time.Minute))
		logOp("op=apt-upgrade-stream (stream)")
		dispatchAptUpgradeStream(c)
		return
	case "apt-autoremove-stream":
		_ = c.SetDeadline(time.Now().Add(35 * time.Minute))
		logOp("op=apt-autoremove-stream (stream)")
		dispatchAptStream(c, "autoremove")
		return
	case "apt-upgrade-log", "apt-action-log":
		_ = writeResponse(c, dispatchAptActionLog())
		return
	case "apt-upgrade-status", "apt-action-status":
		_ = writeResponse(c, dispatchAptActionStatus())
		return
	}
	resp := d.Dispatch(ctx, req.Argv)
	_ = writeResponse(c, resp)
}

func writeResponse(c net.Conn, resp Response) error {
	enc := json.NewEncoder(c)
	return enc.Encode(resp)
}

// ServeDefault starts the broker on DefaultSocket until SIGTERM (used by main).
func ServeDefault() error {
	ctx := context.Background()
	RevertPendingChanges()
	// Also covers an appliance whose guard file arrived with an upgrade.
	if err := reloadNftGuard(ctx, DefaultRunner); err != nil {
		logOp("%v", err)
	}
	return Serve(ctx, DefaultSocket)
}

// ReadRequest decodes one request (for tests).
func ReadRequest(r io.Reader) (Request, error) {
	var req Request
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()
	err := dec.Decode(&req)
	return req, err
}
