package hostd

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"os"
	"os/user"
	"strconv"
	"time"
)

// DefaultSocket is the unix socket path (root:easy-waf 0660).
const DefaultSocket = "/run/easy-waf/hostd.sock"

var easyWafUID = -1

func init() {
	u, err := user.Lookup("easy-waf")
	if err == nil {
		easyWafUID, _ = strconv.Atoi(u.Uid)
	}
}

// Serve listens on sockPath until ctx is cancelled.
func Serve(ctx context.Context, sockPath string) error {
	if sockPath == "" {
		sockPath = DefaultSocket
	}
	_ = os.Remove(sockPath)
	dir := "/run/easy-waf"
	_ = os.MkdirAll(dir, 0o750)
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		return err
	}
	defer ln.Close()
	if err := os.Chmod(sockPath, 0o660); err != nil {
		return err
	}
	logOp("listening on %s", sockPath)

	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	d := &Dispatcher{Runner: DefaultRunner}
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				return err
			}
		}
		go handleConn(ctx, conn, d)
	}
}

func handleConn(ctx context.Context, c net.Conn, d *Dispatcher) {
	defer c.Close()
	if uc, ok := c.(*net.UnixConn); ok && easyWafUID >= 0 {
		if err := allowPeer(uc); err != nil {
			logOp("reject peer: %v", err)
			_ = writeResponse(c, failResp("peer not allowed", 1))
			return
		}
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
	if req.Argv[0] == "apt-upgrade-stream" {
		_ = c.SetDeadline(time.Now().Add(35 * time.Minute))
		dispatchAptUpgradeStream(c)
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
