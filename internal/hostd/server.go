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

// easyWafUID is the uid easy-waf-api runs as. It stays -1 when the account cannot
// be resolved, in which case allowPeer accepts root only — an unresolvable
// service account must not turn the peer check into a no-op.
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
	// Fail closed: anything that is not a verifiable unix peer is rejected.
	uc, ok := c.(*net.UnixConn)
	if !ok {
		logOp("reject peer: not a unix connection")
		_ = writeResponse(c, failResp("peer not allowed", 1))
		return
	}
	if err := allowPeer(uc); err != nil {
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
	switch req.Argv[0] {
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
