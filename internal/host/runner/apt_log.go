// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package runner

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/easy-waf/easy-waf/internal/host/hostspec"
)

// DownloadAPTLog copies a validated saved-log snapshot to dst in bounded chunks.
// It issues only a fixed read-only opcode and closes immediately on sink failure.
// Callers must not publish the partial output before this returns nil.
func DownloadAPTLog(ctx context.Context, dst io.Writer) error {
	ctx, cancel := context.WithTimeout(ctx, hostspec.APTLogDownloadTimeout)
	defer cancel()
	if !BrokerAvailable() {
		return fmt.Errorf("APT saved log: host broker unavailable")
	}
	dialCtx, cancelDial := context.WithTimeout(ctx, 15*time.Second)
	defer cancelDial()
	conn, err := (&net.Dialer{}).DialContext(dialCtx, "unix", BrokerSocket())
	if err != nil {
		return fmt.Errorf("APT saved log: dial: %w", brokerIOError(ctx, err))
	}
	defer conn.Close()
	stop := closeOnCancel(ctx, conn)
	defer stop()
	deadline, _ := ctx.Deadline()
	if err := conn.SetDeadline(deadline); err != nil {
		return err
	}
	if err := json.NewEncoder(conn).Encode(brokerRequest{Argv: []string{"apt-action-log-stream"}}); err != nil {
		return fmt.Errorf("APT saved log: request: %w", brokerIOError(ctx, err))
	}
	return copyAPTLogEvents(ctx, conn, dst)
}

func copyAPTLogEvents(ctx context.Context, input io.Reader, dst io.Writer) error {
	scanner := brokerRecordScanner(input, hostspec.MaxAPTLogFrameBytes)
	var total int64
	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return err
		}
		var event struct {
			Type  string `json:"type"`
			Data  string `json:"data"`
			Code  *int   `json:"code"`
			Error string `json:"error"`
		}
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			return fmt.Errorf("APT saved log: invalid event: %w", err)
		}
		switch event.Type {
		case "line":
			if event.Error != "" || (event.Code != nil && *event.Code != 0) || len(event.Data) > 3*(hostspec.APTLogChunkBytes+3) || int64(len(event.Data)) > hostspec.MaxAPTLogTextBytes-total {
				return fmt.Errorf("APT saved log: invalid or oversized chunk")
			}
			n, err := io.WriteString(dst, event.Data)
			if err != nil {
				return fmt.Errorf("APT saved log: save: %w", err)
			}
			if n != len(event.Data) {
				return io.ErrShortWrite
			}
			total += int64(n)
		case "exit":
			if event.Code == nil || *event.Code != 0 || event.Error != "" {
				return fmt.Errorf("APT saved log: incomplete download: %s", event.Error)
			}
			return nil
		default:
			return fmt.Errorf("APT saved log: unsupported event (refresh broker/worker after upgrade)")
		}
	}
	if err := brokerIOError(ctx, scanner.Err()); err != nil {
		return fmt.Errorf("APT saved log: read: %w", err)
	}
	return fmt.Errorf("APT saved log: missing terminal result: %w", io.ErrUnexpectedEOF)
}
