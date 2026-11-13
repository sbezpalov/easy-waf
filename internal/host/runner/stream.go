// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package runner

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"time"
)

// PrivilegedStream calls the host broker and relays each NDJSON line to onLine.
// Application status is in {"type":"exit"} events; transport errors are returned separately.
func PrivilegedStream(ctx context.Context, onLine func([]byte) error, argv ...string) error {
	if len(argv) == 0 {
		return fmt.Errorf("privileged stream: empty args")
	}
	if !BrokerAvailable() {
		return fmt.Errorf("privileged stream: host broker unavailable at %s", BrokerSocket())
	}
	dialCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	conn, err := (&net.Dialer{}).DialContext(dialCtx, "unix", BrokerSocket())
	cancel()
	if err != nil {
		return fmt.Errorf("privileged stream: dial broker: %w", err)
	}
	defer conn.Close()
	// Use the request context, not the short dial context: apt may stream for
	// many minutes and continues in hostd after this client disconnects.
	stop := closeOnCancel(ctx, conn)
	defer stop()

	if err := json.NewEncoder(conn).Encode(brokerRequest{Argv: argv}); err != nil {
		return fmt.Errorf("privileged stream: encode request: %w", brokerIOError(ctx, err))
	}

	br := bufio.NewReader(conn)
	relay := true
	for {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("privileged stream: read: %w", err)
		}
		line, err := br.ReadBytes('\n')
		if len(line) > 0 {
			trimmed := bytes.TrimSpace(line)
			if len(trimmed) > 0 {
				if relay {
					if err := onLine(trimmed); err != nil {
						relay = false
					}
				}
			}
		}
		if err != nil {
			if err == io.EOF && ctx.Err() == nil {
				return nil
			}
			return fmt.Errorf("privileged stream: read: %w", brokerIOError(ctx, err))
		}
	}
}
