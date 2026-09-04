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
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(dialCtx, "unix", BrokerSocket())
	if err != nil {
		return fmt.Errorf("privileged stream: dial broker: %w", err)
	}
	defer conn.Close()

	if err := json.NewEncoder(conn).Encode(brokerRequest{Argv: argv}); err != nil {
		return fmt.Errorf("privileged stream: encode request: %w", err)
	}

	br := bufio.NewReader(conn)
	relay := true
	for {
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
			if err == io.EOF {
				return nil
			}
			return fmt.Errorf("privileged stream: read: %w", err)
		}
	}
}
