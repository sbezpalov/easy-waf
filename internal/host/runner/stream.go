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

	return relayBrokerStream(ctx, conn, onLine)
}

// Apt's scanner accepts up to 1 MiB of text per line; JSON escaping can expand
// that sixfold. Bound framing without rejecting any event hostd can produce.
const maxBrokerStreamRecordBytes = 8 << 20

func relayBrokerStream(ctx context.Context, input io.Reader, onLine func([]byte) error) error {
	scanner := brokerRecordScanner(input, maxBrokerStreamRecordBytes)
	return relayBrokerEvents(ctx, scanner, onLine)
}

func brokerRecordScanner(input io.Reader, limit int) *bufio.Scanner {
	scanner := bufio.NewScanner(input)
	scanner.Buffer(make([]byte, 64<<10), limit)
	scanner.Split(func(data []byte, atEOF bool) (int, []byte, error) {
		if i := bytes.IndexByte(data, '\n'); i >= 0 {
			return i + 1, data[:i], nil
		}
		if atEOF && len(data) > 0 {
			return 0, nil, io.ErrUnexpectedEOF
		}
		return 0, nil, nil
	})
	return scanner
}

func relayBrokerEvents(ctx context.Context, scanner *bufio.Scanner, onLine func([]byte) error) error {
	relay := true
	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("privileged stream: read: %w", err)
		}
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var event struct {
			Type  string `json:"type"`
			Data  string `json:"data"`
			Code  *int   `json:"code"`
			Error string `json:"error"`
		}
		if json.Unmarshal(line, &event) != nil {
			return fmt.Errorf("privileged stream: invalid JSON event")
		}
		switch event.Type {
		case "line":
		case "exit":
			if event.Code == nil || (*event.Code == 0 && event.Error != "") {
				return fmt.Errorf("privileged stream: invalid exit event")
			}
		default:
			return fmt.Errorf("privileged stream: unknown event type")
		}
		if relay {
			if err := onLine(line); err != nil {
				relay = false
			}
		}
		if event.Type == "exit" {
			return nil
		}
	}
	if err := brokerIOError(ctx, scanner.Err()); err != nil {
		return fmt.Errorf("privileged stream: read: %w", err)
	}
	return fmt.Errorf("privileged stream: missing exit event: %w", io.ErrUnexpectedEOF)
}
