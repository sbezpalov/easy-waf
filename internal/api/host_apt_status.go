// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

const maxAPTStatusPayloadBytes = 64 << 10

// A missing/unparseable status is unknown, never an inactive operation. Retain
// raw values so future metadata and integer precision survive the API boundary.
func decodeAPTStatus(payload []byte) (map[string]json.RawMessage, error) {
	if len(payload) == 0 || len(payload) > maxAPTStatusPayloadBytes {
		return nil, errors.New("invalid APT status payload size")
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	start, err := decoder.Token()
	if err != nil || start != json.Delim('{') {
		return nil, errors.New("APT status must be an object")
	}
	fields := make(map[string]json.RawMessage)
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return nil, fmt.Errorf("APT status field: %w", err)
		}
		key, ok := token.(string)
		if !ok {
			return nil, errors.New("invalid APT status field name")
		}
		if _, exists := fields[key]; exists {
			return nil, errors.New("duplicate APT status field")
		}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return nil, fmt.Errorf("APT status value: %w", err)
		}
		fields[key] = value
	}
	if end, err := decoder.Token(); err != nil || end != json.Delim('}') {
		return nil, errors.New("incomplete APT status object")
	}
	var extra json.RawMessage
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, errors.New("trailing APT status data")
	}
	if _, exists := fields["active"]; !exists {
		return nil, errors.New("APT status requires an explicit active boolean")
	}
	// Struct decoding matches keys case-insensitively. Decode exact raw keys
	// instead, so another spelling cannot conceal a missing/null known field.
	for _, field := range []struct {
		name   string
		target any
	}{
		{"active", new(bool)}, {"exit_code", new(int64)}, {"error", new(string)},
		{"action", new(string)}, {"stream", new(bool)}, {"run_id", new(string)},
	} {
		if raw, present := fields[field.name]; present {
			if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
				return nil, fmt.Errorf("null APT status field %s", field.name)
			}
			if err := json.Unmarshal(raw, field.target); err != nil {
				return nil, fmt.Errorf("APT status field %s: %w", field.name, err)
			}
		}
	}
	return fields, nil
}
