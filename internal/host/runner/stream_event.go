// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package runner

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"unicode/utf8"
)

type brokerStreamEvent struct {
	Type  string
	Data  string
	Code  *int
	Error string
}

const maxBrokerStreamFields = 128

// Both live relay and saved-log download must interpret the same wire event.
// Struct unmarshaling permits case-folded aliases, duplicates and null strings;
// those can hide a failed result or disagree with a downstream JSON consumer.
func decodeBrokerStreamEvent(line []byte) (brokerStreamEvent, error) {
	var event brokerStreamEvent
	if !utf8.Valid(line) {
		return event, errors.New("invalid UTF-8 event")
	}
	decoder := json.NewDecoder(bytes.NewReader(line))
	if start, err := decoder.Token(); err != nil || start != json.Delim('{') {
		return event, errors.New("event must be an object")
	}
	fields := make(map[string]json.RawMessage)
	for decoder.More() {
		if len(fields) >= maxBrokerStreamFields {
			return event, errors.New("event has too many fields")
		}
		token, err := decoder.Token()
		if err != nil {
			return event, errors.New("invalid event field name")
		}
		key, ok := token.(string)
		if !ok {
			return event, errors.New("invalid event field name")
		}
		if _, duplicate := fields[key]; duplicate {
			return event, errors.New("duplicate event field")
		}
		for _, reserved := range []string{"type", "data", "code", "error"} {
			if key != reserved && strings.EqualFold(key, reserved) {
				return event, errors.New("event field has noncanonical casing")
			}
		}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return event, errors.New("invalid event JSON value")
		}
		fields[key] = value
	}
	if end, err := decoder.Token(); err != nil || end != json.Delim('}') {
		return event, errors.New("incomplete event object")
	}
	var extra json.RawMessage
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return event, errors.New("trailing event data")
	}
	for _, field := range []struct {
		name   string
		target any
	}{
		{"type", &event.Type}, {"data", &event.Data},
		{"code", &event.Code}, {"error", &event.Error},
	} {
		if raw, present := fields[field.name]; present {
			if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) || json.Unmarshal(raw, field.target) != nil {
				return event, errors.New("invalid event field type")
			}
		}
	}
	const maxSafeInteger = 1<<53 - 1
	if event.Code != nil && (int64(*event.Code) > maxSafeInteger || int64(*event.Code) < -maxSafeInteger) {
		return event, errors.New("event code exceeds interoperable integer range")
	}
	switch event.Type {
	case "line": // Empty data may be omitted by the worker's JSON encoder.
	case "exit":
		if event.Code == nil || (*event.Code == 0 && event.Error != "") {
			return event, errors.New("invalid exit event")
		}
	default:
		return event, errors.New("unknown event type")
	}
	return event, nil
}
