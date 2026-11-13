// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package runner

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestBrokerEventAmbiguityFailsBeforeRelayOrDownload(t *testing.T) {
	for _, event := range []string{
		`{"Type":"exit","Code":0}`,
		`{"type":"exit","code":100,"Code":0}`,
		`{"type":"exit","code":-1,"code":0}`,
		`{"type":"line","type":"exit","code":0}`,
		`{"type":"exit","code":null,"Code":0}`,
		`{"type":"exit","code":0,"error":null}`,
		`{"type":"exit","code":0,"error":"private failure","Error":""}`,
		`{"type":"exit","code":0,"data":null}`,
		`{"type":"exit","code":0,"future":1,"future":2}`,
		`{"type":"exit","code":100,"co\u0064e":0}`,
		`{"type":"line","data":"private original","Data":"different"}`,
		`{"type":"line","data":null}`,
		`{"type":"line","error":null}`,
		`{"type":"line","code":null}`,
		`{"type":"exit","code":9007199254740992}`,
		"{\"type\":\"line\",\"data\":\"\xff\"}",
	} {
		t.Run(event[:min(len(event), 55)], func(t *testing.T) {
			wire := event + "\n{\"type\":\"exit\",\"code\":0}\n"
			calls := 0
			if err := relayBrokerStream(t.Context(), strings.NewReader(wire), func([]byte) error { calls++; return nil }); err == nil || calls != 0 {
				t.Errorf("ambiguous event reached live client/result: err=%v calls=%d", err, calls)
			}
			var out bytes.Buffer
			if err := copyAPTLogEvents(t.Context(), strings.NewReader(wire), &out); err == nil || out.Len() != 0 {
				t.Errorf("ambiguous event completed download or changed saved data: err=%v bytes=%d", err, out.Len())
			}
		})
	}
}

func TestBrokerEventFieldBudget(t *testing.T) {
	event := `{"type":"exit","code":0`
	for i := range maxBrokerStreamFields - 2 {
		event += fmt.Sprintf(`,"future_%d":null`, i)
	}
	if _, err := decodeBrokerStreamEvent([]byte(event + "}")); err != nil {
		t.Fatalf("exact field budget rejected: %v", err)
	}
	if _, err := decodeBrokerStreamEvent([]byte(event + `,"overflow":true}`)); err == nil {
		t.Fatal("unbounded event key bookkeeping accepted")
	}
}

func FuzzBrokerEventExactInterpretation(f *testing.F) {
	for _, seed := range []string{
		`{"type":"line","data":"世🙂"}`, `{"type":"exit","code":0}`,
		`{"type":"exit","code":-1,"error":"unknown"}`,
		`{"type":"exit","code":100,"Code":0}`, `{"type":"line","data":null}`,
		`{"type":"exit","code":100,"code":0}`, `{"Type":"exit","Code":0}`,
		`{"type":"line","data":"","future":9007199254740993}`,
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, payload []byte) {
		if len(payload) > 64<<10 {
			return // Record/chunk/total budgets have separate deterministic tests.
		}
		event, err := decodeBrokerStreamEvent(payload)
		if err != nil {
			return
		}
		// A case-sensitive generic consumer must see the same type/result as
		// the typed runner, without accepting null or inventing a zero result.
		var fields map[string]json.RawMessage
		var kind string
		if !utf8.Valid(payload) || json.Unmarshal(payload, &fields) != nil || json.Unmarshal(fields["type"], &kind) != nil || kind != event.Type {
			t.Fatal("accepted event has a different exact type on the wire")
		}
		if event.Type == "exit" {
			var code *int
			if json.Unmarshal(fields["code"], &code) != nil || code == nil || event.Code == nil || *code != *event.Code || (*code == 0 && event.Error != "") {
				t.Fatal("accepted event invented or reinterpreted the terminal result")
			}
		}
	})
}

func TestBrokerEventsKeepLegacyAndFutureWireValues(t *testing.T) {
	for _, event := range []string{
		`{"type":"line"}`, `{"type":"line","data":""}`,
		`{"type":"line","data":"世🙂","code":0,"error":""}`,
		`{"type":"line","data":"original","future_counter":9007199254740993,"future":{"Code":42}}`,
		`{"type":"line","d\u0061ta":"escaped exact name"}`,
	} {
		want := []string{event, `{"type":"exit","code":0}`}
		var got []string
		if err := relayBrokerStream(t.Context(), strings.NewReader(strings.Join(want, "\n")+"\n"), func(line []byte) error {
			got = append(got, string(line))
			return nil
		}); err != nil || strings.Join(got, "\n") != strings.Join(want, "\n") {
			t.Fatalf("compatible event rejected/rewritten: err=%v", err)
		}
	}
}
