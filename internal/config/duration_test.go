// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"encoding/json"
	"testing"
	"time"
)

func TestDuration_JSONRoundTrip(t *testing.T) {
	type row struct {
		D Duration `json:"d"`
	}
	for _, tc := range []struct {
		in   string
		want time.Duration
	}{
		{`{"d":"24h"}`, 24 * time.Hour},
		{`{"d":"30m"}`, 30 * time.Minute},
		{`{"d":"50s"}`, 50 * time.Second},
		{`{"d":"0s"}`, 0},
		{`{"d":86400000000000}`, 24 * time.Hour},
	} {
		var r row
		if err := json.Unmarshal([]byte(tc.in), &r); err != nil {
			t.Fatalf("unmarshal %s: %v", tc.in, err)
		}
		if time.Duration(r.D) != tc.want {
			t.Fatalf("%s: got %v want %v", tc.in, time.Duration(r.D), tc.want)
		}
		b, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		var r2 row
		if err := json.Unmarshal(b, &r2); err != nil {
			t.Fatalf("roundtrip unmarshal %s: %v", string(b), err)
		}
		if r2.D != r.D {
			t.Fatalf("roundtrip mismatch: %s vs %s", string(b), tc.in)
		}
	}
}
