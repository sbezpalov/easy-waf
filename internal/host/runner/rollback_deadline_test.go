// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package runner

import (
	"context"
	"encoding/json"
	"net"
	"testing"
	"time"

	"github.com/easy-waf/easy-waf/internal/hostd"
)

func TestPrivilegedRollbackDeadline(t *testing.T) {
	for _, scenario := range []string{"broker deadline", "already expired", "legacy broker", "failed apply", "ordinary output"} {
		t.Run(scenario, func(t *testing.T) {
			socket := shortTempSock(t)
			ln, err := net.Listen("unix", socket)
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			t.Setenv("EASY_WAF_HOSTD_SOCKET", socket)
			deadline := time.Now().UTC().Add(20 * time.Second)
			if scenario == "already expired" {
				deadline = deadline.Add(-time.Minute)
			}
			response := hostd.Response{OK: true, Stdout: "command output", RollbackExpiresAt: &deadline}
			if scenario == "legacy broker" {
				response.RollbackExpiresAt = nil
			}
			if scenario == "failed apply" {
				response.OK, response.Code, response.Error = false, 1, "apply rejected"
			}
			type observation struct {
				at  time.Time
				err error
			}
			done := make(chan observation, 1)
			go func() {
				conn, err := ln.Accept()
				if err != nil {
					done <- observation{err: err}
					return
				}
				defer conn.Close()
				var req hostd.Request
				if err := json.NewDecoder(conn).Decode(&req); err != nil {
					done <- observation{err: err}
					return
				}
				at := time.Now()
				time.Sleep(30 * time.Millisecond) // Apply/transport latency must not reset the window.
				done <- observation{at: at, err: json.NewEncoder(conn).Encode(response)}
			}()
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancel()
			started := time.Now()
			var got time.Time
			var callErr error
			if scenario == "ordinary output" {
				// The same response remains readable by existing Privileged callers.
				var out []byte
				out, callErr = Privileged(ctx, "nft-list")
				if callErr != nil || string(out) != "command output" {
					t.Fatalf("new response broke ordinary output: %q, %v", out, callErr)
				}
			} else {
				got, callErr = PrivilegedWithRollback(ctx, 90*time.Second, "netplan-apply-confirm", "staged", "90", "abcdef01")
			}
			if scenario == "failed apply" {
				if callErr == nil || !got.IsZero() {
					t.Fatalf("failed apply exposed a usable deadline: %v, %v", got, callErr)
				}
			} else if callErr != nil {
				t.Fatal(callErr)
			}
			observed := <-done
			if observed.err != nil {
				t.Fatal(observed.err)
			}
			if scenario == "legacy broker" {
				if got.Before(started.Add(90*time.Second)) || got.After(observed.at.Add(90*time.Second)) {
					t.Fatalf("legacy fallback reset the window after apply: %v", got)
				}
			} else if scenario != "failed apply" && scenario != "ordinary output" && !got.Equal(deadline) {
				t.Fatalf("broker deadline replaced: got %v, want %v", got, deadline)
			}
		})
	}
}
