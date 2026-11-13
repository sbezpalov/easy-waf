// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package hostd

import "time"

const maxHostRequestBytes = 64 << 10

// Request is one privileged operation from easy-waf-api.
type Request struct {
	Argv []string `json:"argv"`
}

// Response is returned for each request.
type Response struct {
	OK     bool   `json:"ok"`
	Stdout string `json:"stdout"`
	Stderr string `json:"stderr"`
	Code   int    `json:"code"`
	Error  string `json:"error,omitempty"`
	// Only confirmed changes carry the conservative deadline of their timer.
	RollbackExpiresAt *time.Time `json:"rollback_expires_at,omitempty"`
}
