// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package crowdsec

import "errors"

var (
	// ErrDecisionNotFound is returned when LAPI responds 404 to DELETE /v1/decisions/{id}.
	ErrDecisionNotFound = errors.New("crowdsec: decision not found")
	// ErrInvalidDecisionIP is returned when AddDecision receives a non-IP value string.
	ErrInvalidDecisionIP = errors.New("crowdsec: invalid IP address")
)
