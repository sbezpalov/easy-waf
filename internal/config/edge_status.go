// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package config

import "time"

const (
	EdgeApplyOutcomeSuccess  = "success"
	EdgeApplyOutcomeFailed   = "failed"
	EdgeApplyOutcomeUnknown  = "unknown"
	EdgeApplyOutcomeRollback = "rollback"

	EdgeRuntimeKnown   = "known"
	EdgeRuntimeUnknown = "unknown"
)

// EdgeLastApply is the durable, non-secret outcome of the most recent edge
// operation. RevisionSHA identifies the managed HAProxy artifact, not backend
// health. ErrorCode is a stable category and never contains command output.
type EdgeLastApply struct {
	Outcome     string    `json:"outcome"`
	At          time.Time `json:"at"`
	RevisionSHA string    `json:"revision_sha,omitempty"`
	ErrorCode   string    `json:"error_code,omitempty"`
}

// EdgeRuntimeStatus describes the managed live haproxy.cfg artifact observed
// by the API. It deliberately does not claim that HAProxy or any backend is up.
type EdgeRuntimeStatus struct {
	State       string    `json:"state"`
	CheckedAt   time.Time `json:"checked_at"`
	RevisionSHA string    `json:"revision_sha,omitempty"`
	ErrorCode   string    `json:"error_code,omitempty"`
}

// EdgeStatus is the authoritative GET /api/v1/edge/status response contract.
// AppliedGeneration and Pending are null until a successful Apply or startup
// reconcile proves which saved generation produced the managed live artifact.
type EdgeStatus struct {
	SavedGeneration   int64             `json:"saved_generation"`
	AppliedGeneration *int64            `json:"applied_generation"`
	Pending           *bool             `json:"pending"`
	LastApply         *EdgeLastApply    `json:"last_apply"`
	Runtime           EdgeRuntimeStatus `json:"runtime"`
}
