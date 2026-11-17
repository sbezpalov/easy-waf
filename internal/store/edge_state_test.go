// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"testing"

	"github.com/easy-waf/easy-waf/internal/config"
)

func TestNormalizeEdgeApplyRecordRejectsAmbiguousTruth(t *testing.T) {
	generation := int64(2)
	for _, record := range []EdgeApplyRecord{
		{Outcome: config.EdgeApplyOutcomeSuccess},
		{Outcome: config.EdgeApplyOutcomeSuccess, AppliedGeneration: &generation, ErrorCode: "failed"},
		{Outcome: config.EdgeApplyOutcomeFailed},
		{Outcome: config.EdgeApplyOutcomeFailed, AppliedGeneration: &generation, ErrorCode: "failed"},
		{Outcome: config.EdgeApplyOutcomeUnknown},
		{Outcome: config.EdgeApplyOutcomeRollback},
		{Outcome: "healthy", AppliedGeneration: &generation},
	} {
		if _, err := normalizeEdgeApplyRecord(record); err == nil {
			t.Fatalf("ambiguous record accepted: %+v", record)
		}
	}
}

func TestNormalizeEdgeApplyRecordAcceptsContractOutcomes(t *testing.T) {
	generation := int64(2)
	for _, record := range []EdgeApplyRecord{
		{Outcome: config.EdgeApplyOutcomeSuccess, AppliedGeneration: &generation, RevisionSHA: "abc"},
		{Outcome: config.EdgeApplyOutcomeFailed, ErrorCode: "validation_failed"},
		{Outcome: config.EdgeApplyOutcomeUnknown, ErrorCode: "bookkeeping_failed"},
		{Outcome: config.EdgeApplyOutcomeRollback, RevisionSHA: "abc"},
	} {
		if _, err := normalizeEdgeApplyRecord(record); err != nil {
			t.Fatalf("valid record rejected: %+v: %v", record, err)
		}
	}
}
