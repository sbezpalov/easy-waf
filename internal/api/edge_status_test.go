// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/easy-waf/easy-waf/internal/config"
)

func TestComposeEdgeStatusKeepsUnknownTruthExplicit(t *testing.T) {
	now := time.Date(2026, 11, 17, 10, 5, 12, 0, time.UTC)
	status := composeEdgeStatus(config.EdgeStatus{SavedGeneration: 184}, "", errors.New("missing"), now)
	if status.AppliedGeneration != nil || status.Pending != nil {
		t.Fatalf("unknown generation became known: %+v", status)
	}
	if status.Runtime.State != config.EdgeRuntimeUnknown || status.Runtime.ErrorCode != "live_artifact_unavailable" {
		t.Fatalf("runtime error became healthy: %+v", status.Runtime)
	}
	b, err := json.Marshal(status)
	if err != nil {
		t.Fatal(err)
	}
	jsonText := string(b)
	for _, want := range []string{`"applied_generation":null`, `"pending":null`, `"last_apply":null`, `"state":"unknown"`} {
		if !strings.Contains(jsonText, want) {
			t.Errorf("contract response missing %s: %s", want, jsonText)
		}
	}
}

func TestComposeEdgeStatusReportsManagedArtifactWithoutHealthClaim(t *testing.T) {
	now := time.Date(2026, 11, 17, 10, 5, 12, 0, time.UTC)
	applied, pending := int64(184), false
	status := composeEdgeStatus(config.EdgeStatus{
		SavedGeneration:   184,
		AppliedGeneration: &applied,
		Pending:           &pending,
	}, strings.Repeat("a", 64), nil, now)
	if status.Runtime.State != config.EdgeRuntimeKnown || status.Runtime.RevisionSHA != strings.Repeat("a", 64) {
		t.Fatalf("known artifact omitted: %+v", status.Runtime)
	}
}
