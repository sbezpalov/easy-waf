// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"testing"
	"time"

	"github.com/easy-waf/easy-waf/internal/config"
)

func TestEdgeStateIgnoresUnchangedSetting(t *testing.T) {
	st := openFresh(t, freshSchemaDSN(t))
	ctx := t.Context()
	set := func(value string, wantGeneration int64) {
		t.Helper()
		if err := st.SetSetting(ctx, "edge-generation-test", value); err != nil {
			t.Fatal(err)
		}
		status, err := st.GetEdgeStatus(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if status.SavedGeneration != wantGeneration {
			t.Fatalf("setting %q: saved generation = %d, want %d", value, status.SavedGeneration, wantGeneration)
		}
	}
	set("original", 2)
	set("original", 2)
	set("changed", 3)
	set("changed", 3)
}

func TestEdgeStateTracksWritesAndApplyOutcomes(t *testing.T) {
	st := openFresh(t, freshSchemaDSN(t))
	ctx := context.Background()

	status, err := st.GetEdgeStatus(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if status.SavedGeneration != 1 || status.AppliedGeneration != nil || status.Pending != nil || status.LastApply != nil {
		t.Fatalf("fresh migration claimed applied truth: %+v", status)
	}

	app := config.Application{
		Name:        "generation-test",
		PublicHost:  "generation.example.test",
		BackendHost: "192.0.2.10",
		BackendPort: 8080,
		Profile:     "balanced",
		ListenMode:  "http_only",
		Enabled:     true,
		Security:    config.DefaultApplicationSecurity(),
	}
	if err := st.UpsertApplication(ctx, &app); err != nil {
		t.Fatal(err)
	}
	status, err = st.GetEdgeStatus(ctx)
	if err != nil || status.SavedGeneration != 2 {
		t.Fatalf("application write did not advance generation: %+v err=%v", status, err)
	}
	generation := status.SavedGeneration
	if err := st.AppendRevisionAndAudit(ctx, "test", "abc", "/tmp/manifest", "apply", map[string]any{"test": true}, EdgeApplyRecord{
		Outcome:           config.EdgeApplyOutcomeSuccess,
		AppliedGeneration: &generation,
		RevisionSHA:       "abc",
	}); err != nil {
		t.Fatal(err)
	}
	status, err = st.GetEdgeStatus(ctx)
	if err != nil || status.AppliedGeneration == nil || *status.AppliedGeneration != 2 || status.Pending == nil || *status.Pending || status.LastApply == nil || status.LastApply.Outcome != config.EdgeApplyOutcomeSuccess {
		t.Fatalf("successful apply truth not recorded: %+v err=%v", status, err)
	}

	app.BackendPort = 8081
	if err := st.UpsertApplication(ctx, &app); err != nil {
		t.Fatal(err)
	}
	if err := st.RecordEdgeApply(ctx, EdgeApplyRecord{Outcome: config.EdgeApplyOutcomeFailed, ErrorCode: "validation_failed"}); err != nil {
		t.Fatal(err)
	}
	status, err = st.GetEdgeStatus(ctx)
	if err != nil || status.SavedGeneration != 3 || status.AppliedGeneration == nil || *status.AppliedGeneration != 2 || status.Pending == nil || !*status.Pending || status.LastApply == nil || status.LastApply.ErrorCode != "validation_failed" {
		t.Fatalf("failed apply cleared pending truth: %+v err=%v", status, err)
	}

	source := config.IPBLExternalSource{Name: "fixture", URL: "https://example.test/list.txt", Enabled: true}
	if err := st.UpsertIPBLExternalSource(ctx, &source); err != nil {
		t.Fatal(err)
	}
	status, err = st.GetEdgeStatus(ctx)
	if err != nil {
		t.Fatal(err)
	}
	generation = status.SavedGeneration
	if err := st.RecordEdgeApply(ctx, EdgeApplyRecord{Outcome: config.EdgeApplyOutcomeSuccess, AppliedGeneration: &generation, RevisionSHA: "def"}); err != nil {
		t.Fatal(err)
	}
	if err := st.TouchIPBLSourceFetch(ctx, source.ID, time.Now().UTC(), "fixture fetch failure"); err != nil {
		t.Fatal(err)
	}
	afterFetch, err := st.GetEdgeStatus(ctx)
	if err != nil || afterFetch.SavedGeneration != generation {
		t.Fatalf("fetch metadata created false pending state: before=%d after=%+v err=%v", generation, afterFetch, err)
	}

	if err := st.DeleteApplication(ctx, "missing"); err != nil {
		t.Fatalf("missing delete = %v", err)
	}
	afterMissingDelete, err := st.GetEdgeStatus(ctx)
	if err != nil || afterMissingDelete.SavedGeneration != generation {
		t.Fatalf("no-op delete advanced generation: before=%d after=%+v err=%v", generation, afterMissingDelete, err)
	}

	if err := st.FactoryReset(ctx); err != nil {
		t.Fatal(err)
	}
	afterReset, err := st.GetEdgeStatus(ctx)
	if err != nil || afterReset.SavedGeneration != generation+1 || afterReset.AppliedGeneration != nil || afterReset.Pending != nil || afterReset.LastApply != nil {
		t.Fatalf("factory reset did not preserve unknown edge state: %+v err=%v", afterReset, err)
	}
}
