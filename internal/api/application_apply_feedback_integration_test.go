// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/easy-waf/easy-waf/internal/engine"
)

func TestApplicationMutationApplyOutcome(t *testing.T) {
	for _, operation := range []string{"save", "mode", "maintenance"} {
		for _, outcome := range []string{"applied", "manual", "rejected"} {
			t.Run(operation+"/"+outcome, func(t *testing.T) {
				s := applyFailingServer(t)
				switch outcome {
				case "manual":
					t.Setenv("EASY_WAF_NO_AUTO_APPLY", "1")
				case "applied":
					// Validate successfully without reloading a host service. The
					// real apply still renders, publishes and records its revision.
					cfg := s.Eng.Settings()
					cfg.HAProxyBinary = "/bin/true"
					s.Eng = engine.New(s.Eng.StateDir, s.Eng.Store, cfg)
					if err := s.Eng.SaveSettings(t.Context()); err != nil {
						t.Fatal(err)
					}
				}
				a := testApp(fmt.Sprintf("feedback%d", time.Now().UnixNano()))
				if err := s.Eng.Store.UpsertApplication(t.Context(), &a); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = s.Eng.Store.DeleteApplication(context.Background(), a.ID) })
				var w *httptest.ResponseRecorder
				switch operation {
				case "save":
					a.BackendPort = 8123
					w = putApp(t, s, a)
				case "mode":
					w = httptest.NewRecorder()
					r := withURLParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"mode":"full"}`)), "id", a.ID)
					s.postAppSecurityMode(w, r)
				case "maintenance":
					w = httptest.NewRecorder()
					r := withURLParam(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"enabled":true}`)), "id", a.ID)
					s.postAppMaintenance(w, r)
				}
				wantCode, wantHeader := http.StatusOK, "true"
				switch outcome {
				case "manual":
					wantHeader = "false"
				case "rejected":
					wantCode, wantHeader = http.StatusUnprocessableEntity, ""
				}
				if w.Code != wantCode {
					t.Fatalf("status %d, want %d: %s", w.Code, wantCode, w.Body.String())
				}
				if got := w.Header().Get("X-Easy-Waf-Applied"); got != wantHeader {
					t.Errorf("Apply outcome %q, want %q", got, wantHeader)
				}
				if !json.Valid(w.Body.Bytes()) {
					t.Fatal("response is not JSON")
				}
				stored, err := s.Eng.Store.GetApplication(t.Context(), a.ID)
				if err != nil {
					t.Fatal(err)
				}
				changed := operation == "save" && stored.BackendPort == 8123 ||
					operation == "mode" && stored.Security.Mode == "full" ||
					operation == "maintenance" && stored.Maintenance
				if changed != (outcome != "rejected") {
					t.Fatal("stored mutation does not match accepted/rejected outcome")
				}
			})
		}
	}
}
