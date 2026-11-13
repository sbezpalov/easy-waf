// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/easy-waf/easy-waf/internal/config"
	"github.com/easy-waf/easy-waf/internal/engine"
)

func TestApplicationMutationsWaitBeforeChangingRows(t *testing.T) {
	s := applyFailingServer(t)
	release, err := s.Eng.Store.AcquireAdvisoryLock(t.Context(), engine.ApplyOrUndoAdvisoryLockKey)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := release(); err != nil {
			t.Errorf("release test gate: %v", err)
		}
	})
	for _, kind := range []string{"upsert", "delete", "maintenance", "security-put", "security-patch", "security-mode"} {
		t.Run(kind, func(t *testing.T) {
			app := testApp(fmt.Sprintf("mutation%d", time.Now().UnixNano()))
			if err := s.Eng.Store.UpsertApplication(t.Context(), &app); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				if err := s.Eng.Store.DeleteApplication(ctx, app.ID); err != nil {
					t.Errorf("clean test application: %v", err)
				}
			})
			before, err := s.Eng.Store.GetApplication(t.Context(), app.ID)
			if err != nil {
				t.Fatal(err)
			}
			var body []byte
			var handler http.HandlerFunc
			method := http.MethodPost
			switch kind {
			case "upsert":
				changed := before
				changed.BackendPort = 9090
				body, err = json.Marshal(changed)
				handler = s.upsertApp
			case "delete":
				method, handler = http.MethodDelete, s.deleteApp
			case "maintenance":
				body, handler = []byte(`{"enabled":true}`), s.postAppMaintenance
			case "security-put":
				sec := config.DefaultApplicationSecurity()
				sec.Mode, sec.BasicWAFEnabled = "custom", !before.Security.BasicWAFEnabled
				body, err = json.Marshal(sec)
				method, handler = http.MethodPut, s.putAppSecurity
			case "security-patch":
				body, method, handler = []byte(`{"rate_limit_enabled":false}`), http.MethodPatch, s.patchAppSecurity
			case "security-mode":
				body, handler = []byte(`{"mode":"trusted-lan"}`), s.postAppSecurityMode
			}
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			req := httptest.NewRequest(method, "/applications/"+app.ID, bytes.NewReader(body)).WithContext(ctx)
			req = withURLParam(req, "id", app.ID)
			rec := httptest.NewRecorder()
			handler(rec, req)
			if rec.Code != http.StatusServiceUnavailable {
				t.Fatalf("blocked mutation status = %d: %s", rec.Code, rec.Body.String())
			}
			after, err := s.Eng.Store.GetApplication(t.Context(), app.ID)
			if err != nil {
				t.Fatalf("blocked mutation changed or deleted the row: %v", err)
			}
			beforeJSON, err := json.Marshal(before)
			if err != nil {
				t.Fatal(err)
			}
			afterJSON, err := json.Marshal(after)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(beforeJSON, afterJSON) {
				t.Fatal("mutation changed its row before obtaining the application gate")
			}
		})
	}
}
