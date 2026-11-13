// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestApplyRejectsNULLabelBeforeInvokingEngine(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("invalid label invoked the unconfigured engine: %v", r)
		}
	}()
	s := &Server{}
	rec := httptest.NewRecorder()
	s.apply(rec, httptest.NewRequest(http.MethodPost, "/api/v1/apply", strings.NewReader(`{"label":"invalid\u0000label"}`)))
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "invalid label") {
		t.Fatalf("invalid revision label accepted: %d %s", rec.Code, rec.Body.String())
	}
}
