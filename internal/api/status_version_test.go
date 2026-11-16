// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/easy-waf/easy-waf/internal/engine"
)

func TestStatusReportsBuiltVersionWithoutEnvironmentOverride(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "VERSION"))
	if err != nil {
		t.Fatal(err)
	}
	want := strings.TrimSpace(string(data))
	for _, value := range []string{"", "0.0.0-spoofed"} {
		t.Run(value, func(t *testing.T) {
			t.Setenv("EASY_WAF_VERSION", value)
			s := &Server{Eng: &engine.Engine{StateDir: t.TempDir()}}
			w := httptest.NewRecorder()
			s.handleStatus(w, httptest.NewRequest(http.MethodGet, "/api/v1/status", nil))
			var got struct{ Version string }
			if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
				t.Fatal(err)
			}
			if w.Code != http.StatusOK || got.Version != want || want == "" {
				t.Fatalf("status %d version %q, want %q", w.Code, got.Version, want)
			}
		})
	}
}
