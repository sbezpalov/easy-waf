// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/easy-waf/easy-waf/internal/config"
	"github.com/easy-waf/easy-waf/internal/engine"
)

func TestValidateRuntimeSettingsACMEEmail(t *testing.T) {
	for _, email := range []string{"", "ops@example.test", "ops+alerts@sub.example.test", "Ops@Example.TEST"} {
		s := config.DefaultSettings("/var/lib/easy-waf")
		s.ACMEEmail = email
		if err := validateRuntimeSettings(s); err != nil {
			t.Fatalf("valid contact rejected: %v", err)
		}
	}
	for name, email := range map[string]string{
		"missing domain": "ops", "missing local": "@example.test", "missing host": "ops@",
		"display name": "Operator <ops@example.test>", "list": "ops@example.test, other@example.test",
		"comment": "ops@example.test (Operator)", "prefix space": " ops@example.test", "suffix space": "ops@example.test ",
		"newline": "ops@example.test\n", "header": "ops@example.test\r\nBcc: other@example.test",
		"space": "ops team@example.test", "oversized": strings.Repeat("a", 245) + "@example.test",
	} {
		t.Run(name, func(t *testing.T) {
			s := config.DefaultSettings("/var/lib/easy-waf")
			s.ACMEEmail = email
			err := validateRuntimeSettings(s)
			if err == nil {
				t.Fatal("invalid ACME contact accepted")
			}
			if !strings.Contains(err.Error(), "acme_email") || strings.Contains(err.Error(), email) {
				t.Fatal("contact error must name the field without echoing input")
			}
		})
	}
}

func TestSettingsRejectInvalidACMEContactWithoutPersisting(t *testing.T) {
	s := applyFailingServer(t)
	// The settings API intentionally validates appliance paths with POSIX
	// semantics. Keep the engine's native temporary state directory for any
	// filesystem work, but seed this settings-only test with target paths so it
	// exercises ACME contact validation on Windows and macOS too.
	targetSettings := config.DefaultSettings("/var/lib/easy-waf")
	targetSettings.HAProxyBinary = "/bin/false"
	targetSettings.IPBLExternalEnabled = false
	s.Eng = engine.New(s.Eng.StateDir, s.Eng.Store, targetSettings)
	if err := s.Eng.SaveSettings(t.Context()); err != nil {
		t.Fatal(err)
	}
	before, err := s.Eng.Store.GetSetting(t.Context(), "global_settings_json")
	if err != nil {
		t.Fatal(err)
	}
	memory := s.Eng.Settings()
	for _, method := range []string{http.MethodPatch, http.MethodPut} {
		for _, email := range []string{"not-an-email", "Operator <ops@example.test>", "ops@example.test, other@example.test"} {
			body, err := json.Marshal(map[string]any{"acme_email": email, "acme_staging": false})
			if err != nil {
				t.Fatal(err)
			}
			request := httptest.NewRequest(method, "/api/v1/settings", strings.NewReader(string(body)))
			response := httptest.NewRecorder()
			if method == http.MethodPatch {
				s.patchSettings(response, request)
			} else {
				s.putSettings(response, request)
			}
			if method == http.MethodPut {
				if response.Code != http.StatusMethodNotAllowed || response.Header().Get("Allow") != "GET, PATCH" {
					t.Fatalf("disabled PUT status %d", response.Code)
				}
			} else if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "acme_email") {
				t.Fatalf("invalid contact status %d", response.Code)
			}
			stored, err := s.Eng.Store.GetSetting(t.Context(), "global_settings_json")
			if err != nil {
				t.Fatal(err)
			}
			if stored != before || !reflect.DeepEqual(s.Eng.Settings(), memory) {
				t.Fatal("rejected contact changed stored or live settings")
			}
		}
	}
	response := httptest.NewRecorder()
	s.patchSettings(response, httptest.NewRequest(http.MethodPatch, "/api/v1/settings", strings.NewReader(`{"acme_email":"ops+alerts@example.test","acme_staging":false}`)))
	if response.Code != http.StatusOK {
		t.Fatalf("valid contact status %d: %s", response.Code, response.Body.String())
	}
	stored, err := s.Eng.Store.GetSetting(t.Context(), "global_settings_json")
	if err != nil {
		t.Fatal(err)
	}
	var got config.GlobalSettings
	if err := json.Unmarshal([]byte(stored), &got); err != nil {
		t.Fatal(err)
	}
	if got.ACMEEmail != "ops+alerts@example.test" || got.ACMEStaging || s.Eng.Settings().ACMEEmail != got.ACMEEmail {
		t.Fatal("valid contact not persisted")
	}
}
