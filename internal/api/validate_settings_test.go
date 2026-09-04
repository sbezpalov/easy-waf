// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"testing"

	"github.com/easy-waf/easy-waf/internal/config"
)

func TestValidateRuntimeSettingsRejectsHAProxyInjection(t *testing.T) {
	base := config.DefaultSettings("/var/lib/easy-waf")
	tests := []struct {
		name   string
		mutate func(*config.GlobalSettings)
	}{
		{"engine newline", func(s *config.GlobalSettings) { s.CrowdSecEngineName = "crowdsec\nprogram" }},
		{"spoe newline", func(s *config.GlobalSettings) { s.SPOEConfigPath = "/etc/crowdsec.cfg\nprogram" }},
		{"map relative", func(s *config.GlobalSettings) { s.IPBlacklistMapPath = "relative.map" }},
		{"url userinfo", func(s *config.GlobalSettings) { s.CrowdSecLAPIURL = "http://secret@127.0.0.1:8080" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := base
			tt.mutate(&s)
			if err := validateRuntimeSettings(s); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestValidateRuntimeSettingsAcceptsDefaults(t *testing.T) {
	if err := validateRuntimeSettings(config.DefaultSettings("/var/lib/easy-waf")); err != nil {
		t.Fatal(err)
	}
}
