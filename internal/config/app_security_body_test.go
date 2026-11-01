// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strings"
	"testing"
)

// A client that sends only the body settings must keep the default protections.
func TestNormalizeKeepsBodySettingsWhenFillingDefaults(t *testing.T) {
	limit := int64(1 << 20)
	block := true
	sec := ApplicationSecurity{
		MaxBodyBytesOverride:   &limit,
		BlockMultipartOverride: &block,
		MultipartAllowedPaths:  []string{"/upload"},
	}

	NormalizeApplicationSecurity(&sec)

	if !sec.BasicWAFEnabled || sec.Mode != "balanced" {
		t.Fatalf("defaults were not applied: %+v", sec)
	}
	if sec.MaxBodyBytesOverride == nil || *sec.MaxBodyBytesOverride != limit {
		t.Fatalf("limit lost: %+v", sec.MaxBodyBytesOverride)
	}
	if sec.BlockMultipartOverride == nil || !*sec.BlockMultipartOverride {
		t.Fatalf("multipart override lost: %+v", sec.BlockMultipartOverride)
	}
	if len(sec.MultipartAllowedPaths) != 1 {
		t.Fatalf("paths lost: %v", sec.MultipartAllowedPaths)
	}
}

func bodyPolicyApp(sec ApplicationSecurity) *Application {
	return &Application{PublicHost: "a.example.com", BackendHost: "10.0.0.1", BackendPort: 80, Security: sec}
}

func TestValidateBodyPolicy(t *testing.T) {
	negative, tooBig, fine := int64(-1), MaxBodyBytesLimit+1, int64(1<<20)
	for name, tc := range map[string]struct {
		sec     ApplicationSecurity
		wantErr string
	}{
		"nothing set":     {},
		"limit":           {sec: ApplicationSecurity{MaxBodyBytesOverride: &fine}},
		"negative limit":  {sec: ApplicationSecurity{MaxBodyBytesOverride: &negative}, wantErr: "max_body_bytes_override"},
		"limit too large": {sec: ApplicationSecurity{MaxBodyBytesOverride: &tooBig}, wantErr: "max_body_bytes_override"},
		"allowed path":    {sec: ApplicationSecurity{MultipartAllowedPaths: []string{"/upload"}}},
		"relative path":   {sec: ApplicationSecurity{MultipartAllowedPaths: []string{"upload"}}, wantErr: "multipart_allowed_paths"},
		"injection":       {sec: ApplicationSecurity{MultipartAllowedPaths: []string{"/a\n\tbind *:1"}}, wantErr: "multipart_allowed_paths"},
		"dots":            {sec: ApplicationSecurity{MultipartAllowedPaths: []string{"/a/../b"}}, wantErr: "multipart_allowed_paths"},
		"root":            {sec: ApplicationSecurity{MultipartAllowedPaths: []string{"/"}}, wantErr: "multipart_allowed_paths"},
		"too many":        {sec: ApplicationSecurity{MultipartAllowedPaths: make([]string, MaxMultipartAllowedPaths+1)}, wantErr: "multipart_allowed_paths"},
	} {
		t.Run(name, func(t *testing.T) {
			err := ValidateApplicationRenderSafety(bodyPolicyApp(tc.sec))
			if tc.wantErr == "" && err != nil {
				t.Fatal(err)
			}
			if tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)) {
				t.Fatalf("err = %v, want it to mention %s", err, tc.wantErr)
			}
		})
	}
}
