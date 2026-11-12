// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package diagnostics

import (
	"strings"
	"testing"
)

func TestMaskEasyWAFEnvLine_secrets(t *testing.T) {
	cases := []struct{ in, want string }{
		{"CROWDSEC_LAPI_KEY=secret123", "CROWDSEC_LAPI_KEY=***MASKED***"},
		{"EASY_WAF_JWT_SECRET=abc", "EASY_WAF_JWT_SECRET=***MASKED***"},
		{"EASY_WAF_ADMIN_TOKEN=tok", "EASY_WAF_ADMIN_TOKEN=***MASKED***"},
		{"GEOIP_IPINFO_TOKEN=geo", "GEOIP_IPINFO_TOKEN=***MASKED***"},
		{"AWS_SECRET_ACCESS_KEY=aws", "AWS_SECRET_ACCESS_KEY=***MASKED***"},
		{"CUSTOM_API_KEY=custom", "CUSTOM_API_KEY=***MASKED***"},
		{"FOO=bar", "FOO=bar"},
		{"# comment", "# comment"},
	}
	for _, c := range cases {
		got := MaskEasyWAFEnvLine(c.in)
		if got != c.want {
			t.Fatalf("in %q: got %q want %q", c.in, got, c.want)
		}
	}
	for _, in := range []string{
		"DATABASE_URL=postgres://easywaf:myPass@127.0.0.1:5432/easywaf?sslmode=disable",
		"DATABASE_URL=postgresql://u@h/db?password=query-secret",
		"DATABASE_URL=host=db user=easywaf password=keyword-secret",
	} {
		got := MaskEasyWAFEnvLine(in)
		if got != "DATABASE_URL=***MASKED***" {
			t.Fatalf("DATABASE_URL masking failed: in %q got %q", in, got)
		}
	}
}

func TestMaskHAProxyConfigContent(t *testing.T) {
	const secret = "forward-auth-secret"
	raw := []byte("frontend f_apps\n" +
		"  http-request lua.easywaf_auth \"https://auth.example/verify?token=" + secret + "\" if !{ src 192.0.2.0/24 }\n" +
		"  server app 192.0.2.10:8080\n")
	got := string(MaskHAProxyConfigContent(raw))
	if strings.Contains(got, secret) || strings.Contains(got, "https://auth.example") {
		t.Fatalf("forward-auth target leaked:\n%s", got)
	}
	if !strings.Contains(got, `lua.easywaf_auth "***MASKED***" if`) || !strings.Contains(got, "server app 192.0.2.10:8080") {
		t.Fatalf("unexpected masked config:\n%s", got)
	}

	malformed := string(MaskHAProxyConfigContent([]byte(`http-request lua.easywaf_auth "https://auth.example/?token=` + secret)))
	if strings.Contains(malformed, secret) {
		t.Fatalf("malformed directive leaked target: %s", malformed)
	}
}
