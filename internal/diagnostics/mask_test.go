// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package diagnostics

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func FuzzMaskQuotedSecretValue(f *testing.F) {
	for _, seed := range []string{"plain", "first\nFAKE_SETTING=tail", "\\\"\r\n'next", "\x00\xff"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, value string) {
		if len(value) > 1<<16 {
			t.Skip()
		}
		escaped := strings.NewReplacer("\\", "\\\\", "\"", "\\\"").Replace(value)
		raw := "TOKEN=\"fixture-sensitive-head\n" + escaped + "\nfixture-sensitive-tail\"\nPUBLIC=visible\n"
		if string(MaskEasyWAFEnvContent([]byte(raw))) != "TOKEN=***MASKED***\nPUBLIC=visible\n" {
			t.Fatal("quoted secret was not fully replaced or damaged the following entry")
		}
	})
}

func TestMaskEasyWAFEnvContentMultiline(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "environment-multiline.env.example"))
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile(filepath.Join("testdata", "environment-multiline.masked.example"))
	if err != nil {
		t.Fatal(err)
	}
	masked := string(MaskEasyWAFEnvContent(raw))
	if strings.Contains(masked, "fixture-sensitive") {
		t.Error("multiline file secret leaked")
	}
	if masked != string(want) {
		t.Fatal("multiline environment masking differs from the shared fixture")
	}
	for _, raw := range []string{
		"TOKEN=\"head\r\nfixture-sensitive-tail\"\r\nPUBLIC=visible\r\n",
		"TOKEN='head\nfixture-sensitive-tail",
		"TOKEN=head\\\nfixture-sensitive-tail",
	} {
		got := string(MaskEasyWAFEnvContent([]byte(raw)))
		if strings.Contains(got, "fixture-sensitive") {
			t.Fatal("multiline secret suffix leaked")
		}
		if strings.Contains(raw, "PUBLIC=visible") && !strings.Contains(got, "PUBLIC=visible") {
			t.Fatal("following public setting was discarded")
		}
	}
}

func TestMaskEasyWAFEnvLine_secrets(t *testing.T) {
	cases := []struct{ in, want string }{
		{"CROWDSEC_LAPI_KEY=secret123", "CROWDSEC_LAPI_KEY=***MASKED***"},
		{"EASY_WAF_JWT_SECRET=abc", "EASY_WAF_JWT_SECRET=***MASKED***"},
		{"EASY_WAF_ADMIN_TOKEN=tok", "EASY_WAF_ADMIN_TOKEN=***MASKED***"},
		{"GEOIP_IPINFO_TOKEN=geo", "GEOIP_IPINFO_TOKEN=***MASKED***"},
		{"AWS_SECRET_ACCESS_KEY=aws", "AWS_SECRET_ACCESS_KEY=***MASKED***"},
		{"CUSTOM_API_KEY=custom", "CUSTOM_API_KEY=***MASKED***"},
		{"TOKEN=fixture-exact-token", "TOKEN=***MASKED***"},
		{"PASSWORD_HINT=fixture-prefix-password", "PASSWORD_HINT=***MASKED***"},
		{"  CROWDSEC_LAPI_KEY = fixture-spaced-crowdsec", "CROWDSEC_LAPI_KEY=***MASKED***"},
		{"EASY_WAF_JWT_SECRET   =fixture-spaced-jwt", "EASY_WAF_JWT_SECRET=***MASKED***"},
		{"token =fixture-lowercase-token", "token=***MASKED***"},
		{"  DATABASE_URL =host=fixture password=fixture-spaced-dsn", "DATABASE_URL=***MASKED***"},
		{"# TOKEN=comment-example", "# TOKEN=comment-example"},
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
