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
		"DATABASE_URL=postgresql://u:p@h/db",
	} {
		got := MaskEasyWAFEnvLine(in)
		if !strings.Contains(got, "***MASKED***") || strings.Contains(got, "myPass") || strings.Contains(got, ":p@") {
			t.Fatalf("DATABASE_URL masking failed: in %q got %q", in, got)
		}
	}
}
