package config

import "testing"

func TestNormalizeListenMode(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"", "https_only"},
		{"  HTTPS_ONLY  ", "https_only"},
		{"Http_Only", "http_only"},
		{"HTTP_AND_HTTPS", "http_and_https"},
		{"redirect_to_https", "redirect_to_https"},
		{"garbage", "https_only"},
	}
	for _, tc := range cases {
		a := &Application{ListenMode: tc.in}
		NormalizeListenMode(a)
		if a.ListenMode != tc.want {
			t.Errorf("NormalizeListenMode(%q): got %q, want %q", tc.in, a.ListenMode, tc.want)
		}
	}
	NormalizeListenMode(nil)
}

func TestListenModeRequiresCertificate(t *testing.T) {
	if ListenModeRequiresCertificate("http_only") {
		t.Error("http_only should not require certificate")
	}
	for _, m := range []string{"https_only", "http_and_https", "redirect_to_https", "", "HTTPS_ONLY"} {
		if !ListenModeRequiresCertificate(m) {
			t.Errorf("mode %q should require certificate", m)
		}
	}
}
