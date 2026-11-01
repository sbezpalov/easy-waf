// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package haproxy

import (
	"strings"
	"testing"

	"github.com/easy-waf/easy-waf/internal/config"
)

func renderBodyPolicy(t *testing.T, profile string, sec config.ApplicationSecurity) string {
	t.Helper()
	sec.Mode = "custom"
	out, err := Render(RenderInput{
		Settings: goldenGlobalSettings("testdata/golden/spoe/crowdsec-vendor.cfg", "crowdsec"),
		Applications: []config.Application{{
			ID: "bp1", Name: "Body", PublicHost: "body.example.local", BackendHost: "192.168.1.60", BackendPort: 80,
			Profile: profile, ListenMode: "http_only", Enabled: true, Security: sec,
		}},
		Certificates: map[string]config.Certificate{},
		CRTListPath:  "testdata/golden/http-only-app.crt-list.txt",
	})
	if err != nil {
		t.Fatal(err)
	}
	return out.HAProxyConfig
}

func TestBodyPolicyOffRendersNothing(t *testing.T) {
	cfg := renderBodyPolicy(t, "balanced", config.ApplicationSecurity{})

	for _, want := range []string{"multipart", "content-length", "transfer-encoding"} {
		if strings.Contains(cfg, want) {
			t.Fatalf("%q in a config with no body policy", want)
		}
	}
}

func TestBodyLimitAlsoRefusesBodiesOfUnknownLength(t *testing.T) {
	limit := int64(1048576)

	cfg := renderBodyPolicy(t, "balanced", config.ApplicationSecurity{MaxBodyBytesOverride: &limit})

	for _, want := range []string{
		"req.hdr_val(content-length) gt 1048576",
		"req.fhdr(transfer-encoding) -m found",
		"method POST PUT PATCH",
		"return status 413",
		"return status 411",
	} {
		if !strings.Contains(cfg, want) {
			t.Errorf("missing %q", want)
		}
	}
}

func TestMultipartBlockWithoutExceptions(t *testing.T) {
	cfg := renderBodyPolicy(t, "php-app", config.ApplicationSecurity{})

	if !strings.Contains(cfg, "req.hdr(content-type) -m beg -i multipart/") {
		t.Fatal("no multipart acl")
	}
	if !strings.Contains(cfg, "return status 415") {
		t.Fatal("no 415 rule")
	}
	if strings.Contains(cfg, "_mp_allowed") {
		t.Fatal("exception rendered with no allowed paths")
	}
}

// Without the second rule, POST /upload/../x.php would match the exception here
// and reach x.php on the backend.
func TestMultipartExceptionDoesNotCoverPathTraversal(t *testing.T) {
	cfg := renderBodyPolicy(t, "php-app", config.ApplicationSecurity{MultipartAllowedPaths: []string{"/upload", "/files/"}})

	for _, want := range []string{
		"path -m str /upload /files\n",
		"path_beg /upload/ /files/\n",
		`path -m reg -i (\.|%2e){2}`,
	} {
		if !strings.Contains(cfg, want) {
			t.Errorf("missing %q", want)
		}
	}
	// A bare prefix would also allow /upload.php.
	if strings.Contains(cfg, "path_beg /upload ") {
		t.Fatal("prefix without a trailing slash")
	}
	if strings.Count(cfg, "return status 415") < 2 {
		t.Fatal("want one 415 rule for other paths and one for traversal")
	}
}
