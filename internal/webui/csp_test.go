// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package webui

import (
	"regexp"
	"strings"
	"testing"
)

func TestInlineScriptHash(t *testing.T) {
	got, err := inlineScriptHash([]byte("<html><script>alert(1)</script></html>"))
	if err != nil {
		t.Fatal(err)
	}
	// echo -n 'alert(1)' | openssl dgst -sha256 -binary | base64
	if want := "sha256-bhHHL3z2vDgxUt0W3dWQOrprscmda2Y5pLsLg4GF+pI="; got != want {
		t.Fatalf("got %s, want %s", got, want)
	}
	if _, err := inlineScriptHash([]byte("<script>a</script><script>b</script>")); err == nil {
		t.Fatal("a second script block would be blocked by the policy")
	}
}

// Inline event handlers are not covered by a script hash: one in the page
// would silently stop working under the policy.
func TestPageHasNoInlineEventHandlers(t *testing.T) {
	html, err := Assets.ReadFile("dist/index.html")
	if err != nil {
		t.Fatal(err)
	}
	markup, _, _ := strings.Cut(string(html), "<script>")
	if m := regexp.MustCompile(`(?i)<[^>]+\son[a-z]+\s*=`).FindString(markup); m != "" {
		t.Fatalf("inline handler: %s", m)
	}
}

func TestPolicyRestrictsScripts(t *testing.T) {
	for _, want := range []string{"script-src 'sha256-", "default-src 'self'", "object-src 'none'", "frame-ancestors 'none'"} {
		if !strings.Contains(ContentSecurityPolicy, want) {
			t.Errorf("policy lacks %q: %s", want, ContentSecurityPolicy)
		}
	}
	if strings.Contains(ContentSecurityPolicy, "script-src 'unsafe") {
		t.Errorf("unsafe script source: %s", ContentSecurityPolicy)
	}
}
