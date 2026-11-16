// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package webui

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

// ContentSecurityPolicy is the policy for every response. The session token
// lives in sessionStorage, where any script on the page can read it, and it
// reaches the root broker, so scripts are limited to the one inline block the
// UI ships. Its hash comes from the embedded file, so it cannot go stale.
var ContentSecurityPolicy = mustPolicy()

func mustPolicy() string {
	html, err := Assets.ReadFile("dist/index.html")
	if err != nil {
		panic(err)
	}
	hash, err := inlineScriptHash(html)
	if err != nil {
		panic(err)
	}
	return "default-src 'self'; script-src '" + hash + "'; style-src 'self' 'unsafe-inline'; " +
		"img-src 'self' data:; connect-src 'self'; form-action 'self'; " +
		"frame-ancestors 'none'; base-uri 'self'; object-src 'none'"
}

// inlineScriptHash returns the CSP source for the page's only script block.
func inlineScriptHash(html []byte) (string, error) {
	const open, closing = "<script>", "</script>"
	if n := bytes.Count(html, []byte("<script")); n != 1 {
		return "", fmt.Errorf("webui: want one script block, found %d", n)
	}
	start := bytes.Index(html, []byte(open))
	end := bytes.Index(html, []byte(closing))
	if start < 0 || end < start {
		return "", fmt.Errorf("webui: no plain %s block", open)
	}
	// HTML input preprocessing turns CRLF and lone CR into LF before the
	// browser computes an inline script's CSP hash. Match that script text,
	// including when a Windows checkout supplies CRLF-encoded embedded assets.
	script := html[start+len(open) : end]
	script = bytes.ReplaceAll(script, []byte("\r\n"), []byte("\n"))
	script = bytes.ReplaceAll(script, []byte("\r"), []byte("\n"))
	sum := sha256.Sum256(script)
	return "sha256-" + base64.StdEncoding.EncodeToString(sum[:]), nil
}
