// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package haproxy

import (
	"fmt"
	"strings"
)

// errorPageTexts replace HAProxy's built-in error bodies for the responses it
// makes itself: denials, no server available, timeouts, malformed requests.
// Pages name neither HAProxy nor this product.
var errorPageTexts = []struct {
	code        int
	title, text string
}{
	{400, "Bad request", "The request could not be understood."},
	{401, "Unauthorized", "This address needs credentials the request did not carry."},
	{403, "Access denied", "The request was refused by this site's security policy."},
	{404, "Not found", "Nothing is published at this address."},
	{405, "Method not allowed", "This request method is not allowed here."},
	{408, "Request timeout", "The request took too long to arrive."},
	{413, "Request too large", "The request body is larger than this site accepts."},
	{429, "Too many requests", "Too many requests from your address. Wait a moment and try again."},
	{500, "Internal error", "Something went wrong while handling the request."},
	{502, "Bad gateway", "The service behind this address sent an invalid response."},
	{503, "Service unavailable", "The service behind this address is not available right now. Try again in a few minutes."},
	{504, "Gateway timeout", "The service behind this address did not answer in time."},
}

// htmlPage builds a small self-contained page. It goes inside a double-quoted
// HAProxy string, so it must not contain a double quote, a backslash or a
// dollar sign (environment expansion); attributes use single quotes.
func htmlPage(title, text string) string {
	return "<!doctype html><html lang='en'><head><meta charset='utf-8'>" +
		"<meta name='viewport' content='width=device-width,initial-scale=1'><title>" + title + "</title>" +
		"<style>body{font-family:system-ui,sans-serif;margin:0;min-height:100vh;display:flex;align-items:center;" +
		"justify-content:center;background:#f4f5f7;color:#1f2328}main{max-width:32rem;padding:2rem}" +
		"h1{font-size:1.4rem;margin:0 0 .5rem}p{color:#57606a;line-height:1.5;margin:0}</style></head>" +
		"<body><main><h1>" + title + "</h1><p>" + text + "</p></main></body></html>"
}

// errorPages renders one http-error line per status for the defaults section.
func errorPages() string {
	lines := make([]string, 0, len(errorPageTexts))
	for _, p := range errorPageTexts {
		lines = append(lines, fmt.Sprintf("\thttp-error status %d content-type \"text/html; charset=utf-8\" hdr Cache-Control no-store string \"%s\"",
			p.code, htmlPage(fmt.Sprintf("%d %s", p.code, p.title), p.text)))
	}
	return strings.Join(lines, "\n")
}

// maintenancePage is the body of a maintenance-mode 503.
func maintenancePage() string {
	return htmlPage("Down for maintenance", "This service is down for planned maintenance. Please try again later.")
}
