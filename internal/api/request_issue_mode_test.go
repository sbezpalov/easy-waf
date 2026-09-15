// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package api

import "testing"

func TestResolveRequestIssueMode(t *testing.T) {
	cases := []struct {
		name      string
		requested string
		stored    string
		want      string
		wantOK    bool
	}{
		// The regression: the UI's Issue and Renew buttons post "{}", so an empty
		// requested mode must not rewrite a dns-01 certificate to http-01.
		{name: "empty body keeps dns-01", requested: "", stored: "dns-01", want: "dns-01", wantOK: true},
		{name: "empty body keeps http-01", requested: "", stored: "http-01", want: "http-01", wantOK: true},
		{name: "empty body on mixed case stored", requested: "", stored: " DNS-01 ", want: "dns-01", wantOK: true},

		// A certificate not yet on an ACME mode starts on http-01, which is what
		// the button has always meant for manual and uploaded certificates.
		{name: "manual defaults to http-01", requested: "", stored: "manual", want: "http-01", wantOK: true},
		{name: "unset defaults to http-01", requested: "", stored: "", want: "http-01", wantOK: true},

		// An explicit mode wins, including switching a certificate over.
		{name: "explicit dns-01 over stored http-01", requested: "dns-01", stored: "http-01", want: "dns-01", wantOK: true},
		{name: "explicit http-01 over stored dns-01", requested: "http-01", stored: "dns-01", want: "http-01", wantOK: true},
		{name: "explicit is case-insensitive", requested: "DNS-01", stored: "manual", want: "dns-01", wantOK: true},

		// An explicit nonsense mode is refused rather than stored: acmed would
		// otherwise park the certificate in a mode nothing can issue.
		{name: "explicit garbage refused", requested: "tls-alpn-01", stored: "http-01", wantOK: false},
		{name: "explicit manual refused", requested: "manual", stored: "http-01", wantOK: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := resolveRequestIssueMode(tc.requested, tc.stored)
			if ok != tc.wantOK {
				t.Fatalf("resolveRequestIssueMode(%q, %q) ok = %v, want %v", tc.requested, tc.stored, ok, tc.wantOK)
			}
			if ok && got != tc.want {
				t.Fatalf("resolveRequestIssueMode(%q, %q) = %q, want %q", tc.requested, tc.stored, got, tc.want)
			}
		})
	}
}
