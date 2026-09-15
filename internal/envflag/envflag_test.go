// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package envflag

import "testing"

func TestEnabled(t *testing.T) {
	const name = "EASY_WAF_ENVFLAG_TEST"

	cases := []struct {
		raw  string
		want bool
	}{
		{raw: "", want: false},    // set but empty
		{raw: "   ", want: false}, // whitespace only
		{raw: "1", want: true},
		{raw: "t", want: true},
		{raw: "T", want: true},
		{raw: "true", want: true},
		{raw: "TRUE", want: true},
		{raw: "True", want: true},
		{raw: "yes", want: true},
		{raw: "YES", want: true},
		{raw: "y", want: true},
		{raw: "on", want: true},
		{raw: "On", want: true},
		{raw: " 1 ", want: true},
		{raw: "1\r", want: true}, // CRLF env file

		// The whole point of this package: these used to count as "set".
		{raw: "0", want: false},
		{raw: "f", want: false},
		{raw: "false", want: false},
		{raw: "FALSE", want: false},
		{raw: "no", want: false},
		{raw: "n", want: false},
		{raw: "off", want: false},
		{raw: "0\r", want: false},
		{raw: " 0 ", want: false},

		// Unparseable is off, not on: this switch disables a safety step.
		{raw: "banana", want: false},
		{raw: "2", want: false},
		{raw: "-1", want: false},
		{raw: "enabled", want: false},
	}

	for _, tc := range cases {
		t.Run("value="+tc.raw, func(t *testing.T) {
			t.Setenv(name, tc.raw)
			if got := Enabled(name); got != tc.want {
				t.Fatalf("Enabled(%q=%q) = %v, want %v", name, tc.raw, got, tc.want)
			}
		})
	}
}

// TestEnabledUnset checks the unset case on its own, because t.Setenv cannot
// express "not in the environment at all".
func TestEnabledUnset(t *testing.T) {
	if Enabled("EASY_WAF_ENVFLAG_DEFINITELY_NOT_SET") {
		t.Fatal("an unset variable must be off")
	}
}

// TestEnabledShippedDefault is the regression this package was written for: the
// value the stock easy-waf.env.example carried must not disable anything.
func TestEnabledShippedDefault(t *testing.T) {
	for _, name := range []string{"EASY_WAF_SKIP_RELOAD", "EASY_WAF_SKIP_VALIDATE"} {
		t.Setenv(name, "0")
		if Enabled(name) {
			t.Fatalf("%s=0 must be off — that value ships in easy-waf.env.example", name)
		}
	}
}
