// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

// Package envflag reads boolean toggles out of the process environment.
//
// It exists because "set means non-empty" is the wrong rule for a switch that
// turns a safety step off. The shipped configs/defaults/easy-waf.env.example
// carried
//
//	EASY_WAF_SKIP_RELOAD=0
//	EASY_WAF_SKIP_VALIDATE=0
//
// uncommented, and that file becomes /etc/easy-waf/easy-waf.env on every
// install. Under the old os.Getenv(...) != "" test, "0" counted as set, so a
// stock appliance wrote HAProxy configuration that was never checked with
// haproxy -c and never reloaded — the operator saw a successful apply and an
// edge that had not moved.
package envflag

import (
	"log"
	"os"
	"strconv"
	"strings"
	"sync"
)

// warned keeps the "not a boolean" complaint to once per variable per process:
// Enabled is called on every apply, and a log line per apply would bury it.
var warned sync.Map

// Enabled reports whether the environment variable name holds a true value.
//
// Unset, empty and whitespace are false. Values are read the way
// strconv.ParseBool reads them ("1", "t", "T", "TRUE", "true", "True" and their
// false counterparts), plus "yes"/"y"/"on" and "no"/"n"/"off", case-insensitive.
//
// A value that is none of those is false, and says so once in the log. Every
// caller of this package switches off a check — config validation, the HAProxy
// reload, the apply after certificate issuance — so a typo must not be the thing
// that disables it. Carriage returns are stripped first: the env file is edited
// on Windows often enough that a trailing \r reaching strconv.ParseBool would
// turn "1" into an unparseable value.
func Enabled(name string) bool {
	raw := strings.TrimSpace(strings.ReplaceAll(os.Getenv(name), "\r", ""))
	if raw == "" {
		return false
	}
	if b, err := strconv.ParseBool(raw); err == nil {
		return b
	}
	switch strings.ToLower(raw) {
	case "yes", "y", "on":
		return true
	case "no", "n", "off":
		return false
	}
	if _, seen := warned.LoadOrStore(name, struct{}{}); !seen {
		log.Printf("envflag: %s=%q is not a boolean value — treating it as off", name, raw)
	}
	return false
}
