// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package haproxy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGoldenReverseProxyOnlyMinimalRules(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("testdata", "golden", "app-reverse-proxy-only.cfg"))
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	if strings.Contains(s, "filter spoe") {
		t.Fatal("reverse-proxy-only golden must not load SPOE when no app uses CrowdSec")
	}
	if strings.Contains(s, "stick-table") {
		t.Fatal("reverse-proxy-only app must not use stick-table")
	}
	if strings.Contains(s, "http-request deny deny_status 403 if app_dbg1_host") {
		t.Fatal("reverse-proxy-only app must not emit per-app 403 denies")
	}
	if !strings.Contains(s, "use_backend bk_debug_example_com if app_dbg1_host") {
		t.Fatal("expected use_backend for debug host")
	}
}

func TestGoldenMixedAppsCrowdSecFilter(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("testdata", "golden", "mixed-apps.cfg"))
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	if !strings.Contains(s, "filter spoe") {
		t.Fatal("mixed-apps: at least one app has CrowdSec → SPOE filter must be present")
	}
	if !strings.Contains(s, "http-request send-spoe-group") {
		t.Fatal("expected send-spoe-group for CrowdSec-enabled apps")
	}
}
