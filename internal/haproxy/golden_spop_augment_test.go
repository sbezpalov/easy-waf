// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package haproxy

import (
	"bytes"
	"testing"
)

func TestRewriteStatsSocketPathForHAProxyCheck(t *testing.T) {
	raw := []byte("global\n\tstats socket rel/path/sock mode 660 level admin\n")
	got := string(rewriteStatsSocketPathForHAProxyCheck(raw, "/run/abs.sock"))
	want := "global\n\tstats socket /run/abs.sock mode 660 level admin\n"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestAugmentGoldenHAProxyCfgForHaproxyCheck_idempotent(t *testing.T) {
	raw := []byte("frontend fe\n\tbind :80\n")
	once := augmentGoldenHAProxyCfgForHaproxyCheck(raw)
	if !bytes.Contains(once, []byte("backend crowdsec-socket")) {
		t.Fatal("expected SPOP backend appended")
	}
	twice := augmentGoldenHAProxyCfgForHaproxyCheck(once)
	if !bytes.Equal(once, twice) {
		t.Fatal("expected idempotent augment")
	}
}
