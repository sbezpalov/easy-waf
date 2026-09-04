// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package profiles

import (
	"testing"

	"github.com/easy-waf/easy-waf/internal/config"
)

func TestApplyModeAndDetect(t *testing.T) {
	var sec config.ApplicationSecurity
	ApplyMode(&sec, ModeFull)
	if DetectMode(sec) != ModeFull {
		t.Fatalf("full: got %s", DetectMode(sec))
	}
	ApplyMode(&sec, ModeReverseProxyOnly)
	if DetectMode(sec) != ModeReverseProxyOnly {
		t.Fatalf("rpo: got %s", DetectMode(sec))
	}
	ApplyMode(&sec, ModeBalanced)
	if DetectMode(sec) != ModeBalanced {
		t.Fatalf("balanced: got %s", DetectMode(sec))
	}
	ApplyMode(&sec, ModeTrustedLAN)
	if DetectMode(sec) != ModeTrustedLAN {
		t.Fatalf("trusted-lan: got %s", DetectMode(sec))
	}
	sec.BasicWAFEnabled = false
	sec.MethodFilterEnabled = true
	sec.GeoIPEnabled = true
	if DetectMode(sec) != ModeCustom {
		t.Fatalf("expected custom, got %s", DetectMode(sec))
	}
}
