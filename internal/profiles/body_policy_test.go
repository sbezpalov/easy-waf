// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package profiles

import (
	"testing"

	"github.com/easy-waf/easy-waf/internal/config"
)

func TestBodyPolicy(t *testing.T) {
	limit, off := int64(1<<20), int64(0)
	yes, no := true, false
	php := All()[PHPApp]
	balanced := All()[Balanced]

	for name, tc := range map[string]struct {
		profile   Profile
		sec       config.ApplicationSecurity
		wantMax   int64
		wantBlock bool
	}{
		"profile default is off":     {profile: balanced},
		"php-app turns both on":      {profile: php, wantMax: 32 << 20, wantBlock: true},
		"app raises the limit":       {profile: php, sec: config.ApplicationSecurity{MaxBodyBytesOverride: &limit}, wantMax: limit, wantBlock: true},
		"app removes the limit":      {profile: php, sec: config.ApplicationSecurity{MaxBodyBytesOverride: &off}, wantBlock: true},
		"app allows multipart":       {profile: php, sec: config.ApplicationSecurity{BlockMultipartOverride: &no}, wantMax: 32 << 20},
		"app blocks on open profile": {profile: balanced, sec: config.ApplicationSecurity{BlockMultipartOverride: &yes}, wantBlock: true},
	} {
		t.Run(name, func(t *testing.T) {
			gotMax, gotBlock := tc.profile.BodyPolicy(tc.sec)
			if gotMax != tc.wantMax || gotBlock != tc.wantBlock {
				t.Fatalf("got (%d, %v), want (%d, %v)", gotMax, gotBlock, tc.wantMax, tc.wantBlock)
			}
		})
	}
}

// An upgrade must not start rejecting uploads on an application nobody touched.
func TestOnlyPHPAppRestrictsBodiesByDefault(t *testing.T) {
	for name, p := range All() {
		if name == PHPApp {
			continue
		}
		if p.MaxBodyBytes != 0 || p.BlockMultipart {
			t.Errorf("profile %s restricts bodies: %d, %v", name, p.MaxBodyBytes, p.BlockMultipart)
		}
	}
}

func TestPHPAppIsResolvable(t *testing.T) {
	p, err := Resolve("php-app")

	if err != nil {
		t.Fatal(err)
	}
	if p.Name != PHPApp || len(p.BlockPaths) == 0 {
		t.Fatalf("profile %+v", p)
	}
}
