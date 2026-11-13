// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package hostd

import (
	"context"
	"os"
	"strings"
	"testing"
)

func writeGuard(t *testing.T) {
	t.Helper()
	if err := os.WriteFile(nftGuardPath, []byte("table inet easy_waf_guard\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func writeRules(t *testing.T) {
	t.Helper()
	if err := os.WriteFile(nftRulesPath, []byte("table inet easy_waf {\n}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestNftApplyReloadsGuardLast(t *testing.T) {
	m, _ := rollbackTestEnv(t)
	writeRules(t)
	writeGuard(t)
	d := &Dispatcher{Runner: m}
	if r := d.Dispatch(context.Background(), []string{"nft-apply"}); !r.OK {
		t.Fatal(r.Error)
	}
	want := "/usr/sbin/nft -f " + nftGuardPath
	if last := m.calls[len(m.calls)-1]; last != want {
		t.Fatalf("last call %q, want %q: %v", last, want, m.calls)
	}
}

func TestNftApplyFailsWhenGuardCannotBeReloaded(t *testing.T) {
	m, _ := rollbackTestEnv(t)
	writeRules(t)
	writeGuard(t)
	m.failOn["/usr/sbin/nft -f "+nftGuardPath] = true
	d := &Dispatcher{Runner: m}
	r := d.Dispatch(context.Background(), []string{"nft-apply"})
	if r.OK || !strings.Contains(r.Error, "firewall guard") {
		t.Fatalf("response %+v", r)
	}
}

// The operator runs the firewall: nothing to load, and no failure.
func TestNftApplyWithoutGuardFile(t *testing.T) {
	m, _ := rollbackTestEnv(t)
	writeRules(t)
	d := &Dispatcher{Runner: m}
	if r := d.Dispatch(context.Background(), []string{"nft-apply"}); !r.OK {
		t.Fatal(r.Error)
	}
	for _, c := range m.calls {
		if strings.Contains(c, "guard") {
			t.Fatalf("guard loaded though absent: %v", m.calls)
		}
	}
}

func TestRevertNftReloadsGuard(t *testing.T) {
	m, _ := rollbackTestEnv(t)
	writeRules(t)
	writeGuard(t)
	if _, err := beginConfirmedChange(context.Background(), m, "nft", testToken, nftRulesPath, nftRulesMode, 90); err != nil {
		t.Fatal(err)
	}
	if err := RunRevert("nft", testToken); err != nil {
		t.Fatal(err)
	}
	want := "/usr/sbin/nft -f " + nftGuardPath
	if last := m.calls[len(m.calls)-1]; last != want {
		t.Fatalf("last call %q, want %q", last, want)
	}
}
