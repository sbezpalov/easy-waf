// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package hostd

import "testing"

func TestValidateNetplanYAMLAllowlist(t *testing.T) {
	ok := []byte(`network:
  version: 2
  ethernets:
    eth0:
      dhcp4: true
`)
	if err := validateNetplanYAML(ok); err != nil {
		t.Fatal(err)
	}
	bad := []byte(`network:
  version: 2
  tunnels:
    tun0:
      mode: gre
`)
	if err := validateNetplanYAML(bad); err == nil {
		t.Fatal("expected tunnels rejected")
	}
	empty := []byte("   \n")
	if err := validateNetplanYAML(empty); err == nil {
		t.Fatal("expected empty rejected")
	}
}
