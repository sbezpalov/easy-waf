// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package hostd

import (
	"strings"
	"testing"
)

func TestValidateNetplanYAMLAllowsNarrowConfiguration(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"ethernet": `network:
  version: 2
  renderer: networkd
  ethernets:
    eth0:
      dhcp4: true
`,
		"flow bridge": `{network: {version: 2, bridges: {br0: {interfaces: [eth0]}}}}`,
		"quoted keys": `"network":
  "version": 2
  "wifis": {}
`,
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if err := validateNetplanYAML([]byte(input)); err != nil {
				t.Fatalf("validateNetplanYAML() error = %v", err)
			}
		})
	}
}

func TestValidateNetplanYAMLRejectsUnsafeConfiguration(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"empty": "   \n",
		"multiple documents": `network:
  version: 2
  ethernets: {}
---
network:
  version: 2
  ethernets: {}
`,
		"duplicate key": `network:
  version: 2
  version: 2
  ethernets: {}
`,
		"alias": `network: &network
  version: 2
  ethernets: {}
copy: *network
`,
		"merge": `defaults: &defaults
  dhcp4: true
network:
  version: 2
  ethernets:
    eth0:
      <<: *defaults
`,
		"explicit tag": `network:
  version: !!int 2
  ethernets: {}
`,
		"unknown root": `network:
  version: 2
  ethernets: {}
extra: true
`,
		"unknown network key": `network:
  version: 2
  routes: []
  ethernets: {}
`,
		"quoted version": `network:
  version: "2"
  ethernets: {}
`,
		"no interfaces": `network:
  version: 2
`,
		"forbidden type": `network:
  version: 2
  ethernets:
    tun0:
      type: vxlan
`,
		"forbidden bare key": `network:
  version: 2
  tunnels: {}
`,
		"forbidden double quoted key": `network:
  version: 2
  "tunnels": {}
`,
		"forbidden single quoted key": `network:
  version: 2
  'openvswitch': {}
`,
		"forbidden flow key": `{network: {version: 2, ethernets: {eth0: {wireguard: {}}}}}`,
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if err := validateNetplanYAML([]byte(input)); err == nil {
				t.Fatal("validateNetplanYAML() accepted unsafe configuration")
			}
		})
	}
}

func TestValidateNetplanYAMLParserErrorDoesNotEchoInput(t *testing.T) {
	t.Parallel()
	const secret = "do-not-return-this-secret"
	err := validateNetplanYAML([]byte("network: [" + secret))
	if err == nil {
		t.Fatal("validateNetplanYAML() accepted invalid yaml")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("parser error leaked staged content: %v", err)
	}
}
