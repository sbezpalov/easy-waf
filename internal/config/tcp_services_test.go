// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package config

import "testing"

func TestValidateTCPServices(t *testing.T) {
	ok := []TCPService{{Name: "mqtt", ListenPort: 8883, BackendHost: "10.0.0.1", BackendPort: 1883, AllowCIDRs: []string{"192.168.0.0/16"}}}
	if err := validateTCPServices(ok); err != nil {
		t.Fatal(err)
	}
	bad := map[string][]TCPService{
		"name":     {{Name: "MQTT x", ListenPort: 8883, BackendHost: "h", BackendPort: 1}},
		"reserved": {{Name: "a", ListenPort: 443, BackendHost: "h", BackendPort: 1}},
		"dup port": {{Name: "a", ListenPort: 1000, BackendHost: "h", BackendPort: 1}, {Name: "b", ListenPort: 1000, BackendHost: "h", BackendPort: 1}},
		"dup name": {{Name: "a", ListenPort: 1000, BackendHost: "h", BackendPort: 1}, {Name: "a", ListenPort: 1001, BackendHost: "h", BackendPort: 1}},
		"host":     {{Name: "a", ListenPort: 1000, BackendHost: "h\n\tserver x", BackendPort: 1}},
		"allow":    {{Name: "a", ListenPort: 1000, BackendHost: "h", BackendPort: 1, AllowCIDRs: []string{"1.2.3.4 } || {"}}},
	}
	for name, list := range bad {
		if err := validateTCPServices(list); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestValidateTLSPassthrough(t *testing.T) {
	ok := []TLSPassthrough{
		{ServerName: "vpn.example.com", BackendHost: "10.0.0.5", BackendPort: 443, AllowCIDRs: []string{"192.168.0.0/16"}},
		{ServerName: "*.k8s.example.com", BackendHost: "ingress.lan", BackendPort: 443, SendProxy: true},
	}
	if err := validateTLSPassthrough(ok); err != nil {
		t.Fatal(err)
	}
	bad := map[string][]TLSPassthrough{
		"upper":    {{ServerName: "VPN.example.com", BackendHost: "h", BackendPort: 1}},
		"no dot":   {{ServerName: "vpn", BackendHost: "h", BackendPort: 1}},
		"inject":   {{ServerName: "a.com } || {", BackendHost: "h", BackendPort: 1}},
		"mid star": {{ServerName: "a.*.com", BackendHost: "h", BackendPort: 1}},
		"dup":      {{ServerName: "a.com", BackendHost: "h", BackendPort: 1}, {ServerName: "a.com", BackendHost: "h", BackendPort: 2}},
		"port":     {{ServerName: "a.com", BackendHost: "h", BackendPort: 0}},
		"host":     {{ServerName: "a.com", BackendHost: "h\n\tserver x", BackendPort: 1}},
		"allow":    {{ServerName: "a.com", BackendHost: "h", BackendPort: 1, AllowCIDRs: []string{"x"}}},
	}
	for name, list := range bad {
		if err := validateTLSPassthrough(list); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if !TLSPassthroughMatches("*.k8s.example.com", "a.k8s.example.com") || TLSPassthroughMatches("*.k8s.example.com", "k8s.example.com") ||
		!TLSPassthroughMatches("a.com", "a.com") || TLSPassthroughMatches("a.com", "b.a.com") {
		t.Fatal("TLSPassthroughMatches")
	}
}
