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
