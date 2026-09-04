// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"testing"

	"github.com/easy-waf/easy-waf/internal/config"
)

func TestValidateAppHostnames_OK(t *testing.T) {
	app := &config.Application{
		PublicHost:  "home.example.com",
		BackendHost: "192.168.1.10",
		BackendPort: 8123,
	}
	if err := validateAppHostnames(app); err != nil {
		t.Fatal(err)
	}
}

func TestValidateAppHostnames_InvalidPublic(t *testing.T) {
	app := &config.Application{
		PublicHost:  "evil;inject",
		BackendHost: "10.0.0.1",
		BackendPort: 80,
	}
	if err := validateAppHostnames(app); err == nil {
		t.Fatal("expected error")
	}
}

func TestValidateAppHostnames_InvalidPort(t *testing.T) {
	app := &config.Application{
		PublicHost:  "ok.example.com",
		BackendHost: "10.0.0.1",
		BackendPort: 0,
	}
	if err := validateAppHostnames(app); err == nil {
		t.Fatal("expected error")
	}
}

func TestValidateAppHostnames_rejectsHAProxyInjection(t *testing.T) {
	base := config.Application{
		ID: "app-1", Name: "safe", PublicHost: "app.example.test",
		BackendHost: "192.0.2.10", BackendPort: 8080,
	}
	cases := []config.Application{
		func() config.Application { a := base; a.Name = "safe\nbackend injected"; return a }(),
		func() config.Application { a := base; a.HealthPath = "/ok\nserver evil"; return a }(),
		func() config.Application {
			a := base
			a.RestrictedPaths = []config.RestrictedPath{{PathPrefix: "/admin\nhttp-request allow", AllowedCIDRs: []string{"10.0.0.0/8"}}}
			return a
		}(),
		func() config.Application {
			a := base
			a.RestrictedPaths = []config.RestrictedPath{{PathPrefix: "/admin", AllowedCIDRs: []string{"10.0.0.0/8\nhttp-request allow"}}}
			return a
		}(),
	}
	for i := range cases {
		if err := validateAppHostnames(&cases[i]); err == nil {
			t.Fatalf("case %d: expected rejection", i)
		}
	}
}
