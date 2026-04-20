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
