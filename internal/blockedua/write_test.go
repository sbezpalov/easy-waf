package blockedua

import (
	"path/filepath"
	"testing"

	"github.com/easy-waf/easy-waf/internal/config"
)

func TestMapPath(t *testing.T) {
	g := config.GlobalSettings{
		BlockedUserAgentsMapPath: "/custom/path/ua.map",
	}
	if got := MapPath(g, "/var/lib/easy-waf"); got != "/custom/path/ua.map" {
		t.Errorf("MapPath custom = %q; want /custom/path/ua.map", got)
	}

	gDefault := config.GlobalSettings{}
	wantDefault := filepath.Join("/var/lib/easy-waf", "haproxy", "blocked_ua.map")
	if got := MapPath(gDefault, "/var/lib/easy-waf"); got != wantDefault {
		t.Errorf("MapPath default = %q; want %q", got, wantDefault)
	}
}

func TestUseInRender(t *testing.T) {
	if UseInRender(false, "/any/path") {
		t.Errorf("expected UseInRender(false) = false")
	}
	if UseInRender(true, "") {
		t.Errorf("expected UseInRender(true, \"\") = false")
	}
	if UseInRender(true, "/nonexistent/path/map.txt") {
		t.Errorf("expected UseInRender with non-existent file = false")
	}
}
