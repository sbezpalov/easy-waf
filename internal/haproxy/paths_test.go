package haproxy

import (
	"path/filepath"
	"testing"
)

func TestLiveCfgPath(t *testing.T) {
	sd := filepath.FromSlash("/var/lib/easy-waf")
	wantDefault := filepath.Join(sd, "haproxy", "haproxy.cfg")
	if got := LiveCfgPath(sd, ""); got != wantDefault {
		t.Fatalf("empty settings path: got %q want %q", got, wantDefault)
	}
	custom := filepath.FromSlash("/etc/haproxy/haproxy.cfg")
	if got := LiveCfgPath(sd, custom); got != custom {
		t.Fatalf("custom path: got %q want %q", got, custom)
	}
	if got := LiveCfgPath(sd, "  "+custom+"  "); got != custom {
		t.Fatalf("trim+clean: got %q want %q", got, custom)
	}
}
