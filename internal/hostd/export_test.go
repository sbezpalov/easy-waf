package hostd

import (
	"os"
	"testing"
)

// TestMain enables unix-socket tests when `go test` runs as a user other than easy-waf.
func TestMain(m *testing.M) {
	SetBypassPeerCheckForTest(true)
	os.Exit(m.Run())
}
