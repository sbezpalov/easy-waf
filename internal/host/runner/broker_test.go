package runner

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
)

func TestPrivileged_noSocket(t *testing.T) {
	t.Setenv("EASY_WAF_HOSTD_SOCKET", filepath.Join(t.TempDir(), "missing.sock"))
	_, err := Privileged(context.Background(), "nft-list")
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "unavailable") {
		t.Fatalf("got %v", err)
	}
}
