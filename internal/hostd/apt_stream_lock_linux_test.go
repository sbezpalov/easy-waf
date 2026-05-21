//go:build linux

package hostd

import (
	"context"
	"io"
	"strings"
	"testing"
)

func TestDispatchAptUpgradeStream_dpkgLockHint(t *testing.T) {
	resetAptUpgradeState()
	SetAptUpgradeStreamHookForTest(func(ctx context.Context, emit func(string) error) (int, error) {
		return 0, nil
	})
	dpkgLockBusyHook = func() bool { return true }
	defer func() {
		dpkgLockBusyHook = nil
		resetAptUpgradeState()
	}()

	pr, pw := io.Pipe()
	go func() {
		dispatchAptUpgradeStream(pw)
		_ = pw.Close()
	}()
	events := readStreamEvents(t, pr)
	found := false
	for _, ev := range events {
		if ev.Type == "line" && strings.Contains(ev.Data, "apt is locked") {
			found = true
		}
	}
	if !found {
		t.Fatalf("lock hint missing: %+v", events)
	}
}
