package hostd

import (
	"context"
	"strings"
	"testing"
)

type mockRunner struct {
	lastName string
	lastArgs []string
}

func (m *mockRunner) Run(ctx context.Context, name string, args ...string) ([]byte, []byte, int, error) {
	m.lastName = name
	m.lastArgs = args
	if name == "systemctl" && len(args) >= 2 && args[0] == "reboot" {
		return nil, nil, 0, nil
	}
	if name == "/usr/sbin/nft" {
		return []byte("table inet x\n"), nil, 0, nil
	}
	return []byte("ok"), nil, 0, nil
}

func TestDispatch_unknownOp(t *testing.T) {
	d := &Dispatcher{Runner: &mockRunner{}}
	r := d.Dispatch(context.Background(), []string{"evil-cmd"})
	if r.OK {
		t.Fatal("expected reject")
	}
	if !strings.Contains(r.Error, "unknown") {
		t.Fatalf("got %q", r.Error)
	}
}

func TestDispatch_systemctlReject(t *testing.T) {
	d := &Dispatcher{Runner: &mockRunner{}}
	r := d.Dispatch(context.Background(), []string{"systemctl", "mask", "ssh.service"})
	if r.OK {
		t.Fatal("ssh not allowed")
	}
	r = d.Dispatch(context.Background(), []string{"systemctl", "restart", "haproxy.service"})
	if !r.OK {
		t.Fatalf("haproxy restart: %v", r.Error)
	}
}

func TestDispatch_userdelRoot(t *testing.T) {
	d := &Dispatcher{Runner: &mockRunner{}}
	r := d.Dispatch(context.Background(), []string{"userdel", "root"})
	if r.OK {
		t.Fatal("root protected")
	}
}

func TestDispatch_nftList(t *testing.T) {
	m := &mockRunner{}
	d := &Dispatcher{Runner: m}
	r := d.Dispatch(context.Background(), []string{"nft-list"})
	if !r.OK {
		t.Fatal(r.Error)
	}
	if m.lastName != "/usr/sbin/nft" || m.lastArgs[0] != "list" {
		t.Fatalf("got %s %v", m.lastName, m.lastArgs)
	}
}

func TestDispatch_invalidStagedPath(t *testing.T) {
	d := &Dispatcher{Runner: &mockRunner{}}
	r := d.Dispatch(context.Background(), []string{"netplan-apply-confirm", "/etc/passwd", "90", "abcdef0123456789abcdef0123456789"})
	if r.OK {
		t.Fatal("path rejected")
	}
}

func TestDispatch_journalBadFlag(t *testing.T) {
	d := &Dispatcher{Runner: &mockRunner{}}
	r := d.Dispatch(context.Background(), []string{"journal", "--follow"})
	if r.OK {
		t.Fatal("flag rejected")
	}
}
