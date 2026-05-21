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

func TestDispatch_fail2banReject(t *testing.T) {
	d := &Dispatcher{Runner: &mockRunner{}}
	for _, argv := range [][]string{
		{"fail2ban", "reload"},
		{"fail2ban", "set", "sshd", "banip", "1.2.3.4"},
		{"fail2ban", "status", "../evil"},
		{"fail2ban", "set", "sshd", "unbanip", "not-ip"},
	} {
		r := d.Dispatch(context.Background(), argv)
		if r.OK {
			t.Fatalf("expected reject: %v", argv)
		}
		if !strings.Contains(r.Error, "not allowed") {
			t.Fatalf("%v: %q", argv, r.Error)
		}
	}
}

func TestDispatch_fail2banAllowed(t *testing.T) {
	if resolveFail2banClient() == "" {
		t.Skip("fail2ban-client not installed")
	}
	m := &mockRunner{}
	d := &Dispatcher{Runner: m}
	for _, argv := range [][]string{
		{"fail2ban", "ping"},
		{"fail2ban", "status"},
		{"fail2ban", "status", "sshd"},
		{"fail2ban", "set", "sshd", "unbanip", "203.0.113.1"},
	} {
		r := d.Dispatch(context.Background(), argv)
		if !r.OK {
			t.Fatalf("%v: %s", argv, r.Error)
		}
		if m.lastName == "" {
			t.Fatalf("%v: runner not called", argv)
		}
	}
}
