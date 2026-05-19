package fail2ban

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestClient_Overview_pingAndJails(t *testing.T) {
	calls := 0
	c := &Client{
		Bin: "/usr/bin/fail2ban-client",
		Run: func(ctx context.Context, bin string, args ...string) ([]byte, error) {
			calls++
			switch strings.Join(args, " ") {
			case "ping":
				return []byte("Server replied: pong\n"), nil
			case "status":
				return []byte("` - Jail list:\tsshd\n"), nil
			case "status sshd":
				return []byte("` - Banned IP list:\t1.2.3.4\n"), nil
			default:
				return nil, errors.New("unexpected: " + strings.Join(args, " "))
			}
		},
	}
	ov, err := c.Overview(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !ov.Status.Running {
		t.Fatalf("status: %+v", ov.Status)
	}
	if len(ov.Jails) != 1 || ov.Jails[0].Name != "sshd" || len(ov.Jails[0].BannedIPs) != 1 {
		t.Fatalf("jails: %+v", ov.Jails)
	}
	if calls < 3 {
		t.Fatalf("expected >=3 calls, got %d", calls)
	}
}

func TestClient_UnbanIP_validation(t *testing.T) {
	c := &Client{Bin: "/bin/fail2ban-client", Run: execRunner}
	err := c.UnbanIP(context.Background(), "../evil", "1.2.3.4")
	if !errors.Is(err, ErrInvalidJail) {
		t.Fatalf("jail: %v", err)
	}
	err = c.UnbanIP(context.Background(), "sshd", "not-ip")
	if !errors.Is(err, ErrInvalidIP) {
		t.Fatalf("ip: %v", err)
	}
}
