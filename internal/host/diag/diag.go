package diag

import (
	"context"
	"net"
	"os"
	"strings"
	"time"

	"github.com/easy-waf/easy-waf/internal/host/runner"
)

// Ping runs ping -c count host (unprivileged when permitted).
func Ping(ctx context.Context, host string, count int) (string, error) {
	host = strings.TrimSpace(host)
	if host == "" || (net.ParseIP(host) == nil && !isHostname(host)) {
		return "", errInvalid("invalid host")
	}
	if count <= 0 || count > 10 {
		count = 4
	}
	out, err := runner.Run(ctx, 30*time.Second, "/usr/bin/ping", "-c", itoa(count), "-W", "2", "--", host)
	return string(out), err
}

// Trace runs tracepath (or traceroute) to host.
func Trace(ctx context.Context, host string) (string, error) {
	host = strings.TrimSpace(host)
	if host == "" || (net.ParseIP(host) == nil && !isHostname(host)) {
		return "", errInvalid("invalid host")
	}
	bin := "/usr/bin/tracepath"
	if _, err := os.Stat(bin); err != nil {
		bin = "/usr/sbin/traceroute"
	}
	out, err := runner.Run(ctx, 60*time.Second, bin, "--", host)
	return string(out), err
}

func isHostname(s string) bool {
	if len(s) == 0 || len(s) > 253 || strings.HasPrefix(s, "-") {
		return false
	}
	for _, part := range strings.Split(s, ".") {
		if part == "" || len(part) > 63 {
			return false
		}
		for i, c := range part {
			ok := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-'
			if !ok {
				return false
			}
			if (i == 0 || i == len(part)-1) && c == '-' {
				return false
			}
		}
	}
	return true
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [12]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

type hostError string

func (e hostError) Error() string {
	return string(e)
}

func errInvalid(msg string) error {
	return hostError(msg)
}
