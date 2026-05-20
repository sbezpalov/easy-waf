package journal

import (
	"context"
	"strconv"
	"strings"

	"github.com/easy-waf/easy-waf/internal/host/runner"
)

// Query parameters for journalctl.
type Query struct {
	Unit     string
	Lines    int
	Since    string
	Until    string
	Priority string
}

// Read returns journal lines via the privileged helper.
func Read(ctx context.Context, q Query) (string, error) {
	args := []string{"journal", "--no-pager"}
	if q.Lines > 0 {
		args = append(args, "-n", strconv.Itoa(q.Lines))
	} else {
		args = append(args, "-n", "200")
	}
	if u := strings.TrimSpace(q.Unit); u != "" {
		args = append(args, "-u", u)
	}
	if s := strings.TrimSpace(q.Since); s != "" {
		args = append(args, "--since", s)
	}
	if u := strings.TrimSpace(q.Until); u != "" {
		args = append(args, "--until", u)
	}
	if p := strings.TrimSpace(q.Priority); p != "" {
		args = append(args, "-p", p)
	}
	out, err := runner.Privileged(ctx, args...)
	return string(out), err
}
