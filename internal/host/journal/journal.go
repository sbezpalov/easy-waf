package journal

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/easy-waf/easy-waf/internal/host/runner"
	hostsystemd "github.com/easy-waf/easy-waf/internal/host/systemd"
)

// Query parameters for journalctl.
type Query struct {
	Unit     string
	Lines    int
	Since    string
	Until    string
	Priority string
}

var (
	journalSinceRE = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}( [0-9]{2}:[0-9]{2}(:[0-9]{2})?)?$|^[0-9]+[smhdw]?$`)
	journalOutput  = map[string]struct{}{
		"short": {}, "short-iso": {}, "short-precise": {}, "short-iso-precise": {},
		"verbose": {}, "export": {}, "json": {}, "json-pretty": {}, "json-sse": {},
		"json-seq": {}, "cat": {},
	}
	journalPriority = map[string]struct{}{
		"0": {}, "1": {}, "2": {}, "3": {}, "4": {}, "5": {}, "6": {}, "7": {},
		"emerg": {}, "alert": {}, "crit": {}, "err": {}, "warning": {}, "notice": {}, "info": {}, "debug": {},
	}
)

// Read returns journal lines via the privileged helper (allowlisted flags only).
func Read(ctx context.Context, q Query) (string, error) {
	args, err := buildJournalArgs(q)
	if err != nil {
		return "", err
	}
	out, err := runner.Privileged(ctx, args...)
	return string(out), err
}

func buildJournalArgs(q Query) ([]string, error) {
	lines := q.Lines
	if lines <= 0 {
		lines = 200
	}
	if lines > 2000 {
		lines = 2000
	}
	args := []string{"journal", "--no-pager", "-n", strconv.Itoa(lines)}

	if u := strings.TrimSpace(q.Unit); u != "" {
		if !strings.HasSuffix(u, ".service") {
			u += ".service"
		}
		if !hostsystemd.AllowedUnit(u) {
			return nil, fmt.Errorf("unit not allowed")
		}
		args = append(args, "-u", u)
	}
	if s := strings.TrimSpace(q.Since); s != "" {
		if !journalSinceRE.MatchString(s) {
			return nil, fmt.Errorf("invalid since")
		}
		args = append(args, "--since", s)
	}
	if u := strings.TrimSpace(q.Until); u != "" {
		if !journalSinceRE.MatchString(u) {
			return nil, fmt.Errorf("invalid until")
		}
		args = append(args, "--until", u)
	}
	if p := strings.TrimSpace(q.Priority); p != "" {
		if _, ok := journalPriority[strings.ToLower(p)]; !ok {
			return nil, fmt.Errorf("invalid priority")
		}
		args = append(args, "-p", p)
	}
	return args, nil
}
