// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package journal

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/easy-waf/easy-waf/internal/blocklog"
	"github.com/easy-waf/easy-waf/internal/commandoutput"
	"github.com/easy-waf/easy-waf/internal/host/hostspec"
	"github.com/easy-waf/easy-waf/internal/host/runner"
	"github.com/easy-waf/easy-waf/internal/host/systemdallow"
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
	u := strings.TrimSpace(q.Unit)
	if u == "" {
		return nil, fmt.Errorf("unit required")
	}
	if !strings.HasSuffix(u, ".service") {
		u += ".service"
	}
	if !systemdallow.AllowedJournalUnit(u) {
		return nil, fmt.Errorf("unit not allowed")
	}
	args := []string{"journal", "--no-pager", "-n", strconv.Itoa(lines), "-u", u, "--output", "short-iso"}
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
	if err := hostspec.ValidateJournalArgs(args[1:]); err != nil {
		return nil, err
	}
	return args, nil
}

// BlockedLines caps one ReadBlocked call.
const BlockedLines = 5000

// PolicyLines bounds the JSON journal output even when many rules match.
const PolicyLines = 1000

// Sample contains complete JSON lines. Truncated means the query hit a
// line limit or had to discard older rows to fit the broker output budget.
type Sample struct {
	JSON      string
	Truncated bool
}

// ReadBlocked returns haproxy.service journal entries since the given time whose
// message looks refused by the edge, as journalctl JSON lines.
func ReadBlocked(ctx context.Context, since time.Time, lines int) (Sample, error) {
	return readHAProxyJournal(ctx, since, lines, BlockedLines, blocklog.JournalGrepBlocked, runner.Privileged)
}

// ReadPolicy returns HAProxy entries with at least one publication rule match.
func ReadPolicy(ctx context.Context, since time.Time, lines int) (Sample, error) {
	return readHAProxyJournal(ctx, since, lines, PolicyLines, blocklog.JournalGrepPolicy, runner.Privileged)
}

func readHAProxyJournal(ctx context.Context, since time.Time, lines, maxLines int, pattern string, run func(context.Context, ...string) ([]byte, error)) (Sample, error) {
	if lines <= 0 || lines > maxLines {
		lines = maxLines
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	cutoff := since.UTC().Format("2006-01-02 15:04:05.000000 UTC")
	legacyCutoff := false
	reduced := false
	for {
		args, err := buildHAProxyJournalArgs(cutoff, lines, pattern)
		if err != nil {
			return Sample{}, err
		}
		out, err := run(ctx, args...)
		if ctxErr := ctx.Err(); ctxErr != nil {
			return Sample{}, ctxErr
		}
		switch {
		case err == nil:
			data := string(out)
			count := strings.Count(strings.TrimSuffix(data, "\n"), "\n")
			return Sample{JSON: data, Truncated: reduced || (data != "" && count+1 >= lines)}, nil
		case len(out) == 0 && err.Error() == "exit code 1":
			// journalctl --grep exits 1 silently when nothing matches.
			return Sample{}, nil
		case !legacyCutoff && len(out) == 0 && err.Error() == "journal: invalid --since":
			// The API can restart before the broker during a package upgrade.
			// Retry with the local timestamp syntax accepted by older brokers.
			cutoff = since.Local().Format("2006-01-02 15:04:05")
			legacyCutoff = true
		case errors.Is(err, commandoutput.ErrLimit) && lines > 1:
			// The failed output may end mid-record. Requery the newest
			// entries with a smaller row budget to get a complete sample.
			lines /= 2
			reduced = true
		default:
			return Sample{}, err
		}
	}
}

func buildHAProxyJournalArgs(cutoff string, lines int, pattern string) ([]string, error) {
	args := []string{"journal", "--no-pager", "-n", strconv.Itoa(lines), "-u", "haproxy.service",
		"--since", cutoff,
		"--grep", pattern, "--output", "json"}
	if err := hostspec.ValidateJournalArgs(args[1:]); err != nil {
		return nil, err
	}
	return args, nil
}
