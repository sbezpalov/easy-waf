// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package blockedua

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/easy-waf/easy-waf/internal/config"
	"github.com/easy-waf/easy-waf/internal/ipbl"
	"github.com/easy-waf/easy-waf/internal/store"
)

// WriteMap writes non-empty patterns from DB to a HAProxy map file (one pattern per line, # comments stripped on read).
func WriteMap(ctx context.Context, st *store.Store, outPath string) error {
	if outPath == "" {
		return fmt.Errorf("blockedua: empty map path")
	}
	_ = os.MkdirAll(filepath.Dir(outPath), 0o750)

	rows, err := st.ListBlockedUserAgents(ctx)
	if err != nil {
		return err
	}
	patterns := make([]string, 0, len(rows))
	for _, e := range rows {
		patterns = append(patterns, e.Pattern)
	}
	lines := normalizePatterns(patterns)

	var b strings.Builder
	b.WriteString("# easy-waf blocked User-Agent substrings — generated; do not edit by hand\n")
	for _, ln := range lines {
		b.WriteString(ln)
		b.WriteByte('\n')
	}
	tmp := outPath + ".tmp"
	if err := os.WriteFile(tmp, []byte(b.String()), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, outPath)
}

// normalizePatterns trims, drops empty and comment lines, removes duplicates and
// sorts what is left.
//
// Deduplication matches what the ipbl/ipwl generators already do: the map file is
// regenerated from the database on every apply, so duplicate rows would emit
// duplicate lines that grow the file each time an operator re-adds a pattern.
func normalizePatterns(patterns []string) []string {
	seen := make(map[string]struct{}, len(patterns))
	out := make([]string, 0, len(patterns))
	for _, p := range patterns {
		p = strings.TrimSpace(p)
		if p == "" || strings.HasPrefix(p, "#") {
			continue
		}
		if _, dup := seen[p]; dup {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// MapPath resolves output path from settings.
func MapPath(g config.GlobalSettings, stateDir string) string {
	if g.BlockedUserAgentsMapPath != "" {
		return g.BlockedUserAgentsMapPath
	}
	return filepath.Join(stateDir, "haproxy", "blocked_ua.map")
}

// UseInRender is true when blocked-UA ACL should appear (enabled + non-empty map file).
func UseInRender(enabled bool, mapPath string) bool {
	if !enabled || mapPath == "" {
		return false
	}
	st, err := os.Stat(mapPath)
	if err != nil || st.Size() == 0 {
		return false
	}
	b, err := os.ReadFile(mapPath)
	if err != nil {
		return false
	}
	return ipbl.FileHasEntries(b)
}
