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
	var lines []string
	for _, e := range rows {
		p := strings.TrimSpace(e.Pattern)
		if p == "" || strings.HasPrefix(p, "#") {
			continue
		}
		lines = append(lines, p)
	}
	sort.Strings(lines)

	var b strings.Builder
	b.WriteString("# easy-waf blocked User-Agent substrings — generated; do not edit by hand\n")
	for _, ln := range lines {
		b.WriteString(ln)
		b.WriteByte('\n')
	}
	tmp := outPath + ".tmp"
	if err := os.WriteFile(tmp, []byte(b.String()), 0o640); err != nil {
		return err
	}
	return os.Rename(tmp, outPath)
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
