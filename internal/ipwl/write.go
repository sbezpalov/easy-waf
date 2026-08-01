package ipwl

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/easy-waf/easy-waf/internal/config"
	"github.com/easy-waf/easy-waf/internal/store"
)

// WriteLocalMap writes ipwl_local rows to a HAProxy-compatible map file (one IPv4/IPv6 or CIDR per line).
func WriteLocalMap(ctx context.Context, st *store.Store, outPath string) error {
	if outPath == "" {
		return fmt.Errorf("ipwl: empty map path")
	}
	_ = os.MkdirAll(filepath.Dir(outPath), 0o750)

	rows, err := st.ListIPWLLocal(ctx)
	if err != nil {
		return err
	}
	lines := make([]string, 0, len(rows))
	for _, e := range rows {
		line := strings.TrimSpace(e.CIDR)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if err := validateCIDRLine(line); err != nil {
			continue
		}
		lines = append(lines, line)
	}
	sort.Strings(lines)

	var b strings.Builder
	b.WriteString("# easy-waf ip allowlist — generated; do not edit by hand\n")
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

func validateCIDRLine(s string) error {
	if strings.Contains(s, "/") {
		_, _, err := net.ParseCIDR(s)
		return err
	}
	if ip := net.ParseIP(s); ip == nil {
		return fmt.Errorf("invalid ip")
	}
	return nil
}

// FileHasEntries returns true if data contains at least one non-comment line.
func FileHasEntries(data []byte) bool {
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		return true
	}
	return false
}

// UseInRender is true when allowlist should appear in HAProxy config (enabled + non-empty map file).
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
	return FileHasEntries(b)
}

// MapPath resolves the output path from settings with stateDir fallback.
func MapPath(g config.GlobalSettings, stateDir string) string {
	if g.IPAllowlistMapPath != "" {
		return g.IPAllowlistMapPath
	}
	return filepath.Join(stateDir, "haproxy", "ip_allowlist.map")
}
