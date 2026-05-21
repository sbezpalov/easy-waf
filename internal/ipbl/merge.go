package ipbl

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/easy-waf/easy-waf/internal/config"
	"github.com/easy-waf/easy-waf/internal/store"
)

// SyncResult describes a merge operation for observability.
type SyncResult struct {
	LocalLines    int
	ExternalLines int
	TotalLines    int
	MapPath       string
	// AllCIDRs is the sorted unique CIDR/IP lines written to the blacklist map (GeoIP batch uses this).
	AllCIDRs []string `json:"all_cidrs,omitempty"`
}

// SyncAndWrite merges local DB entries and optional external HTTP lists into a HAProxy-compatible text file
// (one IPv4/IPv6 or CIDR per line). Comments with # are stripped from downloads.
func SyncAndWrite(ctx context.Context, st *store.Store, g config.GlobalSettings, stateDir string) (SyncResult, error) {
	outPath := g.IPBlacklistMapPath
	if outPath == "" {
		outPath = filepath.Join(stateDir, "haproxy", "ip_blacklist.map")
	}
	_ = os.MkdirAll(filepath.Dir(outPath), 0o750)

	local, err := st.ListIPBLLocal(ctx)
	if err != nil {
		return SyncResult{}, err
	}
	set := map[string]struct{}{}
	for _, e := range local {
		if !e.Enabled {
			continue
		}
		line := strings.TrimSpace(e.CIDR)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if err := validateCIDRLine(line); err != nil {
			continue
		}
		set[line] = struct{}{}
	}
	localN := len(set)

	extN := 0
	if g.IPBLExternalEnabled {
		srcs, err := st.ListIPBLExternalSources(ctx)
		if err != nil {
			return SyncResult{}, err
		}
		client := newIPBLHTTPClient(g.IPBLAllowPrivateFetch)
		for _, src := range srcs {
			if !src.Enabled {
				continue
			}
			lines, ferr := fetchPlainList(ctx, client, src.URL, g.IPBLAllowPrivateFetch)
			if ferr != nil {
				_ = st.TouchIPBLSourceFetch(ctx, src.ID, time.Now().UTC(), ferr.Error())
				continue
			}
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
				if err := validateCIDRLine(line); err != nil {
					continue
				}
				set[line] = struct{}{}
				extN++
			}
			_ = st.TouchIPBLSourceFetch(ctx, src.ID, time.Now().UTC(), "")
		}
	}

	var lines []string
	for k := range set {
		lines = append(lines, k)
	}
	sort.Strings(lines)

	var b strings.Builder
	b.WriteString("# easy-waf ip blacklist — generated; do not edit by hand\n")
	for _, ln := range lines {
		b.WriteString(ln)
		b.WriteByte('\n')
	}

	tmp := outPath + ".tmp"
	if err := os.WriteFile(tmp, []byte(b.String()), 0o640); err != nil {
		return SyncResult{}, err
	}
	if err := os.Rename(tmp, outPath); err != nil {
		return SyncResult{}, err
	}

	return SyncResult{
		LocalLines:    localN,
		ExternalLines: extN,
		TotalLines:    len(lines),
		MapPath:       outPath,
		AllCIDRs:      append([]string(nil), lines...),
	}, nil
}

// CollectBlacklistCIDRs returns the merged blacklist CIDR set without writing the map (tests / tooling).
// It does not update external source fetch metadata (use SyncAndWrite for production sync).
func CollectBlacklistCIDRs(ctx context.Context, st *store.Store, g config.GlobalSettings) ([]string, error) {
	set := map[string]struct{}{}
	local, err := st.ListIPBLLocal(ctx)
	if err != nil {
		return nil, err
	}
	for _, e := range local {
		if !e.Enabled {
			continue
		}
		line := strings.TrimSpace(e.CIDR)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if err := validateCIDRLine(line); err != nil {
			continue
		}
		set[line] = struct{}{}
	}
	if g.IPBLExternalEnabled {
		srcs, err := st.ListIPBLExternalSources(ctx)
		if err != nil {
			return nil, err
		}
		client := newIPBLHTTPClient(g.IPBLAllowPrivateFetch)
		for _, src := range srcs {
			if !src.Enabled {
				continue
			}
			lines, ferr := fetchPlainList(ctx, client, src.URL, g.IPBLAllowPrivateFetch)
			if ferr != nil {
				continue
			}
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
				if err := validateCIDRLine(line); err != nil {
					continue
				}
				set[line] = struct{}{}
			}
		}
	}
	var lines []string
	for k := range set {
		lines = append(lines, k)
	}
	sort.Strings(lines)
	return lines, nil
}

// FileHasEntries returns true if data contains at least one non-comment line (used before enabling HAProxy ACL).
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

func fetchPlainList(ctx context.Context, client *http.Client, u string, allowPrivate bool) ([]string, error) {
	parsed, err := url.Parse(u)
	if err != nil {
		return nil, err
	}
	if err := validateIPBLFetchURL(ctx, parsed, allowPrivate); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("http %d", resp.StatusCode)
	}
	var lines []string
	sc := bufio.NewScanner(resp.Body)
	const maxLine = 1 << 20
	buf := make([]byte, 0, 64*1024)
	sc.Buffer(buf, maxLine)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lines = append(lines, line)
	}
	return lines, sc.Err()
}
