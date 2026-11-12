// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package ipbl

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/easy-waf/easy-waf/internal/apply"
	"github.com/easy-waf/easy-waf/internal/config"
	"github.com/easy-waf/easy-waf/internal/mapfile"
	"github.com/easy-waf/easy-waf/internal/store"
)

// SyncResult describes a merge operation for observability.
type SyncResult struct {
	LocalLines    int    `json:"local_lines"`
	ExternalLines int    `json:"external_lines"`
	TotalLines    int    `json:"total_lines"`
	MapPath       string `json:"map_path"`
	// AllCIDRs is the sorted unique CIDR/IP lines written to the blacklist map
	// (GeoIP batch uses this). It is not part of the API response: it can run
	// to hundreds of thousands of lines and the map file already holds it.
	AllCIDRs []string `json:"-"`
}

// SyncAndWrite merges local DB entries and optional external HTTP lists into a HAProxy-compatible text file
// (one IPv4/IPv6 or CIDR per line). Comments with # are stripped from downloads.
// PrefetchFeeds downloads enabled external feeds into the on-disk cache.
// Call it outside the HAProxy apply lock so Apply/SyncIPBL only hold the lock
// for merge + atomic map promote.
func PrefetchFeeds(ctx context.Context, st *store.Store, g config.GlobalSettings, stateDir string) error {
	if !g.IPBLExternalEnabled {
		return nil
	}
	srcs, err := st.ListIPBLExternalSources(ctx)
	if err != nil {
		return err
	}
	fetch := guardedFetch(ParseFeedAllowedPrefixes(g))
	cacheDir := FeedCacheDir(stateDir)
	pruneFeedCache(cacheDir, srcs)
	for _, src := range srcs {
		if !src.Enabled {
			continue
		}
		now := time.Now().UTC()
		out := refreshFeed(ctx, src, fetch, cacheDir, now)
		_ = st.TouchIPBLSourceFetch(ctx, src.ID, now, out.lastError)
	}
	return nil
}

// SyncOptions controls whether SyncAndWrite performs network fetches.
type SyncOptions struct {
	// SkipFetch uses only local rows and already-cached feed copies (after
	// PrefetchFeeds). Network work must not run under the apply lock.
	SkipFetch bool
}

// A feed that fails to download contributes its last good copy (see FeedMaxStale).
func SyncAndWrite(ctx context.Context, st *store.Store, g config.GlobalSettings, stateDir string) (SyncResult, error) {
	return SyncAndWriteOpts(ctx, st, g, stateDir, SyncOptions{})
}

// SyncAndWriteOpts merges local + external IPBL entries and writes the map.
func SyncAndWriteOpts(ctx context.Context, st *store.Store, g config.GlobalSettings, stateDir string, opts SyncOptions) (SyncResult, error) {
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
	if !g.IPBLExternalEnabled {
		// Feeds are switched off: no source may come back from a saved copy.
		ForgetAllFeedCopies(stateDir)
	} else {
		srcs, err := st.ListIPBLExternalSources(ctx)
		if err != nil {
			return SyncResult{}, err
		}
		cacheDir := FeedCacheDir(stateDir)
		pruneFeedCache(cacheDir, srcs)
		var fetch func(context.Context, string) ([]string, error)
		if !opts.SkipFetch {
			fetch = guardedFetch(ParseFeedAllowedPrefixes(g))
		}
		for _, src := range srcs {
			if !src.Enabled {
				continue
			}
			now := time.Now().UTC()
			var out feedOutcome
			if opts.SkipFetch {
				out = feedFromCacheOnly(src, cacheDir, now)
			} else {
				out = refreshFeed(ctx, src, fetch, cacheDir, now)
				_ = st.TouchIPBLSourceFetch(ctx, src.ID, now, out.lastError)
			}
			for _, line := range out.lines {
				set[line] = struct{}{}
				extN++
			}
		}
	}

	lines := make([]string, 0, len(set))
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

	// 0640: HAProxy reads this as the haproxy user, a member of the easy-waf group.
	if err := apply.WriteAtomic(outPath, []byte(b.String()), 0o640); err != nil {
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

// guardedFetch downloads a feed through the SSRF guard: destination checked
// before the request, at dial time and on every redirect. Policy refusals
// match ErrFeedRejected; DNS, network and HTTP failures do not.
func guardedFetch(allowed []netip.Prefix) func(context.Context, string) ([]string, error) {
	client := newFeedClient(allowed)
	return func(ctx context.Context, u string) ([]string, error) {
		if _, err := validateFeedURLContext(ctx, u, allowed); err != nil {
			return nil, err
		}
		return fetchPlainList(ctx, client, u)
	}
}

// FileHasEntries returns true if data contains at least one non-comment line
// (used before enabling a HAProxy ACL). Thin wrapper over mapfile.HasEntries,
// kept for the existing callers.
func FileHasEntries(data []byte) bool { return mapfile.HasEntries(data) }

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

func fetchPlainList(ctx context.Context, client *http.Client, u string) ([]string, error) {
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
	const (
		maxFeedBytes   = 16 << 20
		maxFeedEntries = 250_000
		maxLineBytes   = 64 << 10
	)
	limited := &io.LimitedReader{R: resp.Body, N: maxFeedBytes + 1}
	var lines []string
	sc := bufio.NewScanner(limited)
	buf := make([]byte, 0, 64*1024)
	sc.Buffer(buf, maxLineBytes)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lines = append(lines, line)
		if len(lines) > maxFeedEntries {
			return nil, fmt.Errorf("feed exceeds %d entries", maxFeedEntries)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if limited.N == 0 {
		return nil, fmt.Errorf("feed exceeds %d bytes", maxFeedBytes)
	}
	return lines, nil
}
