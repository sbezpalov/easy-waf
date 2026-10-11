// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package ipbl

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/easy-waf/easy-waf/internal/apply"
	"github.com/easy-waf/easy-waf/internal/config"
)

// FeedMaxStale is how long the last successfully fetched copy of an external
// feed keeps protecting after the feed starts failing. Every render refetches
// the feeds; without a fallback, one transient outage during an unrelated
// apply would silently drop every block that feed supplied. Past this age a
// failing feed contributes nothing, so a feed that is gone for good does not
// keep blocking with ever older data.
const FeedMaxStale = 7 * 24 * time.Hour

// ErrFeedRejected matches errors where the fetch policy refused a feed: a
// destination the SSRF guard or ipbl_fetch_allowed_cidrs forbids (checked
// before the request, at dial time and on every redirect), or a URL with a
// bad scheme or shape. That is configuration saying "do not use this feed",
// not an outage, so the last good copy is not used for it. DNS failures are
// outages and do not match.
var ErrFeedRejected = errors.New("feed URL rejected by fetch policy")

const (
	feedCacheHeader  = "# easy-waf ipbl feed cache — last good download; do not edit"
	feedCacheURL     = "# url: "
	feedCacheFetched = "# fetched: "
)

// FeedCacheDir holds one last-known-good file per external source.
func FeedCacheDir(stateDir string) string {
	return filepath.Join(stateDir, "ipbl", "feeds")
}

// feedOutcome is the result of refreshing one source.
type feedOutcome struct {
	lines []string // entries to merge (fresh, or last known good)
	// lastError is stored as the source's last_error: empty after a
	// successful download, else the failure and whether a cached copy was used.
	lastError string
}

// refreshFeed downloads src with fetch. On success the valid entries are
// stored as the source's last-known-good copy. On failure the last-known-good
// copy is used when it was downloaded from the same URL less than FeedMaxStale
// ago. cacheDir == "" disables the fallback.
func refreshFeed(ctx context.Context, src config.IPBLExternalSource, fetch func(context.Context, string) ([]string, error), cacheDir string, now time.Time) feedOutcome {
	raw, err := fetch(ctx, src.URL)
	if err == nil {
		lines := validFeedLines(raw)
		if cacheDir != "" {
			if werr := writeFeedCache(cacheDir, src, lines, now); werr != nil {
				// The fresh list is still used; only the fallback is degraded.
				return feedOutcome{lines: lines, lastError: "fetched, but saving the last-good copy failed: " + werr.Error()}
			}
		}
		return feedOutcome{lines: lines}
	}
	if errors.Is(err, ErrFeedRejected) {
		return feedOutcome{lastError: err.Error() + "; refused by the fetch policy, so no last-good copy is used"}
	}
	if cacheDir == "" {
		return feedOutcome{lastError: err.Error()}
	}
	lines, fetched, cerr := readFeedCache(cacheDir, src)
	switch {
	case errors.Is(cerr, fs.ErrNotExist):
		return feedOutcome{lastError: err.Error() + "; no last-good copy yet"}
	case cerr != nil:
		return feedOutcome{lastError: err.Error() + "; no usable last-good copy: " + cerr.Error()}
	case now.Sub(fetched) > FeedMaxStale:
		return feedOutcome{lastError: fmt.Sprintf("%v; last-good copy from %s is older than %s and was dropped",
			err, fetched.UTC().Format(time.RFC3339), FeedMaxStale)}
	default:
		return feedOutcome{lines: lines, lastError: fmt.Sprintf("%v; using last-good copy from %s",
			err, fetched.UTC().Format(time.RFC3339))}
	}
}

func validFeedLines(raw []string) []string {
	out := make([]string, 0, len(raw))
	for _, line := range raw {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if validateCIDRLine(line) != nil {
			continue
		}
		out = append(out, line)
	}
	return out
}

func feedCachePath(cacheDir string, src config.IPBLExternalSource) (string, error) {
	if err := config.ValidateResourceID("ipbl source", src.ID); err != nil {
		return "", err
	}
	return filepath.Join(cacheDir, src.ID+".list"), nil
}

func writeFeedCache(cacheDir string, src config.IPBLExternalSource, lines []string, now time.Time) error {
	path, err := feedCachePath(cacheDir, src)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(cacheDir, 0o750); err != nil {
		return err
	}
	var b bytes.Buffer
	b.WriteString(feedCacheHeader + "\n")
	b.WriteString(feedCacheURL + src.URL + "\n")
	b.WriteString(feedCacheFetched + now.UTC().Format(time.RFC3339) + "\n")
	for _, ln := range lines {
		b.WriteString(ln)
		b.WriteByte('\n')
	}
	return apply.WriteAtomic(path, b.Bytes(), 0o640)
}

var errFeedCacheOtherURL = errors.New("cached copy belongs to a different URL")

func readFeedCache(cacheDir string, src config.IPBLExternalSource) ([]string, time.Time, error) {
	path, err := feedCachePath(cacheDir, src)
	if err != nil {
		return nil, time.Time{}, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, time.Time{}, err
	}
	var (
		url     string
		fetched time.Time
		lines   []string
	)
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 64<<10)
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, feedCacheURL):
			url = strings.TrimPrefix(line, feedCacheURL)
		case strings.HasPrefix(line, feedCacheFetched):
			if t, perr := time.Parse(time.RFC3339, strings.TrimPrefix(line, feedCacheFetched)); perr == nil {
				fetched = t
			}
		case strings.HasPrefix(line, "#"):
		default:
			lines = append(lines, line)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, time.Time{}, err
	}
	if fetched.IsZero() {
		return nil, time.Time{}, errors.New("cached copy has no fetch time")
	}
	// A source edited to point elsewhere must not inherit the old URL's list.
	if url != src.URL {
		return nil, time.Time{}, errFeedCacheOtherURL
	}
	return validFeedLines(lines), fetched, nil
}

// pruneFeedCache removes cached copies of sources that are deleted or
// disabled. It runs on every sync, under the apply lock, so no concurrent
// download can write a copy back; a re-enabled source then starts from its
// next successful download.
func pruneFeedCache(cacheDir string, srcs []config.IPBLExternalSource) {
	entries, err := os.ReadDir(cacheDir)
	if err != nil {
		return
	}
	keep := make(map[string]struct{}, len(srcs))
	for _, s := range srcs {
		if s.Enabled {
			keep[s.ID+".list"] = struct{}{}
		}
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".list") {
			continue
		}
		if _, ok := keep[e.Name()]; !ok {
			_ = os.Remove(filepath.Join(cacheDir, e.Name()))
		}
	}
}

// ForgetAllFeedCopies deletes every saved copy; a sync runs it when external
// feeds are switched off, so none can come back through the fallback.
func ForgetAllFeedCopies(stateDir string) {
	if strings.TrimSpace(stateDir) == "" {
		return
	}
	pruneFeedCache(FeedCacheDir(stateDir), nil)
}
