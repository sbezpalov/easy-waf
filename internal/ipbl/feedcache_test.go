// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package ipbl

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/easy-waf/easy-waf/internal/config"
)

func okFeed(lines ...string) func(context.Context, string) ([]string, error) {
	return func(context.Context, string) ([]string, error) { return lines, nil }
}

func failingFeed(context.Context, string) ([]string, error) {
	return nil, errors.New("http 503")
}

var testSrc = config.IPBLExternalSource{ID: "src-1", URL: "https://feed.example/list", Enabled: true}

// R5: a successful download followed by a failing one keeps the previous
// protection instead of dropping the feed's entries.
func TestRefreshFeed_FailureKeepsLastGood(t *testing.T) {
	dir := t.TempDir()
	t0 := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	first := refreshFeed(context.Background(), testSrc, okFeed("192.0.2.1", "bogus", "2001:db8::/32"), dir, t0)
	if first.lastError != "" {
		t.Fatalf("first fetch: %s", first.lastError)
	}
	want := []string{"192.0.2.1", "2001:db8::/32"}
	if !reflect.DeepEqual(first.lines, want) {
		t.Fatalf("first fetch lines: %v", first.lines)
	}

	second := refreshFeed(context.Background(), testSrc, failingFeed, dir, t0.Add(time.Hour))
	if !reflect.DeepEqual(second.lines, want) {
		t.Fatalf("failed fetch dropped the last good entries: %v", second.lines)
	}
	if !strings.Contains(second.lastError, "http 503") || !strings.Contains(second.lastError, "last-good copy from 2026-10-01T12:00:00Z") {
		t.Fatalf("last error does not say a stale copy is in use: %q", second.lastError)
	}
}

func TestRefreshFeed_StaleCopyExpires(t *testing.T) {
	dir := t.TempDir()
	t0 := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	refreshFeed(context.Background(), testSrc, okFeed("192.0.2.1"), dir, t0)
	out := refreshFeed(context.Background(), testSrc, failingFeed, dir, t0.Add(FeedMaxStale+time.Second))
	if len(out.lines) != 0 {
		t.Fatalf("copy older than FeedMaxStale still used: %v", out.lines)
	}
	if !strings.Contains(out.lastError, "older than") {
		t.Fatalf("last error: %q", out.lastError)
	}
}

// A source re-pointed at another URL must not inherit the old URL's list.
func TestRefreshFeed_CopyFromOtherURLIgnored(t *testing.T) {
	dir := t.TempDir()
	t0 := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	refreshFeed(context.Background(), testSrc, okFeed("192.0.2.1"), dir, t0)
	moved := testSrc
	moved.URL = "https://other.example/list"
	out := refreshFeed(context.Background(), moved, failingFeed, dir, t0.Add(time.Minute))
	if len(out.lines) != 0 {
		t.Fatalf("other URL's copy used: %v", out.lines)
	}
}

func TestRefreshFeed_NoCopyYet(t *testing.T) {
	out := refreshFeed(context.Background(), testSrc, failingFeed, t.TempDir(), time.Now())
	if len(out.lines) != 0 || !strings.Contains(out.lastError, "no last-good copy") {
		t.Fatalf("got %v %q", out.lines, out.lastError)
	}
}

// Deleting a source removes only that source's entries: its cached copy goes.
func TestPruneFeedCache_RemovesDeletedSources(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	other := config.IPBLExternalSource{ID: "src-2", URL: "https://two.example/list"}
	refreshFeed(context.Background(), testSrc, okFeed("192.0.2.1"), dir, now)
	refreshFeed(context.Background(), other, okFeed("198.51.100.1"), dir, now)
	other.Enabled = true
	pruneFeedCache(dir, []config.IPBLExternalSource{other})
	if _, err := os.Stat(filepath.Join(dir, "src-1.list")); !os.IsNotExist(err) {
		t.Fatalf("deleted source's copy kept: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "src-2.list")); err != nil {
		t.Fatalf("remaining source's copy removed: %v", err)
	}
}

// Source IDs become file names; anything that could escape the directory is
// refused rather than used as a path.
func TestRefreshFeed_UnsafeIDNotCached(t *testing.T) {
	dir := t.TempDir()
	bad := testSrc
	bad.ID = "../escape"
	out := refreshFeed(context.Background(), bad, okFeed("192.0.2.1"), dir, time.Now())
	if len(out.lines) != 1 || !strings.Contains(out.lastError, "saving the last-good copy failed") {
		t.Fatalf("got %v %q", out.lines, out.lastError)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(dir), "escape.list")); !os.IsNotExist(err) {
		t.Fatal("file written outside the cache directory")
	}
}

// A disabled source loses its copy too: re-enabling it must not bring back
// entries the operator switched off.
func TestPruneFeedCache_RemovesDisabledSources(t *testing.T) {
	dir := t.TempDir()
	refreshFeed(context.Background(), testSrc, okFeed("192.0.2.1"), dir, time.Now())
	disabled := testSrc
	disabled.Enabled = false
	pruneFeedCache(dir, []config.IPBLExternalSource{disabled})
	if _, err := os.Stat(filepath.Join(dir, "src-1.list")); !os.IsNotExist(err) {
		t.Fatalf("disabled source's copy kept: %v", err)
	}
}

// A URL the fetch policy refuses is configuration, not an outage: no fallback.
func TestRefreshFeed_PolicyRejectionSkipsLastGood(t *testing.T) {
	dir := t.TempDir()
	t0 := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	refreshFeed(context.Background(), testSrc, okFeed("192.0.2.1"), dir, t0)
	rejected := func(context.Context, string) ([]string, error) {
		return nil, fmt.Errorf("%w: %w", ErrFeedRejected, errors.New("destination 10.0.0.5 not allowed"))
	}
	out := refreshFeed(context.Background(), testSrc, rejected, dir, t0.Add(time.Minute))
	if len(out.lines) != 0 {
		t.Fatalf("rejected feed still contributed %v", out.lines)
	}
	if !strings.Contains(out.lastError, "not allowed") || strings.Contains(out.lastError, "last-good") {
		t.Fatalf("last error: %q", out.lastError)
	}
}

// The destination policy can refuse a feed before the request, at dial time
// or on a redirect; all three must count as a rejection (no fallback).
func TestPolicyRefusalsMatchErrFeedRejected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("192.0.2.1\n"))
	}))
	defer srv.Close()
	ctx := context.Background()

	// Pre-check: loopback literal is hard-blocked.
	_, err := guardedFetch(nil)(ctx, srv.URL)
	if !errors.Is(err, ErrFeedRejected) || !strings.Contains(err.Error(), "blocked") {
		t.Fatalf("pre-check: %v", err)
	}
	// Dial time: skip the pre-check, as when DNS changes between check and dial.
	_, err = fetchPlainList(ctx, newFeedClient(nil), srv.URL)
	if !errors.Is(err, ErrFeedRejected) || !strings.Contains(err.Error(), "dial blocked") {
		t.Fatalf("dial: %v", err)
	}
	// Redirect to a forbidden destination.
	client := newFeedClient(nil)
	first, _ := http.NewRequest(http.MethodGet, "https://feed.example/list", nil)
	next, _ := http.NewRequest(http.MethodGet, "http://127.0.0.1/list", nil)
	if err := client.CheckRedirect(next, []*http.Request{first}); !errors.Is(err, ErrFeedRejected) {
		t.Fatalf("redirect: %v", err)
	}
	// Bad scheme; the message is unchanged for the API that shows it.
	if _, err := validateFeedURLContext(ctx, "ftp://feed.example/list", nil); !errors.Is(err, ErrFeedRejected) ||
		err.Error() != `scheme not allowed: "ftp" (use http/https)` {
		t.Fatalf("scheme: %v", err)
	}
}

// A DNS failure is an outage: the feed keeps its last good copy.
func TestDNSFailureKeepsLastGood(t *testing.T) {
	ctx := context.Background()
	src := config.IPBLExternalSource{ID: "src-dns", URL: "https://no-such-feed.invalid/list", Enabled: true}
	_, err := guardedFetch(nil)(ctx, src.URL)
	if err == nil {
		t.Skip("resolver answered for .invalid; cannot simulate a DNS failure here")
	}
	if errors.Is(err, ErrFeedRejected) {
		t.Fatalf("DNS failure classified as a policy rejection: %v", err)
	}
	dir := t.TempDir()
	t0 := time.Now()
	refreshFeed(ctx, src, okFeed("192.0.2.1"), dir, t0)
	out := refreshFeed(ctx, src, guardedFetch(nil), dir, t0.Add(time.Minute))
	if len(out.lines) != 1 || !strings.Contains(out.lastError, "last-good copy") {
		t.Fatalf("DNS outage dropped the feed: %v %q", out.lines, out.lastError)
	}
}

func TestForgetFeedCopy(t *testing.T) {
	state := t.TempDir()
	refreshFeed(context.Background(), testSrc, okFeed("192.0.2.1"), FeedCacheDir(state), time.Now())
	if err := ForgetFeedCopy(state, testSrc); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(FeedCacheDir(state), "src-1.list")); !os.IsNotExist(err) {
		t.Fatalf("copy kept: %v", err)
	}
	if err := ForgetFeedCopy(state, testSrc); err != nil {
		t.Fatalf("second forget: %v", err)
	}
}
