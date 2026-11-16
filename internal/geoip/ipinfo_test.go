// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package geoip

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/synctest"
	"time"
)

type ipinfoRoundTripFunc func(*http.Request) (*http.Response, error)

func (f ipinfoRoundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func rateTestProvider(calls chan<- time.Time) *IPInfoProvider {
	return &IPInfoProvider{MinInterval: time.Hour, HTTP: &http.Client{
		Transport: ipinfoRoundTripFunc(func(*http.Request) (*http.Response, error) {
			calls <- time.Now()
			return &http.Response{StatusCode: http.StatusOK,
				Body: io.NopCloser(strings.NewReader(`{"country":"US"}`)), Header: make(http.Header)}, nil
		}),
	}}
}

func TestIPInfoRateWaitCancellation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		calls := make(chan time.Time, 4)
		p := rateTestProvider(calls)
		if _, err := p.Lookup(t.Context(), "8.8.8.8"); err != nil {
			t.Fatal(err)
		}
		first := <-calls
		// Check a single waiter first. A regression to sleeping under a mutex
		// must fail here, before a mutex-blocked second waiter prevents the
		// synctest clock from advancing during cleanup.
		singleCtx, cancelSingle := context.WithCancel(t.Context())
		defer cancelSingle()
		single := make(chan error, 1)
		go func() { _, err := p.Lookup(singleCtx, "8.8.4.4"); single <- err }()
		synctest.Wait()
		cancelSingle()
		synctest.Wait()
		select {
		case err := <-single:
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("single waiting lookup: %v", err)
			}
		default:
			t.Fatal("canceled lookup continued waiting for the rate interval")
		}
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		waiting := make(chan error, 1)
		go func() { _, err := p.Lookup(ctx, "8.8.4.4"); waiting <- err }()
		synctest.Wait()

		queuedCtx, cancelQueued := context.WithCancel(t.Context())
		defer cancelQueued()
		queued := make(chan error, 1)
		go func() { _, err := p.Lookup(queuedCtx, "1.1.1.1"); queued <- err }()
		synctest.Wait()
		cancelQueued()
		synctest.Wait()
		select {
		case err := <-queued:
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("queued lookup: %v", err)
			}
		default:
			t.Fatal("canceled lookup remained blocked behind another rate waiter")
		}
		cancel()
		synctest.Wait()
		select {
		case err := <-waiting:
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("waiting lookup: %v", err)
			}
		default:
			t.Fatal("canceled lookup continued waiting for the rate interval")
		}
		if time.Now() != first || len(calls) != 0 {
			t.Fatal("cancellation waited or sent an upstream request")
		}

		next := make(chan error, 1)
		go func() { _, err := p.Lookup(t.Context(), "9.9.9.9"); next <- err }()
		synctest.Wait()
		if len(calls) != 0 {
			t.Fatal("next lookup bypassed rate limit")
		}
		time.Sleep(time.Hour)
		synctest.Wait()
		if err := <-next; err != nil {
			t.Fatal(err)
		}
		if at := <-calls; at.Sub(first) != time.Hour {
			t.Fatalf("canceled lookup consumed a future slot: delay %v", at.Sub(first))
		}
	})
}

func TestIPInfoConcurrentRateLimit(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		calls := make(chan time.Time, 4)
		p := rateTestProvider(calls)
		results := make(chan error, 4)
		for range 4 {
			go func() { _, err := p.Lookup(t.Context(), "8.8.8.8"); results <- err }()
		}
		for range 4 {
			if err := <-results; err != nil {
				t.Fatal(err)
			}
		}
		previous := <-calls
		for range 3 {
			at := <-calls
			if at.Sub(previous) < time.Hour {
				t.Fatalf("concurrent calls bypassed rate interval: %v", at.Sub(previous))
			}
			previous = at
		}
	})
}

func TestIPInfoCanceledLookupDoesNotCallUpstream(t *testing.T) {
	for _, interval := range []time.Duration{0, time.Hour} {
		t.Run(interval.String(), func(t *testing.T) {
			calls := make(chan time.Time, 1)
			p := rateTestProvider(calls)
			p.MinInterval = interval
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			if _, err := p.Lookup(ctx, "8.8.8.8"); !errors.Is(err, context.Canceled) {
				t.Fatalf("already canceled: %v", err)
			}
			if len(calls) != 0 {
				t.Fatal("already canceled lookup called upstream")
			}
		})
	}
}

func TestIPInfoRateWaitDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		calls := make(chan time.Time, 2)
		p := rateTestProvider(calls)
		if _, err := p.Lookup(t.Context(), "8.8.8.8"); err != nil {
			t.Fatal(err)
		}
		first := <-calls
		ctx, cancel := context.WithTimeout(t.Context(), time.Second)
		defer cancel()
		if _, err := p.Lookup(ctx, "8.8.4.4"); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("expired lookup: %v", err)
		}
		if time.Since(first) != time.Second || len(calls) != 0 {
			t.Fatal("deadline did not interrupt rate wait before upstream request")
		}
	})
}

func TestIPInfoProviderLookup(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/8.8.8.8/json" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"country": "US"})
	}))
	defer srv.Close()

	p := &IPInfoProvider{
		BaseURL:     srv.URL,
		HTTP:        srv.Client(),
		MinInterval: 0,
	}
	cc, err := p.Lookup(context.Background(), "8.8.8.8")
	if err != nil {
		t.Fatal(err)
	}
	if cc != "US" {
		t.Fatalf("country %q", cc)
	}
}

func TestIPInfoTokenNeverInURL(t *testing.T) {
	var gotAuth, gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth, gotQuery = r.Header.Get("Authorization"), r.URL.RawQuery
		_, _ = w.Write([]byte(`{"country":"DE"}`))
	}))
	defer srv.Close()
	p := NewIPInfoProvider("tok-secret")
	p.BaseURL = srv.URL
	p.MinInterval = 0
	if _, err := p.Lookup(context.Background(), "8.8.8.8"); err != nil {
		t.Fatal(err)
	}
	if gotAuth != "Bearer tok-secret" || strings.Contains(gotQuery, "tok-secret") {
		t.Fatalf("auth %q query %q", gotAuth, gotQuery)
	}
}
