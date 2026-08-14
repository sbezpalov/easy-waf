package ipbl

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func feedClient(body string) *http.Client {
	return &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(body)),
			Header:     make(http.Header),
		}, nil
	})}
}

func TestFetchPlainList(t *testing.T) {
	lines, err := fetchPlainList(context.Background(), feedClient("# comment\n192.0.2.1\n\n2001:db8::/32\n"), "https://feed.example/list")
	if err != nil {
		t.Fatal(err)
	}
	if len(lines) != 2 {
		t.Fatalf("got %v", lines)
	}
}

func TestFetchPlainListRejectsOversizedLine(t *testing.T) {
	_, err := fetchPlainList(context.Background(), feedClient(strings.Repeat("1", (64<<10)+1)), "https://feed.example/list")
	if err == nil {
		t.Fatal("expected oversized line to fail")
	}
}
