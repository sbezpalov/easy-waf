package ipbl

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestValidateIPBLFetchURL_blocksLoopback(t *testing.T) {
	ctx := context.Background()
	for _, raw := range []string{
		"http://127.0.0.1/list.txt",
		"http://127.0.0.1:8080/list.txt",
	} {
		u, err := http.NewRequest(http.MethodGet, raw, nil)
		if err != nil {
			t.Fatal(err)
		}
		err = validateIPBLFetchURL(ctx, u.URL, false)
		if !errors.Is(err, ErrPrivateFetchBlocked) {
			t.Fatalf("%s: got %v", raw, err)
		}
	}
}

func TestValidateIPBLFetchURL_blocksMetadataIP(t *testing.T) {
	ctx := context.Background()
	req, _ := http.NewRequest(http.MethodGet, "http://169.254.169.254/latest/meta-data/", nil)
	err := validateIPBLFetchURL(ctx, req.URL, false)
	if !errors.Is(err, ErrPrivateFetchBlocked) {
		t.Fatalf("got %v", err)
	}
}

func TestFetchPlainList_blocksPrivateURL(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("1.2.3.4\n"))
	}))
	defer srv.Close()

	_, err := fetchPlainList(context.Background(), newIPBLHTTPClient(false), srv.URL, false)
	if err == nil {
		t.Fatal("expected error for loopback server URL")
	}
	if !errors.Is(err, ErrPrivateFetchBlocked) {
		t.Fatalf("got %v", err)
	}
}

func TestFetchPlainList_allowPrivateLab(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("203.0.113.1\n"))
	}))
	defer srv.Close()

	lines, err := fetchPlainList(context.Background(), newIPBLHTTPClient(true), srv.URL, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(lines) != 1 || lines[0] != "203.0.113.1" {
		t.Fatalf("lines: %v", lines)
	}
}
