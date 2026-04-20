package bootstrap

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestAcmeInternalListenAddr(t *testing.T) {
	t.Setenv("EASY_WAF_ACME_INTERNAL_HTTP", "")
	if got := acmeInternalListenAddr(); got != "127.0.0.1:8089" {
		t.Fatalf("default: got %q", got)
	}
	t.Setenv("EASY_WAF_ACME_INTERNAL_HTTP", "0")
	if got := acmeInternalListenAddr(); got != "" {
		t.Fatalf("0: got %q", got)
	}
	t.Setenv("EASY_WAF_ACME_INTERNAL_HTTP", "off")
	if got := acmeInternalListenAddr(); got != "" {
		t.Fatalf("off: got %q", got)
	}
	t.Setenv("EASY_WAF_ACME_INTERNAL_HTTP", "127.0.0.1:9999")
	if got := acmeInternalListenAddr(); got != "127.0.0.1:9999" {
		t.Fatalf("custom: got %q", got)
	}
}

func TestAcmeChallengeHandler(t *testing.T) {
	root := t.TempDir()
	challengeDir := filepath.Join(root, ".well-known", "acme-challenge")
	if err := os.MkdirAll(challengeDir, 0o755); err != nil {
		t.Fatal(err)
	}
	token := "test-token-abc"
	if err := os.WriteFile(filepath.Join(challengeDir, token), []byte("challenge-body\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	h := acmeChallengeHandler(root)

	t.Run("ok", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/.well-known/acme-challenge/"+token, nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status %d body %q", rec.Code, rec.Body.String())
		}
		if got := rec.Body.String(); got != "challenge-body\n" {
			t.Fatalf("body %q", got)
		}
	})

	t.Run("reject traversal in URL path", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/.well-known/acme-challenge/../"+token, nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("want 404 got %d", rec.Code)
		}
	})

	t.Run("reject slash in token", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/.well-known/acme-challenge/a/b", nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("want 404 got %d", rec.Code)
		}
	})

	t.Run("wrong prefix", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/foo", nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("want 404 got %d", rec.Code)
		}
	})
}

func TestAcmeWebrootPath(t *testing.T) {
	dir := t.TempDir()
	got, err := acmeWebrootPath(dir, "")
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(dir, "acme", "webroot")
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
	custom := filepath.Join(dir, "custom-webroot")
	got2, err := acmeWebrootPath(dir, custom)
	if err != nil {
		t.Fatal(err)
	}
	if got2 != custom {
		t.Fatalf("configured: got %q want %q", got2, custom)
	}
}
