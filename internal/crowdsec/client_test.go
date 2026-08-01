package crowdsec

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDeleteDecision_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete || r.URL.Path != "/v1/decisions/42" {
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("X-Api-Key") != "k" {
			t.Fatalf("missing X-Api-Key auth, got %q", r.Header.Get("X-Api-Key"))
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := Client{BaseURL: srv.URL, APIKey: "k"}
	if err := c.DeleteDecision(context.Background(), "42"); err != nil {
		t.Fatal(err)
	}
}

func TestDeleteDecision_NotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, `{"message":"not found"}`)
	}))
	defer srv.Close()

	c := Client{BaseURL: srv.URL, APIKey: "k"}
	err := c.DeleteDecision(context.Background(), "999")
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, ErrDecisionNotFound) {
		t.Fatalf("expected ErrDecisionNotFound, got %v", err)
	}
}

func TestAddDecision_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/decisions" {
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		b, _ := io.ReadAll(r.Body)
		if !strings.Contains(string(b), `"value":"203.0.113.1"`) {
			t.Fatalf("body: %s", b)
		}
		if !strings.Contains(string(b), `"duration":"24h"`) {
			t.Fatalf("body: %s", b)
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`[]`))
	}))
	defer srv.Close()

	c := Client{BaseURL: srv.URL, APIKey: "k"}
	err := c.AddDecision(context.Background(), AddDecisionRequest{
		IP:       "203.0.113.1",
		Type:     "ban",
		Duration: "24h",
		Reason:   "test",
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestAddDecision_Whitelist(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		if !strings.Contains(string(b), `"type":"whitelist"`) {
			t.Fatalf("body: %s", b)
		}
		if !strings.Contains(string(b), `"duration":"876000h"`) {
			t.Fatalf("body: %s", b)
		}
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()

	c := Client{BaseURL: srv.URL, APIKey: "k"}
	err := c.AddDecision(context.Background(), AddDecisionRequest{
		IP:   "203.0.113.2",
		Type: "whitelist",
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestDecisionsSample_XApiKey(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Api-Key") != "secret" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[]`))
	}))
	defer srv.Close()

	c := Client{BaseURL: srv.URL, APIKey: "secret"}
	raw, err := c.DecisionsSample(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != "[]" {
		t.Fatalf("got %s", raw)
	}
}

func TestAddDecision_InvalidIP(t *testing.T) {
	c := Client{BaseURL: "http://127.0.0.1:9", APIKey: "k"}
	err := c.AddDecision(context.Background(), AddDecisionRequest{
		IP:       "not-an-ip",
		Type:     "ban",
		Duration: "1h",
		Reason:   "x",
	})
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, ErrInvalidDecisionIP) {
		t.Fatalf("expected ErrInvalidDecisionIP, got %v", err)
	}
}
