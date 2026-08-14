package crowdsec

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func testClient(t *testing.T, srv *httptest.Server, key string) Client {
	t.Helper()
	t.Setenv("CROWDSEC_LAPI_ALLOWED_ORIGINS", "")
	o, err := ParseOrigin(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	return Client{BaseURL: srv.URL, APIKey: key, AllowedOrigins: []Origin{o}}
}

func TestParseOrigin_rejectsUserinfo(t *testing.T) {
	if _, err := ParseOrigin("http://secret@127.0.0.1:8080"); err == nil {
		t.Fatal("expected userinfo rejection")
	}
}

func TestValidateLAPIURL_defaultLoopback(t *testing.T) {
	t.Setenv("CROWDSEC_LAPI_ALLOWED_ORIGINS", "")
	if _, err := ValidateLAPIURL("http://127.0.0.1:8080/", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateLAPIURL("http://[::1]:8080", nil); err != nil {
		t.Fatal(err)
	}
}

func TestValidateLAPIURL_unapprovedHost(t *testing.T) {
	t.Setenv("CROWDSEC_LAPI_ALLOWED_ORIGINS", "")
	if _, err := ValidateLAPIURL("http://192.0.2.1:8080", nil); err == nil {
		t.Fatal("expected unapproved host")
	}
}

func TestValidateLAPIURL_alternatePort(t *testing.T) {
	t.Setenv("CROWDSEC_LAPI_ALLOWED_ORIGINS", "")
	if _, err := ValidateLAPIURL("http://127.0.0.1:8081", nil); err == nil {
		t.Fatal("expected alternate port rejected")
	}
}

func TestValidateLAPIURL_approvedRemote(t *testing.T) {
	t.Setenv("CROWDSEC_LAPI_ALLOWED_ORIGINS", "")
	extra := []Origin{{Scheme: "https", Host: "crowdsec.example.test", Port: "8443"}}
	if _, err := ValidateLAPIURL("https://crowdsec.example.test:8443/v1", extra); err != nil {
		t.Fatal(err)
	}
}

func TestValidateLAPIURL_envApprovedRemote(t *testing.T) {
	t.Setenv("CROWDSEC_LAPI_ALLOWED_ORIGINS", "https://crowdsec.example.test:8443")
	if _, err := ValidateLAPIURL("https://crowdsec.example.test:8443/", nil); err != nil {
		t.Fatal(err)
	}
}

func TestClient_redirectRefused(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Api-Key") == "" {
			t.Fatal("missing key on first hop")
		}
		http.Redirect(w, r, "http://192.0.2.55/steal", http.StatusFound)
	}))
	defer srv.Close()
	c := testClient(t, srv, "super-secret-key")
	_, err := c.DecisionsSample(context.Background())
	if err == nil || !strings.Contains(err.Error(), "redirect") {
		t.Fatalf("expected redirect refusal, got %v", err)
	}
	if err != nil && strings.Contains(err.Error(), "super-secret-key") {
		t.Fatalf("error leaked api key: %v", err)
	}
}

func TestClient_unapprovedBaseURL(t *testing.T) {
	t.Setenv("CROWDSEC_LAPI_ALLOWED_ORIGINS", "")
	c := Client{BaseURL: "http://192.0.2.9:8080", APIKey: "k"}
	st := c.Ping(context.Background())
	if st.Reachable {
		t.Fatal("unapproved origin must not be reachable")
	}
	if strings.Contains(st.LastMessage, "k") {
		t.Fatalf("leaked key: %s", st.LastMessage)
	}
}

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

	c := testClient(t, srv, "k")
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

	c := testClient(t, srv, "k")
	err := c.DeleteDecision(context.Background(), "999")
	if err == nil {
		t.Fatal("expected error")
	}
	if err != ErrDecisionNotFound {
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
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`[]`))
	}))
	defer srv.Close()

	c := testClient(t, srv, "k")
	err := c.AddDecision(context.Background(), AddDecisionRequest{
		IP: "203.0.113.1", Type: "ban", Duration: "24h", Reason: "test",
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
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()

	c := testClient(t, srv, "k")
	if err := c.AddDecision(context.Background(), AddDecisionRequest{IP: "203.0.113.2", Type: "whitelist"}); err != nil {
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

	c := testClient(t, srv, "secret")
	raw, err := c.DecisionsSample(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != "[]" {
		t.Fatalf("got %s", raw)
	}
}

func TestAddDecision_InvalidIP(t *testing.T) {
	c := Client{BaseURL: "http://127.0.0.1:8080", APIKey: "k"}
	err := c.AddDecision(context.Background(), AddDecisionRequest{IP: "not-an-ip", Type: "ban", Duration: "1h", Reason: "x"})
	if err == nil {
		t.Fatal("expected error")
	}
}
