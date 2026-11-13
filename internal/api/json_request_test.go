// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type jsonRequestErrorReader struct{ err error }

func (r jsonRequestErrorReader) Read([]byte) (int, error) { return 0, r.err }

func TestDecodeJSONRequestRequiresCompleteSingleValue(t *testing.T) {
	for _, body := range []string{`{"value":"ok"} {}`, `{"value":"ok"} garbage`, `{"value":"ok"} "unfinished`} {
		var got struct{ Value string }
		err := decodeJSONRequest(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body)), &got)
		if err == nil || errors.Is(err, io.EOF) {
			t.Fatalf("invalid suffix accepted or treated as an empty body: %q: %v", body, err)
		}
	}
	failure := errors.New("request stream failed after first value")
	var got struct{ Value string }
	req := httptest.NewRequest(http.MethodPost, "/", io.MultiReader(strings.NewReader(`{"value":"ok"}`), jsonRequestErrorReader{err: failure}))
	if err := decodeJSONRequest(req, &got); !errors.Is(err, failure) {
		t.Fatalf("request stream failure ignored: %v", err)
	}
}

func TestDecodeJSONRequestPreservesOptionalAndCompatibleBodies(t *testing.T) {
	if err := decodeJSONRequest(&http.Request{}, new(any)); !errors.Is(err, io.EOF) {
		t.Fatalf("absent body lost EOF semantics: %v", err)
	}
	for _, body := range []string{"", " \t\r\n"} {
		var got struct{ Value string }
		if err := decodeJSONRequest(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body)), &got); !errors.Is(err, io.EOF) {
			t.Fatalf("empty body lost EOF semantics: %v", err)
		}
	}
	var got struct{ Value string }
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{\"value\":\"ok\",\"future_field\":true} \n\t"))
	if err := decodeJSONRequest(req, &got); err != nil || got.Value != "ok" {
		t.Fatalf("valid body/unknown field rejected: %+v, %v", got, err)
	}
}

func TestDecodeJSONRequestEnforcesStreamLimitAfterFirstValue(t *testing.T) {
	for _, tc := range []struct {
		name     string
		body     string
		tooLarge bool
	}{
		{"at limit", "{}  ", false},
		{"trailing whitespace over limit", "{}   ", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			called := false
			h := limitRequestBody(4)(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				called = true
				var got map[string]any
				err := decodeJSONRequest(r, &got)
				var sizeErr *http.MaxBytesError
				if tc.tooLarge {
					if !errors.As(err, &sizeErr) || sizeErr.Limit != 4 {
						t.Fatalf("streamed limit lost after first value: %v", err)
					}
				} else if err != nil {
					t.Fatalf("body at limit rejected: %v", err)
				}
			}))
			req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(tc.body))
			req.ContentLength = -1 // Force enforcement while reading, without a known length.
			h.ServeHTTP(httptest.NewRecorder(), req)
			if !called {
				t.Fatal("streamed request did not reach decoder")
			}
		})
	}
}

func TestSensitiveJSONHandlersRejectSuffixBeforeStateAccess(t *testing.T) {
	for _, tc := range []struct {
		name   string
		body   string
		handle func(*Server, http.ResponseWriter, *http.Request)
	}{
		{"apply", `{"label":"manual"} {}`, (*Server).apply},
		{"login", `{"username":"operator","password":"test-password"} {}`, (*Server).handleLogin},
		{"enroll", `{"secret":"test-secret","password":"test-password"} {}`, (*Server).handleEnroll},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("invalid suffix reached unconfigured state: %v", r)
				}
			}()
			rec := httptest.NewRecorder()
			tc.handle(&Server{}, rec, httptest.NewRequest(http.MethodPost, "/", strings.NewReader(tc.body)))
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("malformed request accepted: %d %s", rec.Code, rec.Body.String())
			}
		})
	}
}

func TestKnownOversizedBodyRejectedBeforeHandler(t *testing.T) {
	called := false
	h := limitRequestBody(4)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/apply", strings.NewReader(`{}   `)))
	if called || rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized request invoked handler: called=%v status=%d", called, rec.Code)
	}
}

func TestAuthenticationJSONLimitsIncludeTrailingWhitespace(t *testing.T) {
	for _, tc := range []struct {
		name   string
		body   string
		handle func(*Server, http.ResponseWriter, *http.Request)
	}{
		{"login", `{"username":"operator","password":"test-password"}`, (*Server).handleLogin},
		{"enroll", `{"secret":"test-secret","password":"test-password"}`, (*Server).handleEnroll},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			body := tc.body + strings.Repeat(" ", int(maxLoginRequestBodyBytes))
			tc.handle(&Server{}, rec, httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body)))
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("authentication limit bypassed with trailing whitespace: %d", rec.Code)
			}
		})
	}
}

func TestRequestBodyLimitExemptsOnlyExactBinaryPath(t *testing.T) {
	const binaryPath = "/api/v1/geoip/database"
	for _, tc := range []struct {
		path   string
		exempt bool
	}{
		{binaryPath, true},
		{binaryPath + "/extra", false},
		{binaryPath + "-other", false},
	} {
		t.Run(tc.path, func(t *testing.T) {
			called := false
			h := limitRequestBody(4, binaryPath)(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				called = true
				body, err := io.ReadAll(r.Body)
				if err != nil || string(body) != "12345" {
					t.Fatalf("binary exemption changed body: %q, %v", body, err)
				}
			}))
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, tc.path, strings.NewReader("12345")))
			if called != tc.exempt || (!tc.exempt && rec.Code != http.StatusRequestEntityTooLarge) {
				t.Fatalf("incorrect path exemption: called=%v status=%d", called, rec.Code)
			}
		})
	}
}
