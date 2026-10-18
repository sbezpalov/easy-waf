// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package crowdsec

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDecisionsSampleRefusesOversizedResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`[{"value":"` + strings.Repeat("a", maxDecisionsBytes) + `"}]`))
	}))
	defer srv.Close()
	c := testClient(t, srv, "k")
	if raw, err := c.DecisionsSample(context.Background()); err == nil {
		t.Fatalf("got %d bytes of truncated JSON instead of an error", len(raw))
	}
}

func TestAddDecisionEmptyIPIsInvalidInput(t *testing.T) {
	c := Client{BaseURL: "http://127.0.0.1:8080"}
	err := c.AddDecision(context.Background(), AddDecisionRequest{IP: "  "})
	if !errors.Is(err, ErrInvalidDecisionIP) {
		t.Fatalf("err = %v, want ErrInvalidDecisionIP", err)
	}
}
