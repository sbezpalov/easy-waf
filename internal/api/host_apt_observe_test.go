// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/easy-waf/easy-waf/internal/audit"
	"github.com/easy-waf/easy-waf/internal/auth"
	"github.com/easy-waf/easy-waf/internal/config"
	"github.com/easy-waf/easy-waf/internal/engine"
	"github.com/easy-waf/easy-waf/internal/store"
)

const aptObserveTestID = "0123456789abcdef0123456789abcdef"

func TestHostAptObservationRequiresAdminAndXHRWithoutStepUp(t *testing.T) {
	previous := privilegedStreamFn
	t.Cleanup(func() { privilegedStreamFn = previous })
	calls := 0
	privilegedStreamFn = func(_ context.Context, onLine func([]byte) error, args ...string) error {
		calls++
		if !slices.Equal(args, []string{"apt-action-attach-stream", aptObserveTestID}) {
			t.Fatalf("observation invoked a mutating/incorrect opcode: %v", args)
		}
		if err := onLine([]byte(`{"type":"line","data":"saved output"}`)); err != nil {
			return err
		}
		return onLine([]byte(`{"type":"exit","code":7}`))
	}
	r := chi.NewRouter()
	r.Use(RequireXHR)
	(&Server{}).mountHostRoutes(r)
	for _, fixture := range []struct {
		name string
		p    *auth.Principal
		xhr  bool
		want int
	}{
		{"anonymous", nil, true, http.StatusUnauthorized},
		{"viewer", &auth.Principal{Role: config.RoleViewer}, true, http.StatusForbidden},
		{"unknown_role", &auth.Principal{Role: "unknown"}, true, http.StatusForbidden},
		{"admin_without_xhr", &auth.Principal{Role: config.RoleAdmin}, false, http.StatusForbidden},
		{"admin_without_step_up", &auth.Principal{Role: config.RoleAdmin}, true, http.StatusOK},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			before := calls
			req := httptest.NewRequest(http.MethodPost, "/host/updates/attach/stream?run_id="+aptObserveTestID, nil)
			if fixture.p != nil {
				req = req.WithContext(auth.WithPrincipal(req.Context(), fixture.p))
			}
			if fixture.xhr {
				req.Header.Set("X-Requested-With", "XMLHttpRequest")
			}
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)
			if w.Code != fixture.want {
				t.Fatalf("status %d: %s", w.Code, w.Body.String())
			}
			if fixture.want != http.StatusOK {
				if calls != before {
					t.Fatal("unauthorized observation reached the broker")
				}
				return
			}
			if calls != before+1 || !w.Flushed || w.Header().Get("Content-Type") != "application/x-ndjson" || !strings.Contains(w.Body.String(), `"code":7`) {
				t.Fatalf("observation did not relay/flush the original result: %s", w.Body.String())
			}
		})
	}
}

func TestHostAptObservationValidatesOneRunIDBeforeBrokerCall(t *testing.T) {
	previous := privilegedStreamFn
	t.Cleanup(func() { privilegedStreamFn = previous })
	privilegedStreamFn = func(context.Context, func([]byte) error, ...string) error {
		t.Fatal("invalid observation reached the broker")
		return nil
	}
	for _, query := range []string{
		"", "run_id=", "run_id=bad", "run_id=" + strings.Repeat("a", 31),
		"run_id=" + strings.Repeat("a", 33), "run_id=" + strings.Repeat("A", 32),
		"run_id=../upgrade", "run_id=" + aptObserveTestID + "&run_id=" + aptObserveTestID,
		"run_id=" + aptObserveTestID + "&run_id=", "run_id=%00" + aptObserveTestID,
		"run_id=" + aptObserveTestID + "&run_id=%ZZ", "run_id=" + aptObserveTestID + ";run_id=bad",
	} {
		req := httptest.NewRequest(http.MethodPost, "/?"+query, nil)
		w := httptest.NewRecorder()
		(&Server{}).hostAptAttachStream(w, req)
		if w.Code != http.StatusBadRequest {
			t.Errorf("query %q: status %d: %s", query, w.Code, w.Body.String())
		}
	}
}

func TestHostAptObservationDoesNotFallBackAfterBrokerFailure(t *testing.T) {
	previous := privilegedStreamFn
	t.Cleanup(func() { privilegedStreamFn = previous })
	for _, fixture := range []struct{ name, event string }{
		{"unsupported_broker", ""},
		{"replaced_run", `{"type":"exit","code":-1,"error":"APT operation changed"}`},
		{"missing_completion", `{"type":"line","data":"saved output"}`},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			calls := 0
			privilegedStreamFn = func(_ context.Context, onLine func([]byte) error, args ...string) error {
				calls++
				if !slices.Equal(args, []string{"apt-action-attach-stream", aptObserveTestID}) {
					t.Fatalf("unsafe observation fallback: %v", args)
				}
				if fixture.event == "" {
					return errors.New("unknown broker opcode")
				}
				return onLine([]byte(fixture.event))
			}
			w := httptest.NewRecorder()
			(&Server{}).hostAptAttachStream(w, httptest.NewRequest(http.MethodPost, "/?run_id="+aptObserveTestID, nil))
			lines := strings.Split(strings.TrimSpace(w.Body.String()), "\n")
			var last struct {
				Type  string `json:"type"`
				Code  int    `json:"code"`
				Error string `json:"error"`
			}
			if err := json.Unmarshal([]byte(lines[len(lines)-1]), &last); err != nil {
				t.Fatal(err)
			}
			if calls != 1 || last.Type != "exit" || last.Code != -1 || last.Error == "" {
				t.Fatalf("failed observation reported success/retried: calls=%d body=%s", calls, w.Body.String())
			}
		})
	}
}

func TestHostAptObservationAuditDoesNotClaimAnUpgrade(t *testing.T) {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL not set")
	}
	st, err := store.OpenPostgres(dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	previous := privilegedStreamFn
	t.Cleanup(func() { privilegedStreamFn = previous })
	s := &Server{Eng: engine.New(t.TempDir(), st, config.GlobalSettings{})}
	for _, fixture := range []struct {
		name, event string
		code        int
	}{
		{"completed", `{"type":"exit","code":0}`, 0},
		{"replaced", `{"type":"exit","code":-1,"error":"run changed"}`, -1},
		{"transport", "", -1},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			privilegedStreamFn = func(_ context.Context, onLine func([]byte) error, _ ...string) error {
				if fixture.event == "" {
					return errors.New("fixture disconnect")
				}
				return onLine([]byte(fixture.event))
			}
			user := "apt-observer-" + uuid.NewString()
			ctx := audit.WithMeta(t.Context(), audit.Meta{User: user})
			req := httptest.NewRequest(http.MethodPost, "/?run_id="+aptObserveTestID, nil).WithContext(ctx)
			s.hostAptAttachStream(httptest.NewRecorder(), req)
			entries, more, err := st.ListAuditLogs(ctx, store.AuditListParams{User: user, Limit: 10})
			want := 2
			if fixture.event == "" {
				want = 1
			}
			if err != nil || more || len(entries) != want {
				t.Fatalf("observation audit count: entries=%+v more=%v err=%v", entries, more, err)
			}
			for i, entry := range entries {
				expected := "host_apt_attach"
				if want == 2 && i == 0 {
					expected = "host_apt_attach_done"
				}
				var detail struct {
					RunID string `json:"run_id"`
					Code  *int   `json:"exit_code"`
					Level string `json:"level"`
				}
				if err := json.Unmarshal(entry.Details, &detail); err != nil {
					t.Fatal(err)
				}
				if entry.Action != expected || detail.RunID != aptObserveTestID {
					t.Fatalf("observation logged a mutation or lost run ID: %+v", entry)
				}
				if expected == "host_apt_attach_done" {
					if detail.Code == nil || *detail.Code != fixture.code || (fixture.code != 0 && detail.Level != "warn") {
						t.Fatalf("observation audit claimed the wrong outcome: %+v", entry)
					}
				} else if detail.Code != nil {
					t.Fatalf("request audit retroactively acquired an exit result: %+v", entry)
				}
			}
		})
	}
}
