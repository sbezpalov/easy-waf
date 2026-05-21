package api

import (
	"bufio"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/easy-waf/easy-waf/internal/config"
	"github.com/easy-waf/easy-waf/internal/engine"
)

func TestHostAptUpgradeStream_requiresXHR(t *testing.T) {
	eng := &engine.Engine{Settings: config.GlobalSettings{ManagementAllowedCIDRs: []string{"127.0.0.0/8"}}}
	s := &Server{Eng: eng, JWTSecret: []byte("test")}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/host/updates/upgrade/stream", strings.NewReader("{}"))
	req.RemoteAddr = "127.0.0.1:12345"
	w := httptest.NewRecorder()
	RequireXHR(http.HandlerFunc(s.hostAptUpgradeStream)).ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status %d", w.Code)
	}
}

func TestHostAptUpgradeStream_setsNDJSONContentType(t *testing.T) {
	eng := &engine.Engine{Settings: config.GlobalSettings{ManagementAllowedCIDRs: []string{"127.0.0.0/8"}}}
	s := &Server{Eng: eng, JWTSecret: []byte("test")}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/host/updates/upgrade/stream", strings.NewReader("{}"))
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	req.RemoteAddr = "127.0.0.1:12345"
	w := httptest.NewRecorder()
	s.hostAptUpgradeStream(w, req)
	ct := w.Header().Get("Content-Type")
	if !strings.Contains(ct, "application/x-ndjson") {
		t.Fatalf("content-type %q", ct)
	}
	if w.Header().Get("X-Accel-Buffering") != "no" {
		t.Fatal("expected X-Accel-Buffering: no")
	}
	body := strings.TrimSpace(w.Body.String())
	if body != "" {
		sc := bufio.NewScanner(strings.NewReader(body))
		for sc.Scan() {
			var m map[string]any
			if json.Unmarshal([]byte(sc.Text()), &m) != nil {
				t.Fatalf("not json: %q", sc.Text())
			}
		}
	}
}
