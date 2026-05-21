package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/easy-waf/easy-waf/internal/config"
	"github.com/easy-waf/easy-waf/internal/engine"
	"github.com/easy-waf/easy-waf/internal/host/rollback"
)

func TestHostNetplanApply_invalidYAML(t *testing.T) {
	eng := &engine.Engine{Settings: config.GlobalSettings{ManagementAllowedCIDRs: []string{"127.0.0.0/8"}}}
	s := &Server{Eng: eng, JWTSecret: []byte("test")}
	body, _ := json.Marshal(map[string]any{"yaml": "", "rollback_seconds": 90})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/host/network/netplan/apply", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	w := httptest.NewRecorder()
	s.hostNetplanApply(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status %d body %s", w.Code, w.Body.String())
	}
}

func TestHostFirewallApplyRB_invalidRuleset(t *testing.T) {
	eng := &engine.Engine{Settings: config.GlobalSettings{ManagementAllowedCIDRs: []string{"127.0.0.0/8"}}}
	s := &Server{Eng: eng, JWTSecret: []byte("test")}
	body, _ := json.Marshal(map[string]any{"ruleset": "not valid nft {", "rollback_seconds": 29})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/host/firewall/apply-rollback", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	w := httptest.NewRecorder()
	s.hostFirewallApplyRB(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status %d body %s", w.Code, w.Body.String())
	}
}

func TestRollbackClampInHandler(t *testing.T) {
	if rollback.ClampRollbackSeconds(29) != 30 {
		t.Fatal("clamp 29")
	}
	if rollback.ClampRollbackSeconds(9999) != 600 {
		t.Fatal("clamp 9999")
	}
}
