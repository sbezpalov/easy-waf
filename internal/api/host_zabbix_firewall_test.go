// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/easy-waf/easy-waf/internal/config"
	"github.com/easy-waf/easy-waf/internal/engine"
	"github.com/easy-waf/easy-waf/internal/host/nft"
)

func TestHostFirewallZabbixAgentReappliesUnchangedRuleset(t *testing.T) {
	s := applyFailingServer(t)
	previous := nft.RulesPath
	nft.RulesPath = filepath.Join(t.TempDir(), "easy-waf.nft")
	t.Cleanup(func() { nft.RulesPath = previous })
	const ruleset = "table inet easy_waf {\n  chain input {\n    tcp dport 22 accept\n  }\n}\n"
	if err := os.WriteFile(nft.RulesPath, []byte(ruleset), 0o600); err != nil {
		t.Fatal(err)
	}
	call := func(body string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		s.hostFirewallZabbixAgent(rec, httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/", strings.NewReader(body)))
		return rec
	}

	socket := filepath.Join(t.TempDir(), "s.sock")
	t.Setenv("EASY_WAF_HOSTD_SOCKET", socket)
	if rec := call(`{"enabled":false}`); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"status":"unchanged"`) {
		t.Fatalf("default request: %d %s", rec.Code, rec.Body.String())
	}

	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	deadline := time.Now().UTC().Add(90 * time.Second).Truncate(time.Second)
	done := make(chan error, 1)
	go func() {
		done <- verifyZabbixReapplyRequest(listener, ruleset, deadline)
	}()
	rec := call(`{"enabled":false,"reapply":true}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("explicit reapply: %d %s", rec.Code, rec.Body.String())
	}
	var response struct {
		Status      string    `json:"status"`
		Token       string    `json:"token"`
		OperationID string    `json:"operation_id"`
		ExpiresAt   time.Time `json:"expires_at"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Status != "applied" || response.Token == "" ||
		response.OperationID != auditRollbackTokenDigest(response.Token) || !response.ExpiresAt.Equal(deadline) {
		t.Fatalf("reapply did not return a confirmation capability, status=%q", response.Status)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func verifyZabbixReapplyRequest(listener net.Listener, ruleset string, deadline time.Time) error {
	conn, err := listener.Accept()
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	var request struct {
		Argv []string `json:"argv"`
	}
	if err := json.NewDecoder(conn).Decode(&request); err != nil {
		return err
	}
	if len(request.Argv) != 4 || request.Argv[0] != "nft-apply-confirm" || request.Argv[2] != "90" {
		return fmt.Errorf("unexpected firewall request: %v", request.Argv)
	}
	if data, err := os.ReadFile(request.Argv[1]); err != nil || string(data) != ruleset {
		return fmt.Errorf("reapply did not stage the unchanged file: %v", err)
	}
	return json.NewEncoder(conn).Encode(map[string]any{"ok": true, "rollback_expires_at": deadline})
}

func TestHostFirewallZabbixAgentMissingRuleset(t *testing.T) {
	eng := engine.New("", nil, config.GlobalSettings{ManagementAllowedCIDRs: []string{"127.0.0.0/8"}})
	s := &Server{Eng: eng, JWTSecret: []byte("test")}

	old := nft.RulesPath
	nft.RulesPath = filepath.Join(t.TempDir(), "missing.nft")
	t.Cleanup(func() { nft.RulesPath = old })

	req := httptest.NewRequest(http.MethodPost, "/api/v1/host/firewall/zabbix-agent", strings.NewReader(`{"enabled":true}`))
	rec := httptest.NewRecorder()
	s.hostFirewallZabbixAgent(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("code=%d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "managed nftables ruleset missing") {
		t.Fatalf("body=%s", rec.Body.String())
	}
}

func TestHostFirewallZabbixAgentRequiresEnabled(t *testing.T) {
	s := &Server{}
	for _, body := range []string{`{}`, `{"enabled":null}`} {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/host/firewall/zabbix-agent", strings.NewReader(body))
		rec := httptest.NewRecorder()
		s.hostFirewallZabbixAgent(rec, req)
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "enabled is required") {
			t.Fatalf("request %s: code=%d body=%s", body, rec.Code, rec.Body.String())
		}
	}
}
