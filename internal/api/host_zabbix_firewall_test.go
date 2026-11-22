// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/easy-waf/easy-waf/internal/config"
	"github.com/easy-waf/easy-waf/internal/engine"
	"github.com/easy-waf/easy-waf/internal/host/nft"
)

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
