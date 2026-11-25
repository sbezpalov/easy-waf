// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/easy-waf/easy-waf/internal/auth"
	"github.com/easy-waf/easy-waf/internal/config"
	"github.com/easy-waf/easy-waf/internal/store"
)

func TestMCPHTTPSDoctorAndRevocation(t *testing.T) {
	s := applyFailingServer(t)
	s.JWTSecret = []byte(newSecret())
	internalToken := newSecret()
	t.Setenv("EASY_WAF_MCP_API_TOKEN", internalToken)
	s.MCPAPIToken = auth.LoadMCPAPIToken(s.JWTSecret)
	user := "mcp-" + newSecret()[:10]
	if err := s.Eng.Store.CreateUser(t.Context(), &config.AdminUser{Username: user, PasswordHash: "unused", Role: config.RoleAdmin}); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Eng.Store.DeleteUserByUsername(t.Context(), user) }()
	u, err := s.Eng.Store.GetUserByUsername(t.Context(), user)
	if err != nil {
		t.Fatal(err)
	}
	admin, err := auth.SignStepUpJWT(s.JWTSecret, user, u.SessionVersion, time.Now().Add(time.Hour), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewTLSServer(s.Router())
	defer srv.Close()
	origin := srv.URL
	client := srv.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	call := func(method, path, typ, body, token string, want int) (http.Header, []byte) {
		t.Helper()
		r, err := http.NewRequestWithContext(t.Context(), method, origin+path, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set("Content-Type", typ)
		r.Header.Set("Accept", "application/json, text/event-stream")
		if strings.HasPrefix(path, "/api/v1/") {
			r.Header.Set("X-Requested-With", "XMLHttpRequest")
		}
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != want {
			t.Fatalf("%s expected %d got %d", r.URL.Path, want, resp.StatusCode)
		}
		return resp.Header, b
	}
	field := func(b []byte, key string) string {
		t.Helper()
		var v map[string]any
		if err := json.Unmarshal(b, &v); err != nil {
			t.Fatal(err)
		}
		out, ok := v[key].(string)
		if !ok || out == "" {
			t.Fatalf("missing %s", key)
		}
		return out
	}
	const rpc = `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"doctor","arguments":{}}}`
	call("POST", "/mcp", "application/json", rpc, "", 401)
	_, b := call("POST", "/oauth/register", "application/json", `{"client_name":"OpenClaw MCP","redirect_uris":["http://127.0.0.1:8989/oauth/callback"],"token_endpoint_auth_method":"none"}`, "", 201)
	id := field(b, "client_id")
	verifier := newSecret()
	q := url.Values{"client_id": {id}, "resource": {srv.URL + "/mcp"}, "response_type": {"code"}, "redirect_uri": {"http://127.0.0.1:8989/oauth/callback"}, "code_challenge": {digest(verifier)}, "code_challenge_method": {"S256"}, "state": {"opaque"}}
	h, _ := call("GET", "/oauth/authorize?"+q.Encode(), "", "", "", 303)
	_, query, ok := strings.Cut(h.Get("Location"), "#mcp?")
	if !ok {
		t.Fatal("consent redirect missing")
	}
	body, _ := json.Marshal(map[string]string{"query": query})
	_, b = call("POST", "/api/v1/integrations/mcp/approve", "application/json", string(body), admin, 200)
	callback, err := url.Parse(field(b, "redirect"))
	if err != nil || callback.Query().Get("state") != "opaque" {
		t.Fatal("invalid callback")
	}
	form := url.Values{"client_id": {id}, "resource": {srv.URL + "/mcp"}, "grant_type": {"authorization_code"}, "redirect_uri": {q.Get("redirect_uri")}, "code": {callback.Query().Get("code")}, "code_verifier": {newSecret()}}
	const formType = "application/x-www-form-urlencoded"
	call("POST", "/oauth/token", formType, form.Encode(), "", 400)
	form.Set("code_verifier", verifier)
	_, b = call("POST", "/oauth/token", formType, form.Encode(), "", 200)
	call("POST", "/oauth/token", formType, form.Encode(), "", 400)
	refresh := url.Values{"grant_type": {"refresh_token"}, "client_id": {id}, "refresh_token": {field(b, "refresh_token")}}
	_, b = call("POST", "/oauth/token", formType, refresh.Encode(), "", 200)
	token := field(b, "access_token")
	refresh.Set("refresh_token", field(b, "refresh_token"))
	_, b = call("POST", "/mcp", "application/json", rpc, token, 200)
	var reply struct {
		Result struct {
			Content []struct{ Text string }
			IsError bool
		}
	}
	if err = json.Unmarshal(b, &reply); err != nil || reply.Result.IsError || len(reply.Result.Content) != 1 || field([]byte(reply.Result.Content[0].Text), "database") != "ok" {
		t.Fatalf("doctor did not return ready PostgreSQL: %s", b)
	}
	alias := httptest.NewTLSServer(srv.Config.Handler)
	defer alias.Close()
	origin = alias.URL
	call("POST", "/mcp", "application/json", rpc, token, 401)
	const grants = "/api/v1/integrations/mcp/grants"
	_, b = call("GET", grants, "", "", admin, 200)
	var list []store.MCPGrant
	if err = json.Unmarshal(b, &list); err != nil {
		t.Fatal(err)
	}
	var grantID string
	for _, grant := range list {
		if grant.ApprovedBy == user && grant.Issuer == srv.URL && grant.RedirectURI == q.Get("redirect_uri") && grant.LastUsed != nil {
			grantID = grant.ID
		}
	}
	if grantID == "" {
		t.Fatal("grant from original issuer missing on alternate management address")
	}
	call("DELETE", grants+"/"+grantID, "", "", admin, 204)
	origin = srv.URL
	call("POST", "/mcp", "application/json", rpc, token, 401)
	call("POST", "/oauth/token", formType, refresh.Encode(), "", 400)
}
