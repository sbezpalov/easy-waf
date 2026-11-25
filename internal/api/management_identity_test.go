// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/easy-waf/easy-waf/internal/mgmttls"
)

func TestManagementIdentityLifecycle(t *testing.T) {
	certPath, _, err := mgmttls.EnsureSelfSigned(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{MgmtTLS: new(mgmttls.Manager), MgmtTLSCertPath: certPath}
	request := func(method, scheme, body, fingerprint string, want int) string {
		t.Helper()
		req := httptest.NewRequest(method, scheme+"://management.example/api/v1/settings/management-identity", strings.NewReader(body))
		req.Header.Set("X-Identity-SHA256", fingerprint)
		rec := httptest.NewRecorder()
		s.managementIdentity(rec, req)
		if rec.Code != want || strings.Contains(rec.Body.String(), "PRIVATE KEY") {
			t.Fatalf("%s status %d, want %d", method, rec.Code, want)
		}
		return strings.TrimSpace(rec.Body.String())
	}
	request(http.MethodPut, "http", `{"hostname":"test"}`, "", 400)
	request(http.MethodPut, "https", `{"hostname":"*.example"}`, "", 400)
	payload := request(http.MethodPut, "https", `{"hostname":"WAF.Home.Arpa."}`, "", 200)
	var id mgmttls.Identity
	if err := json.Unmarshal([]byte(payload), &id); err != nil || id.Hostname != "waf.home.arpa" || len(id.SHA256) != 64 {
		t.Fatal("invalid generated identity")
	}
	if got := request(http.MethodGet, "https", "", "", 200); got != payload {
		t.Fatal("readback differs")
	}
	request(http.MethodDelete, "https", "", "old", 409)
	request(http.MethodDelete, "https", "", id.SHA256, 204)
	if got := request(http.MethodGet, "https", "", "", 200); got != "null" {
		t.Fatal("removed identity returned")
	}
}
