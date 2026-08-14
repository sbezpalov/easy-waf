package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/easy-waf/easy-waf/internal/config"
	"github.com/easy-waf/easy-waf/internal/engine"
)

func TestTrustedRealIP_IgnoresSpoofedHeaderFromUntrustedPeer(t *testing.T) {
	var got string
	h := TrustedRealIP(defaultTrustedProxyCIDRs())(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip, ok := clientIP(r)
		if ok {
			got = ip.String()
		}
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "203.0.113.50:12345"
	req.Header.Set("X-Forwarded-For", "127.0.0.1")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if got != "203.0.113.50" {
		t.Fatalf("expected direct peer IP, got %q", got)
	}
}

func TestTrustedRealIP_TrustsHeaderFromLoopbackPeer(t *testing.T) {
	var got string
	h := TrustedRealIP(defaultTrustedProxyCIDRs())(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip, ok := clientIP(r)
		if ok {
			got = ip.String()
		}
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "127.0.0.1:54321"
	req.Header.Set("X-Forwarded-For", "192.168.1.50")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if got != "192.168.1.50" {
		t.Fatalf("expected forwarded client IP, got %q", got)
	}
}

func TestTrustedRealIP_UsesProxyAppendedRightmostAddress(t *testing.T) {
	var got string
	h := TrustedRealIP(defaultTrustedProxyCIDRs())(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		ip, _ := clientIP(r)
		got = ip.String()
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "127.0.0.1:54321"
	req.Header.Set("X-Forwarded-For", "127.0.0.1, 192.168.1.50")
	h.ServeHTTP(httptest.NewRecorder(), req)
	if got != "192.168.1.50" {
		t.Fatalf("expected proxy-provided rightmost IP, got %q", got)
	}
}

func TestTrustedRealIP_IgnoresAlternateClientIPHeaders(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("True-Client-IP", "127.0.0.1")
	req.Header.Set("X-Real-IP", "127.0.0.1")
	if got := clientIPFromForwardingHeaders(req); got != "" {
		t.Fatalf("unexpected client IP %q", got)
	}
}

func TestManagementACL_RejectsSpoofedXFFFromWAN(t *testing.T) {
	eng := &engine.Engine{
		Settings: config.GlobalSettings{
			ManagementAllowedCIDRs: []string{"127.0.0.0/8", "192.168.0.0/16"},
		},
	}
	s := &Server{Eng: eng, JWTSecret: []byte("test-secret")}
	r := httptest.NewRequest(http.MethodGet, "/api/v1/applications", nil)
	r.RemoteAddr = "203.0.113.50:12345"
	r.Header.Set("X-Forwarded-For", "127.0.0.1")
	rec := httptest.NewRecorder()
	s.Router().ServeHTTP(rec, r)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("spoofed XFF from WAN peer should be denied by ACL, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestManagementACL_AllowsForwardedLANViaLoopbackProxy(t *testing.T) {
	eng := &engine.Engine{
		Settings: config.GlobalSettings{
			ManagementAllowedCIDRs: []string{"127.0.0.0/8", "192.168.0.0/16"},
		},
	}
	s := &Server{Eng: eng, JWTSecret: []byte("test-secret")}
	r := httptest.NewRequest(http.MethodGet, "/api/v1/applications", nil)
	r.RemoteAddr = "127.0.0.1:12345"
	r.Header.Set("X-Forwarded-For", "192.168.1.50")
	rec := httptest.NewRecorder()
	s.Router().ServeHTTP(rec, r)
	if rec.Code == http.StatusForbidden {
		t.Fatalf("LAN client via loopback proxy should pass ACL, got %d body=%s", rec.Code, rec.Body.String())
	}
}
