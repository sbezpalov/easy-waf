package bootstrap

import (
	"testing"
)

func TestResolveManagementHTTP_defaultOff(t *testing.T) {
	t.Setenv("EASY_WAF_LISTEN_HTTP", "")
	t.Setenv("EASY_WAF_LISTEN", "")
	t.Setenv("EASY_WAF_ALLOW_INSECURE_HTTP", "")
	d := ResolveManagementHTTP("", "")
	if d.Addr != "" || d.Refused {
		t.Fatalf("%+v", d)
	}
}

func TestResolveManagementHTTP_explicitOff(t *testing.T) {
	t.Setenv("EASY_WAF_ALLOW_INSECURE_HTTP", "")
	d := ResolveManagementHTTP("off", "")
	if d.Addr != "" {
		t.Fatalf("%+v", d)
	}
}

func TestResolveManagementHTTP_loopback(t *testing.T) {
	t.Setenv("EASY_WAF_ALLOW_INSECURE_HTTP", "")
	d := ResolveManagementHTTP("127.0.0.1:8000", "")
	if d.Addr != "127.0.0.1:8000" || !d.Loopback || d.Insecure {
		t.Fatalf("%+v", d)
	}
}

func TestResolveManagementHTTP_ipv6Loopback(t *testing.T) {
	t.Setenv("EASY_WAF_ALLOW_INSECURE_HTTP", "")
	d := ResolveManagementHTTP("[::1]:8000", "")
	if !d.Loopback || d.Addr == "" {
		t.Fatalf("%+v", d)
	}
}

func TestResolveManagementHTTP_nonLoopbackRequiresAllow(t *testing.T) {
	t.Setenv("EASY_WAF_ALLOW_INSECURE_HTTP", "")
	d := ResolveManagementHTTP("0.0.0.0:8000", "")
	if !d.Refused || d.Addr != "" {
		t.Fatalf("expected refuse, got %+v", d)
	}
}

func TestResolveManagementHTTP_legacyAllow(t *testing.T) {
	t.Setenv("EASY_WAF_ALLOW_INSECURE_HTTP", "1")
	d := ResolveManagementHTTP("0.0.0.0:8000", "")
	if d.Addr != "0.0.0.0:8000" || !d.Insecure || d.Warning == "" {
		t.Fatalf("%+v", d)
	}
}

func TestResolveManagementHTTPS_default(t *testing.T) {
	t.Setenv("EASY_WAF_LISTEN_HTTPS", "")
	if got := ResolveManagementHTTPS("", false); got != "0.0.0.0:8443" {
		t.Fatalf("%s", got)
	}
	if got := ResolveManagementHTTPS("", true); got != "" {
		t.Fatalf("disabled: %s", got)
	}
}

func TestAcmeInternalListenUnchanged(t *testing.T) {
	t.Setenv("EASY_WAF_ACME_INTERNAL_HTTP", "")
	if acmeInternalListenAddr() != "127.0.0.1:8089" {
		t.Fatal(acmeInternalListenAddr())
	}
}
