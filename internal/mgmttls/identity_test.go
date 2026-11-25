// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package mgmttls

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestNamedManagementTLS(t *testing.T) {
	certPath, keyPath, err := EnsureSelfSigned(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	first := new(Manager)
	const name = "waf.home.arpa"
	info, err := first.SetIdentity(certPath, name, "", false)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(info.Certificate, "PRIVATE") {
		t.Fatal("private material in response")
	}
	same, err := first.SetIdentity(certPath, name, "", false)
	if err != nil || same.SHA256 != info.SHA256 {
		t.Fatalf("retry changed trust: %v", err)
	}
	m := new(Manager)
	if err = m.LoadFromFiles(certPath, keyPath); err != nil {
		t.Fatal(err)
	}
	if err = m.LoadIdentity(certPath); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defaultCert, _ := m.GetCertificate(nil)
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: m.GetCertificate, Certificates: []tls.Certificate{*defaultCert}}
	server.StartTLS()
	defer server.Close()
	dial := func(sni, pub string) error {
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM([]byte(pub)) {
			t.Fatal("bad public certificate")
		}
		c, err := tls.Dial("tcp", server.Listener.Addr().String(), &tls.Config{MinVersion: tls.VersionTLS12, ServerName: sni, RootCAs: roots})
		if err == nil {
			c.Close()
		}
		return err
	}
	if err = dial(name, info.Certificate); err != nil {
		t.Fatal(err)
	}
	bootstrap, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	if err = dial("127.0.0.1", string(bootstrap)); err != nil {
		t.Fatal(err)
	}
	next, err := m.SetIdentity(certPath, name, info.SHA256, true)
	if err != nil || next.SHA256 == info.SHA256 {
		t.Fatalf("renewal: %v", err)
	}
	if dial(name, info.Certificate) == nil || dial(name, next.Certificate) != nil {
		t.Fatal("unexpected trust after renewal")
	}
	if _, err = m.SetIdentity(certPath, name, info.SHA256, true); err != ErrIdentityChanged {
		t.Fatal("stale renewal should preserve the active certificate")
	}
	if err = m.RemoveIdentity(certPath, info.SHA256); err != ErrIdentityChanged {
		t.Fatal("stale removal should preserve the active certificate")
	}
	if err = m.RemoveIdentity(certPath, next.SHA256); err != nil {
		t.Fatal(err)
	}
	if dial(name, next.Certificate) == nil || dial("127.0.0.1", string(bootstrap)) != nil {
		t.Fatal("unexpected trust after removal")
	}
	if _, err = os.Stat(identityPath(certPath)); !os.IsNotExist(err) {
		t.Fatal("identity still on disk")
	}
}
