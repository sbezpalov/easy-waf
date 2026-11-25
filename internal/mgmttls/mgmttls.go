// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

// Package mgmttls holds the management UI TLS certificate (self-signed bootstrap + optional user PEM from API).
package mgmttls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/easy-waf/easy-waf/internal/apply"
)

// Paths returns filesystem paths for the management TLS PEM pair under stateDir/secrets/.
func Paths(stateDir string) (certPath, keyPath string) {
	d := filepath.Join(stateDir, "secrets")
	return filepath.Join(d, "management.crt"), filepath.Join(d, "management.key")
}

// Manager holds the in-memory certificate for tls.Config.GetCertificate (hot reload after API upload).
type Manager struct {
	v       atomic.Value // *tls.Certificate
	named   atomic.Pointer[tls.Certificate]
	namedMu sync.Mutex
}

func (m *Manager) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if cert := m.named.Load(); cert != nil && hello != nil && strings.EqualFold(hello.ServerName, cert.Leaf.DNSNames[0]) {
		return cert, nil
	}
	x := m.v.Load()
	if x == nil {
		return nil, fmt.Errorf("management tls: no certificate loaded")
	}
	return x.(*tls.Certificate), nil
}

// LoadFromFiles reads PEM pair from disk into the manager.
func (m *Manager) LoadFromFiles(certPath, keyPath string) error {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return err
	}
	m.v.Store(&cert)
	return nil
}

// ErrInvalidPEMPair marks a certificate/key pair that does not parse or match:
// the caller's fault, unlike a failure to write the files.
var ErrInvalidPEMPair = errors.New("invalid pem pair")

// Store validates PEM material, persists atomically, and updates the manager.
func (m *Manager) Store(certPath, keyPath string, certPEM, keyPEM []byte) error {
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidPEMPair, err)
	}
	if err := writePEMAtomic(certPath, certPEM, 0o644); err != nil {
		return err
	}
	if err := writePEMAtomic(keyPath, keyPEM, 0o600); err != nil {
		return err
	}
	m.v.Store(&cert)
	return nil
}

// EnsureSelfSigned creates a long-lived self-signed ECDSA certificate if files are missing.
func EnsureSelfSigned(stateDir string) (certPath, keyPath string, err error) {
	certPath, keyPath = Paths(stateDir)
	if err := os.MkdirAll(filepath.Dir(certPath), 0o700); err != nil {
		return "", "", err
	}
	if fileExists(certPath) && fileExists(keyPath) {
		return certPath, keyPath, nil
	}
	certPEM, keyPEM, err := selfSigned("easy-waf-management", []string{"localhost", "easy-waf-management"}, []net.IP{net.IPv4(127, 0, 0, 1)}, time.Now().AddDate(10, 0, 0))
	if err != nil {
		return "", "", err
	}
	if err := writePEMAtomic(certPath, certPEM, 0o644); err != nil {
		return "", "", err
	}
	if err := writePEMAtomic(keyPath, keyPEM, 0o600); err != nil {
		return "", "", err
	}
	return certPath, keyPath, nil
}

func selfSigned(name string, names []string, ips []net.IP, expires time.Time) ([]byte, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}
	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{"Easy Home WAF"},
			CommonName:   name,
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              expires,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              names,
		IPAddresses:           ips,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, key.Public(), key)
	if err != nil {
		return nil, nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM, nil
}

func writePEMAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return apply.WriteAtomic(path, data, perm)
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}
