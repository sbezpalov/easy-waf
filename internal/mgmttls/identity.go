// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package mgmttls

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/easy-waf/easy-waf/internal/host/hostspec"
)

var ErrIdentityChanged = errors.New("management identity changed; reload System before retrying")

type Identity struct {
	Hostname    string    `json:"hostname"`
	Certificate string    `json:"certificate_pem"`
	SHA256      string    `json:"sha256"`
	Expires     time.Time `json:"expires_at"`
}

func identityPath(defaultCert string) string {
	return filepath.Join(filepath.Dir(defaultCert), "management-identity.pem")
}

func describeIdentity(cert *tls.Certificate) Identity {
	raw := cert.Certificate[0]
	sum := sha256.Sum256(raw)
	return Identity{
		Hostname:    cert.Leaf.DNSNames[0],
		Certificate: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw})),
		SHA256:      hex.EncodeToString(sum[:]),
		Expires:     cert.Leaf.NotAfter,
	}
}

func (m *Manager) Identity() *Identity {
	if cert := m.named.Load(); cert != nil {
		info := describeIdentity(cert)
		return &info
	}
	return nil
}

func parseIdentity(bundle []byte) (*tls.Certificate, error) {
	cert, err := tls.X509KeyPair(bundle, bundle)
	if err != nil {
		return nil, err
	}
	cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, err
	}
	if len(cert.Leaf.DNSNames) != 1 || !hostspec.ValidManagementName(cert.Leaf.DNSNames[0]) {
		return nil, errors.New("invalid management identity DNS name")
	}
	return &cert, nil
}

func (m *Manager) LoadIdentity(defaultCert string) error {
	data, err := os.ReadFile(identityPath(defaultCert))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	cert, err := parseIdentity(data)
	if err == nil {
		m.named.Store(cert)
	}
	return err
}

// SetIdentity publishes the complete named pair in one rename before enabling SNI.
// A retry for the same valid identity preserves trust already installed on clients.
func (m *Manager) SetIdentity(defaultCert, name, expected string, renew bool) (Identity, error) {
	m.namedMu.Lock()
	defer m.namedMu.Unlock()
	if !hostspec.ValidManagementName(name) {
		return Identity{}, errors.New("invalid management DNS name")
	}
	current := m.Identity()
	if current != nil && current.Hostname == name && !renew && time.Now().Before(current.Expires) {
		return *current, nil
	}
	if (current == nil && expected != "") || (current != nil && current.SHA256 != expected) {
		return Identity{}, ErrIdentityChanged
	}
	pub, key, err := selfSigned(name, []string{name}, nil, time.Now().AddDate(1, 0, 0))
	if err != nil {
		return Identity{}, err
	}
	bundle := slices.Concat(pub, key)
	cert, err := parseIdentity(bundle)
	if err != nil {
		return Identity{}, err
	}
	if err := writePEMAtomic(identityPath(defaultCert), bundle, 0o600); err != nil {
		return Identity{}, err
	}
	m.named.Store(cert)
	return describeIdentity(cert), nil
}

func (m *Manager) RemoveIdentity(defaultCert, expected string) error {
	m.namedMu.Lock()
	defer m.namedMu.Unlock()
	if current := m.Identity(); current != nil && current.SHA256 != expected {
		return ErrIdentityChanged
	}
	if err := os.Remove(identityPath(defaultCert)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	m.named.Store(nil)
	return nil
}
