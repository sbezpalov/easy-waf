// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package acme

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/easy-waf/easy-waf/internal/apply"
	"github.com/easy-waf/easy-waf/internal/config"
	"github.com/go-acme/lego/v4/certificate"
)

// WriteCertificateResource writes a validated pair into a fresh private generation.
// Only commit these immutable paths after both files are complete. Interrupted or
// ambiguous DB commits may leave an unreferenced generation; never remove it on
// a commit error, because the DB may have committed despite a lost acknowledgement.
func WriteCertificateResource(stateDir, certID string, res *certificate.Resource) (fullchainPath, keyPath string, notBefore, notAfter time.Time, err error) {
	if res == nil {
		return "", "", time.Time{}, time.Time{}, fmt.Errorf("nil resource")
	}
	if err := config.ValidateResourceID("certificate", certID); err != nil {
		return "", "", time.Time{}, time.Time{}, err
	}
	// Parse before touching disk so a malformed chain never replaces a good one.
	if _, err := tls.X509KeyPair(res.Certificate, res.PrivateKey); err != nil {
		return "", "", time.Time{}, time.Time{}, fmt.Errorf("certificate key pair: %w", err)
	}
	nb, na, err := parseFirstCertTimes(res.Certificate)
	if err != nil {
		return "", "", time.Time{}, time.Time{}, err
	}
	parent := filepath.Join(stateDir, "certs", certID)
	if err := os.MkdirAll(parent, 0o750); err != nil {
		return "", "", time.Time{}, time.Time{}, err
	}
	dir, err := os.MkdirTemp(parent, "generation-*")
	if err != nil {
		return "", "", time.Time{}, time.Time{}, err
	}
	fullchainPath = filepath.Join(dir, "fullchain.pem")
	keyPath = filepath.Join(dir, "privkey.pem")
	defer func(full, key string) {
		if err != nil {
			_ = os.Remove(key)
			_ = os.Remove(full)
			_ = os.Remove(dir)
		}
	}(fullchainPath, keyPath)
	if err = apply.WriteAtomic(keyPath, res.PrivateKey, 0o600); err != nil {
		return "", "", time.Time{}, time.Time{}, err
	}
	if err = apply.WriteAtomic(fullchainPath, res.Certificate, 0o600); err != nil {
		return "", "", time.Time{}, time.Time{}, err
	}
	// The render policy uses forward-slash paths on Windows development hosts
	// as well as Unix; os file APIs accept them on both platforms.
	return filepath.ToSlash(fullchainPath), filepath.ToSlash(keyPath), nb, na, nil
}

// SaveOrphanCertificateResource keeps PEMs when the ACME claim was lost after a
// successful Obtain so Let's Encrypt quota is not thrown away. Files land under
// certs/<id>/orphan-<stamp>/ for operator recovery / later reuse.
func SaveOrphanCertificateResource(stateDir, certID string, res *certificate.Resource) (string, error) {
	if res == nil {
		return "", fmt.Errorf("nil resource")
	}
	if err := config.ValidateResourceID("certificate", certID); err != nil {
		return "", err
	}
	dir := filepath.Join(stateDir, "certs", certID, "orphan-"+time.Now().UTC().Format("20060102-150405"))
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return "", err
	}
	if err := apply.WriteAtomic(filepath.Join(dir, "fullchain.pem"), res.Certificate, 0o600); err != nil {
		return "", err
	}
	if err := apply.WriteAtomic(filepath.Join(dir, "privkey.pem"), res.PrivateKey, 0o600); err != nil {
		return "", err
	}
	return dir, nil
}

func parseFirstCertTimes(pemChain []byte) (time.Time, time.Time, error) {
	var block *pem.Block
	rest := pemChain
	for len(rest) > 0 {
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return time.Time{}, time.Time{}, err
		}
		return cert.NotBefore, cert.NotAfter, nil
	}
	return time.Time{}, time.Time{}, fmt.Errorf("no certificate in PEM")
}
