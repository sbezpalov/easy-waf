// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package acme

import (
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

// WriteCertificateResource writes Lego output to PEM files and returns paths + validity window.
func WriteCertificateResource(stateDir, certID string, res *certificate.Resource) (fullchainPath, keyPath string, notBefore, notAfter time.Time, err error) {
	if res == nil {
		return "", "", time.Time{}, time.Time{}, fmt.Errorf("nil resource")
	}
	if err := config.ValidateResourceID("certificate", certID); err != nil {
		return "", "", time.Time{}, time.Time{}, err
	}
	dir := filepath.Join(stateDir, "certs", certID)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return "", "", time.Time{}, time.Time{}, err
	}
	fullchainPath = filepath.Join(dir, "fullchain.pem")
	keyPath = filepath.Join(dir, "privkey.pem")
	// Parse before touching disk so a malformed chain never replaces a good one.
	nb, na, err := parseFirstCertTimes(res.Certificate)
	if err != nil {
		return "", "", time.Time{}, time.Time{}, err
	}
	// Each file is replaced atomically; callers hold the HAProxy apply lock so
	// no render reads the pair between the two renames.
	oldKey, oldKeyErr := os.ReadFile(keyPath)
	if err := apply.WriteAtomic(keyPath, res.PrivateKey, 0o600); err != nil {
		return "", "", time.Time{}, time.Time{}, err
	}
	if err := apply.WriteAtomic(fullchainPath, res.Certificate, 0o600); err != nil {
		// Never leave a new key next to the old chain: that pair fails haproxy -c
		// and would block every later apply.
		if oldKeyErr == nil {
			_ = apply.WriteAtomic(keyPath, oldKey, 0o600)
		} else {
			_ = os.Remove(keyPath)
		}
		return "", "", time.Time{}, time.Time{}, err
	}
	return fullchainPath, keyPath, nb, na, nil
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
