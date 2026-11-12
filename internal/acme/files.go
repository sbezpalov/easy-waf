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

// WriteCertificateResource writes Lego output to *.pem.new sidecars and returns
// the final paths. Call PromoteCertificateFiles after the DB commit so a crash
// mid-transaction never leaves new PEMs with a row still "issuing".
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
	if err := apply.WriteAtomic(keyPath+".new", res.PrivateKey, 0o600); err != nil {
		return "", "", time.Time{}, time.Time{}, err
	}
	if err := apply.WriteAtomic(fullchainPath+".new", res.Certificate, 0o600); err != nil {
		_ = os.Remove(keyPath + ".new")
		return "", "", time.Time{}, time.Time{}, err
	}
	return fullchainPath, keyPath, nb, na, nil
}

// PromoteCertificateFiles renames *.pem.new into the live PEM paths after the
// certificate row has been committed ready.
func PromoteCertificateFiles(fullchainPath, keyPath string) error {
	oldKey, oldKeyErr := os.ReadFile(keyPath)
	oldFull, oldFullErr := os.ReadFile(fullchainPath)
	if err := os.Rename(keyPath+".new", keyPath); err != nil {
		_ = os.Remove(keyPath + ".new")
		_ = os.Remove(fullchainPath + ".new")
		return err
	}
	if err := os.Rename(fullchainPath+".new", fullchainPath); err != nil {
		// Never leave a new key next to the old chain.
		if oldKeyErr == nil {
			_ = apply.WriteAtomic(keyPath, oldKey, 0o600)
		}
		if oldFullErr == nil {
			_ = apply.WriteAtomic(fullchainPath, oldFull, 0o600)
		}
		_ = os.Remove(fullchainPath + ".new")
		return err
	}
	return nil
}

// DiscardCertificateStaging removes *.pem.new left after a failed commit.
func DiscardCertificateStaging(fullchainPath, keyPath string) {
	_ = os.Remove(keyPath + ".new")
	_ = os.Remove(fullchainPath + ".new")
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
